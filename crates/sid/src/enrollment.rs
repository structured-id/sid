// SPDX-License-Identifier: AGPL-3.0-only
//! Enrollment: the policy in force (the one an administrator stored, else the
//! defaults, with the mode the deployment pins, if it pins one), invite codes
//! and registration statistics. The same operations for the service and an
//! embedding application. The policy is read from the store on every use,
//! so every replica applies a change at once.

use std::sync::Arc;

use prost::Message;
use sid_authn::caller::{Caller, CallerError};
use sid_authn::operation::{CommandError, Effect, KeyedCommand, OperationError};
use sid_core::Error as SidError;
use sid_core::models::{
    AuditEntry, EnrollmentMode, EnrollmentPolicy, Invite, InviteCreator, InviteFilter, InviteId,
    InviteStatus, MachineUserId, ModeWrite, MutationContext, OperationContext, ProfileId,
    SecurityPolicy, generate_invite_code,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::admin::enrollment_service as keyed;
use sid_proto::sid::v1::admin as v1;
use tracing::info;

use crate::wire::{FieldError, stored_id, to_timestamp, wire_id};

/// Invites one bulk request creates at most.
const MAX_BULK_INVITES: u32 = 100;
/// Invites one listing page holds by default, and at most.
const DEFAULT_PAGE_SIZE: u64 = 50;
const MAX_PAGE_SIZE: u64 = 500;

/// The largest use limit an invite stores (a signed 32-bit column).
pub const MAX_INVITE_USES: u32 = i32::MAX as u32;

/// The stored policy, or the defaults while none is stored.
pub async fn stored_or_default(storage: &dyn StorageBackend) -> sid_core::Result<EnrollmentPolicy> {
    Ok(storage
        .enrollment_policy()
        .await?
        .unwrap_or_else(|| SecurityPolicy::ce_default().enrollment))
}

/// The policy in force: the stored one with the pinned mode over its own.
pub async fn effective(
    storage: &dyn StorageBackend,
    pinned: Option<EnrollmentMode>,
) -> sid_core::Result<EnrollmentPolicy> {
    let mut policy = stored_or_default(storage).await?;
    if let Some(mode) = pinned {
        policy.mode = mode;
    }
    Ok(policy)
}

/// Why an administrator's policy is not stored.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The deployment pins another mode.
    #[error("the deployment pins the enrollment mode to {0}")]
    Pinned(EnrollmentMode),
    /// Domain-restricted enrollment without any domain would admit no one
    /// while looking configured.
    #[error("a domain-restricted policy needs at least one allowed domain")]
    NoDomain,
    /// An allowed domain that is not a domain name.
    #[error("{0:?} is not a domain name")]
    BadDomain(String),
    /// A default use limit above what an invite can store.
    #[error("the default invite use limit is at most {MAX_INVITE_USES}")]
    TooManyUses,
    /// A default expiry later than any representable time.
    #[error("the default invite expiry is too far in the future")]
    ExpiryTooFar,
}

/// When an invite created at `now` expires under a default of `hours`
/// (0: never); `None` when that time cannot be represented.
pub fn default_expiry(
    now: chrono::DateTime<chrono::Utc>,
    hours: u32,
) -> Option<Option<chrono::DateTime<chrono::Utc>>> {
    if hours == 0 {
        return Some(None);
    }
    chrono::TimeDelta::try_hours(i64::from(hours))
        .and_then(|delta| now.checked_add_signed(delta))
        .map(Some)
}

/// `policy` as it is stored: allowed domains trimmed, lowercased and without
/// repeats (registration compares them case-insensitively). While a mode is
/// pinned the request carries that mode, as the API reports it, and the
/// `stored_mode` is kept, so removing the pin restores it. Refused when it
/// changes a pinned mode, leaves a domain-restricted mode (stored or pinned)
/// without a usable domain, or sets a default use limit no invite can hold.
pub fn validated(
    mut policy: EnrollmentPolicy,
    pinned: Option<EnrollmentMode>,
    stored_mode: EnrollmentMode,
) -> Result<EnrollmentPolicy, Refusal> {
    if let Some(mode) = pinned {
        if policy.mode != mode {
            return Err(Refusal::Pinned(mode));
        }
        policy.mode = stored_mode;
    }
    if policy.invite.default_max_uses > MAX_INVITE_USES {
        return Err(Refusal::TooManyUses);
    }
    if default_expiry(chrono::Utc::now(), policy.invite.default_expiry_hours).is_none() {
        return Err(Refusal::ExpiryTooFar);
    }
    let mut domains = Vec::with_capacity(policy.allowed_domains.len());
    for domain in &policy.allowed_domains {
        let domain = domain.trim().to_ascii_lowercase();
        // Host name syntax, RFC 1035 §2.3.1 as relaxed by RFC 1123 §2.1
        // (labels may start with a digit); an IDN appears in its A-label form.
        let valid = !domain.is_empty()
            && domain.len() <= 253
            && domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        if !valid {
            return Err(Refusal::BadDomain(domain));
        }
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    // The domains apply under the mode in force (a pinned one) and under the
    // stored one once the pin is removed.
    let restricted = |mode: Option<EnrollmentMode>| mode == Some(EnrollmentMode::DomainRestricted);
    if (restricted(Some(policy.mode)) || restricted(pinned)) && domains.is_empty() {
        return Err(Refusal::NoDomain);
    }
    policy.allowed_domains = domains;
    Ok(policy)
}

/// Why an enrollment operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The keyed command conflicts, is refused its period or its outcome is
    /// unknown.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation (a broken invariant); its cause is in
    /// the log, not the refusal.
    #[error("internal error")]
    Internal,
    /// A required field is absent.
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// The deployment pins the mode the update would change.
    #[error("{0}")]
    ModePinned(Refusal),
    #[error("invite {0} not found")]
    InviteNotFound(InviteId),
}

impl From<EnrollmentError> for Effect<EnrollmentError> {
    fn from(e: EnrollmentError) -> Self {
        Self::Refused(e)
    }
}

impl From<CommandError<EnrollmentError>> for EnrollmentError {
    fn from(e: CommandError<EnrollmentError>) -> Self {
        e.refusal()
    }
}

impl From<FieldError> for EnrollmentError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

fn invalid_field(field: &'static str, reason: impl Into<String>) -> EnrollmentError {
    EnrollmentError::InvalidField {
        field,
        reason: reason.into(),
    }
}

/// An internal failure of `operation`: logged with its cause.
fn internal(operation: &'static str, cause: impl std::fmt::Display) -> EnrollmentError {
    tracing::error!(operation, error = %cause, "internal failure");
    EnrollmentError::Internal
}

/// Who manages an invite: an administrator Profile, or a machine user the
/// host admitted to the invite action (a token for the enrollment API with
/// the action in its scopes and granted on that resource).
#[derive(Debug, Clone, Copy)]
pub enum Inviter {
    Administrator(ProfileId),
    Machine(MachineUserId),
}

impl Inviter {
    /// `caller` as an inviter: only an administrator manages invites.
    pub fn administrator(caller: &Caller) -> Result<Self, EnrollmentError> {
        caller.require_admin()?;
        Ok(Self::Administrator(caller.profile_id))
    }

    fn creator(self) -> InviteCreator {
        match self {
            Self::Administrator(id) => InviteCreator::Profile(id),
            Self::Machine(id) => InviteCreator::MachineUser(id),
        }
    }

    /// The audit entry of `action` on `resource` with this inviter.
    fn audit(self, action: &str, resource: String) -> AuditEntry {
        match self {
            Self::Administrator(id) => AuditEntry::admin(id.to_string(), action, resource),
            Self::Machine(id) => AuditEntry::machine(id.to_string(), action, resource),
        }
    }

    /// This inviter's command `M` of `req` under `context`: an
    /// administrator's in its Profile's namespace, a machine user's in its own.
    fn command<M: sid_proto::KeyedMethod>(
        self,
        context: OperationContext,
        req: &M::Request,
    ) -> KeyedCommand {
        match self {
            Self::Administrator(id) => KeyedCommand::by_profile::<M>(id, context, req),
            Self::Machine(id) => KeyedCommand::of::<M>(format!("machine:{id}"), context, req),
        }
    }
}

/// An invite expiry: a valid timestamp in the future, never replaced by
/// another value.
fn invite_expiry(
    ts: Option<prost_types::Timestamp>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, EnrollmentError> {
    ts.map(|ts| {
        u32::try_from(ts.nanos)
            .ok()
            .and_then(|nanos| chrono::DateTime::from_timestamp(ts.seconds, nanos))
            .filter(|at| *at > chrono::Utc::now())
            .ok_or_else(|| invalid_field("expires_at", "not a timestamp in the future"))
    })
    .transpose()
}

/// The listing filter of a request: an undefined status value is refused,
/// never read as "any status".
fn invite_filter(status: i32, search: &str) -> Result<InviteFilter, EnrollmentError> {
    use v1::InviteStatus as P;
    let status = match P::try_from(status) {
        Ok(P::Unspecified) => None,
        Ok(P::Active) => Some(InviteStatus::Active),
        Ok(P::Consumed) => Some(InviteStatus::Consumed),
        Ok(P::Revoked) => Some(InviteStatus::Revoked),
        Ok(P::Expired) => Some(InviteStatus::Expired),
        Err(_) => return Err(invalid_field("status", "not an invite status")),
    };
    let search = search.trim();
    Ok(InviteFilter {
        status,
        search: (!search.is_empty()).then(|| search.to_string()),
    })
}

/// The offset a page token names: empty is the first page; any other token
/// is one this engine issued, bounded to i64 (the stores take a BIGINT).
fn page_offset(token: &str) -> Result<u64, EnrollmentError> {
    if token.is_empty() {
        return Ok(0);
    }
    token
        .parse::<i64>()
        .ok()
        .and_then(|o| u64::try_from(o).ok())
        .ok_or_else(|| invalid_field("page_token", "not a token this service issued"))
}

/// AIP-158: a page size above the maximum is coerced to it.
fn page_limit(size: u32) -> u64 {
    match u64::from(size) {
        0 => DEFAULT_PAGE_SIZE,
        n => n.min(MAX_PAGE_SIZE),
    }
}

/// The token of the page after `offset`: a full page may have a next one; an
/// offset past BIGINT has none.
fn next_page(offset: u64, limit: u64, returned: usize) -> String {
    offset
        .checked_add(limit)
        .filter(|next| returned as u64 == limit && i64::try_from(*next).is_ok())
        .map(|next| next.to_string())
        .unwrap_or_default()
}

/// The enrollment of one installation.
pub struct Enrollment {
    storage: Arc<dyn StorageBackend>,
    /// The enrollment mode the deployment pins over the stored one.
    pinned_mode: Option<EnrollmentMode>,
}

impl Enrollment {
    pub fn new(storage: Arc<dyn StorageBackend>, pinned_mode: Option<EnrollmentMode>) -> Self {
        Self {
            storage,
            pinned_mode,
        }
    }

    /// The policy in force, as the API reports it.
    pub async fn policy_in_force(&self) -> Result<v1::EnrollmentPolicy, EnrollmentError> {
        let policy = effective(self.storage.as_ref(), self.pinned_mode).await?;
        let mut proto = policy_to_proto(&policy);
        proto.mode_pinned = self.pinned_mode.is_some();
        Ok(proto)
    }

    /// Whether the administrator claim is open: public, since the
    /// registration page asks for the claim token while it is.
    pub async fn instance_status(&self) -> Result<v1::InstanceStatus, EnrollmentError> {
        use sid_authn::admin_claim::ClaimState;
        let claim = match sid_authn::admin_claim::state(self.storage.as_ref()).await? {
            ClaimState::Open => v1::AdministratorClaim::Open,
            ClaimState::Claimed => v1::AdministratorClaim::Claimed,
            ClaimState::Unavailable => v1::AdministratorClaim::Unavailable,
        };
        Ok(v1::InstanceStatus {
            claim: claim.into(),
        })
    }

    /// Store an administrator's policy. A retry of a completed update answers
    /// with the policy it put in force and never writes it over a later
    /// update.
    pub async fn update_policy(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: v1::UpdateEnrollmentPolicyRequest,
    ) -> Result<v1::EnrollmentPolicy, EnrollmentError> {
        caller.require_admin()?;
        let command = KeyedCommand::by_profile::<keyed::UpdateEnrollmentPolicy>(
            caller.profile_id,
            operation,
            &req,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        let policy = policy_from_proto(req.policy.ok_or(EnrollmentError::MissingField("policy"))?)?;
        let stored_mode = stored_or_default(self.storage.as_ref()).await?.mode;
        let policy =
            validated(policy, self.pinned_mode, stored_mode).map_err(|refusal| match refusal {
                Refusal::Pinned(_) => EnrollmentError::ModePinned(refusal),
                Refusal::NoDomain | Refusal::BadDomain(_) => {
                    invalid_field("policy.allowed_domains", refusal.to_string())
                }
                Refusal::TooManyUses => {
                    invalid_field("policy.invite.default_max_uses", refusal.to_string())
                }
                Refusal::ExpiryTooFar => {
                    invalid_field("policy.invite.default_expiry_hours", refusal.to_string())
                }
            })?;
        // Under a pin the stored mode stays, decided in the write's own
        // transaction; the mode read above is written only when none is
        // stored yet.
        let mode_write = match self.pinned_mode {
            Some(_) => ModeWrite::KeepStored,
            None => ModeWrite::Replace,
        };
        // The policy in force once stored: a pinned mode overrides the stored
        // one, as `policy_in_force` reads it.
        let mut in_force = policy.clone();
        if let Some(mode) = self.pinned_mode {
            in_force.mode = mode;
        }
        let mut response = policy_to_proto(&in_force);
        response.mode_pinned = self.pinned_mode.is_some();
        let ctx = MutationContext::from(AuditEntry::admin(
            caller.profile_id.to_string(),
            "enrollment_policy.update",
            "installation".to_string(),
        ))
        .with_operation(command.completion(response.encode_to_vec()));
        match self
            .storage
            .set_enrollment_policy(&policy, mode_write, ctx)
            .await
        {
            Ok(_) => {}
            Err(SidError::OperationCompleted(_)) => {
                let recorded = command.committed_elsewhere(&*self.storage).await?;
                return v1::EnrollmentPolicy::decode(recorded.as_slice())
                    .map_err(|e| internal("read a recorded policy", e));
            }
            // The stored mode, kept under a pin, is domain-restricted and the
            // update leaves it without a domain.
            Err(SidError::Validation(message)) => {
                return Err(invalid_field("policy.allowed_domains", message));
            }
            Err(e) => return Err(e.into()),
        }
        info!(mode = %policy.mode, "enrollment policy updated");
        Ok(response)
    }

    /// The use limit and expiry of a new invite: those the request gives,
    /// else the stored policy's defaults (a default expiry of 0 hours is
    /// none); `never_expires` asks for no expiry and `unlimited_uses` for no
    /// use limit, whatever the defaults.
    async fn invite_terms(
        &self,
        max_uses: u32,
        unlimited_uses: bool,
        expires_at: Option<prost_types::Timestamp>,
        never_expires: bool,
    ) -> Result<(u32, Option<chrono::DateTime<chrono::Utc>>), EnrollmentError> {
        if unlimited_uses && max_uses != 0 {
            return Err(invalid_field(
                "unlimited_uses",
                "an invite with a use limit cannot also be unlimited",
            ));
        }
        if max_uses > MAX_INVITE_USES {
            return Err(invalid_field(
                "max_uses",
                format!("at most {MAX_INVITE_USES}"),
            ));
        }
        if never_expires && expires_at.is_some() {
            return Err(invalid_field(
                "never_expires",
                "an invite with an expiry cannot also never expire",
            ));
        }
        let expires_at = invite_expiry(expires_at)?;
        let defaults = stored_or_default(self.storage.as_ref()).await?.invite;
        // 0 stores no limit (Invite.max_uses).
        let max_uses = match max_uses {
            0 if unlimited_uses => 0,
            0 => defaults.default_max_uses,
            limit => limit,
        };
        let expires_at = match expires_at {
            Some(at) => Some(at),
            None if never_expires => None,
            // Stored defaults are checked when stored; one that is not
            // representable now is an inconsistency, not a client error.
            None => default_expiry(chrono::Utc::now(), defaults.default_expiry_hours).ok_or_else(
                || internal("invite expiry", "the default expiry is not representable"),
            )?,
        };
        Ok((max_uses, expires_at))
    }

    /// The display name of an invite's creator, recorded with the invite for
    /// the listing search; empty for one that no longer exists.
    async fn inviter_name(&self, inviter: Inviter) -> Result<String, EnrollmentError> {
        match inviter {
            Inviter::Administrator(id) => self.profile_name(id).await,
            Inviter::Machine(id) => Ok(self
                .storage
                .get_machine_user(id)
                .await?
                .map(|m| m.display_name)
                .unwrap_or_default()),
        }
    }

    /// The display name of `id` (an invite's creator, a referrer); empty for
    /// a profile that no longer exists.
    async fn profile_name(&self, id: ProfileId) -> Result<String, EnrollmentError> {
        Ok(self
            .storage
            .get_profile(id)
            .await?
            .and_then(|p| p.formatted_name().or(p.username))
            .unwrap_or_default())
    }

    /// The stored invite `invite_id` names.
    async fn stored_invite(
        &self,
        invite_id: Option<&sid_proto::sid::v1::ids::InviteId>,
    ) -> Result<Invite, EnrollmentError> {
        let invite_id: InviteId = wire_id(invite_id, "invite_id")?;
        self.storage
            .get_invite(invite_id)
            .await?
            .ok_or(EnrollmentError::InviteNotFound(invite_id))
    }

    /// Create one invite. A retry of a completed creation answers with the
    /// invite it created and creates no second one.
    pub async fn create_invite(
        &self,
        inviter: Inviter,
        operation: OperationContext,
        req: v1::CreateInviteRequest,
    ) -> Result<v1::Invite, EnrollmentError> {
        let command = inviter.command::<keyed::CreateInvite>(operation, &req);
        command
            .execute(&*self.storage, || async {
                let (max_uses, expires_at) = self
                    .invite_terms(
                        req.max_uses,
                        req.unlimited_uses,
                        req.expires_at,
                        req.never_expires,
                    )
                    .await?;
                let invite = Invite {
                    id: InviteId::generate(),
                    code: generate_invite_code(),
                    created_by: inviter.creator(),
                    created_by_name: self.inviter_name(inviter).await?,
                    metadata: req.metadata.clone().into_iter().collect(),
                    max_uses,
                    use_count: 0,
                    expires_at,
                    active: true,
                    created_at: chrono::Utc::now(),
                };
                let response = invite_to_proto(&invite);
                let ctx =
                    MutationContext::from(inviter.audit("invite.create", invite.id.to_string()))
                        .with_operation(command.completion(response.encode_to_vec()));
                self.storage
                    .create_invites(std::slice::from_ref(&invite), ctx)
                    .await?;
                info!("Created invite {}", invite.id);
                Ok(response)
            })
            .await
            .map_err(CommandError::refusal)
    }

    pub async fn get_invite(
        &self,
        req: v1::GetInviteRequest,
    ) -> Result<v1::Invite, EnrollmentError> {
        Ok(invite_to_proto(
            &self.stored_invite(req.invite_id.as_ref()).await?,
        ))
    }

    pub async fn list_invite_redemptions(
        &self,
        req: v1::ListInviteRedemptionsRequest,
    ) -> Result<v1::ListInviteRedemptionsResponse, EnrollmentError> {
        let invite = self.stored_invite(req.invite_id.as_ref()).await?;
        let limit = page_limit(req.page_size);
        let offset = page_offset(&req.page_token)?;
        let redemptions = self
            .storage
            .list_invite_redemptions(invite.id, offset, limit)
            .await?;
        let next_page_token = next_page(offset, limit, redemptions.len());
        Ok(v1::ListInviteRedemptionsResponse {
            redemptions: redemptions
                .into_iter()
                .map(|r| {
                    Ok(v1::InviteRedemption {
                        profile_id: Some(r.profile_id.into()),
                        credential_id: match r.credential_id {
                            Some(c) => stored_id::<sid_ids::CredentialId, _>(c.0)
                                .map_err(|e| internal("stored identifier", e))?,
                            None => None,
                        },
                        redeemed_at: Some(to_timestamp(r.redeemed_at)),
                    })
                })
                .collect::<Result<_, EnrollmentError>>()?,
            next_page_token,
        })
    }

    pub async fn list_invites(
        &self,
        req: v1::ListInvitesRequest,
    ) -> Result<v1::ListInvitesResponse, EnrollmentError> {
        let limit = page_limit(req.page_size);
        let offset = page_offset(&req.page_token)?;
        let filter = invite_filter(req.status, &req.search)?;
        let invites = self.storage.list_invites(&filter, offset, limit).await?;
        let total_count = self.storage.count_invites(&filter).await?;
        Ok(v1::ListInvitesResponse {
            next_page_token: next_page(offset, limit, invites.len()),
            invites: invites.iter().map(invite_to_proto).collect(),
            // The field is uint32: a larger count is reported as its maximum
            // rather than wrapped to a small number.
            total_count: u32::try_from(total_count).unwrap_or(u32::MAX),
        })
    }

    pub async fn revoke_invite(
        &self,
        inviter: Inviter,
        req: v1::RevokeInviteRequest,
    ) -> Result<(), EnrollmentError> {
        let invite_id = self.stored_invite(req.invite_id.as_ref()).await?.id;
        self.storage
            .revoke_invite(
                invite_id,
                inviter.audit("invite.revoke", invite_id.to_string()).into(),
            )
            .await?;
        info!("Revoked invite {}", invite_id);
        Ok(())
    }

    /// Create `count` invites: all commit together or none do, once per key;
    /// a request for more than the limit is refused, never quietly cut.
    pub async fn bulk_create_invites(
        &self,
        inviter: Inviter,
        operation: OperationContext,
        req: v1::BulkCreateInvitesRequest,
    ) -> Result<v1::BulkCreateInvitesResponse, EnrollmentError> {
        let count = req.count;
        if count == 0 {
            return Err(EnrollmentError::MissingField("count"));
        }
        if count > MAX_BULK_INVITES {
            return Err(invalid_field(
                "count",
                format!("at most {MAX_BULK_INVITES} invites per request"),
            ));
        }
        let command = inviter.command::<keyed::BulkCreateInvites>(operation, &req);
        command
            .execute(&*self.storage, || async {
                let (max_uses, expires_at) = self
                    .invite_terms(
                        req.max_uses,
                        req.unlimited_uses,
                        req.expires_at,
                        req.never_expires,
                    )
                    .await?;
                let created_by_name = self.inviter_name(inviter).await?;
                let now = chrono::Utc::now();
                let invites: Vec<Invite> = (0..count)
                    .map(|_| Invite {
                        id: InviteId::generate(),
                        code: generate_invite_code(),
                        created_by: inviter.creator(),
                        created_by_name: created_by_name.clone(),
                        metadata: req.metadata.clone().into_iter().collect(),
                        max_uses,
                        use_count: 0,
                        expires_at,
                        active: true,
                        created_at: now,
                    })
                    .collect();
                let response = v1::BulkCreateInvitesResponse {
                    invites: invites.iter().map(invite_to_proto).collect(),
                };
                let ids: Vec<String> = invites.iter().map(|i| i.id.to_string()).collect();
                let ctx = MutationContext::from(inviter.audit("invite.bulk_create", ids.join(",")))
                    .with_operation(command.completion(response.encode_to_vec()));
                self.storage.create_invites(&invites, ctx).await?;
                info!("Bulk created {} invites", invites.len());
                Ok(response)
            })
            .await
            .map_err(CommandError::refusal)
    }

    /// Registrations by source and the top referrers over the last
    /// `period_days` (30 by default): an administrator's, since they name the
    /// referrers.
    pub async fn registration_stats(
        &self,
        caller: &Caller,
        req: v1::GetRegistrationStatsRequest,
    ) -> Result<v1::RegistrationStats, EnrollmentError> {
        caller.require_admin()?;
        let period_days = if req.period_days == 0 {
            30
        } else {
            req.period_days
        };
        // A period reaching before the representable time is refused rather
        // than overflowing.
        let since = chrono::Utc::now()
            .checked_sub_signed(chrono::Duration::days(i64::from(period_days)))
            .ok_or_else(|| invalid_field("period_days", "too long"))?;
        let by_source = self.storage.count_registrations_by_source(since).await?;
        let total: u64 = by_source.iter().map(|(_, c)| c).sum();
        let top_referrers = self.storage.top_referrers(since, 10).await?;
        let total_referrals: u64 = top_referrers.iter().map(|(_, c)| c).sum();
        let mut referrers = Vec::with_capacity(top_referrers.len());
        for (pid, count) in &top_referrers {
            referrers.push(v1::ReferrerEntry {
                profile_id: Some((*pid).into()),
                display_name: self.profile_name(*pid).await?,
                referral_count: *count as u32,
            });
        }
        Ok(v1::RegistrationStats {
            total: total as u32,
            by_source: by_source
                .iter()
                .map(|(st, count)| v1::SourceBreakdown {
                    source_type: source_type_to_proto(st) as i32,
                    count: *count as u32,
                    percentage: if total > 0 {
                        (*count as f64 / total as f64) * 100.0
                    } else {
                        0.0
                    },
                })
                .collect(),
            top_referrers: referrers,
            total_referrals: total_referrals as u32,
            unique_referrers: top_referrers.len() as u32,
        })
    }
}

// ── Messages ────────────────────────────────────────────────────────

fn policy_to_proto(ep: &EnrollmentPolicy) -> v1::EnrollmentPolicy {
    v1::EnrollmentPolicy {
        mode: mode_to_proto(&ep.mode) as i32,
        invite: Some(v1::InviteConfig {
            default_max_uses: ep.invite.default_max_uses,
            default_expiry_hours: ep.invite.default_expiry_hours,
        }),
        allowed_domains: ep.allowed_domains.clone(),
        track_source: ep.track_source,
        mode_pinned: false,
    }
}

/// An administrator's policy as stored. An unspecified or unknown mode and a
/// missing invite configuration are refused, never read as a default; the
/// output-only `mode_pinned` is ignored.
fn policy_from_proto(p: v1::EnrollmentPolicy) -> Result<EnrollmentPolicy, EnrollmentError> {
    use v1::EnrollmentMode as P;
    let mode = match P::try_from(p.mode) {
        Ok(P::Open) => EnrollmentMode::Open,
        Ok(P::InviteOnly) => EnrollmentMode::InviteOnly,
        Ok(P::AdminOnly) => EnrollmentMode::AdminOnly,
        Ok(P::DomainRestricted) => EnrollmentMode::DomainRestricted,
        Ok(P::Unspecified) => return Err(EnrollmentError::MissingField("policy.mode")),
        Err(_) => return Err(invalid_field("policy.mode", "not an enrollment mode")),
    };
    let invite = p
        .invite
        .ok_or(EnrollmentError::MissingField("policy.invite"))?;
    Ok(EnrollmentPolicy {
        mode,
        invite: sid_core::models::InviteConfig {
            default_max_uses: invite.default_max_uses,
            default_expiry_hours: invite.default_expiry_hours,
        },
        allowed_domains: p.allowed_domains,
        track_source: p.track_source,
    })
}

fn mode_to_proto(m: &EnrollmentMode) -> v1::EnrollmentMode {
    match m {
        EnrollmentMode::Open => v1::EnrollmentMode::Open,
        EnrollmentMode::InviteOnly => v1::EnrollmentMode::InviteOnly,
        EnrollmentMode::AdminOnly => v1::EnrollmentMode::AdminOnly,
        EnrollmentMode::DomainRestricted => v1::EnrollmentMode::DomainRestricted,
    }
}

fn invite_status_to_proto(s: &InviteStatus) -> v1::InviteStatus {
    match s {
        InviteStatus::Active => v1::InviteStatus::Active,
        InviteStatus::Consumed => v1::InviteStatus::Consumed,
        InviteStatus::Revoked => v1::InviteStatus::Revoked,
        InviteStatus::Expired => v1::InviteStatus::Expired,
    }
}

fn source_type_to_proto(
    s: &sid_core::models::RegistrationSourceType,
) -> v1::RegistrationSourceType {
    use sid_core::models::RegistrationSourceType as S;
    match s {
        S::SelfSignup => v1::RegistrationSourceType::SelfSignup,
        S::Invite => v1::RegistrationSourceType::Invite,
        S::AdminCreated => v1::RegistrationSourceType::AdminCreated,
        S::ScimProvisioned => v1::RegistrationSourceType::ScimProvisioned,
        S::Federation => v1::RegistrationSourceType::Federation,
        S::IdentityBrokered => v1::RegistrationSourceType::IdentityBrokered,
    }
}

/// `invite` as the API returns it: `created_by` names only a Profile creator,
/// a machine user creator has its own field.
fn invite_to_proto(invite: &Invite) -> v1::Invite {
    use v1::invite::CreatedBy;
    let created_by = match invite.created_by {
        InviteCreator::Profile(id) => CreatedBy::CreatedByProfileId(id.into()),
        InviteCreator::MachineUser(id) => CreatedBy::CreatedByMachineUserId(id.into()),
    };
    v1::Invite {
        id: Some(invite.id.into()),
        code: invite.code.clone(),
        created_by: Some(created_by),
        created_by_name: invite.created_by_name.clone(),
        metadata: invite.metadata.clone().into_iter().collect(),
        max_uses: invite.max_uses,
        use_count: invite.use_count,
        expires_at: invite.expires_at.map(to_timestamp),
        active: invite.active,
        status: invite_status_to_proto(&invite.status()) as i32,
        created_at: Some(to_timestamp(invite.created_at)),
    }
}

#[cfg(test)]
mod tests;
