// SPDX-License-Identifier: AGPL-3.0-only
//! Enrollment service gRPC implementation.
//!
//! Manages enrollment policy, invite codes, and registration statistics.

use sid_authn::caller::{Caller, authenticate};
use sid_authn::jwt::JwtService;
use sid_authn::resource_token::ResourceTokenVerifier;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::service_auth::{AuthenticatedService, ServiceCaller, authenticate_service};
use sid_authz::{AuthzCheckRequest, CeAuthzEngine};
use sid_core::grpc_error::refuse::{
    dependency_unavailable, internal, invalid_field, missing_field, not_found, storage_failure,
};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{
    AuditEntry, INVITE_CREATE, INVITE_READ, INVITE_REVOKE, Invite, InviteCreator, InviteFilter,
    InviteId, InviteStatus, ModeWrite, ProfileId, ResourceId, generate_invite_code,
};
use sid_plugin::storage::StorageBackend;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;

use super::convert;

/// Invites one bulk request creates at most.
const MAX_BULK_INVITES: u32 = 100;
/// Invites one listing page holds by default, and at most.
const DEFAULT_PAGE_SIZE: u64 = 50;
const MAX_PAGE_SIZE: u64 = 500;

/// An invite expiry: a valid timestamp in the future, never replaced by
/// another value.
#[allow(clippy::result_large_err)]
fn invite_expiry(
    ts: Option<prost_types::Timestamp>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, Status> {
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
#[allow(clippy::result_large_err)]
fn invite_filter(status: i32, search: &str) -> Result<InviteFilter, Status> {
    use sid_proto::sid::v1::admin::InviteStatus as P;
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
/// is one this service issued, bounded to i64 (the stores take a BIGINT).
#[allow(clippy::result_large_err)]
fn page_offset(token: &str) -> Result<u64, Status> {
    if token.is_empty() {
        return Ok(0);
    }
    token
        .parse::<i64>()
        .ok()
        .and_then(|o| u64::try_from(o).ok())
        .ok_or_else(|| invalid_field("page_token", "not a token this service issued"))
}

type ProtoEnrollmentPolicy = sid_proto::sid::v1::admin::EnrollmentPolicy;
type ProtoInvite = sid_proto::sid::v1::admin::Invite;

/// Services that may manage invites: a machine user with its own token for
/// the enrollment API, holding the invite action on that resource.
pub struct InviteServices {
    pub engine: Arc<CeAuthzEngine<dyn StorageBackend>>,
    pub tokens: Arc<ResourceTokenVerifier>,
    /// The enrollment API resource the actions are held on.
    pub resource: ResourceId,
}

/// Who manages an invite: an administrator Profile or an authorized machine
/// user.
#[derive(Debug, Clone, Copy)]
enum InviteActor {
    Admin(ProfileId),
    Machine(sid_core::models::MachineUserId),
}

impl InviteActor {
    fn creator(self) -> InviteCreator {
        match self {
            Self::Admin(id) => InviteCreator::Profile(id),
            Self::Machine(id) => InviteCreator::MachineUser(id),
        }
    }

    /// The audit entry of `action` on `resource` with this actor.
    fn audit(self, action: &str, resource: String) -> AuditEntry {
        match self {
            Self::Admin(id) => AuditEntry::admin(id.to_string(), action, resource),
            Self::Machine(id) => AuditEntry::machine(id.to_string(), action, resource),
        }
    }
}

fn denied() -> Status {
    ApiError::new(
        ErrorReason::InsufficientPermissions,
        "the caller may not perform this operation",
    )
    .into()
}

pub struct EnrollmentServiceImpl {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    /// The enrollment mode the deployment pins over the stored one.
    pinned_mode: Option<sid_core::models::EnrollmentMode>,
    /// Services admitted to the invite RPCs; none: administrators only.
    invite_services: Option<InviteServices>,
}

impl EnrollmentServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            storage,
            jwt,
            revocation,
            pinned_mode: None,
            invite_services: None,
        }
    }

    /// Also admit to the invite RPCs the services `services` describes.
    pub fn with_invite_services(mut self, services: InviteServices) -> Self {
        self.invite_services = Some(services);
        self
    }

    /// Report `mode` as the one in force and refuse updates changing it: the
    /// deployment pins it (`SID_ENROLLMENT_MODE`).
    pub fn with_pinned_mode(mut self, mode: Option<sid_core::models::EnrollmentMode>) -> Self {
        self.pinned_mode = mode;
        self
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
    ) -> Result<(u32, Option<chrono::DateTime<chrono::Utc>>), Status> {
        if unlimited_uses && max_uses != 0 {
            return Err(invalid_field(
                "unlimited_uses",
                "an invite with a use limit cannot also be unlimited",
            ));
        }
        if max_uses > crate::enrollment::MAX_INVITE_USES {
            return Err(invalid_field(
                "max_uses",
                format!("at most {}", crate::enrollment::MAX_INVITE_USES),
            ));
        }
        if never_expires && expires_at.is_some() {
            return Err(invalid_field(
                "never_expires",
                "an invite with an expiry cannot also never expire",
            ));
        }
        let expires_at = invite_expiry(expires_at)?;
        let defaults = crate::enrollment::stored_or_default(self.storage.as_ref())
            .await
            .map_err(storage_failure)?
            .invite;
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
            None => {
                crate::enrollment::default_expiry(chrono::Utc::now(), defaults.default_expiry_hours)
                    .ok_or_else(|| {
                        internal("invite expiry", "the default expiry is not representable")
                    })?
            }
        };
        Ok((max_uses, expires_at))
    }

    /// The policy in force, as the API reports it.
    async fn policy_in_force(&self) -> Result<ProtoEnrollmentPolicy, Status> {
        let policy = crate::enrollment::effective(self.storage.as_ref(), self.pinned_mode)
            .await
            .map_err(storage_failure)?;
        let mut proto = enrollment_policy_to_proto(&policy);
        proto.mode_pinned = self.pinned_mode.is_some();
        Ok(proto)
    }

    /// Authenticate the caller and require the administrator role: invite codes
    /// grant registration on an invite-only instance, and the statistics name
    /// the referrers.
    #[allow(clippy::result_large_err)]
    async fn admin<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let caller = authenticate(request, self.jwt.verifier(), &self.revocation).await?;
        caller.require_admin()?;
        Ok(caller)
    }

    /// Who may perform invite `action` on `request`: a service with its own
    /// token for the enrollment API holding `action` there, or else an
    /// administrator Profile. A service token is valid only for the
    /// enrollment API and a user's sign-in token never is, so each
    /// credential has one path.
    async fn invite_actor<T>(
        &self,
        request: &Request<T>,
        action: &str,
    ) -> Result<InviteActor, Status> {
        if let Some(services) = &self.invite_services {
            match authenticate_service(
                request,
                self.storage.as_ref(),
                &services.tokens,
                &self.revocation,
            )
            .await
            {
                // The action must be both within the token's scopes and
                // granted by the service's current role assignments.
                Ok(service) if !service.may(action) => {
                    return Err(ApiError::new(
                        ErrorReason::ScopeNotGranted,
                        "the access token does not grant this operation",
                    )
                    .into());
                }
                Ok(AuthenticatedService {
                    caller: ServiceCaller::Machine { machine, .. },
                    ..
                }) => {
                    let decision = services
                        .engine
                        .check(&AuthzCheckRequest {
                            subject: format!("machine:{machine}"),
                            action: action.to_owned(),
                            resource: format!("oauth_resource:{}", services.resource),
                            context: Default::default(),
                        })
                        .await
                        .map_err(|e| dependency_unavailable("invite authorization", e))?;
                    return if decision.is_allowed() {
                        Ok(InviteActor::Machine(machine))
                    } else {
                        Err(denied())
                    };
                }
                // An invite names a Profile or a machine user as creator; an
                // OAuth client acting for itself is neither.
                Ok(AuthenticatedService {
                    caller: ServiceCaller::Client { .. },
                    ..
                }) => return Err(denied()),
                Err(status) if status.code() == tonic::Code::Unauthenticated => {}
                Err(status) => return Err(status),
            }
        }
        Ok(InviteActor::Admin(self.admin(request).await?.profile_id))
    }

    /// The stored invite `invite_id` names; NOT_FOUND for an unknown one.
    async fn stored_invite(&self, invite_id: &str) -> Result<Invite, Status> {
        let invite_id = uuid::Uuid::parse_str(invite_id)
            .map(InviteId)
            .map_err(|_| invalid_field("invite_id", "not an invite identifier"))?;
        self.storage
            .get_invite(invite_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                not_found(
                    ErrorReason::InviteNotFound,
                    "Invite",
                    invite_id.0.to_string(),
                )
            })
    }

    /// The display name of an invite's creator, recorded with the invite for
    /// the listing search; empty for one that no longer exists.
    async fn invite_creator_name(&self, actor: InviteActor) -> Result<String, Status> {
        match actor {
            InviteActor::Admin(id) => self.creator_name(id).await,
            InviteActor::Machine(id) => Ok(self
                .storage
                .get_machine_user(id)
                .await
                .map_err(storage_failure)?
                .map(|m| m.display_name)
                .unwrap_or_default()),
        }
    }

    /// The display name of `id` (an invite's creator, a referrer); empty for
    /// a profile that no longer exists. An invite records it for the listing
    /// search.
    async fn creator_name(&self, id: ProfileId) -> Result<String, Status> {
        Ok(self
            .storage
            .get_profile(id)
            .await
            .map_err(storage_failure)?
            .and_then(|p| p.formatted_name().or(p.username))
            .unwrap_or_default())
    }
}

#[tonic::async_trait]
impl sid_proto::sid::v1::admin::enrollment_service_server::EnrollmentService
    for EnrollmentServiceImpl
{
    #[tracing::instrument(skip_all, fields(rpc = "get_enrollment_policy"))]
    async fn get_enrollment_policy(
        &self,
        _request: Request<()>,
    ) -> Result<Response<ProtoEnrollmentPolicy>, Status> {
        self.policy_in_force().await.map(Response::new)
    }

    /// Public: the registration page asks for the claim token while the claim
    /// is open.
    #[tracing::instrument(skip_all, fields(rpc = "get_instance_status"))]
    async fn get_instance_status(
        &self,
        _request: Request<()>,
    ) -> Result<Response<sid_proto::sid::v1::admin::InstanceStatus>, Status> {
        use sid_authn::admin_claim::ClaimState;
        use sid_proto::sid::v1::admin::AdministratorClaim;
        let claim = match sid_authn::admin_claim::state(self.storage.as_ref())
            .await
            .map_err(storage_failure)?
        {
            ClaimState::Open => AdministratorClaim::Open,
            ClaimState::Claimed => AdministratorClaim::Claimed,
            ClaimState::Unavailable => AdministratorClaim::Unavailable,
        };
        Ok(Response::new(sid_proto::sid::v1::admin::InstanceStatus {
            claim: claim.into(),
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_enrollment_policy"))]
    async fn update_enrollment_policy(
        &self,
        request: Request<sid_proto::sid::v1::admin::UpdateEnrollmentPolicyRequest>,
    ) -> Result<Response<ProtoEnrollmentPolicy>, Status> {
        use crate::enrollment::Refusal;
        let caller = self.admin(&request).await?;
        let policy = request
            .into_inner()
            .policy
            .ok_or_else(|| missing_field("policy"))
            .and_then(enrollment_policy_from_proto)?;
        let stored_mode = crate::enrollment::stored_or_default(self.storage.as_ref())
            .await
            .map_err(storage_failure)?
            .mode;
        let policy = crate::enrollment::validated(policy, self.pinned_mode, stored_mode).map_err(
            |refusal| match refusal {
                Refusal::Pinned(_) => Status::from(
                    ApiError::new(ErrorReason::InvalidState, refusal.to_string())
                        .with_precondition(
                            "pinned_by_deployment",
                            "enrollment_policy.mode",
                            refusal.to_string(),
                        ),
                ),
                Refusal::NoDomain | Refusal::BadDomain(_) => {
                    invalid_field("policy.allowed_domains", refusal.to_string())
                }
                Refusal::TooManyUses => {
                    invalid_field("policy.invite.default_max_uses", refusal.to_string())
                }
                Refusal::ExpiryTooFar => {
                    invalid_field("policy.invite.default_expiry_hours", refusal.to_string())
                }
            },
        )?;
        // Under a pin the stored mode stays, decided in the write's own
        // transaction; the mode read above is written only when none is
        // stored yet.
        let mode_write = match self.pinned_mode {
            Some(_) => ModeWrite::KeepStored,
            None => ModeWrite::Replace,
        };
        self.storage
            .set_enrollment_policy(
                &policy,
                mode_write,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "enrollment_policy.update",
                    "installation".to_string(),
                )
                .into(),
            )
            .await
            .map_err(|e| match e {
                // The stored mode, kept under a pin, is domain-restricted
                // and the update leaves it without a domain.
                sid_core::Error::Validation(message) => {
                    invalid_field("policy.allowed_domains", message)
                }
                e => storage_failure(e),
            })?;
        info!(mode = %policy.mode, "enrollment policy updated");
        self.policy_in_force().await.map(Response::new)
    }

    #[tracing::instrument(skip_all, fields(rpc = "create_invite"))]
    async fn create_invite(
        &self,
        request: Request<sid_proto::sid::v1::admin::CreateInviteRequest>,
    ) -> Result<Response<ProtoInvite>, Status> {
        let actor = self.invite_actor(&request, INVITE_CREATE).await?;
        let req = request.into_inner();

        let (max_uses, expires_at) = self
            .invite_terms(
                req.max_uses,
                req.unlimited_uses,
                req.expires_at,
                req.never_expires,
            )
            .await?;

        let invite = Invite {
            id: InviteId::new(),
            code: generate_invite_code(),
            created_by: actor.creator(),
            created_by_name: self.invite_creator_name(actor).await?,
            metadata: req.metadata.into_iter().collect(),
            max_uses,
            use_count: 0,
            expires_at,
            active: true,
            created_at: chrono::Utc::now(),
        };

        self.storage
            .create_invite(
                &invite,
                actor.audit("invite.create", invite.id.0.to_string()).into(),
            )
            .await
            .map_err(storage_failure)?;

        info!("Created invite {}", invite.id.0);
        Ok(Response::new(invite_to_proto(&invite)))
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_invite"))]
    async fn get_invite(
        &self,
        request: Request<sid_proto::sid::v1::admin::GetInviteRequest>,
    ) -> Result<Response<ProtoInvite>, Status> {
        self.invite_actor(&request, INVITE_READ).await?;
        let invite = self.stored_invite(&request.into_inner().invite_id).await?;
        Ok(Response::new(invite_to_proto(&invite)))
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_invite_redemptions"))]
    async fn list_invite_redemptions(
        &self,
        request: Request<sid_proto::sid::v1::admin::ListInviteRedemptionsRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::ListInviteRedemptionsResponse>, Status> {
        self.invite_actor(&request, INVITE_READ).await?;
        let req = request.into_inner();
        let invite = self.stored_invite(&req.invite_id).await?;
        // AIP-158: a page size above the maximum is coerced to it.
        let limit = match u64::from(req.page_size) {
            0 => DEFAULT_PAGE_SIZE,
            n => n.min(MAX_PAGE_SIZE),
        };
        let offset = page_offset(&req.page_token)?;
        let redemptions = self
            .storage
            .list_invite_redemptions(invite.id, offset, limit)
            .await
            .map_err(storage_failure)?;
        // A full page may have a next one; an offset past BIGINT has none.
        let next_page_token = offset
            .checked_add(limit)
            .filter(|next| redemptions.len() as u64 == limit && i64::try_from(*next).is_ok())
            .map(|next| next.to_string())
            .unwrap_or_default();
        Ok(Response::new(
            sid_proto::sid::v1::admin::ListInviteRedemptionsResponse {
                redemptions: redemptions
                    .into_iter()
                    .map(|r| sid_proto::sid::v1::admin::InviteRedemption {
                        profile_id: r.profile_id.to_string(),
                        redeemed_at: Some(convert::to_timestamp(r.redeemed_at)),
                    })
                    .collect(),
                next_page_token,
            },
        ))
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_invites"))]
    async fn list_invites(
        &self,
        request: Request<sid_proto::sid::v1::admin::ListInvitesRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::ListInvitesResponse>, Status> {
        self.invite_actor(&request, INVITE_READ).await?;
        let req = request.into_inner();

        // AIP-158: a page size above the maximum is coerced to it.
        let limit = match u64::from(req.page_size) {
            0 => DEFAULT_PAGE_SIZE,
            n => n.min(MAX_PAGE_SIZE),
        };
        let offset = page_offset(&req.page_token)?;
        let filter = invite_filter(req.status, &req.search)?;

        let invites = self
            .storage
            .list_invites(&filter, offset, limit)
            .await
            .map_err(storage_failure)?;
        let total_count = self
            .storage
            .count_invites(&filter)
            .await
            .map_err(storage_failure)?;

        // A full page may have a next one; an offset past BIGINT has none.
        let next_page_token = offset
            .checked_add(limit)
            .filter(|next| invites.len() as u64 == limit && i64::try_from(*next).is_ok())
            .map(|next| next.to_string())
            .unwrap_or_default();
        Ok(Response::new(
            sid_proto::sid::v1::admin::ListInvitesResponse {
                invites: invites.iter().map(invite_to_proto).collect(),
                next_page_token,
                // The field is uint32: a larger count is reported as its
                // maximum rather than wrapped to a small number.
                total_count: u32::try_from(total_count).unwrap_or(u32::MAX),
            },
        ))
    }

    #[tracing::instrument(skip_all, fields(rpc = "revoke_invite"))]
    async fn revoke_invite(
        &self,
        request: Request<sid_proto::sid::v1::admin::RevokeInviteRequest>,
    ) -> Result<Response<()>, Status> {
        let actor = self.invite_actor(&request, INVITE_REVOKE).await?;
        let req = request.into_inner();

        let invite_id = uuid::Uuid::parse_str(&req.invite_id)
            .map(InviteId)
            .map_err(|_| invalid_field("invite_id", "not an invite identifier"))?;

        self.storage
            .get_invite(invite_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                not_found(
                    ErrorReason::InviteNotFound,
                    "Invite",
                    invite_id.0.to_string(),
                )
            })?;

        self.storage
            .revoke_invite(
                invite_id,
                actor.audit("invite.revoke", invite_id.0.to_string()).into(),
            )
            .await
            .map_err(storage_failure)?;

        info!("Revoked invite {}", invite_id.0);
        Ok(Response::new(()))
    }

    #[tracing::instrument(skip_all, fields(rpc = "bulk_create_invites"))]
    async fn bulk_create_invites(
        &self,
        request: Request<sid_proto::sid::v1::admin::BulkCreateInvitesRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::BulkCreateInvitesResponse>, Status> {
        let actor = self.invite_actor(&request, INVITE_CREATE).await?;
        let req = request.into_inner();

        // A request for more is refused, never quietly cut to the limit.
        let count = req.count;
        if count == 0 {
            return Err(missing_field("count"));
        }
        if count > MAX_BULK_INVITES {
            return Err(invalid_field(
                "count",
                format!("at most {MAX_BULK_INVITES} invites per request"),
            ));
        }

        let (max_uses, expires_at) = self
            .invite_terms(
                req.max_uses,
                req.unlimited_uses,
                req.expires_at,
                req.never_expires,
            )
            .await?;
        let created_by_name = self.invite_creator_name(actor).await?;

        let mut invites = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let invite = Invite {
                id: InviteId::new(),
                code: generate_invite_code(),
                created_by: actor.creator(),
                created_by_name: created_by_name.clone(),
                metadata: req.metadata.clone().into_iter().collect(),
                max_uses,
                use_count: 0,
                expires_at,
                active: true,
                created_at: chrono::Utc::now(),
            };

            self.storage
                .create_invite(
                    &invite,
                    actor
                        .audit("invite.bulk_create", invite.id.0.to_string())
                        .into(),
                )
                .await
                .map_err(storage_failure)?;

            invites.push(invite);
        }

        info!("Bulk created {} invites", invites.len());
        Ok(Response::new(
            sid_proto::sid::v1::admin::BulkCreateInvitesResponse {
                invites: invites.iter().map(invite_to_proto).collect(),
            },
        ))
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_registration_stats"))]
    async fn get_registration_stats(
        &self,
        request: Request<sid_proto::sid::v1::admin::GetRegistrationStatsRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::RegistrationStats>, Status> {
        self.admin(&request).await?;
        let req = request.into_inner();

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

        let by_source = self
            .storage
            .count_registrations_by_source(since)
            .await
            .map_err(storage_failure)?;

        let total: u64 = by_source.iter().map(|(_, c)| c).sum();

        let top_referrers = self
            .storage
            .top_referrers(since, 10)
            .await
            .map_err(storage_failure)?;

        let total_referrals: u64 = top_referrers.iter().map(|(_, c)| c).sum();
        let mut referrers = Vec::with_capacity(top_referrers.len());
        for (pid, count) in &top_referrers {
            referrers.push(sid_proto::sid::v1::admin::ReferrerEntry {
                profile_id: pid.to_string(),
                display_name: self.creator_name(*pid).await?,
                referral_count: *count as u32,
            });
        }

        Ok(Response::new(
            sid_proto::sid::v1::admin::RegistrationStats {
                total: total as u32,
                by_source: by_source
                    .iter()
                    .map(|(st, count)| sid_proto::sid::v1::admin::SourceBreakdown {
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
            },
        ))
    }
}

// ── Proto conversion helpers ────────────────────────────────────

fn enrollment_policy_to_proto(ep: &sid_core::models::EnrollmentPolicy) -> ProtoEnrollmentPolicy {
    ProtoEnrollmentPolicy {
        mode: enrollment_mode_to_proto(&ep.mode) as i32,
        invite: Some(sid_proto::sid::v1::admin::InviteConfig {
            default_max_uses: ep.invite.default_max_uses,
            default_expiry_hours: ep.invite.default_expiry_hours,
        }),
        allowed_domains: ep.allowed_domains.clone(),
        track_source: ep.track_source,
        mode_pinned: false,
    }
}

/// An administrator's policy as stored. An unspecified or unknown mode and
/// a missing invite configuration are refused, never read as a default; the
/// output-only `mode_pinned` is ignored.
#[allow(clippy::result_large_err)]
fn enrollment_policy_from_proto(
    p: ProtoEnrollmentPolicy,
) -> Result<sid_core::models::EnrollmentPolicy, Status> {
    use sid_core::models::EnrollmentMode;
    use sid_proto::sid::v1::admin::EnrollmentMode as P;
    let mode = match P::try_from(p.mode) {
        Ok(P::Open) => EnrollmentMode::Open,
        Ok(P::InviteOnly) => EnrollmentMode::InviteOnly,
        Ok(P::AdminOnly) => EnrollmentMode::AdminOnly,
        Ok(P::DomainRestricted) => EnrollmentMode::DomainRestricted,
        Ok(P::Unspecified) => return Err(missing_field("policy.mode")),
        Err(_) => return Err(invalid_field("policy.mode", "not an enrollment mode")),
    };
    let invite = p.invite.ok_or_else(|| missing_field("policy.invite"))?;
    Ok(sid_core::models::EnrollmentPolicy {
        mode,
        invite: sid_core::models::InviteConfig {
            default_max_uses: invite.default_max_uses,
            default_expiry_hours: invite.default_expiry_hours,
        },
        allowed_domains: p.allowed_domains,
        track_source: p.track_source,
    })
}

fn enrollment_mode_to_proto(
    m: &sid_core::models::EnrollmentMode,
) -> sid_proto::sid::v1::admin::EnrollmentMode {
    match m {
        sid_core::models::EnrollmentMode::Open => sid_proto::sid::v1::admin::EnrollmentMode::Open,
        sid_core::models::EnrollmentMode::InviteOnly => {
            sid_proto::sid::v1::admin::EnrollmentMode::InviteOnly
        }
        sid_core::models::EnrollmentMode::AdminOnly => {
            sid_proto::sid::v1::admin::EnrollmentMode::AdminOnly
        }
        sid_core::models::EnrollmentMode::DomainRestricted => {
            sid_proto::sid::v1::admin::EnrollmentMode::DomainRestricted
        }
    }
}

fn invite_status_to_proto(s: &InviteStatus) -> sid_proto::sid::v1::admin::InviteStatus {
    match s {
        InviteStatus::Active => sid_proto::sid::v1::admin::InviteStatus::Active,
        InviteStatus::Consumed => sid_proto::sid::v1::admin::InviteStatus::Consumed,
        InviteStatus::Revoked => sid_proto::sid::v1::admin::InviteStatus::Revoked,
        InviteStatus::Expired => sid_proto::sid::v1::admin::InviteStatus::Expired,
    }
}

fn source_type_to_proto(
    s: &sid_core::models::RegistrationSourceType,
) -> sid_proto::sid::v1::admin::RegistrationSourceType {
    match s {
        sid_core::models::RegistrationSourceType::SelfSignup => {
            sid_proto::sid::v1::admin::RegistrationSourceType::SelfSignup
        }
        sid_core::models::RegistrationSourceType::Invite => {
            sid_proto::sid::v1::admin::RegistrationSourceType::Invite
        }
        sid_core::models::RegistrationSourceType::AdminCreated => {
            sid_proto::sid::v1::admin::RegistrationSourceType::AdminCreated
        }
        sid_core::models::RegistrationSourceType::ScimProvisioned => {
            sid_proto::sid::v1::admin::RegistrationSourceType::ScimProvisioned
        }
        sid_core::models::RegistrationSourceType::Federation => {
            sid_proto::sid::v1::admin::RegistrationSourceType::Federation
        }
        sid_core::models::RegistrationSourceType::IdentityBrokered => {
            sid_proto::sid::v1::admin::RegistrationSourceType::IdentityBrokered
        }
    }
}

/// `invite` as the API returns it: `created_by` names only a Profile
/// creator, a machine user creator has its own field.
fn invite_to_proto(invite: &Invite) -> ProtoInvite {
    let (created_by, created_by_machine_user_id) = match invite.created_by {
        InviteCreator::Profile(id) => (id.to_string(), String::new()),
        InviteCreator::MachineUser(id) => (String::new(), id.to_string()),
    };
    ProtoInvite {
        id: invite.id.0.to_string(),
        code: invite.code.clone(),
        created_by,
        created_by_machine_user_id,
        created_by_name: invite.created_by_name.clone(),
        metadata: invite.metadata.clone().into_iter().collect(),
        max_uses: invite.max_uses,
        use_count: invite.use_count,
        expires_at: invite.expires_at.map(convert::to_timestamp),
        active: invite.active,
        status: invite_status_to_proto(&invite.status()) as i32,
        created_at: Some(convert::to_timestamp(invite.created_at)),
    }
}
