// SPDX-License-Identifier: AGPL-3.0-only
//! Enrollment service gRPC implementation.
//!
//! Manages enrollment policy, invite codes, and registration statistics.

use sid_authn::caller::{Caller, authenticate};
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::grpc_error::ErrorReason;
use sid_core::grpc_error::refuse::{
    invalid_field, missing_field, not_found, not_in_this_build, storage_failure,
};
use sid_core::models::{
    AuditEntry, Invite, InviteFilter, InviteId, InviteStatus, ProfileId, generate_invite_code,
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

pub struct EnrollmentServiceImpl {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
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
        }
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
        // Hardcoded defaults.
        let ce = sid_core::models::SecurityPolicy::ce_default();
        Ok(Response::new(enrollment_policy_to_proto(&ce.enrollment)))
    }

    /// Public: the registration page asks for the claim token while this is false.
    #[tracing::instrument(skip_all, fields(rpc = "get_instance_status"))]
    async fn get_instance_status(
        &self,
        _request: Request<()>,
    ) -> Result<Response<sid_proto::sid::v1::admin::InstanceStatus>, Status> {
        let claimed = self.storage.admin_exists().await.map_err(storage_failure)?;
        Ok(Response::new(sid_proto::sid::v1::admin::InstanceStatus {
            claimed,
        }))
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_enrollment_policy"))]
    async fn update_enrollment_policy(
        &self,
        _request: Request<sid_proto::sid::v1::admin::UpdateEnrollmentPolicyRequest>,
    ) -> Result<Response<ProtoEnrollmentPolicy>, Status> {
        // This build's enrollment policy is fixed.
        Err(not_in_this_build("enrollment_policy"))
    }

    #[tracing::instrument(skip_all, fields(rpc = "create_invite"))]
    async fn create_invite(
        &self,
        request: Request<sid_proto::sid::v1::admin::CreateInviteRequest>,
    ) -> Result<Response<ProtoInvite>, Status> {
        let created_by = self.admin(&request).await?.profile_id;
        let req = request.into_inner();

        let max_uses = if req.max_uses == 0 { 1 } else { req.max_uses };
        let expires_at = invite_expiry(req.expires_at)?;

        let invite = Invite {
            id: InviteId::new(),
            code: generate_invite_code(),
            created_by,
            created_by_name: self.creator_name(created_by).await?,
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
                AuditEntry::admin(
                    created_by.to_string(),
                    "invite.create",
                    invite.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!("Created invite {}", invite.id.0);
        Ok(Response::new(invite_to_proto(&invite)))
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_invites"))]
    async fn list_invites(
        &self,
        request: Request<sid_proto::sid::v1::admin::ListInvitesRequest>,
    ) -> Result<Response<sid_proto::sid::v1::admin::ListInvitesResponse>, Status> {
        self.admin(&request).await?;
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
        let caller = self.admin(&request).await?;
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
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "invite.revoke",
                    invite_id.0.to_string(),
                )
                .into(),
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
        let created_by = self.admin(&request).await?.profile_id;
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

        let max_uses = if req.max_uses == 0 { 1 } else { req.max_uses };
        let expires_at = invite_expiry(req.expires_at)?;
        let created_by_name = self.creator_name(created_by).await?;

        let mut invites = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let invite = Invite {
                id: InviteId::new(),
                code: generate_invite_code(),
                created_by,
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
                    AuditEntry::admin(
                        created_by.to_string(),
                        "invite.bulk_create",
                        invite.id.0.to_string(),
                    )
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
    }
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

fn invite_to_proto(invite: &Invite) -> ProtoInvite {
    ProtoInvite {
        id: invite.id.0.to_string(),
        code: invite.code.clone(),
        created_by: invite.created_by.to_string(),
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
