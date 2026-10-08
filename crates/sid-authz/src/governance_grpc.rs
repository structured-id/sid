// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC GovernanceService implementation.
//!
//! CE governance: 1-step access requests, temporary roles with auto-expiry.
//! ListRoleAssignments and CheckSodConflicts are in AuthzService.

use sid_authn::caller::{Caller, authenticate};
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::grpc_error::refuse::{invalid_field, missing_field, not_found, storage_failure};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{
    AccessRequest, AccessRequestId, AccessRequestStatus as DomainAccessRequestStatus, AuditEntry,
    ProfileId, ProjectId, Role, RoleAssignment, RoleAssignmentPrincipal,
};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::authz::governance_service_server::GovernanceService;
use sid_proto::sid::v1::authz::{
    AccessRequestDetail, AccessRequestMessage, AccessRequestResponse, AccessRequestStatus,
    DecideRequestRequest, DecideRequestResponse, GrantTemporaryRoleRequest,
    GrantTemporaryRoleResponse, ListPendingRequestsRequest, ListPendingRequestsResponse,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, instrument};

fn to_timestamp(dt: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

fn to_opt_timestamp(dt: Option<chrono::DateTime<chrono::Utc>>) -> Option<prost_types::Timestamp> {
    dt.map(to_timestamp)
}

#[allow(clippy::result_large_err)]
fn parse_profile_id(field: &'static str, id: &str) -> Result<ProfileId, Status> {
    ProfileId::parse(id).map_err(|_| invalid_field(field, "not a profile identifier"))
}

fn profile_not_found(id: ProfileId) -> Status {
    not_found(ErrorReason::ProfileNotFound, "Profile", id.to_string())
}

/// INVALID_STATE: the access request `id` is no longer pending.
fn already_decided(id: AccessRequestId) -> Status {
    ApiError::new(
        ErrorReason::InvalidState,
        "the access request was already decided",
    )
    .with_precondition("ACCESS_REQUEST_STATE", id.0.to_string(), "not pending")
    .into()
}

fn domain_status_to_proto(status: DomainAccessRequestStatus) -> i32 {
    match status {
        DomainAccessRequestStatus::Pending => AccessRequestStatus::Pending as i32,
        DomainAccessRequestStatus::Approved => AccessRequestStatus::Approved as i32,
        DomainAccessRequestStatus::Denied => AccessRequestStatus::Denied as i32,
        DomainAccessRequestStatus::Expired => AccessRequestStatus::Expired as i32,
        DomainAccessRequestStatus::Cancelled => AccessRequestStatus::Cancelled as i32,
    }
}

/// Governance default: access requests expire after 7 days if not acted upon.
const DEFAULT_REQUEST_EXPIRY_DAYS: i64 = 7;

pub struct GovernanceServiceImpl {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
}

impl GovernanceServiceImpl {
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

    /// Authenticate the caller of `request`.
    #[allow(clippy::result_large_err)]
    async fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        authenticate(request, self.jwt.verifier(), &self.revocation).await
    }

    /// Authenticate the caller and require the administrator role: in CE the
    /// approver of access requests and the grantor of temporary roles is a site
    /// administrator.
    #[allow(clippy::result_large_err)]
    async fn admin<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let caller = self.caller(request).await?;
        caller.require_admin()?;
        Ok(caller)
    }

    /// The role `key` of the project `project_id` names: roles are defined per
    /// project, so both are required. An unknown project or role is NOT_FOUND;
    /// `role_field` names the request field that carries the key.
    async fn project_role(
        &self,
        project_id: &str,
        role_field: &'static str,
        key: &str,
    ) -> Result<Role, Status> {
        let project = uuid::Uuid::parse_str(project_id)
            .map(ProjectId)
            .map_err(|_| invalid_field("project_id", "not a project identifier"))?;
        if key.is_empty() {
            return Err(missing_field(role_field));
        }
        self.storage
            .get_project(project)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                not_found(
                    ErrorReason::ProjectNotFound,
                    "Project",
                    project.0.to_string(),
                )
            })?;
        self.storage
            .list_roles(project)
            .await
            .map_err(storage_failure)?
            .into_iter()
            .find(|r| r.key == key)
            .ok_or_else(|| not_found(ErrorReason::RoleNotFound, "Role", key))
    }
}

#[tonic::async_trait]
impl GovernanceService for GovernanceServiceImpl {
    #[instrument(skip_all, fields(method = "request_access"))]
    async fn request_access(
        &self,
        request: Request<AccessRequestMessage>,
    ) -> Result<Response<AccessRequestResponse>, Status> {
        let caller = self.caller(&request).await?;
        let req = request.into_inner();

        let requester_id = parse_profile_id("requester_profile_id", &req.requester_profile_id)?;
        caller.require_self_or_admin(requester_id)?;

        if req.requested_role.is_empty() {
            return Err(missing_field("requested_role"));
        }

        // Verify the requester profile exists.
        self.storage
            .get_profile(requester_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| profile_not_found(requester_id))?;

        // A request names a role the project defines.
        let role = self
            .project_role(&req.project_id, "requested_role", &req.requested_role)
            .await?;

        let mut access_req = AccessRequest::new(requester_id, role.project_id, &role.key);

        if !req.justification.is_empty() {
            access_req.justification = Some(req.justification);
        }

        // Whole hours, at least one; a duration that is not positive is
        // refused, never replaced by another.
        if let Some(duration) = req.requested_duration {
            if duration.seconds < 0
                || duration.nanos < 0
                || (duration.seconds == 0 && duration.nanos == 0)
            {
                return Err(invalid_field(
                    "requested_duration",
                    "not a positive duration",
                ));
            }
            let hours = u32::try_from((duration.seconds / 3600).max(1))
                .map_err(|_| invalid_field("requested_duration", "too long"))?;
            access_req.requested_duration_hours = Some(hours);
        }

        // Set default expiry for the request itself (7 days).
        access_req.expires_at =
            Some(chrono::Utc::now() + chrono::Duration::days(DEFAULT_REQUEST_EXPIRY_DAYS));

        let created_at = access_req.created_at;

        self.storage
            .create_access_request(
                &access_req,
                AuditEntry::user(
                    caller.profile_id.to_string(),
                    "governance.access_request.create",
                    access_req.id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!(
            "Access request {} created by {} for role '{}'",
            access_req.id.0, requester_id, req.requested_role
        );

        Ok(Response::new(AccessRequestResponse {
            request_id: access_req.id.0.to_string(),
            status: domain_status_to_proto(DomainAccessRequestStatus::Pending),
            created_at: Some(to_timestamp(created_at)),
        }))
    }

    #[instrument(skip_all, fields(method = "list_pending_requests"))]
    async fn list_pending_requests(
        &self,
        request: Request<ListPendingRequestsRequest>,
    ) -> Result<Response<ListPendingRequestsResponse>, Status> {
        self.admin(&request).await?;
        let pending = self
            .storage
            .list_pending_access_requests()
            .await
            .map_err(storage_failure)?;

        // Batch profile lookup for display names (deduplicate requester IDs).
        let requester_ids: std::collections::HashSet<ProfileId> =
            pending.iter().map(|r| r.requester_id).collect();
        let mut display_names = std::collections::HashMap::new();
        // A deleted requester falls back to its id; a failed read is an error.
        for pid in requester_ids {
            let profile = self
                .storage
                .get_profile(pid)
                .await
                .map_err(storage_failure)?;
            if let Some(profile) = profile {
                let name = profile
                    .formatted_name()
                    .or_else(|| profile.username.clone())
                    .unwrap_or_else(|| profile.id.to_string());
                display_names.insert(pid, name);
            }
        }

        let details: Vec<AccessRequestDetail> = pending
            .into_iter()
            .map(|r| {
                let display_name = display_names
                    .get(&r.requester_id)
                    .cloned()
                    .unwrap_or_else(|| r.requester_id.to_string());

                AccessRequestDetail {
                    request_id: r.id.0.to_string(),
                    requester_profile_id: r.requester_id.to_string(),
                    requester_display_name: display_name,
                    requested_role: r.role_key,
                    justification: r.justification.unwrap_or_default(),
                    requested_duration: r.requested_duration_hours.map(|h| prost_types::Duration {
                        seconds: h as i64 * 3600,
                        nanos: 0,
                    }),
                    status: domain_status_to_proto(r.status),
                    created_at: Some(to_timestamp(r.created_at)),
                    expires_at: to_opt_timestamp(r.expires_at),
                }
            })
            .collect();

        Ok(Response::new(ListPendingRequestsResponse {
            requests: details,
            pagination: None,
        }))
    }

    #[instrument(skip_all, fields(method = "decide_request"))]
    async fn decide_request(
        &self,
        request: Request<DecideRequestRequest>,
    ) -> Result<Response<DecideRequestResponse>, Status> {
        let reviewer_id = self.admin(&request).await?.profile_id;
        let req = request.into_inner();

        let request_id = uuid::Uuid::parse_str(&req.request_id)
            .map(AccessRequestId)
            .map_err(|_| invalid_field("request_id", "not an access request identifier"))?;

        let mut access_req = self
            .storage
            .get_access_request(request_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                not_found(
                    ErrorReason::AccessRequestNotFound,
                    "AccessRequest",
                    request_id.0.to_string(),
                )
            })?;

        // Check if expired before deciding.
        if access_req.check_expired() {
            // Recording the expiry loses to a decision made meanwhile; either
            // way this request can no longer be decided here.
            self.storage
                .decide_access_request(
                    &access_req,
                    AuditEntry::admin(
                        "system".to_string(),
                        "governance.access_request.expired",
                        request_id.0.to_string(),
                    )
                    .into(),
                )
                .await
                .map_err(storage_failure)?;

            return Ok(Response::new(DecideRequestResponse {
                request_id: req.request_id,
                status: domain_status_to_proto(DomainAccessRequestStatus::Expired),
            }));
        }

        // reviewer_id extracted from bearer token above.

        let comment = if req.reason.is_empty() {
            None
        } else {
            Some(req.reason.clone())
        };

        if req.approved {
            access_req
                .approve(reviewer_id, comment)
                .map_err(|_| already_decided(request_id))?;
        } else {
            access_req
                .deny(reviewer_id, comment)
                .map_err(|_| already_decided(request_id))?;
        }

        let new_status = access_req.status;
        let audit = AuditEntry::admin(
            reviewer_id.to_string(),
            if req.approved {
                "governance.access_request.approved"
            } else {
                "governance.access_request.denied"
            },
            request_id.0.to_string(),
        )
        .into();

        let decided = if new_status == DomainAccessRequestStatus::Approved {
            // The approval and the role it grants are one write: a role that
            // can no longer be assigned leaves the request pending.
            let role = self
                .storage
                .list_roles(access_req.project_id)
                .await
                .map_err(storage_failure)?
                .into_iter()
                .find(|r| r.key == access_req.role_key)
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorReason::InvalidState,
                        "the requested role no longer exists",
                    )
                    .with_precondition(
                        "REQUESTED_ROLE",
                        access_req.role_key.clone(),
                        "deleted",
                    )
                })?;
            // The approving installation administrator grants it as root of
            // its scope; the record names that reviewer.
            let mut grant = RoleAssignment::new(
                RoleAssignmentPrincipal::Profile(access_req.requester_id),
                role.id,
            )
            .granted(sid_core::models::AssignmentProvenance {
                granted_by: format!("user:{reviewer_id}"),
                basis: None,
                depends_on: None,
                ceiling: None,
            });
            grant.expires_at = access_req.role_expires_at();
            self.storage
                .approve_access_request(&access_req, &grant, audit)
                .await
        } else {
            self.storage.decide_access_request(&access_req, audit).await
        }
        .map_err(storage_failure)?;
        // Another reviewer decided first: this decision grants nothing.
        if !decided {
            return Err(already_decided(request_id));
        }
        info!(
            "Access request {} {:?} for {} (role '{}')",
            request_id.0, new_status, access_req.requester_id, access_req.role_key
        );

        Ok(Response::new(DecideRequestResponse {
            request_id: req.request_id,
            status: domain_status_to_proto(new_status),
        }))
    }

    #[instrument(skip_all, fields(method = "grant_temporary_role"))]
    async fn grant_temporary_role(
        &self,
        request: Request<GrantTemporaryRoleRequest>,
    ) -> Result<Response<GrantTemporaryRoleResponse>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();

        let profile_id = parse_profile_id("profile_id", &req.profile_id)?;

        if req.role.is_empty() {
            return Err(missing_field("role"));
        }

        let expires_at = req.expires_at.ok_or_else(|| missing_field("expires_at"))?;
        let expires_dt = u32::try_from(expires_at.nanos)
            .ok()
            .and_then(|nanos| chrono::DateTime::from_timestamp(expires_at.seconds, nanos))
            .filter(|at| *at > chrono::Utc::now())
            .ok_or_else(|| invalid_field("expires_at", "not a timestamp in the future"))?;

        // Verify profile exists.
        self.storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| profile_not_found(profile_id))?;
        let role = self
            .project_role(&req.project_id, "role", &req.role)
            .await?;

        // The project role itself, until the expiry, granted through the
        // common administration core by the installation's administrator.
        let mut assignment =
            RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
        assignment.expires_at = Some(expires_dt);

        let assignment_id = assignment.id;

        crate::admin::RoleAdministration::new(self.storage.clone())
            .assign(
                &crate::admin::Administrator::Root(sid_core::models::AuthzPrincipal::Profile(
                    caller.profile_id,
                )),
                assignment,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "governance.temporary_role.grant",
                    assignment_id.0.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!(
            "Temporary role '{}' granted to {} until {}",
            req.role, profile_id, expires_dt
        );

        Ok(Response::new(GrantTemporaryRoleResponse {
            assignment_id: assignment_id.0.to_string(),
            expires_at: Some(to_timestamp(expires_dt)),
        }))
    }
}

#[cfg(test)]
mod tests;
