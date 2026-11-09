// SPDX-License-Identifier: AGPL-3.0-only
//! CE governance: one-step access requests a Profile makes for a role its
//! project defines, decided by the installation's administrator, and
//! temporary roles that end on their expiry. Each is a keyed operation: its
//! change, audit and completion commit together and a retry answers with
//! what the first attempt recorded.

use prost::Message;
use sid_authn::caller::Caller;
use sid_authn::operation::{CommandError, KeyedCommand};
use sid_authz::admin::Administrator;
use sid_core::models::{
    AccessRequest, AccessRequestId, AccessRequestStatus as DomainStatus, AssignmentProvenance,
    AuditEntry, AuthzPrincipal, MutationContext, OperationContext, ProfileId, ProjectId, Role,
    RoleAssignment, RoleAssignmentPrincipal,
};
use sid_proto::keyed::authz::governance_service as keyed;
use sid_proto::sid::v1::authz::{
    AccessRequestDetail, AccessRequestMessage, AccessRequestResponse, AccessRequestStatus,
    DecideRequestRequest, DecideRequestResponse, GrantTemporaryRoleRequest,
    GrantTemporaryRoleResponse, ListPendingRequestsResponse,
};
use tracing::info;

use super::{Authorization, AuthorizationError, InstallationAdministrator, invalid_field};
use crate::wire::{to_timestamp, wire_id};

/// Access requests expire after 7 days if not acted upon.
const DEFAULT_REQUEST_EXPIRY_DAYS: i64 = 7;

pub(super) fn status_to_proto(status: DomainStatus) -> i32 {
    let status = match status {
        DomainStatus::Pending => AccessRequestStatus::Pending,
        DomainStatus::Approved => AccessRequestStatus::Approved,
        DomainStatus::Denied => AccessRequestStatus::Denied,
        DomainStatus::Expired => AccessRequestStatus::Expired,
        DomainStatus::Cancelled => AccessRequestStatus::Cancelled,
    };
    status as i32
}

impl Authorization {
    /// The role `key` of the project `project_id` names: roles are defined per
    /// project, so both are required; `role_field` names the request field
    /// that carries the key.
    async fn project_role(
        &self,
        project_id: Option<&sid_proto::sid::v1::ids::ProjectId>,
        role_field: &'static str,
        key: &str,
    ) -> Result<Role, AuthorizationError> {
        let project: ProjectId = wire_id(project_id, "project_id")?;
        if key.is_empty() {
            return Err(AuthorizationError::MissingField(role_field));
        }
        self.storage
            .get_project(project)
            .await?
            .ok_or(AuthorizationError::ProjectNotFound(project))?;
        self.storage
            .list_roles(project)
            .await?
            .into_iter()
            .find(|r| r.key == key)
            .ok_or_else(|| AuthorizationError::RoleNotFound(key.to_owned()))
    }

    async fn existing_profile(&self, id: ProfileId) -> Result<(), AuthorizationError> {
        self.storage
            .get_profile(id)
            .await?
            .map(|_| ())
            .ok_or(AuthorizationError::ProfileNotFound(id))
    }

    /// Request a role for `requester_profile_id`: the caller's own Profile,
    /// or any for an administrator. A retry of a completed request answers
    /// with the request it made and makes no second one.
    pub async fn request_access(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: AccessRequestMessage,
    ) -> Result<AccessRequestResponse, AuthorizationError> {
        let requester_id: ProfileId =
            wire_id(req.requester_profile_id.as_ref(), "requester_profile_id")?;
        caller.require_self_or_admin(requester_id)?;
        if req.requested_role.is_empty() {
            return Err(AuthorizationError::MissingField("requested_role"));
        }
        // Whole hours, at least one; a duration that is not positive is
        // refused, never replaced by another.
        let requested_duration_hours = match req.requested_duration {
            Some(duration) => {
                if duration.seconds < 0
                    || duration.nanos < 0
                    || (duration.seconds == 0 && duration.nanos == 0)
                {
                    return Err(invalid_field(
                        "requested_duration",
                        "not a positive duration",
                    ));
                }
                Some(
                    u32::try_from((duration.seconds / 3600).max(1))
                        .map_err(|_| invalid_field("requested_duration", "too long"))?,
                )
            }
            None => None,
        };
        let command =
            KeyedCommand::by_profile::<keyed::RequestAccess>(caller.profile_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                self.existing_profile(requester_id).await?;
                // A request names a role the project defines.
                let role = self
                    .project_role(
                        req.project_id.as_ref(),
                        "requested_role",
                        &req.requested_role,
                    )
                    .await?;
                let mut access_req = AccessRequest::new(requester_id, role.project_id, &role.key);
                if !req.justification.is_empty() {
                    access_req.justification = Some(req.justification.clone());
                }
                access_req.requested_duration_hours = requested_duration_hours;
                access_req.expires_at =
                    Some(chrono::Utc::now() + chrono::Duration::days(DEFAULT_REQUEST_EXPIRY_DAYS));
                let response = AccessRequestResponse {
                    request_id: Some(access_req.id.into()),
                    status: status_to_proto(DomainStatus::Pending),
                    created_at: Some(to_timestamp(access_req.created_at)),
                };
                let audit = MutationContext::from(AuditEntry::user(
                    caller.profile_id.to_string(),
                    "governance.access_request.create",
                    access_req.id.to_string(),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                self.storage
                    .create_access_request(&access_req, audit)
                    .await?;
                info!(
                    "Access request {} created by {} for role '{}'",
                    access_req.id, requester_id, req.requested_role
                );
                Ok(response)
            })
            .await
            .map_err(CommandError::<AuthorizationError>::refusal)
    }

    pub async fn list_pending_requests(
        &self,
        _admin: &InstallationAdministrator,
    ) -> Result<ListPendingRequestsResponse, AuthorizationError> {
        let pending = self.storage.list_pending_access_requests().await?;

        // One profile read per requester for the display names.
        let requester_ids: std::collections::HashSet<ProfileId> =
            pending.iter().map(|r| r.requester_id).collect();
        let mut display_names = std::collections::HashMap::new();
        // A deleted requester is shown by its id; a failed read is an error.
        for pid in requester_ids {
            if let Some(profile) = self.storage.get_profile(pid).await? {
                let name = profile
                    .formatted_name()
                    .or_else(|| profile.username.clone())
                    .unwrap_or_else(|| profile.id.to_string());
                display_names.insert(pid, name);
            }
        }

        let requests = pending
            .into_iter()
            .map(|r| AccessRequestDetail {
                request_id: Some(r.id.into()),
                requester_profile_id: Some(r.requester_id.into()),
                requester_display_name: display_names
                    .get(&r.requester_id)
                    .cloned()
                    .unwrap_or_else(|| r.requester_id.to_string()),
                requested_role: r.role_key,
                justification: r.justification.unwrap_or_default(),
                requested_duration: r.requested_duration_hours.map(|h| prost_types::Duration {
                    seconds: h as i64 * 3600,
                    nanos: 0,
                }),
                status: status_to_proto(r.status),
                created_at: Some(to_timestamp(r.created_at)),
                expires_at: r.expires_at.map(to_timestamp),
            })
            .collect();
        Ok(ListPendingRequestsResponse {
            requests,
            pagination: None,
        })
    }

    /// Approve or deny a pending request; an approval and the role it grants
    /// are one write. A retry of a completed decision answers as that
    /// decision did, not as a request already decided, and grants nothing
    /// again.
    pub async fn decide_request(
        &self,
        admin: &InstallationAdministrator,
        operation: OperationContext,
        req: DecideRequestRequest,
    ) -> Result<DecideRequestResponse, AuthorizationError> {
        let reviewer_id = admin.caller().profile_id;
        let request_id: AccessRequestId = wire_id(req.request_id.as_ref(), "request_id")?;
        let command =
            KeyedCommand::by_profile::<keyed::DecideRequest>(reviewer_id, operation, &req);
        command
            .execute(&*self.storage, || async {
                let mut access_req = self
                    .storage
                    .get_access_request(request_id)
                    .await?
                    .ok_or(AuthorizationError::AccessRequestNotFound(request_id))?;

                if access_req.check_expired() {
                    // Recording the expiry loses to a decision made
                    // meanwhile; either way this request can no longer be
                    // decided here.
                    let response = DecideRequestResponse {
                        request_id: Some(request_id.into()),
                        status: status_to_proto(DomainStatus::Expired),
                    };
                    let audit = MutationContext::from(AuditEntry::admin(
                        "system".to_string(),
                        "governance.access_request.expired",
                        request_id.to_string(),
                    ))
                    .with_operation(command.completion(response.encode_to_vec()));
                    self.storage
                        .decide_access_request(&access_req, audit)
                        .await?;
                    return Ok(response);
                }

                let comment = (!req.reason.is_empty()).then(|| req.reason.clone());
                let decided = if req.approved {
                    access_req.approve(reviewer_id, comment)
                } else {
                    access_req.deny(reviewer_id, comment)
                };
                decided.map_err(|_| AuthorizationError::AlreadyDecided(request_id))?;

                let new_status = access_req.status;
                let response = DecideRequestResponse {
                    request_id: Some(request_id.into()),
                    status: status_to_proto(new_status),
                };
                let audit = MutationContext::from(AuditEntry::admin(
                    reviewer_id.to_string(),
                    if req.approved {
                        "governance.access_request.approved"
                    } else {
                        "governance.access_request.denied"
                    },
                    request_id.to_string(),
                ))
                .with_operation(command.completion(response.encode_to_vec()));

                let decided = if new_status == DomainStatus::Approved {
                    // A role that can no longer be assigned leaves the
                    // request pending.
                    let role = self
                        .storage
                        .list_roles(access_req.project_id)
                        .await?
                        .into_iter()
                        .find(|r| r.key == access_req.role_key)
                        .ok_or_else(|| {
                            AuthorizationError::RequestedRoleDeleted(access_req.role_key.clone())
                        })?;
                    // The approving installation administrator grants it as
                    // root of its scope; the record names that reviewer.
                    let mut grant = RoleAssignment::new(
                        RoleAssignmentPrincipal::Profile(access_req.requester_id),
                        role.id,
                    )
                    .granted(AssignmentProvenance {
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
                }?;
                // Another reviewer decided first: this decision grants
                // nothing.
                if !decided {
                    return Err(AuthorizationError::AlreadyDecided(request_id).into());
                }
                info!(
                    "Access request {} {:?} for {} (role '{}')",
                    request_id, new_status, access_req.requester_id, access_req.role_key
                );
                Ok(response)
            })
            .await
            .map_err(CommandError::<AuthorizationError>::refusal)
    }

    /// The project role itself until the expiry, granted by the
    /// installation's administrator through the common administration core.
    /// A retry of a completed grant answers with the assignment it made and
    /// grants no second one.
    pub async fn grant_temporary_role(
        &self,
        admin: &InstallationAdministrator,
        operation: OperationContext,
        req: GrantTemporaryRoleRequest,
    ) -> Result<GrantTemporaryRoleResponse, AuthorizationError> {
        let administrator_id = admin.caller().profile_id;
        let profile_id: ProfileId = wire_id(req.profile_id.as_ref(), "profile_id")?;
        if req.role.is_empty() {
            return Err(AuthorizationError::MissingField("role"));
        }
        let expires_at = req
            .expires_at
            .ok_or(AuthorizationError::MissingField("expires_at"))?;
        let expires_dt = u32::try_from(expires_at.nanos)
            .ok()
            .and_then(|nanos| chrono::DateTime::from_timestamp(expires_at.seconds, nanos))
            .filter(|at| *at > chrono::Utc::now())
            .ok_or_else(|| invalid_field("expires_at", "not a timestamp in the future"))?;
        let command = KeyedCommand::by_profile::<keyed::GrantTemporaryRole>(
            administrator_id,
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || async {
                self.existing_profile(profile_id).await?;
                let role = self
                    .project_role(req.project_id.as_ref(), "role", &req.role)
                    .await?;

                let mut assignment =
                    RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
                assignment.expires_at = Some(expires_dt);
                let assignment_id = assignment.id;
                let response = GrantTemporaryRoleResponse {
                    assignment_id: Some(assignment_id.into()),
                    expires_at: Some(to_timestamp(expires_dt)),
                };
                // The grantor is the root of its scope: no administrative
                // refusal applies, and a failed grant is the store's.
                self.administration()
                    .assign_recording(
                        &Administrator::Root(AuthzPrincipal::Profile(administrator_id)),
                        assignment,
                        AuditEntry::admin(
                            administrator_id.to_string(),
                            "governance.temporary_role.grant",
                            assignment_id.to_string(),
                        )
                        .into(),
                        |_| Some(command.completion(response.encode_to_vec())),
                    )
                    .await?;
                info!(
                    "Temporary role '{}' granted to {} until {}",
                    req.role, profile_id, expires_dt
                );
                Ok(response)
            })
            .await
            .map_err(CommandError::<AuthorizationError>::refusal)
    }
}

#[cfg(test)]
mod tests;
