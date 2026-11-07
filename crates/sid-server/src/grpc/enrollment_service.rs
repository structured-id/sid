// SPDX-License-Identifier: AGPL-3.0-only
//! Enrollment service gRPC implementation: authenticates the caller, admits
//! services to the invite RPCs and answers through [`sid::enrollment`].

use sid::enrollment::{Enrollment, EnrollmentError, Inviter};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::resource_token::ResourceTokenVerifier;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::service_auth::{AuthenticatedService, ServiceCaller};
use sid_authz::{AuthzCheckRequest, CeAuthzEngine};
use sid_core::models::{EnrollmentMode, INVITE_CREATE, INVITE_READ, INVITE_REVOKE, ResourceId};
use sid_infra::authn::caller::authenticate;
use sid_infra::authn::operation::context;
use sid_infra::authn::own_token::authenticate_service;
use sid_infra::grpc_error::refuse::{
    dependency_unavailable, invalid_field, missing_field, not_found, storage_failure,
};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::admin as v1;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// The status an enrollment refusal answers with.
pub(crate) fn refusal(e: EnrollmentError) -> Status {
    match e {
        EnrollmentError::Caller(e) => e.into_status(),
        EnrollmentError::Operation(e) => e.into_status(),
        EnrollmentError::Store(e) => storage_failure(e),
        EnrollmentError::Internal => ApiError::internal().into(),
        EnrollmentError::MissingField(field) => missing_field(field),
        EnrollmentError::InvalidField { field, reason } => invalid_field(field, reason),
        EnrollmentError::ModePinned(refusal) => {
            ApiError::new(ErrorReason::InvalidState, refusal.to_string())
                .with_precondition(
                    "pinned_by_deployment",
                    "enrollment_policy.mode",
                    refusal.to_string(),
                )
                .into()
        }
        EnrollmentError::InviteNotFound(id) => {
            not_found(ErrorReason::InviteNotFound, "Invite", id.to_string())
        }
    }
}

/// Services that may manage invites: a machine user with its own token for
/// the enrollment API, holding the invite action on that resource.
pub struct InviteServices {
    pub engine: Arc<CeAuthzEngine<dyn StorageBackend>>,
    pub tokens: Arc<ResourceTokenVerifier>,
    /// The enrollment API resource the actions are held on.
    pub resource: ResourceId,
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
    enrollment: Enrollment,
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
            enrollment: Enrollment::new(storage.clone(), None),
            storage,
            jwt,
            revocation,
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
    pub fn with_pinned_mode(mut self, mode: Option<EnrollmentMode>) -> Self {
        self.enrollment = Enrollment::new(self.storage.clone(), mode);
        self
    }

    async fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        authenticate(request, self.jwt.verifier(), &self.revocation).await
    }

    /// Who may perform invite `action` on `request`: a service with its own
    /// token for the enrollment API holding `action` there, or else an
    /// administrator Profile. A service token is valid only for the
    /// enrollment API and a user's sign-in token never is, so each
    /// credential has one path.
    async fn inviter<T>(&self, request: &Request<T>, action: &str) -> Result<Inviter, Status> {
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
                        Ok(Inviter::Machine(machine))
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
        Inviter::administrator(&self.caller(request).await?).map_err(refusal)
    }
}

#[tonic::async_trait]
impl v1::enrollment_service_server::EnrollmentService for EnrollmentServiceImpl {
    #[tracing::instrument(skip_all, fields(rpc = "get_enrollment_policy"))]
    async fn get_enrollment_policy(
        &self,
        _request: Request<()>,
    ) -> Result<Response<v1::EnrollmentPolicy>, Status> {
        self.enrollment
            .policy_in_force()
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    /// Public: the registration page asks for the claim token while the claim
    /// is open.
    #[tracing::instrument(skip_all, fields(rpc = "get_instance_status"))]
    async fn get_instance_status(
        &self,
        _request: Request<()>,
    ) -> Result<Response<v1::InstanceStatus>, Status> {
        self.enrollment
            .instance_status()
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "update_enrollment_policy"))]
    async fn update_enrollment_policy(
        &self,
        request: Request<v1::UpdateEnrollmentPolicyRequest>,
    ) -> Result<Response<v1::EnrollmentPolicy>, Status> {
        let caller = self.caller(&request).await?;
        caller.require_admin().map_err(|e| refusal(e.into()))?;
        let operation = context(&request)?;
        self.enrollment
            .update_policy(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "create_invite"))]
    async fn create_invite(
        &self,
        request: Request<v1::CreateInviteRequest>,
    ) -> Result<Response<v1::Invite>, Status> {
        let inviter = self.inviter(&request, INVITE_CREATE).await?;
        let operation = context(&request)?;
        self.enrollment
            .create_invite(inviter, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_invite"))]
    async fn get_invite(
        &self,
        request: Request<v1::GetInviteRequest>,
    ) -> Result<Response<v1::Invite>, Status> {
        self.inviter(&request, INVITE_READ).await?;
        self.enrollment
            .get_invite(request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_invite_redemptions"))]
    async fn list_invite_redemptions(
        &self,
        request: Request<v1::ListInviteRedemptionsRequest>,
    ) -> Result<Response<v1::ListInviteRedemptionsResponse>, Status> {
        self.inviter(&request, INVITE_READ).await?;
        self.enrollment
            .list_invite_redemptions(request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "list_invites"))]
    async fn list_invites(
        &self,
        request: Request<v1::ListInvitesRequest>,
    ) -> Result<Response<v1::ListInvitesResponse>, Status> {
        self.inviter(&request, INVITE_READ).await?;
        self.enrollment
            .list_invites(request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "revoke_invite"))]
    async fn revoke_invite(
        &self,
        request: Request<v1::RevokeInviteRequest>,
    ) -> Result<Response<()>, Status> {
        let inviter = self.inviter(&request, INVITE_REVOKE).await?;
        self.enrollment
            .revoke_invite(inviter, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "bulk_create_invites"))]
    async fn bulk_create_invites(
        &self,
        request: Request<v1::BulkCreateInvitesRequest>,
    ) -> Result<Response<v1::BulkCreateInvitesResponse>, Status> {
        let inviter = self.inviter(&request, INVITE_CREATE).await?;
        let operation = context(&request)?;
        self.enrollment
            .bulk_create_invites(inviter, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[tracing::instrument(skip_all, fields(rpc = "get_registration_stats"))]
    async fn get_registration_stats(
        &self,
        request: Request<v1::GetRegistrationStatsRequest>,
    ) -> Result<Response<v1::RegistrationStats>, Status> {
        let caller = self.caller(&request).await?;
        self.enrollment
            .registration_stats(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }
}

#[cfg(test)]
mod tests;
