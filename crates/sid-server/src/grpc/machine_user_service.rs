// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC MachineUserService: the transport of [`sid::machines`], which owns
//! machine users, their credentials and impersonation grants (RFC 8693
//! token exchange). Each call is authenticated here and answered with the
//! status the operation's refusal names.

use std::sync::Arc;

use sid::machines::{MachineError, Machines};
use sid_authn::caller::authenticate;
use sid_authn::jwt::JwtService;
use sid_authn::operation::grpc::context;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::grpc_error::refuse::{
    changed_concurrently, invalid_field, missing_field, not_found, storage_failure,
};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::{
    AddMachineCredentialRequest, AddMachineCredentialResponse, CreateMachineUserRequest,
    CreateMachineUserResponse, DeleteMachineUserRequest, DeleteMachineUserResponse,
    GetMachineUserRequest, GrantImpersonationRequest, GrantImpersonationResponse,
    ListImpersonationGrantsRequest, ListImpersonationGrantsResponse, ListMachineCredentialsRequest,
    ListMachineCredentialsResponse, ListMachineUsersRequest, ListMachineUsersResponse,
    MachineUserResponse, ReactivateMachineUserRequest, RevokeImpersonationRequest,
    RevokeImpersonationResponse, RevokeMachineCredentialRequest, RevokeMachineCredentialResponse,
    RotateMachineCredentialRequest, RotateMachineCredentialResponse, SuspendMachineUserRequest,
    UpdateMachineUserRequest, machine_user_service_server::MachineUserService,
};
use tonic::{Request, Response, Status};

/// gRPC service for machine user management.
pub struct MachineUserServiceImpl {
    machines: Machines,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
}

impl MachineUserServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
        organization: sid_core::models::OrgId,
    ) -> Self {
        Self {
            machines: Machines::new(storage, revocation.clone(), organization),
            jwt,
            revocation,
        }
    }

    #[allow(clippy::result_large_err)]
    async fn caller<T>(&self, request: &Request<T>) -> Result<sid_authn::caller::Caller, Status> {
        authenticate(request, self.jwt.verifier(), &self.revocation).await
    }
}

/// The status of a machine operation's refusal.
fn refusal(e: MachineError) -> Status {
    match e {
        MachineError::Caller(e) => e.into(),
        MachineError::Operation(e) => e.into(),
        MachineError::Store(e) => storage_failure(e),
        MachineError::MissingField(field) => missing_field(field),
        MachineError::InvalidField { field, reason } => invalid_field(field, reason),
        MachineError::NotFound(id) => not_found(
            ErrorReason::MachineUserNotFound,
            "MachineUser",
            id.to_string(),
        ),
        MachineError::CredentialNotFound(kid) => {
            not_found(ErrorReason::CredentialNotFound, "MachineCredential", kid)
        }
        MachineError::MachineState { id, state, change } => ApiError::new(
            ErrorReason::InvalidState,
            format!("a {state} machine user cannot be {change}"),
        )
        .with_precondition("MACHINE_USER_STATE", id.to_string(), state)
        .into(),
        MachineError::CredentialState { kid, state } => ApiError::new(
            ErrorReason::InvalidState,
            "only an active credential can be rotated",
        )
        .with_precondition("MACHINE_CREDENTIAL_STATE", kid, state)
        .into(),
        MachineError::CredentialLimit(id) => ApiError::new(
            ErrorReason::QuotaExceeded,
            "the limit of active machine credentials is reached",
        )
        .with_quota_violation(
            format!("machine_credentials/{id}"),
            format!(
                "at most {} active credentials per machine user",
                sid_core::models::machine_user::MAX_ACTIVE_CREDENTIALS
            ),
        )
        .into(),
        MachineError::ChangedConcurrently => changed_concurrently(),
    }
}

/// The answer of an operation, or the status of its refusal.
#[allow(clippy::result_large_err)]
fn answer<T>(result: Result<T, MachineError>) -> Result<Response<T>, Status> {
    result.map(Response::new).map_err(refusal)
}

#[tonic::async_trait]
impl MachineUserService for MachineUserServiceImpl {
    async fn create_machine_user(
        &self,
        request: Request<CreateMachineUserRequest>,
    ) -> Result<Response<CreateMachineUserResponse>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        answer(
            self.machines
                .create_machine_user(&caller, operation, request.into_inner())
                .await,
        )
    }

    async fn get_machine_user(
        &self,
        request: Request<GetMachineUserRequest>,
    ) -> Result<Response<MachineUserResponse>, Status> {
        let caller = self.caller(&request).await?;
        answer(
            self.machines
                .get_machine_user(&caller, request.into_inner())
                .await,
        )
    }

    async fn update_machine_user(
        &self,
        request: Request<UpdateMachineUserRequest>,
    ) -> Result<Response<MachineUserResponse>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        answer(
            self.machines
                .update_machine_user(&caller, operation, request.into_inner())
                .await,
        )
    }

    async fn delete_machine_user(
        &self,
        request: Request<DeleteMachineUserRequest>,
    ) -> Result<Response<DeleteMachineUserResponse>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        answer(
            self.machines
                .delete_machine_user(&caller, operation, request.into_inner())
                .await,
        )
    }

    async fn list_machine_users(
        &self,
        request: Request<ListMachineUsersRequest>,
    ) -> Result<Response<ListMachineUsersResponse>, Status> {
        let caller = self.caller(&request).await?;
        answer(
            self.machines
                .list_machine_users(&caller, request.into_inner())
                .await,
        )
    }

    async fn suspend_machine_user(
        &self,
        request: Request<SuspendMachineUserRequest>,
    ) -> Result<Response<MachineUserResponse>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        answer(
            self.machines
                .suspend_machine_user(&caller, operation, request.into_inner())
                .await,
        )
    }

    async fn reactivate_machine_user(
        &self,
        request: Request<ReactivateMachineUserRequest>,
    ) -> Result<Response<MachineUserResponse>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        answer(
            self.machines
                .reactivate_machine_user(&caller, operation, request.into_inner())
                .await,
        )
    }

    async fn add_machine_credential(
        &self,
        request: Request<AddMachineCredentialRequest>,
    ) -> Result<Response<AddMachineCredentialResponse>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        answer(
            self.machines
                .add_machine_credential(&caller, operation, request.into_inner())
                .await,
        )
    }

    async fn revoke_machine_credential(
        &self,
        request: Request<RevokeMachineCredentialRequest>,
    ) -> Result<Response<RevokeMachineCredentialResponse>, Status> {
        let caller = self.caller(&request).await?;
        answer(
            self.machines
                .revoke_machine_credential(&caller, request.into_inner())
                .await,
        )
    }

    async fn list_machine_credentials(
        &self,
        request: Request<ListMachineCredentialsRequest>,
    ) -> Result<Response<ListMachineCredentialsResponse>, Status> {
        let caller = self.caller(&request).await?;
        answer(
            self.machines
                .list_machine_credentials(&caller, request.into_inner())
                .await,
        )
    }

    async fn rotate_machine_credential(
        &self,
        request: Request<RotateMachineCredentialRequest>,
    ) -> Result<Response<RotateMachineCredentialResponse>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        answer(
            self.machines
                .rotate_machine_credential(&caller, operation, request.into_inner())
                .await,
        )
    }

    async fn grant_impersonation(
        &self,
        request: Request<GrantImpersonationRequest>,
    ) -> Result<Response<GrantImpersonationResponse>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        answer(
            self.machines
                .grant_impersonation(&caller, operation, request.into_inner())
                .await,
        )
    }

    async fn revoke_impersonation(
        &self,
        request: Request<RevokeImpersonationRequest>,
    ) -> Result<Response<RevokeImpersonationResponse>, Status> {
        let caller = self.caller(&request).await?;
        let operation = context(&request)?;
        answer(
            self.machines
                .revoke_impersonation(&caller, operation, request.into_inner())
                .await,
        )
    }

    async fn list_impersonation_grants(
        &self,
        request: Request<ListImpersonationGrantsRequest>,
    ) -> Result<Response<ListImpersonationGrantsResponse>, Status> {
        let caller = self.caller(&request).await?;
        answer(
            self.machines
                .list_impersonation_grants(&caller, request.into_inner())
                .await,
        )
    }
}

#[cfg(test)]
mod tests;
