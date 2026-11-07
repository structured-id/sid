// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC AdminService implementation: authenticates the caller and answers
//! through [`sid::admin`] (the instance claim, an administrator's Profile
//! update, bulk session revocation, Profile metadata).

use sid::admin::{Admin, AdminError};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_infra::authn::caller::authenticate;
use sid_infra::authn::operation::context;
use sid_infra::grpc_error::refuse::{
    changed_concurrently, invalid_field, not_found, storage_failure,
};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::admin_service_server::AdminService;
use sid_proto::sid::v1::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::instrument;

/// The status an administration refusal answers with.
fn refusal(e: AdminError) -> Status {
    match e {
        AdminError::Caller(e) => e.into_status(),
        AdminError::Operation(e) => e.into_status(),
        AdminError::Store(e) => storage_failure(e),
        AdminError::Internal => ApiError::internal().into(),
        AdminError::InvalidField { field, reason } => invalid_field(field, reason),
        AdminError::ProfileNotFound(id) => {
            not_found(ErrorReason::ProfileNotFound, "Profile", id.to_string())
        }
        AdminError::StatusNotChangeable(id) => ApiError::new(
            ErrorReason::InvalidState,
            "the profile's status cannot be changed by an administrator",
        )
        .with_precondition("PROFILE_STATUS", id.to_string(), "not changeable")
        .into(),
        AdminError::MetadataNotFound { profile, key } => not_found(
            ErrorReason::ProfileMetadataNotFound,
            "ProfileMetadata",
            format!("{profile}:{key}"),
        ),
        AdminError::AlreadyClaimed => ApiError::new(
            ErrorReason::InvalidState,
            "the installation is already claimed",
        )
        .with_precondition("INSTANCE_CLAIM", "installation", "claimed")
        .into(),
        AdminError::ClaimMismatch => ApiError::new(
            ErrorReason::InsufficientPermissions,
            "the claim token does not match",
        )
        .into(),
        AdminError::ChangedConcurrently => changed_concurrently(),
    }
}

pub struct AdminServiceImpl {
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    admin: Admin,
}

impl AdminServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
        cascade: Arc<RevocationCascadeService>,
        key_manager: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            jwt,
            revocation,
            admin: Admin::new(storage, cascade, key_manager),
        }
    }

    async fn caller<T>(&self, req: &Request<T>) -> Result<Caller, Status> {
        authenticate(req, self.jwt.verifier(), &self.revocation).await
    }

    /// The authenticated administrator: checked before the operation
    /// context, so a refused caller learns nothing more about it.
    async fn admin<T>(&self, req: &Request<T>) -> Result<Caller, Status> {
        let caller = self.caller(req).await?;
        caller.require_admin().map_err(|e| e.into_status())?;
        Ok(caller)
    }
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    /// The signed-in caller becomes the first administrator with the claim
    /// token from the service log (enrollment-policy.md, First Administrator).
    #[instrument(skip_all, name = "admin.claim_instance")]
    async fn claim_instance(
        &self,
        request: Request<ClaimInstanceRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        let token = secrecy::SecretString::from(request.into_inner().claim_token);
        self.admin
            .claim_instance(&caller, &token)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "admin.update_profile")]
    async fn admin_update_profile(
        &self,
        request: Request<AdminUpdateProfileRequest>,
    ) -> Result<Response<AdminUpdateProfileResponse>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.admin
            .update_profile(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "admin.revoke_all_sessions")]
    async fn revoke_all_sessions(
        &self,
        request: Request<RevokeAllSessionsRequest>,
    ) -> Result<Response<RevokeAllSessionsResponse>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.admin
            .revoke_all_sessions(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "admin.list_profile_metadata")]
    async fn list_profile_metadata(
        &self,
        request: Request<ListProfileMetadataRequest>,
    ) -> Result<Response<ListProfileMetadataResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.admin
            .list_metadata(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "admin.get_profile_metadata")]
    async fn get_profile_metadata(
        &self,
        request: Request<GetProfileMetadataRequest>,
    ) -> Result<Response<ProfileMetadataEntry>, Status> {
        let caller = self.caller(&request).await?;
        self.admin
            .get_metadata(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "admin.set_profile_metadata")]
    async fn set_profile_metadata(
        &self,
        request: Request<SetProfileMetadataRequest>,
    ) -> Result<Response<ProfileMetadataEntry>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.admin
            .set_metadata(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "admin.delete_profile_metadata")]
    async fn delete_profile_metadata(
        &self,
        request: Request<DeleteProfileMetadataRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.admin
            .delete_metadata(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }
}

#[cfg(test)]
mod tests;
