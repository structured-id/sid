// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC BrandingService implementation: authenticates the caller and answers
//! through [`sid::branding`]. The published branding of a project is public;
//! everything else requires the administrator role.

use sid::branding::{Branding, BrandingError};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_infra::authn::caller::authenticate;
use sid_infra::authn::operation::context;
use sid_infra::grpc_error::refuse::{
    changed_concurrently, invalid_field, not_found, storage_failure,
};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::branding_service_server::BrandingService;
use sid_proto::sid::v1::{self as pb};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::instrument;

/// The status a branding refusal answers with.
fn refusal(e: BrandingError) -> Status {
    let state = |id: sid_core::models::BrandingConfigId, state: &str, why: &'static str| {
        Status::from(
            ApiError::new(ErrorReason::InvalidState, why).with_precondition(
                "BRANDING_STATUS",
                id.to_string(),
                state,
            ),
        )
    };
    match e {
        BrandingError::Caller(e) => e.into_status(),
        BrandingError::Operation(e) => e.into_status(),
        BrandingError::Store(e) => storage_failure(e),
        BrandingError::InvalidField { field, reason } => invalid_field(field, reason),
        BrandingError::NotFound(name) => {
            not_found(ErrorReason::BrandingNotFound, "BrandingConfig", name)
        }
        BrandingError::NotADraft(id) => {
            state(id, "not a draft", "only a draft branding config changes")
        }
        BrandingError::Published(id) => state(
            id,
            "published",
            "a published branding config is not deleted; publish another first",
        ),
        BrandingError::ChangedConcurrently => changed_concurrently(),
    }
}

pub struct BrandingServiceImpl {
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    branding: Branding,
}

impl BrandingServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            jwt,
            revocation,
            branding: Branding::new(storage),
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
impl BrandingService for BrandingServiceImpl {
    #[instrument(skip_all, name = "branding.get_published")]
    async fn get_published_branding(
        &self,
        request: Request<pb::GetPublishedBrandingRequest>,
    ) -> Result<Response<pb::BrandingConfig>, Status> {
        self.branding
            .published(request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "branding.get_config")]
    async fn get_branding_config(
        &self,
        request: Request<pb::GetBrandingConfigRequest>,
    ) -> Result<Response<pb::BrandingConfig>, Status> {
        let caller = self.caller(&request).await?;
        self.branding
            .config(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "branding.list")]
    async fn list_branding_configs(
        &self,
        request: Request<pb::ListBrandingConfigsRequest>,
    ) -> Result<Response<pb::ListBrandingConfigsResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.branding
            .list(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "branding.create")]
    async fn create_branding_config(
        &self,
        request: Request<pb::CreateBrandingConfigRequest>,
    ) -> Result<Response<pb::BrandingConfig>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.branding
            .create(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "branding.update")]
    async fn update_branding_config(
        &self,
        request: Request<pb::UpdateBrandingConfigRequest>,
    ) -> Result<Response<pb::BrandingConfig>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.branding
            .update(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "branding.publish")]
    async fn publish_branding_config(
        &self,
        request: Request<pb::PublishBrandingConfigRequest>,
    ) -> Result<Response<pb::BrandingConfig>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.branding
            .publish(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "branding.delete")]
    async fn delete_branding_config(
        &self,
        request: Request<pb::DeleteBrandingConfigRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        self.branding
            .delete(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip_all, name = "branding.validate_contrast")]
    async fn validate_contrast(
        &self,
        request: Request<pb::ValidateContrastRequest>,
    ) -> Result<Response<pb::ValidateContrastResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.branding
            .validate_contrast(&caller, request.into_inner())
            .map(Response::new)
            .map_err(refusal)
    }
}

#[cfg(test)]
mod tests;
