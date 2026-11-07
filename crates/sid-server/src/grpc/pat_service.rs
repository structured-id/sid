// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC PatService implementation: authenticates the caller and answers
//! through [`sid::pats`] (personal access token lifecycle and exchange).

use sid::pats::{PatError, Pats};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::pat::PAT_MAX_ACTIVE_PER_USER;
use sid_infra::authn::caller::authenticate;
use sid_infra::authn::operation::context;
use sid_infra::grpc_error::refuse::{
    changed_concurrently, invalid_field, missing_field, not_found, storage_failure,
};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::{
    AdminRevokePatRequest, CreatePatRequest, CreatePatResponse, ExchangePatRequest,
    ExchangePatResponse, GetPatRequest, ListAllPatsRequest, ListAllPatsResponse, ListPatsRequest,
    ListPatsResponse, PatResponse, RevokePatRequest, RevokePatResponse,
    pat_service_server::PatService,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// The status a personal access token refusal answers with.
fn refusal(e: PatError) -> Status {
    match e {
        PatError::Caller(e) => e.into_status(),
        PatError::Operation(e) => e.into_status(),
        PatError::Store(e) => storage_failure(e),
        PatError::MissingField(field) => missing_field(field),
        PatError::InvalidField { field, reason } => invalid_field(field, reason),
        PatError::NotFound(id) => not_found(
            ErrorReason::CredentialNotFound,
            "PersonalAccessToken",
            id.to_string(),
        ),
        PatError::Unusable => {
            ApiError::new(ErrorReason::TokenInvalid, "the token is not valid").into()
        }
        PatError::QuotaReached => ApiError::new(
            ErrorReason::QuotaExceeded,
            "the limit of active personal access tokens is reached",
        )
        .with_quota_violation(
            "personal_access_tokens",
            format!("at most {PAT_MAX_ACTIVE_PER_USER} active tokens per user"),
        )
        .into(),
        PatError::NotResourceBound(id) => ApiError::new(
            ErrorReason::InvalidState,
            "the token is not bound to a registered resource; replace it",
        )
        .with_precondition(
            "PAT_RESOURCE_BINDING",
            id.to_string(),
            "the token names no registered resource",
        )
        .into(),
        PatError::ChangedConcurrently => changed_concurrently(),
    }
}

/// gRPC service for personal access token management.
pub struct PatServiceImpl {
    jwt: Arc<JwtService>,
    revocation_cache: Arc<RevocationCache>,
    pats: Pats,
}

impl PatServiceImpl {
    /// Create a new PAT service instance.
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation_cache: Arc<RevocationCache>,
    ) -> Self {
        Self {
            jwt,
            revocation_cache,
            pats: Pats::new(storage),
        }
    }

    async fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        authenticate(request, self.jwt.verifier(), &self.revocation_cache).await
    }
}

#[tonic::async_trait]
impl PatService for PatServiceImpl {
    async fn create_pat(
        &self,
        request: Request<CreatePatRequest>,
    ) -> Result<Response<CreatePatResponse>, Status> {
        let caller = self.caller(&request).await?;
        // Only a user's own sign-in session mints a token; refused before
        // the operation context is read.
        caller.require_interactive().map_err(|e| e.into_status())?;
        let operation = context(&request)?;
        self.pats
            .create(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn list_pats(
        &self,
        request: Request<ListPatsRequest>,
    ) -> Result<Response<ListPatsResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.pats
            .list(&caller)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn get_pat(
        &self,
        request: Request<GetPatRequest>,
    ) -> Result<Response<PatResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.pats
            .get(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn revoke_pat(
        &self,
        request: Request<RevokePatRequest>,
    ) -> Result<Response<RevokePatResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.pats
            .revoke(&caller, request.into_inner())
            .await
            .map(|()| Response::new(RevokePatResponse {}))
            .map_err(refusal)
    }

    async fn exchange_pat(
        &self,
        request: Request<ExchangePatRequest>,
    ) -> Result<Response<ExchangePatResponse>, Status> {
        // Nothing is issued: an exchange is refused with its reason.
        Err(refusal(self.pats.exchange(request.into_inner()).await))
    }

    async fn list_all_pats(
        &self,
        request: Request<ListAllPatsRequest>,
    ) -> Result<Response<ListAllPatsResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.pats
            .list_all(&caller)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn admin_revoke_pat(
        &self,
        request: Request<AdminRevokePatRequest>,
    ) -> Result<Response<RevokePatResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.pats
            .admin_revoke(&caller, request.into_inner())
            .await
            .map(|()| Response::new(RevokePatResponse {}))
            .map_err(refusal)
    }
}

#[cfg(test)]
mod tests;
