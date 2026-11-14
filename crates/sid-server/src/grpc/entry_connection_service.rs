// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC EntryConnectionService: an administrator's management of the
//! installation's entry connections ([`sid::entry_connections`]) and the
//! public list a sign-in page offers.

use std::sync::Arc;

use sid::entry_connections::{EntryConnectionError, EntryConnections};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_infra::authn::caller::authenticate;
use sid_infra::authn::operation::context;
use sid_infra::grpc_error::refuse::{
    changed_concurrently, invalid_field, missing_field, not_found, storage_failure,
};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use sid_proto::sid::v1::entry_connection_service_server::EntryConnectionService;
use sid_proto::sid::v1::{
    CreateEntryConnectionRequest, EntryConnection, ListEntryConnectionsRequest,
    ListEntryConnectionsResponse, ListSignInConnectionsRequest, ListSignInConnectionsResponse,
    RemoveEntryConnectionRequest, UpdateEntryConnectionRequest,
};
use tonic::{Request, Response, Status};

/// The status an entry connection refusal answers with.
fn refusal(e: EntryConnectionError) -> Status {
    match e {
        EntryConnectionError::Caller(e) => e.into_status(),
        EntryConnectionError::Operation(e) => e.into_status(),
        EntryConnectionError::Store(e) => storage_failure(e),
        EntryConnectionError::Internal => ApiError::internal().into(),
        EntryConnectionError::MissingField(field) => missing_field(field),
        EntryConnectionError::InvalidField { field, reason } => invalid_field(field, reason),
        EntryConnectionError::NotFound(handle) => not_found(
            ErrorReason::EntryConnectionNotFound,
            "EntryConnection",
            handle.to_string(),
        ),
        EntryConnectionError::UnknownIssuer(handle) => {
            not_found(ErrorReason::OidcIssuerNotFound, "OidcIssuer", handle)
        }
        EntryConnectionError::IssuerTaken => ApiError::new(
            ErrorReason::EntryConnectionAlreadyExists,
            "the issuer already has an entry connection",
        )
        .into(),
        // The provisioned authority follows the installation's provisioning
        // and is not edited by hand.
        EntryConnectionError::Provisioned => ApiError::new(
            ErrorReason::SystemManaged,
            "the entry connection is set by the installation's provisioning",
        )
        .with_precondition(
            "SYSTEM_MANAGED",
            "EntryConnection",
            "it follows the installation's provisioning",
        )
        .into(),
        EntryConnectionError::ChangedConcurrently => changed_concurrently(),
        // Only provisioning sets an authority; no administrator's call asks.
        EntryConnectionError::Established => ApiError::new(
            ErrorReason::InvalidState,
            "another issuer is the provisioned authority already",
        )
        .with_precondition("PROVISIONED_AUTHORITY", "EntryConnection", "established")
        .into(),
    }
}

/// gRPC service for the installation's entry connections.
pub struct EntryConnectionServiceImpl {
    connections: Arc<EntryConnections>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
}

impl EntryConnectionServiceImpl {
    pub fn new(
        connections: Arc<EntryConnections>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            connections,
            jwt,
            revocation,
        }
    }

    /// The authenticated administrator: checked before the operation
    /// context, so a refused caller learns nothing more about it.
    async fn admin<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let caller = authenticate(request, self.jwt.verifier(), &self.revocation).await?;
        caller.require_admin().map_err(|e| e.into_status())?;
        Ok(caller)
    }
}

#[tonic::async_trait]
impl EntryConnectionService for EntryConnectionServiceImpl {
    async fn list_entry_connections(
        &self,
        request: Request<ListEntryConnectionsRequest>,
    ) -> Result<Response<ListEntryConnectionsResponse>, Status> {
        let caller = self.admin(&request).await?;
        self.connections
            .list(&caller)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn create_entry_connection(
        &self,
        request: Request<CreateEntryConnectionRequest>,
    ) -> Result<Response<EntryConnection>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.connections
            .create(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn update_entry_connection(
        &self,
        request: Request<UpdateEntryConnectionRequest>,
    ) -> Result<Response<EntryConnection>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.connections
            .update(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn remove_entry_connection(
        &self,
        request: Request<RemoveEntryConnectionRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.admin(&request).await?;
        self.connections
            .remove(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn list_sign_in_connections(
        &self,
        request: Request<ListSignInConnectionsRequest>,
    ) -> Result<Response<ListSignInConnectionsResponse>, Status> {
        self.connections
            .sign_in_connections(&request.get_ref().issuer_handle)
            .await
            .map(Response::new)
            .map_err(refusal)
    }
}

#[cfg(test)]
mod tests;
