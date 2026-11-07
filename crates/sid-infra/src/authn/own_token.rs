// SPDX-License-Identifier: AGPL-3.0-only
//! The gRPC entry for a machine user, a service or a provisioning connector
//! presenting a token of its own: the request's bearer, the owning core's
//! decision, and one `unauthenticated` for every failed check.

use sid_authn::connector_auth::{self, ConnectorCaller};
use sid_authn::machine_auth::{self, MachineCaller};
use sid_authn::resource_token::{OwnTokenError, ResourceTokenVerifier};
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::service_auth::{self, AuthenticatedService};
use sid_core::models::OrgId;
use sid_plugin::StorageBackend;
use tonic::{Request, Status};

use super::caller::bearer_token;
use crate::grpc_error::refuse::storage_failure;
use crate::grpc_error::{ApiError, ErrorReason, IntoStatus, OrStatus};

impl IntoStatus for OwnTokenError {
    fn into_status(self) -> Status {
        match self {
            OwnTokenError::Unauthenticated => {
                ApiError::new(ErrorReason::TokenInvalid, "authentication required").into()
            }
            OwnTokenError::Storage(e) => storage_failure(e),
        }
    }
}

/// The machine user `request`'s bearer token authenticates at the resource
/// `tokens` verifies.
#[allow(clippy::result_large_err)]
pub async fn authenticate_machine<T>(
    request: &Request<T>,
    storage: &dyn StorageBackend,
    tokens: &ResourceTokenVerifier,
    revocation: &RevocationCache,
) -> Result<MachineCaller, Status> {
    machine_auth::authenticate_machine(bearer_token(request)?, storage, tokens, revocation)
        .await
        .or_status()
}

/// The service `request`'s bearer token authenticates at the API `tokens`
/// verifies.
#[allow(clippy::result_large_err)]
pub async fn authenticate_service<T>(
    request: &Request<T>,
    storage: &dyn StorageBackend,
    tokens: &ResourceTokenVerifier,
    revocation: &RevocationCache,
) -> Result<AuthenticatedService, Status> {
    service_auth::authenticate_service(bearer_token(request)?, storage, tokens, revocation)
        .await
        .or_status()
}

/// The inbound connector of `org` that `request`'s bearer authenticates.
#[allow(clippy::result_large_err)]
pub async fn authenticate_connector<T>(
    request: &Request<T>,
    storage: &dyn StorageBackend,
    org: OrgId,
    tokens: Option<&ResourceTokenVerifier>,
) -> Result<ConnectorCaller, Status> {
    connector_auth::authenticate_connector(bearer_token(request)?, storage, org, tokens)
        .await
        .or_status()
}

#[cfg(test)]
mod tests;
