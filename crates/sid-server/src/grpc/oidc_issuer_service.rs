// SPDX-License-Identifier: AGPL-3.0-only
//! Issuer lookup for the protocol edge: the canonical URL and public signing
//! keys of the issuer a request path names, from which the edge serves that
//! issuer's discovery documents and JWKS and verifies its tokens, and the
//! registered resource a protected route names as its token audience.

use std::sync::Arc;

use sid_authn::issuer::IssuerRegistry;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{ResourceIndicator, ResourceState};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::oidc_issuer_service_server::OidcIssuerService;
use sid_proto::sid::v1::{
    GetOidcIssuerRequest, GetProtectedResourceRequest, IssuerPublicKey, OidcIssuer,
    ProtectedResourceTarget,
};
use tonic::{Request, Response, Status};

pub struct OidcIssuerServiceImpl {
    issuers: Arc<IssuerRegistry>,
    storage: Arc<dyn StorageBackend>,
}

impl OidcIssuerServiceImpl {
    pub fn new(issuers: Arc<IssuerRegistry>, storage: Arc<dyn StorageBackend>) -> Self {
        Self { issuers, storage }
    }
}

fn internal(e: sid_core::Error) -> Status {
    tracing::error!(error = %e, "reading the issuer registry");
    Status::from(ApiError::internal())
}

#[tonic::async_trait]
impl OidcIssuerService for OidcIssuerServiceImpl {
    /// Public data only (the issuer URL and public keys every relying party
    /// fetches), so the caller is not authenticated.
    async fn get_oidc_issuer(
        &self,
        request: Request<GetOidcIssuerRequest>,
    ) -> Result<Response<OidcIssuer>, Status> {
        let handle = request.into_inner().handle;
        let Some(issuer) = self.issuers.by_handle(&handle).await.map_err(internal)? else {
            return Err(ApiError::new(
                ErrorReason::OidcIssuerNotFound,
                "no OIDC issuer has this handle",
            )
            .with_resource("OidcIssuer", handle)
            .into());
        };
        let mut keys = self.issuers.public_keys(&issuer).await.map_err(internal)?;
        // Newest generation first, as the contract lists them.
        keys.reverse();
        Ok(Response::new(OidcIssuer {
            issuer: issuer.canonical_url,
            keys: keys
                .into_iter()
                .map(|(key_id, public_key)| IssuerPublicKey {
                    key_id,
                    public_key: public_key.to_vec(),
                })
                .collect(),
        }))
    }

    /// Public data only (the issuer and indicator a connection bundle hands
    /// to every client of the resource), so the caller is not authenticated.
    async fn get_protected_resource(
        &self,
        request: Request<GetProtectedResourceRequest>,
    ) -> Result<Response<ProtectedResourceTarget>, Status> {
        let request = request.into_inner();
        let not_found = || -> Status {
            ApiError::new(
                ErrorReason::ResourceNotFound,
                "no protected resource of this issuer has this indicator",
            )
            .with_resource("ProtectedResource", request.resource.clone())
            .into()
        };
        let Some(issuer) = self
            .issuers
            .by_handle(&request.issuer_handle)
            .await
            .map_err(internal)?
        else {
            return Err(not_found());
        };
        // Only the canonical spelling names a resource (RFC 8707 §2 keeps the
        // indicator an identifier, compared as registered).
        let Ok(indicator) = ResourceIndicator::parse(&request.resource) else {
            return Err(not_found());
        };
        let Some(resource) = self
            .storage
            .protected_resource_by_indicator(issuer.id, &indicator)
            .await
            .map_err(internal)?
        else {
            return Err(not_found());
        };
        Ok(Response::new(ProtectedResourceTarget {
            issuer: issuer.canonical_url,
            resource: resource.indicator.to_string(),
            active: resource.state == ResourceState::Active,
            id: Some(resource.id.into()),
        }))
    }
}
