// SPDX-License-Identifier: AGPL-3.0-only
//! Connection details of the installation's own integrations, for their
//! backends: the account BFF proves it holds a registered key and learns the
//! issuer, client, resource and callback it was provisioned with.

use std::sync::Arc;

use sid_authn::client_assertion::{AssertionJtiCache, validate_key_proof};
use sid_authn::system_integration::account_integration;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::IssuerAuthority;
use sid_plugin::cache::CacheBackend;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::system_integration_service_server::SystemIntegrationService;
use sid_proto::sid::v1::{AccountConnection, GetAccountConnectionRequest};
use tonic::{Request, Response, Status};

pub struct SystemIntegrationServiceImpl {
    storage: Arc<dyn StorageBackend>,
    /// The installation's public URL, the base of a key proof's audience.
    installation_url: String,
    proofs: AssertionJtiCache,
}

impl SystemIntegrationServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        installation_url: String,
        cache: Arc<dyn CacheBackend>,
    ) -> Self {
        Self {
            storage,
            installation_url,
            proofs: AssertionJtiCache::new(cache),
        }
    }

    /// The audience of an account connection proof.
    pub fn account_proof_audience(installation_url: &str) -> String {
        format!(
            "{}/account/connection",
            installation_url.trim_end_matches('/')
        )
    }
}

fn internal(e: sid_core::Error) -> Status {
    tracing::error!(error = %e, "reading the account integration");
    Status::from(ApiError::internal())
}

fn unavailable() -> Status {
    ApiError::new(
        ErrorReason::SystemIntegrationUnavailable,
        "the account integration is not provisioned or is disabled",
    )
    .into()
}

#[tonic::async_trait]
impl SystemIntegrationService for SystemIntegrationServiceImpl {
    async fn get_account_connection(
        &self,
        request: Request<GetAccountConnectionRequest>,
    ) -> Result<Response<AccountConnection>, Status> {
        let proof = request.into_inner().proof;
        let integration = account_integration(self.storage.as_ref())
            .await
            .map_err(internal)?
            .ok_or_else(unavailable)?;
        let keys = integration.client.jwks.as_ref().ok_or_else(unavailable)?;
        match validate_key_proof(
            &proof,
            &Self::account_proof_audience(&self.installation_url),
            keys,
            &self.proofs,
        )
        .await
        {
            Ok(()) => {}
            Err(sid_core::Error::Internal(e)) => {
                // A replay record that cannot be read cannot rule out a replay.
                return Err(sid_core::grpc_error::refuse::dependency_unavailable(
                    "proof replay record",
                    e,
                ));
            }
            Err(e) => {
                tracing::warn!(error = %e, "account connection proof refused");
                return Err(ApiError::new(ErrorReason::TokenInvalid, "invalid proof").into());
            }
        }
        if !integration.is_ready() {
            return Err(unavailable());
        }
        let org = integration.client.org_id.ok_or_else(unavailable)?;
        let issuer = self
            .storage
            .oidc_issuer_for(IssuerAuthority::Local, org)
            .await
            .map_err(internal)?
            .filter(|issuer| issuer.id == integration.resource.issuer_id)
            .ok_or_else(|| {
                internal(sid_core::Error::InvalidState(
                    "the account API is not under the account client's issuer".into(),
                ))
            })?;
        let redirect_uri = integration
            .client
            .redirect_uris
            .first()
            .cloned()
            .ok_or_else(unavailable)?;
        Ok(Response::new(AccountConnection {
            issuer: issuer.canonical_url,
            client_id: integration.client.client_id,
            resource: integration.resource.indicator.to_string(),
            scopes: integration.client.allowed_scopes,
            redirect_uri,
            token_endpoint_auth_method: integration.client.token_endpoint_auth_method.to_string(),
        }))
    }
}
