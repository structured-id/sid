// SPDX-License-Identifier: AGPL-3.0-only
//! The account pages' web client and issuer lookup of a host that runs the
//! installation in its own process: the same calls a separate UI host makes
//! at the issuer over the network, made on the installation itself.
//!
//! Nothing about the client is relaxed by sharing a process with its issuer:
//! it is the registered confidential client, it authenticates every token
//! endpoint call with its key (`private_key_jwt`, RFC 7523 §2.2), and the
//! engine's token and revocation operations decide each call as they decide
//! one that arrived over a transport.

use std::sync::Arc;

use sid_authn::application_session::{ApplicationClient, GrantFailure, IssuedTokens};
use sid_authn::client_assertion::JWT_BEARER_ASSERTION_TYPE;
use sid_authn::client_connection::ClientConnection;
use sid_authn::client_key::ClientKey;
use sid_authn::issuer::IssuerRegistry;
use sid_authn::issuer_directory::{
    IssuerRecord, IssuerSource, RegistryUnavailable, ResourceRecord,
};
use sid_authn::relying_party::Connection;
use sid_authn::resource::RequestTarget;
use sid_authn::system_integration::{SIGN_IN_SCOPES, account_integration};
use sid_core::models::{IssuerAuthority, ResourceIndicator, ResourceState};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::{OAuth2RevokeRequest, OAuth2TokenRequest, OAuth2TokenResponse};
use tokio::sync::OnceCell;

use crate::oauth::{OAuth, OAuthError};

/// Why the host cannot act as the account client.
#[derive(Debug, thiserror::Error)]
pub enum AccountClientError {
    /// The client key names no key id: a registration lists its keys by id.
    #[error("the client key names no key id")]
    UnnamedKey,
    /// The account integration is not provisioned, or cannot serve sign-ins
    /// now (a disabled client, a resource that is no token target, no
    /// access).
    #[error("the account integration is not ready: {0}")]
    NotReady(String),
    /// The host's key is not one the client registered.
    #[error("the client key {0} is not registered for the account client")]
    UnregisteredKey(String),
    /// The store could not be read.
    #[error("store: {0}")]
    Store(#[from] sid_core::Error),
}

/// The account client's connection as the installation's committed
/// registration states it, for a host holding the registered key `kid`.
pub async fn connection(
    storage: &dyn StorageBackend,
    kid: &str,
) -> Result<Connection, AccountClientError> {
    let not_ready = |why: &str| AccountClientError::NotReady(why.to_owned());
    let integration = account_integration(storage)
        .await?
        .ok_or_else(|| not_ready("not provisioned"))?;
    let access = integration
        .access
        .as_ref()
        .ok_or_else(|| not_ready("the client has no access to the account API"))?;
    let org = integration
        .client
        .org_id
        .ok_or_else(|| not_ready("the client belongs to no organization"))?;
    let issuer = storage
        .oidc_issuer_for(IssuerAuthority::Local, org)
        .await?
        .filter(|issuer| issuer.id == integration.resource.issuer_id)
        .ok_or_else(|| not_ready("the account API is not under the client's issuer"))?;
    let bundle = ClientConnection::of(
        &issuer,
        &integration.client,
        &integration.resource,
        access,
        &SIGN_IN_SCOPES,
    )
    .map_err(|e| AccountClientError::NotReady(e.to_string()))?;
    if !bundle.key_ids.iter().any(|registered| registered == kid) {
        return Err(AccountClientError::UnregisteredKey(kid.to_owned()));
    }
    Connection::accept(bundle).map_err(|e| AccountClientError::NotReady(e.to_string()))
}

/// The account pages' web client of an installation in this process.
pub struct AccountClient {
    key: ClientKey,
    kid: String,
    oauth: Arc<OAuth>,
    storage: Arc<dyn StorageBackend>,
    /// Read from the registration on first use and kept: an installation
    /// never replaces the issuer or the client of a registration. A failed
    /// read is not kept, so the client is usable as soon as the integration
    /// is provisioned.
    connection: OnceCell<Connection>,
}

impl AccountClient {
    /// The client holding `key`, which the account integration registered,
    /// over the installation's token endpoint operations `oauth` and its
    /// `storage`.
    pub fn new(
        key: ClientKey,
        oauth: Arc<OAuth>,
        storage: Arc<dyn StorageBackend>,
    ) -> Result<Self, AccountClientError> {
        let kid = key.kid().ok_or(AccountClientError::UnnamedKey)?.to_owned();
        Ok(Self {
            key,
            kid,
            oauth,
            storage,
            connection: OnceCell::new(),
        })
    }

    /// A token endpoint call as the client, authenticated with its key.
    async fn token(
        &self,
        connection: &Connection,
        mut request: OAuth2TokenRequest,
    ) -> Result<IssuedTokens, GrantFailure> {
        let endpoint = connection.token_endpoint();
        request.client_id = Some(connection.client_id.clone());
        request.client_assertion = Some(self.assertion(connection, &endpoint)?);
        request.client_assertion_type = Some(JWT_BEARER_ASSERTION_TYPE.into());
        request.issuer_handle = connection.issuer_handle.clone();
        // The request a sender proof would name; the client sends none.
        let target = RequestTarget {
            method: "POST".into(),
            uri: endpoint,
        };
        let OAuth2TokenResponse {
            access_token,
            refresh_token,
            id_token,
            ..
        } = self
            .oauth
            .token(&request, None, None, &target)
            .await
            .map_err(failure)?;
        Ok(IssuedTokens {
            access_token,
            refresh_token,
            id_token,
        })
    }

    /// The client's assertion for a call at `endpoint` (RFC 7523 §3).
    fn assertion(&self, connection: &Connection, endpoint: &str) -> Result<String, GrantFailure> {
        self.key
            .sign(&connection.client_id, endpoint)
            .map_err(|e| GrantFailure::NotSent(e.to_string()))
    }
}

/// What a failed call did, as far as its caller can tell: a refusal names
/// the RFC 6749 §5.2 error the grant or code met; a limit did nothing; a
/// failure of the store or the installation may have taken effect.
fn failure(error: OAuthError) -> GrantFailure {
    let why = error.to_string();
    match error {
        OAuthError::RateLimited { .. } => GrantFailure::Declined(why),
        OAuthError::Unavailable { .. }
        | OAuthError::PolicyChanged
        | OAuthError::Store(_)
        | OAuthError::Internal => GrantFailure::Uncertain(why),
        OAuthError::Token { .. }
        | OAuthError::SlowDown { .. }
        | OAuthError::ClientRefused
        | OAuthError::Target(_)
        | OAuthError::MissingParameter(_)
        | OAuthError::Dpop(_)
        | OAuthError::Caller(_) => GrantFailure::Refused(why),
    }
}

#[async_trait::async_trait]
impl ApplicationClient for AccountClient {
    async fn connection(&self) -> Result<&Connection, GrantFailure> {
        self.connection
            .get_or_try_init(|| connection(self.storage.as_ref(), &self.kid))
            .await
            .map_err(|e| GrantFailure::NotSent(e.to_string()))
    }

    async fn redeem(
        &self,
        connection: &Connection,
        code: String,
        code_verifier: String,
    ) -> Result<IssuedTokens, GrantFailure> {
        self.token(
            connection,
            OAuth2TokenRequest {
                grant_type: "authorization_code".into(),
                code: Some(code),
                redirect_uri: Some(connection.redirect_uri.clone()),
                code_verifier: Some(code_verifier),
                ..Default::default()
            },
        )
        .await
    }

    async fn refresh(
        &self,
        connection: &Connection,
        refresh_token: String,
    ) -> Result<IssuedTokens, GrantFailure> {
        self.token(
            connection,
            OAuth2TokenRequest {
                grant_type: "refresh_token".into(),
                refresh_token: Some(refresh_token),
                ..Default::default()
            },
        )
        .await
    }

    async fn revoke(
        &self,
        connection: &Connection,
        refresh_token: String,
    ) -> Result<(), GrantFailure> {
        let assertion = self.assertion(connection, &connection.token_endpoint())?;
        self.oauth
            .revoke(
                &OAuth2RevokeRequest {
                    token: refresh_token,
                    token_type_hint: Some("refresh_token".into()),
                    issuer_handle: connection.issuer_handle.clone(),
                    client_id: Some(connection.client_id.clone()),
                    client_assertion: Some(assertion),
                    client_assertion_type: Some(JWT_BEARER_ASSERTION_TYPE.into()),
                    ..Default::default()
                },
                None,
            )
            .await
            .map_err(failure)
    }
}

/// The installation's own issuers and registered resources, read from its
/// registry and store in process.
pub struct InstallationIssuers {
    issuers: Arc<IssuerRegistry>,
    storage: Arc<dyn StorageBackend>,
}

impl InstallationIssuers {
    pub fn new(issuers: Arc<IssuerRegistry>, storage: Arc<dyn StorageBackend>) -> Self {
        Self { issuers, storage }
    }
}

fn unavailable(e: sid_core::Error) -> RegistryUnavailable {
    RegistryUnavailable(e.to_string())
}

#[async_trait::async_trait]
impl IssuerSource for InstallationIssuers {
    async fn issuer(&self, handle: &str) -> Result<Option<IssuerRecord>, RegistryUnavailable> {
        let Some(issuer) = self.issuers.by_handle(handle).await.map_err(unavailable)? else {
            return Ok(None);
        };
        let mut keys = self
            .issuers
            .public_keys(&issuer)
            .await
            .map_err(unavailable)?;
        // Newest generation first, as a record lists them.
        keys.reverse();
        Ok(Some(IssuerRecord {
            issuer: issuer.canonical_url,
            keys,
        }))
    }

    async fn resource(
        &self,
        handle: &str,
        resource: &str,
    ) -> Result<Option<ResourceRecord>, RegistryUnavailable> {
        let Some(issuer) = self.issuers.by_handle(handle).await.map_err(unavailable)? else {
            return Ok(None);
        };
        // Only the canonical spelling names a resource (RFC 8707 §2 keeps
        // the indicator an identifier, compared as registered).
        let Ok(indicator) = ResourceIndicator::parse(resource) else {
            return Ok(None);
        };
        let Some(stored) = self
            .storage
            .protected_resource_by_indicator(issuer.id, &indicator)
            .await
            .map_err(unavailable)?
        else {
            return Ok(None);
        };
        Ok(Some(ResourceRecord {
            issuer: issuer.canonical_url,
            resource: stored.indicator.to_string(),
            active: stored.state == ResourceState::Active,
            id: stored.id,
        }))
    }
}

#[cfg(test)]
mod tests;
