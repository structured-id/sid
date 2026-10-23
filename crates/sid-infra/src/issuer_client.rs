// SPDX-License-Identifier: AGPL-3.0-only
//! A browser adapter's calls as the confidential web client its installation
//! registered, over gRPC: learning its connection from the account API by
//! proving its key, and the token endpoint calls it makes as that client
//! (`private_key_jwt`, RFC 7523 §2.2). The connection itself is
//! [`sid_authn::relying_party::Connection`].

use std::path::Path;

use sid_authn::client_assertion::JWT_BEARER_ASSERTION_TYPE;
use sid_authn::client_connection::ClientConnection;
use sid_authn::client_key::{ClientKey, ClientKeyError};
use sid_authn::relying_party::{Connection, ConnectionError};
use sid_proto::sid::v1::auth_service_client::AuthServiceClient;
use sid_proto::sid::v1::system_integration_service_client::SystemIntegrationServiceClient;
use sid_proto::sid::v1::{
    AccountConnection, GetAccountConnectionRequest, OAuth2RevokeRequest, OAuth2TokenRequest,
    OAuth2TokenResponse,
};
use tokio::sync::OnceCell;

/// Why the adapter cannot act as its client right now.
#[derive(Debug, thiserror::Error)]
pub enum RpClientError {
    /// The issuer refused or could not answer the call.
    #[error("the issuer refused the call: {0}")]
    Rpc(#[from] tonic::Status),
    /// The connection details are not ones this adapter can use.
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    /// The client is not configured to act as one.
    #[error("unusable client: {0}")]
    Invalid(String),
    /// The client key could not sign.
    #[error("signing with the client key: {0}")]
    Key(#[from] ClientKeyError),
}

/// The connection the deployment delivered in the file at `path`, for the
/// adapter's key `kid`.
pub fn load_connection(
    path: &Path,
    installation_url: &str,
    kid: &str,
) -> Result<Connection, RpClientError> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| ConnectionError(format!("connection {path:?} cannot be read: {e}")))?;
    Ok(Connection::parse(&json, installation_url, kid)?)
}

/// The account API's answer as the one connection representation. The
/// issuer answers only a proof signed by `kid` that verifies against the
/// client's registered keys, so that key is the one registered key the
/// answer names.
fn answered(answer: AccountConnection, kid: &str) -> ClientConnection {
    ClientConnection {
        issuer: answer.issuer,
        client_id: answer.client_id,
        resource: answer.resource,
        scopes: answer.scopes,
        redirect_uri: answer.redirect_uri,
        token_endpoint_auth_method: answer.token_endpoint_auth_method,
        key_ids: vec![kid.to_owned()],
    }
}

/// The adapter as its web client: its key, its channel to the issuer, and
/// the connection details, delivered or learned once per process.
pub struct RpClient {
    key: ClientKey,
    /// The key's id: what the client registered and what its connection
    /// proofs are issued by.
    kid: String,
    installation_url: String,
    channel: tonic::transport::Channel,
    connection: OnceCell<Connection>,
}

impl std::fmt::Debug for RpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpClient")
            .field("kid", &self.kid)
            .field("installation_url", &self.installation_url)
            .field("connection", &self.connection.get())
            .finish_non_exhaustive()
    }
}

impl RpClient {
    /// A client that learns its connection from the account API. The key
    /// must name itself: the registration lists it by `kid`.
    pub fn new(
        key: ClientKey,
        installation_url: String,
        channel: tonic::transport::Channel,
    ) -> Result<Self, RpClientError> {
        Self::with(key, installation_url, channel, OnceCell::new())
    }

    /// A client whose connection the deployment delivered: it is never asked
    /// of the issuer.
    pub fn delivered(
        key: ClientKey,
        installation_url: String,
        channel: tonic::transport::Channel,
        connection: Connection,
    ) -> Result<Self, RpClientError> {
        Self::with(
            key,
            installation_url,
            channel,
            OnceCell::new_with(Some(connection)),
        )
    }

    fn with(
        key: ClientKey,
        installation_url: String,
        channel: tonic::transport::Channel,
        connection: OnceCell<Connection>,
    ) -> Result<Self, RpClientError> {
        let kid = key
            .kid()
            .ok_or_else(|| RpClientError::Invalid("the client key names no key id".into()))?
            .to_owned();
        Ok(Self {
            key,
            kid,
            installation_url,
            channel,
            connection,
        })
    }

    /// The id of the client's key.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The connection details: the delivered ones, or else asked of the
    /// account API on first use and kept. The issuer never replaces the
    /// issuer or client of a registration, so they hold for the life of the
    /// process. A failed ask is not kept, so the adapter becomes ready as
    /// soon as the integration is provisioned.
    pub async fn connection(&self) -> Result<&Connection, RpClientError> {
        self.connection
            .get_or_try_init(|| async {
                let audience = format!(
                    "{}/account/connection",
                    self.installation_url.trim_end_matches('/')
                );
                let proof = self.key.sign(&self.kid, &audience)?;
                let answer = SystemIntegrationServiceClient::new(self.channel.clone())
                    .get_account_connection(GetAccountConnectionRequest { proof })
                    .await?
                    .into_inner();
                Ok(Connection::accept(
                    answered(answer, &self.kid),
                    &self.installation_url,
                )?)
            })
            .await
    }

    /// Redeem an authorization code (RFC 6749 §4.1.3) with the client's
    /// assertion and the sign-in's PKCE verifier.
    pub async fn redeem(
        &self,
        connection: &Connection,
        code: String,
        code_verifier: String,
    ) -> Result<OAuth2TokenResponse, RpClientError> {
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

    /// Refresh (RFC 6749 §6). The grant keeps its resource; the issuer
    /// rotates the refresh token, so the caller must replace the one it holds.
    pub async fn refresh(
        &self,
        connection: &Connection,
        refresh_token: String,
    ) -> Result<OAuth2TokenResponse, RpClientError> {
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

    /// Revoke a refresh token and the grant it belongs to (RFC 7009 §2.1).
    pub async fn revoke(
        &self,
        connection: &Connection,
        token: String,
    ) -> Result<(), RpClientError> {
        let assertion = self
            .key
            .sign(&connection.client_id, &connection.token_endpoint())?;
        AuthServiceClient::new(self.channel.clone())
            .o_auth2_revoke(OAuth2RevokeRequest {
                token,
                token_type_hint: Some("refresh_token".into()),
                issuer_handle: connection.issuer_handle.clone(),
                client_id: Some(connection.client_id.clone()),
                client_assertion: Some(assertion),
                client_assertion_type: Some(JWT_BEARER_ASSERTION_TYPE.into()),
                ..Default::default()
            })
            .await?;
        Ok(())
    }

    /// A token endpoint call as the client.
    async fn token(
        &self,
        connection: &Connection,
        mut request: OAuth2TokenRequest,
    ) -> Result<OAuth2TokenResponse, RpClientError> {
        request.client_id = Some(connection.client_id.clone());
        request.client_assertion = Some(
            self.key
                .sign(&connection.client_id, &connection.token_endpoint())?,
        );
        request.client_assertion_type = Some(JWT_BEARER_ASSERTION_TYPE.into());
        request.issuer_handle = connection.issuer_handle.clone();
        Ok(AuthServiceClient::new(self.channel.clone())
            .o_auth2_token(request)
            .await?
            .into_inner())
    }
}

#[cfg(test)]
mod tests;
