// SPDX-License-Identifier: AGPL-3.0-only
//! The BFF's link to the web client SID registered for it: the connection
//! details, delivered by the deployment or learned from the account API by
//! proving its key, and the token endpoint calls it makes as that
//! confidential client (`private_key_jwt`, RFC 7523 §2.2).

use std::path::Path;

use sid_authn::client_connection::ClientConnection;
use sid_core::models::{IssuerHandle, ResourceIndicator};
use sid_proto::sid::v1::auth_service_client::AuthServiceClient;
use sid_proto::sid::v1::system_integration_service_client::SystemIntegrationServiceClient;
use sid_proto::sid::v1::{
    AccountConnection, GetAccountConnectionRequest, OAuth2RevokeRequest, OAuth2TokenRequest,
    OAuth2TokenResponse,
};
use tokio::sync::OnceCell;

use crate::client_key::ClientKey;

/// RFC 7523 §2.2 client assertion type.
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Why the BFF cannot act as the account client right now.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// SID refused or could not answer the call.
    #[error("SID refused the call: {0}")]
    Rpc(#[from] tonic::Status),
    /// SID answered with connection details this BFF cannot use.
    #[error("unusable connection details: {0}")]
    Invalid(&'static str),
    /// The client key could not sign.
    #[error("signing with the client key: {0}")]
    Key(#[from] anyhow::Error),
}

/// What the BFF needs to sign users in and call its API, as SID registered
/// its client. Never edited by hand: SID or the deployment's installation
/// tooling supplies it, an operator configures only the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// Exact issuer identifier, `{installation}/i/{handle}`.
    pub issuer: String,
    /// The handle in `issuer`, which names it in token endpoint calls.
    pub issuer_handle: String,
    /// The BFF's web client.
    pub client_id: String,
    /// Resource indicator of the API the BFF forwards to (RFC 8707 §2).
    pub resource: String,
    /// Scopes the BFF requests.
    pub scopes: Vec<String>,
    /// The client's registered callback on the BFF's origin, exactly as
    /// registered: SID compares redirect URIs as strings, so a normalized
    /// spelling would be another callback.
    pub redirect_uri: String,
}

/// The account API's answer as the one connection representation.
fn answered(answer: AccountConnection) -> ClientConnection {
    ClientConnection {
        issuer: answer.issuer,
        client_id: answer.client_id,
        resource: answer.resource,
        scopes: answer.scopes,
        redirect_uri: answer.redirect_uri,
        token_endpoint_auth_method: answer.token_endpoint_auth_method,
    }
}

impl Connection {
    /// The connection the deployment delivered in the file at `path`.
    pub fn load(path: &Path, installation_url: &str) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("BFF connection {path:?} cannot be read: {e}"))?;
        Self::parse(&json, installation_url)
            .map_err(|e| anyhow::anyhow!("BFF connection {path:?}: {e}"))
    }

    /// A delivered connection bundle: JSON of exactly the registration's
    /// fields, validated as [`Connection::accept`] does.
    pub fn parse(json: &str, installation_url: &str) -> anyhow::Result<Self> {
        let bundle: ClientConnection = serde_json::from_str(json)?;
        Ok(Self::accept(bundle, installation_url)?)
    }

    /// The details of `bundle`, accepted only when they name an issuer of
    /// `installation_url` and the client authenticates with its key: a
    /// connection that would have the BFF sign in elsewhere, or as a client
    /// holding a secret it does not have, is refused rather than followed.
    pub fn accept(bundle: ClientConnection, installation_url: &str) -> Result<Self, LinkError> {
        if bundle.token_endpoint_auth_method != "private_key_jwt" {
            return Err(LinkError::Invalid(
                "the client does not authenticate by key",
            ));
        }
        let prefix = format!("{}/i/", installation_url.trim_end_matches('/'));
        let issuer_handle = bundle
            .issuer
            .strip_prefix(&prefix)
            .filter(|handle| IssuerHandle::parse(handle).is_ok())
            .ok_or(LinkError::Invalid(
                "the issuer is not one of this installation's",
            ))?
            .to_owned();
        if bundle.client_id.is_empty() {
            return Err(LinkError::Invalid("the client is missing"));
        }
        // A target SID would refuse at every authorization request is a
        // broken deployment, refused here (RFC 8707 §2).
        ResourceIndicator::parse(&bundle.resource)
            .map_err(|_| LinkError::Invalid("the resource is not a resource indicator"))?;
        // The callback requires an ID token, which SID issues only when
        // `openid` was requested (OIDC Core 1.0 §3.1.2.1).
        if !bundle.scopes.iter().any(|s| s == "openid") {
            return Err(LinkError::Invalid("the scopes lack openid"));
        }
        // Parsed only to refuse what is not a URL; the registered spelling is
        // what goes into requests.
        url::Url::parse(&bundle.redirect_uri)
            .map_err(|_| LinkError::Invalid("the callback is not a URL"))?;
        Ok(Self {
            issuer: bundle.issuer,
            issuer_handle,
            client_id: bundle.client_id,
            resource: bundle.resource,
            scopes: bundle.scopes,
            redirect_uri: bundle.redirect_uri,
        })
    }

    /// What sessions and pending sign-ins are bound to: the issuer, client
    /// and resource their tokens are issued for. A replaced connection
    /// matches none of the records made under the former one.
    pub fn binding(&self) -> String {
        format!("{}\n{}\n{}", self.issuer, self.client_id, self.resource)
    }

    /// The issuer's token endpoint, the audience of every client assertion
    /// (RFC 7523 §3).
    pub fn token_endpoint(&self) -> String {
        format!("{}/oauth2/token", self.issuer)
    }

    /// The authorization request of a new sign-in (RFC 6749 §4.1.1): the
    /// code flow with S256 PKCE (RFC 7636 §4.3) for the account API
    /// (RFC 8707 §2), with the `nonce` its ID token must carry back (OIDC
    /// Core 1.0 §3.1.2.1).
    pub fn authorize_url(&self, code_challenge: &str, state: &str, nonce: &str) -> url::Url {
        let mut url = url::Url::parse(&format!("{}/oauth2/authorize", self.issuer))
            .expect("an issuer URL takes a path");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &self.scopes.join(" "))
            .append_pair("resource", &self.resource)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", state)
            .append_pair("nonce", nonce);
        url
    }
}

/// The BFF as its web client: its key, its channel to SID, and the
/// connection details, delivered or learned once per process.
pub struct AccountLink {
    key: ClientKey,
    installation_url: String,
    channel: tonic::transport::Channel,
    connection: OnceCell<Connection>,
}

impl std::fmt::Debug for AccountLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountLink")
            .field("kid", &self.key.kid())
            .field("installation_url", &self.installation_url)
            .field("connection", &self.connection.get())
            .finish_non_exhaustive()
    }
}

impl AccountLink {
    pub fn new(
        key: ClientKey,
        installation_url: String,
        channel: tonic::transport::Channel,
    ) -> Self {
        Self {
            key,
            installation_url,
            channel,
            connection: OnceCell::new(),
        }
    }

    /// A link whose connection the deployment delivered: it is never asked
    /// of SID.
    pub fn delivered(
        key: ClientKey,
        installation_url: String,
        channel: tonic::transport::Channel,
        connection: Connection,
    ) -> Self {
        Self {
            key,
            installation_url,
            channel,
            connection: OnceCell::new_with(Some(connection)),
        }
    }

    /// The connection details: the delivered ones, or else asked of the
    /// account API on first use and kept. SID never replaces the issuer or
    /// client of a registration, so they hold for the life of the process.
    /// A failed ask is not kept, so the BFF becomes ready as soon as SID has
    /// provisioned the integration.
    pub async fn connection(&self) -> Result<&Connection, LinkError> {
        self.connection
            .get_or_try_init(|| async {
                let audience = format!(
                    "{}/account/connection",
                    self.installation_url.trim_end_matches('/')
                );
                let proof = self.key.sign(self.key.kid(), &audience)?;
                let answer = SystemIntegrationServiceClient::new(self.channel.clone())
                    .get_account_connection(GetAccountConnectionRequest { proof })
                    .await?
                    .into_inner();
                Connection::accept(answered(answer), &self.installation_url)
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
    ) -> Result<OAuth2TokenResponse, LinkError> {
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

    /// Refresh (RFC 6749 §6). The grant keeps its resource; SID rotates the
    /// refresh token, so the caller must replace the one it holds.
    pub async fn refresh(
        &self,
        connection: &Connection,
        refresh_token: String,
    ) -> Result<OAuth2TokenResponse, LinkError> {
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
    pub async fn revoke(&self, connection: &Connection, token: String) -> Result<(), LinkError> {
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
                client_assertion_type: Some(ASSERTION_TYPE.into()),
                ..Default::default()
            })
            .await?;
        Ok(())
    }

    /// A token endpoint call as the account client.
    async fn token(
        &self,
        connection: &Connection,
        mut request: OAuth2TokenRequest,
    ) -> Result<OAuth2TokenResponse, LinkError> {
        request.client_id = Some(connection.client_id.clone());
        request.client_assertion = Some(
            self.key
                .sign(&connection.client_id, &connection.token_endpoint())?,
        );
        request.client_assertion_type = Some(ASSERTION_TYPE.into());
        request.issuer_handle = connection.issuer_handle.clone();
        Ok(AuthServiceClient::new(self.channel.clone())
            .o_auth2_token(request)
            .await?
            .into_inner())
    }
}

#[cfg(test)]
mod tests;
