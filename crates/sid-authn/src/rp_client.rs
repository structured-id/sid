// SPDX-License-Identifier: AGPL-3.0-only
//! A browser adapter as the confidential web client its installation
//! registered: the connection details, delivered by the deployment or
//! learned from the account API by proving its key, and the token endpoint
//! calls it makes as that client (`private_key_jwt`, RFC 7523 §2.2).

use std::path::Path;

use sid_core::models::{IssuerHandle, ResourceIndicator, scope_list};
use sid_proto::sid::v1::auth_service_client::AuthServiceClient;
use sid_proto::sid::v1::system_integration_service_client::SystemIntegrationServiceClient;
use sid_proto::sid::v1::{
    AccountConnection, GetAccountConnectionRequest, OAuth2RevokeRequest, OAuth2TokenRequest,
    OAuth2TokenResponse,
};
use tokio::sync::OnceCell;

use crate::client_assertion::JWT_BEARER_ASSERTION_TYPE;
use crate::client_connection::ClientConnection;
use crate::client_key::{ClientKey, ClientKeyError};

/// Why the adapter cannot act as its client right now.
#[derive(Debug, thiserror::Error)]
pub enum RpClientError {
    /// The issuer refused or could not answer the call.
    #[error("the issuer refused the call: {0}")]
    Rpc(#[from] tonic::Status),
    /// The connection details are not ones this adapter can use.
    #[error("unusable connection details: {0}")]
    Invalid(String),
    /// The client key could not sign.
    #[error("signing with the client key: {0}")]
    Key(#[from] ClientKeyError),
}

/// What the adapter needs to sign users in and call its API, as the issuer
/// registered its client. Never edited by hand: the issuer or the
/// deployment's installation tooling supplies it, an operator configures only
/// the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// Exact issuer identifier, `{installation}/i/{handle}`.
    pub issuer: String,
    /// The handle in `issuer`, which names it in token endpoint calls.
    pub issuer_handle: String,
    /// The adapter's web client.
    pub client_id: String,
    /// Resource indicator of the API the adapter forwards to (RFC 8707 §2).
    pub resource: String,
    /// Scopes the adapter requests.
    pub scopes: Vec<String>,
    /// The client's registered callback, exactly as registered: the issuer
    /// compares redirect URIs as strings, so a normalized spelling would be
    /// another callback.
    pub redirect_uri: String,
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

impl Connection {
    /// The connection the deployment delivered in the file at `path`, for
    /// the adapter's key `kid`.
    pub fn load(path: &Path, installation_url: &str, kid: &str) -> Result<Self, RpClientError> {
        let json = std::fs::read_to_string(path).map_err(|e| {
            RpClientError::Invalid(format!("connection {path:?} cannot be read: {e}"))
        })?;
        Self::parse(&json, installation_url, kid)
    }

    /// A delivered connection bundle: JSON of exactly the registration's
    /// fields, validated as [`Connection::accept`] does, for a client that
    /// registered the adapter's key `kid`. Unlike discovery, nothing proved
    /// the pairing of bundle and key: a bundle of another client would pass
    /// every authorization and fail every code redemption.
    pub fn parse(json: &str, installation_url: &str, kid: &str) -> Result<Self, RpClientError> {
        let bundle: ClientConnection = serde_json::from_str(json)
            .map_err(|e| RpClientError::Invalid(format!("not a connection bundle: {e}")))?;
        if !bundle.key_ids.iter().any(|registered| registered == kid) {
            return Err(RpClientError::Invalid(format!(
                "the client key {kid} is not registered for client {}",
                bundle.client_id
            )));
        }
        Self::accept(bundle, installation_url)
    }

    /// The details of `bundle`, accepted only when they name an issuer of
    /// `installation_url` and the client authenticates with its key: a
    /// connection that would have the adapter sign in elsewhere, or as a
    /// client holding a secret it does not have, is refused rather than
    /// followed.
    pub fn accept(bundle: ClientConnection, installation_url: &str) -> Result<Self, RpClientError> {
        let invalid = |why: &str| Err(RpClientError::Invalid(why.to_owned()));
        if bundle.token_endpoint_auth_method != "private_key_jwt" {
            return invalid("the client does not authenticate by key");
        }
        let prefix = format!("{}/i/", installation_url.trim_end_matches('/'));
        let Some(issuer_handle) = bundle
            .issuer
            .strip_prefix(&prefix)
            .filter(|handle| IssuerHandle::parse(handle).is_ok())
            .map(str::to_owned)
        else {
            return invalid("the issuer is not one of this installation's");
        };
        if bundle.client_id.is_empty() {
            return invalid("the client is missing");
        }
        // A target the issuer would refuse at every authorization request is
        // a broken deployment, refused here (RFC 8707 §2).
        if ResourceIndicator::parse(&bundle.resource).is_err() {
            return invalid("the resource is not a resource indicator");
        }
        // The callback requires an ID token, which the issuer issues only
        // when `openid` was requested (OIDC Core 1.0 §3.1.2.1).
        if !bundle.scopes.iter().any(|s| s == "openid") {
            return invalid("the scopes lack openid");
        }
        // An entry that is not one scope token would reach the issuer as
        // several, none of them a registered scope (RFC 6749 §3.3).
        let Ok(scopes) = scope_list(&bundle.scopes) else {
            return invalid("a scope is not a scope token");
        };
        // Parsed only to refuse what is not a URL; the registered spelling is
        // what goes into requests.
        if url::Url::parse(&bundle.redirect_uri).is_err() {
            return invalid("the callback is not a URL");
        }
        Ok(Self {
            issuer: bundle.issuer,
            issuer_handle,
            client_id: bundle.client_id,
            resource: bundle.resource,
            scopes,
            redirect_uri: bundle.redirect_uri,
        })
    }

    /// What sessions and pending sign-ins are bound to: the issuer, client,
    /// resource and scope set their tokens are issued for. A replaced
    /// connection, a narrowed scope set included, matches none of the records
    /// made under the former one; the order scopes are listed in does not
    /// change what they grant (RFC 6749 §3.3).
    pub fn binding(&self) -> String {
        let mut scopes: Vec<&str> = self.scopes.iter().map(String::as_str).collect();
        scopes.sort_unstable();
        scopes.dedup();
        format!(
            "{}\n{}\n{}\n{}",
            self.issuer,
            self.client_id,
            self.resource,
            scopes.join(" ")
        )
    }

    /// What a pending sign-in is bound to: [`Connection::binding`] and the
    /// callback. A code is redeemed only with the redirect URI it was issued
    /// for (RFC 6749 §4.1.3), so a sign-in started before the callback
    /// changed cannot complete under the new one. Sessions do not depend on
    /// the callback and stay bound to [`Connection::binding`].
    pub fn sign_in_binding(&self) -> String {
        format!("{}\n{}", self.binding(), self.redirect_uri)
    }

    /// The issuer's token endpoint, the audience of every client assertion
    /// (RFC 7523 §3).
    pub fn token_endpoint(&self) -> String {
        crate::issuer::token_endpoint(&self.issuer)
    }

    /// The authorization request of a new sign-in (RFC 6749 §4.1.1): the
    /// code flow with S256 PKCE (RFC 7636 §4.3) for the connection's API
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
                Connection::accept(answered(answer, &self.kid), &self.installation_url)
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
