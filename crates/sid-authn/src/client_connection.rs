// SPDX-License-Identifier: AGPL-3.0-only
//! What a BFF needs to sign users in as a registered confidential web client
//! (auth/session-management.md, deployment-provisioned BFF connection): one
//! representation, read from the committed registration. The account API
//! answers with it; installation tooling delivers it as a deployment's
//! connection bundle. It holds no secret: the client's private key travels
//! apart from it.

use serde::{Deserialize, Serialize};
use sid_core::models::{OAuth2Client, OidcIssuer, ProtectedResource};
use sid_core::{Error as SidError, Result as SidResult};

/// Connection details of one registered web client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConnection {
    /// Exact issuer identifier the client is registered under.
    pub issuer: String,
    /// The client's `client_id`, never changed after registration.
    pub client_id: String,
    /// Resource indicator of the API the client obtains tokens for
    /// (RFC 8707 §2).
    pub resource: String,
    /// Scopes the client requests.
    pub scopes: Vec<String>,
    /// The client's registered callback.
    pub redirect_uri: String,
    /// How the client authenticates at the token endpoint (RFC 7591 §2).
    pub token_endpoint_auth_method: String,
}

impl ClientConnection {
    /// The connection of `client` under `issuer` for `resource`, as stored.
    /// A resource of another issuer or a client without a callback is a
    /// registration that cannot serve a sign-in, never a connection.
    pub fn of(
        issuer: &OidcIssuer,
        client: &OAuth2Client,
        resource: &ProtectedResource,
    ) -> SidResult<Self> {
        if resource.issuer_id != issuer.id {
            return Err(SidError::InvalidState(
                "the resource is not under the client's issuer".into(),
            ));
        }
        let redirect_uri = client
            .redirect_uris
            .first()
            .cloned()
            .ok_or_else(|| SidError::InvalidState("the client has no callback".into()))?;
        Ok(Self {
            issuer: issuer.canonical_url.clone(),
            client_id: client.client_id.clone(),
            resource: resource.indicator.to_string(),
            scopes: client.allowed_scopes.clone(),
            redirect_uri,
            token_endpoint_auth_method: client.token_endpoint_auth_method.to_string(),
        })
    }
}

#[cfg(test)]
mod tests;
