// SPDX-License-Identifier: AGPL-3.0-only
//! A browser adapter as the confidential web client its installation
//! registered: the connection details it signs users in and calls its API
//! under, validated before use. How the details arrive (a delivered bundle, an
//! answer of the account API) and the calls made under them belong to the
//! transport adapters.

use sid_core::models::{IssuerHandle, ResourceIndicator, scope_list};

use crate::client_connection::ClientConnection;

/// Connection details the adapter cannot use.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unusable connection details: {0}")]
pub struct ConnectionError(pub String);

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

impl Connection {
    /// A delivered connection bundle: JSON of exactly the registration's
    /// fields, validated as [`Connection::accept`] does, for a client that
    /// registered the adapter's key `kid`. Unlike discovery, nothing proved
    /// the pairing of bundle and key: a bundle of another client would pass
    /// every authorization and fail every code redemption.
    pub fn parse(json: &str, installation_url: &str, kid: &str) -> Result<Self, ConnectionError> {
        let bundle: ClientConnection = serde_json::from_str(json)
            .map_err(|e| ConnectionError(format!("not a connection bundle: {e}")))?;
        if !bundle.key_ids.iter().any(|registered| registered == kid) {
            return Err(ConnectionError(format!(
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
    pub fn accept(
        bundle: ClientConnection,
        installation_url: &str,
    ) -> Result<Self, ConnectionError> {
        let invalid = |why: &str| Err(ConnectionError(why.to_owned()));
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

#[cfg(test)]
mod tests;
