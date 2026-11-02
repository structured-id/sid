// SPDX-License-Identifier: AGPL-3.0-only
//! Upstream Identity Provider plugin trait.
//!
//! Defines the interface for upstream IdP providers (Google, GitHub, Microsoft, etc.).
//! SID acts as a Relying Party to these upstream providers.
//! Each provider implements `UpstreamIdpProvider` for authorization URL generation
//! and code exchange.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sid_core::Result;
use sid_core::models::{MappedClaims, UpstreamProtocol, UpstreamProviderId};

/// Plugin trait for upstream identity providers.
///
/// Implementors handle the OAuth2/OIDC flow with a specific upstream provider:
/// 1. Generate authorization URL (with PKCE, state, nonce)
/// 2. Exchange authorization code for user claims
///
/// SID ships with a generic OIDC implementation (`OidcProviderClient` in sid-auth).
#[async_trait]
pub trait UpstreamIdpProvider: Send + Sync + 'static {
    /// Protocol used by this provider.
    fn protocol(&self) -> UpstreamProtocol;

    /// Provider ID (matches the stored `UpstreamProvider.id`).
    fn provider_id(&self) -> UpstreamProviderId;

    /// A new authorization request redirecting the user to the upstream IdP
    /// for `redirect_uri`, with PKCE (S256) and, for OIDC, a nonce. Its
    /// state, verifier and nonce are stored as an `UpstreamAuthState` until
    /// the callback.
    async fn authorization_request(
        &self,
        redirect_uri: &str,
        scopes: &[String],
    ) -> Result<AuthorizationRequest>;

    /// Exchange the authorization `code` of the `pending` request for the
    /// user's claims. For OIDC the identity is the validated ID Token's
    /// issuer and subject (OpenID Connect Core 1.0 §3.1.3.7); UserInfo adds
    /// claims only for that same subject (§5.3.2).
    async fn exchange_code(
        &self,
        code: &str,
        pending: &PendingAuthorization<'_>,
    ) -> Result<MappedClaims>;
}

/// An authorization request to an upstream IdP.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// Where the user is redirected.
    pub url: String,
    /// The `state` parameter: CSRF protection and the pending request's key.
    pub state: String,
    /// The PKCE code verifier (RFC 7636), sent only on the token exchange.
    pub code_verifier: String,
    /// The OIDC nonce the ID Token must carry; none for plain OAuth2.
    pub nonce: Option<String>,
}

/// What the callback of an authorization request was started with.
#[derive(Debug, Clone, Copy)]
pub struct PendingAuthorization<'a> {
    pub redirect_uri: &'a str,
    pub code_verifier: &'a str,
    pub nonce: Option<&'a str>,
}

/// Ephemeral state stored during upstream OAuth2 flow.
///
/// Stored in `ChallengeStore<UpstreamAuthState>` with 10 minute TTL.
/// Keyed by `state_token` for CSRF validation on callback.
/// Single-use: `take()` removes it from the store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamAuthState {
    /// Which provider initiated this flow.
    pub provider_id: UpstreamProviderId,

    /// Random state token (CSRF protection). Also the key in ChallengeStore.
    pub state_token: String,

    /// Redirect URI used in the authorization request (must match on callback).
    pub redirect_uri: String,

    /// PKCE code verifier (sent on token exchange, not in authorization URL).
    pub code_verifier: String,

    /// OIDC nonce the ID Token must carry; none for plain OAuth2.
    pub nonce: Option<String>,
}

impl UpstreamAuthState {
    /// The pending request this state stores.
    pub fn pending(&self) -> PendingAuthorization<'_> {
        PendingAuthorization {
            redirect_uri: &self.redirect_uri,
            code_verifier: &self.code_verifier,
            nonce: self.nonce.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests;
