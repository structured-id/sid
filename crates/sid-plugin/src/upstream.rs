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
/// CE ships with a generic OIDC implementation (`OidcProviderClient` in sid-auth).
/// EE can provide specialized implementations for providers with quirks.
#[async_trait]
pub trait UpstreamIdpProvider: Send + Sync + 'static {
    /// Protocol used by this provider.
    fn protocol(&self) -> UpstreamProtocol;

    /// Provider ID (matches the stored `UpstreamProvider.id`).
    fn provider_id(&self) -> UpstreamProviderId;

    /// Generate authorization URL for redirecting the user to the upstream IdP.
    ///
    /// Returns `(authorization_url, state_token)`.
    /// The `state_token` must be stored in `ChallengeStore` for CSRF validation.
    /// PKCE (S256) is always used — the code_verifier is stored in `UpstreamAuthState`.
    async fn authorization_url(
        &self,
        redirect_uri: &str,
        scopes: &[String],
    ) -> Result<(String, String)>;

    /// Exchange authorization code for normalized user claims.
    ///
    /// Performs:
    /// 1. Token exchange (code → access_token + id_token)
    /// 2. Optional UserInfo request
    /// 3. Claim normalization → `MappedClaims`
    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<MappedClaims>;
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
    pub code_verifier: Option<String>,

    /// OIDC nonce (validated in id_token if present).
    pub nonce: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_upstream_auth_state_serde_roundtrip() {
        let state = UpstreamAuthState {
            provider_id: UpstreamProviderId(Uuid::now_v7()),
            state_token: "abc123state".into(),
            redirect_uri: "https://sid.example.com/callback".into(),
            code_verifier: Some("pkce-verifier-xyz".into()),
            nonce: Some("nonce-456".into()),
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: UpstreamAuthState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.state_token, "abc123state");
        assert_eq!(parsed.redirect_uri, "https://sid.example.com/callback");
        assert_eq!(parsed.code_verifier.as_deref(), Some("pkce-verifier-xyz"));
        assert_eq!(parsed.nonce.as_deref(), Some("nonce-456"));
    }

    #[test]
    fn test_upstream_auth_state_without_optionals() {
        let state = UpstreamAuthState {
            provider_id: UpstreamProviderId(Uuid::now_v7()),
            state_token: "state-only".into(),
            redirect_uri: "https://sid.example.com/cb".into(),
            code_verifier: None,
            nonce: None,
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: UpstreamAuthState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.state_token, "state-only");
        assert!(parsed.code_verifier.is_none());
        assert!(parsed.nonce.is_none());
    }
}
