// SPDX-License-Identifier: AGPL-3.0-only
//! Generic OIDC Provider Client.
//!
//! Implements `UpstreamIdpProvider` for any standard OIDC provider.
//! Handles discovery, PKCE, authorization URL generation, code exchange,
//! and UserInfo retrieval.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Client;
use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sid_core::models::{MappedClaims, UpstreamProtocol, UpstreamProvider, UpstreamProviderId};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::UpstreamIdpProvider;
use std::collections::HashMap;
use std::fmt;

/// OIDC Discovery document (subset of fields we need).
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscovery {
    /// Issuer identifier.
    pub issuer: String,
    /// Authorization endpoint URL.
    pub authorization_endpoint: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// UserInfo endpoint URL (optional per spec, but most providers have it).
    pub userinfo_endpoint: Option<String>,
    /// JWKS URI for token validation.
    #[allow(dead_code)]
    pub jwks_uri: String,
}

/// Token response from the OIDC token endpoint.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<u64>,
    #[allow(dead_code)]
    id_token: Option<String>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Generic OIDC provider client.
///
/// Created from an `UpstreamProvider` config + decrypted client secret.
/// Handles the full OIDC code flow:
/// 1. `authorization_url()` → redirect user to IdP
/// 2. `exchange_code()` → swap code for tokens → fetch UserInfo → return `MappedClaims`
pub struct OidcProviderClient {
    provider_id: UpstreamProviderId,
    client_id: String,
    client_secret: SecretBox<String>,
    discovery: OidcDiscovery,
    scopes: Vec<String>,
    http: Client,
}

impl OidcProviderClient {
    /// Create from an UpstreamProvider config and decrypted secret.
    ///
    /// If `discovery_url` is set, fetches the OIDC discovery document.
    /// Otherwise, uses manually configured endpoints.
    pub async fn from_provider(
        provider: &UpstreamProvider,
        decrypted_secret: String,
    ) -> SidResult<Self> {
        let http = sid_plugin::client_builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| SidError::Internal(format!("HTTP client error: {e}")))?;

        let discovery = if let Some(ref discovery_url) = provider.discovery_url {
            Self::fetch_discovery(&http, discovery_url).await?
        } else {
            // Manual endpoint configuration
            OidcDiscovery {
                issuer: provider.name.clone(),
                authorization_endpoint: provider.authorization_endpoint.clone().ok_or_else(
                    || {
                        SidError::Validation(
                            "authorization_endpoint required when no discovery_url".into(),
                        )
                    },
                )?,
                token_endpoint: provider.token_endpoint.clone().ok_or_else(|| {
                    SidError::Validation("token_endpoint required when no discovery_url".into())
                })?,
                userinfo_endpoint: provider.userinfo_endpoint.clone(),
                jwks_uri: String::new(),
            }
        };

        Ok(Self {
            provider_id: provider.id,
            client_id: provider.client_id.clone(),
            client_secret: SecretBox::new(Box::new(decrypted_secret)),
            discovery,
            scopes: provider.scopes.clone(),
            http,
        })
    }

    /// Fetch OIDC discovery document from `.well-known/openid-configuration`.
    async fn fetch_discovery(http: &Client, discovery_url: &str) -> SidResult<OidcDiscovery> {
        let resp = http
            .get(discovery_url)
            .send()
            .await
            .map_err(|e| SidError::Internal(format!("OIDC discovery fetch failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(SidError::Internal(format!(
                "OIDC discovery returned {}",
                resp.status()
            )));
        }

        resp.json::<OidcDiscovery>()
            .await
            .map_err(|e| SidError::Internal(format!("OIDC discovery parse failed: {e}")))
    }

    /// Generate PKCE code_verifier and code_challenge (S256).
    fn generate_pkce() -> (String, String) {
        use rand::TryRng;
        let mut verifier_bytes = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut verifier_bytes)
            .expect("the operating system random source is available");
        let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

        (verifier, challenge)
    }

    /// Generate random state token for CSRF protection.
    fn generate_state() -> String {
        use rand::TryRng;
        let mut state_bytes = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut state_bytes)
            .expect("the operating system random source is available");
        URL_SAFE_NO_PAD.encode(state_bytes)
    }

    /// Fetch user claims from the UserInfo endpoint.
    async fn fetch_userinfo(
        &self,
        access_token: &str,
    ) -> SidResult<HashMap<String, serde_json::Value>> {
        let endpoint = self
            .discovery
            .userinfo_endpoint
            .as_ref()
            .ok_or_else(|| SidError::Internal("No userinfo_endpoint available".into()))?;

        let resp = self
            .http
            .get(endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| SidError::Internal(format!("UserInfo request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(SidError::Internal(format!(
                "UserInfo returned {}",
                resp.status()
            )));
        }

        resp.json::<HashMap<String, serde_json::Value>>()
            .await
            .map_err(|e| SidError::Internal(format!("UserInfo parse failed: {e}")))
    }
}

#[async_trait]
impl UpstreamIdpProvider for OidcProviderClient {
    fn protocol(&self) -> UpstreamProtocol {
        UpstreamProtocol::Oidc
    }

    fn provider_id(&self) -> UpstreamProviderId {
        self.provider_id
    }

    async fn authorization_url(
        &self,
        redirect_uri: &str,
        scopes: &[String],
    ) -> SidResult<(String, String)> {
        let (code_verifier, code_challenge) = Self::generate_pkce();
        let state = Self::generate_state();

        // Merge provider default scopes with requested scopes
        let mut all_scopes: Vec<&str> = self.scopes.iter().map(|s| s.as_str()).collect();
        for s in scopes {
            if !all_scopes.contains(&s.as_str()) {
                all_scopes.push(s.as_str());
            }
        }
        let scope_str = all_scopes.join(" ");

        let params = [
            ("response_type", "code"),
            ("client_id", &self.client_id),
            ("redirect_uri", redirect_uri),
            ("scope", &scope_str),
            ("state", &state),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ];

        let url = reqwest::Url::parse_with_params(&self.discovery.authorization_endpoint, &params)
            .map_err(|e| SidError::Internal(format!("Failed to build auth URL: {e}")))?;

        // Return the URL and state. The caller stores UpstreamAuthState
        // with code_verifier in ChallengeStore.
        // We need to return the verifier so the caller can store it.
        // Convention: state format = "{state_token}:{code_verifier}"
        // Actually, better to return state_token and let caller handle storage.
        // The code_verifier needs to be in UpstreamAuthState, so we encode it
        // alongside the state. Let's use a simple approach: return both in state.
        //
        // Actually per the plan: UpstreamAuthState stores code_verifier separately.
        // The service layer creates UpstreamAuthState with the verifier.
        // So we need to return the verifier too.
        // Let's encode it in the state string with a separator, or return a struct.
        //
        // Simplest approach: return (url, state) where the caller also needs the verifier.
        // But the trait signature is (url, state_token). Let's adjust:
        // We'll put the verifier into the state string separated by a null char (internal only).
        // OR better: change approach — the caller constructs UpstreamAuthState and needs verifier.
        // Let's return (url, state_with_verifier) where format is "{state}\0{verifier}".
        // The service layer splits on \0.
        let state_with_verifier = format!("{state}\0{code_verifier}");

        Ok((url.to_string(), state_with_verifier))
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> SidResult<MappedClaims> {
        // Extract code_verifier if stored (passed via redirect_uri extension or separate param)
        // The service layer passes code_verifier from UpstreamAuthState.
        // For the trait interface, we need to receive it somehow.
        // Since the trait has (code, redirect_uri), let's use an internal convention:
        // redirect_uri format: "{actual_uri}\0{code_verifier}" when PKCE is used.
        let (actual_redirect_uri, code_verifier) = if let Some(idx) = redirect_uri.find('\0') {
            (&redirect_uri[..idx], Some(&redirect_uri[idx + 1..]))
        } else {
            (redirect_uri, None)
        };

        // Token exchange
        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", actual_redirect_uri),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.expose_secret().as_str()),
        ];

        if let Some(verifier) = code_verifier {
            params.push(("code_verifier", verifier));
        }

        let resp = self
            .http
            .post(&self.discovery.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| SidError::Internal(format!("Token exchange failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(SidError::Internal(format!(
                "Token exchange returned {status}: {body}"
            )));
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .map_err(|e| SidError::Internal(format!("Token response parse failed: {e}")))?;

        // Fetch UserInfo claims
        let userinfo = self.fetch_userinfo(&token_resp.access_token).await?;

        // Map to normalized claims
        let mut claims = MappedClaims::from_oidc_userinfo(&userinfo);

        // Set issuer from discovery
        claims.upstream_issuer = Some(self.discovery.issuer.clone());

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pkce() {
        let (verifier, challenge) = OidcProviderClient::generate_pkce();

        // Verifier should be base64url-encoded 32 bytes
        assert!(!verifier.is_empty());
        assert!(verifier.len() >= 32);

        // Challenge should be base64url-encoded SHA256 of verifier
        assert!(!challenge.is_empty());

        // Verify the relationship
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let expected = URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(challenge, expected);
    }

    #[test]
    fn test_generate_pkce_unique() {
        let (v1, _) = OidcProviderClient::generate_pkce();
        let (v2, _) = OidcProviderClient::generate_pkce();
        assert_ne!(v1, v2, "PKCE verifiers should be unique");
    }

    #[test]
    fn test_generate_state() {
        let s1 = OidcProviderClient::generate_state();
        let s2 = OidcProviderClient::generate_state();

        assert!(!s1.is_empty());
        assert!(s1.len() >= 32);
        assert_ne!(s1, s2, "State tokens should be unique");
    }

    #[test]
    fn test_oidc_discovery_deserialize() {
        let json = r#"{
            "issuer": "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"
        }"#;

        let discovery: OidcDiscovery = serde_json::from_str(json).unwrap();
        assert_eq!(discovery.issuer, "https://accounts.google.com");
        assert_eq!(
            discovery.authorization_endpoint,
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
        assert_eq!(
            discovery.token_endpoint,
            "https://oauth2.googleapis.com/token"
        );
        assert!(discovery.userinfo_endpoint.is_some());
    }

    #[test]
    fn test_oidc_discovery_minimal() {
        let json = r#"{
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/.well-known/jwks.json"
        }"#;

        let discovery: OidcDiscovery = serde_json::from_str(json).unwrap();
        assert!(discovery.userinfo_endpoint.is_none());
    }

    #[test]
    fn test_token_response_deserialize() {
        let json = r#"{
            "access_token": "ya29.a0AfH6SMC",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": "eyJhbGciOiJSUzI1NiJ9..."
        }"#;

        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "ya29.a0AfH6SMC");
        assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
        assert_eq!(resp.expires_in, Some(3600));
        assert!(resp.id_token.is_some());
    }

    #[test]
    fn test_token_response_minimal() {
        let json = r#"{"access_token": "token123"}"#;

        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "token123");
        assert!(resp.token_type.is_none());
        assert!(resp.expires_in.is_none());
        assert!(resp.id_token.is_none());
    }

    #[test]
    fn test_state_verifier_encoding() {
        // Test the state\0verifier convention
        let state = "abc123";
        let verifier = "pkce-verifier";
        let combined = format!("{state}\0{verifier}");

        if let Some(idx) = combined.find('\0') {
            assert_eq!(&combined[..idx], "abc123");
            assert_eq!(&combined[idx + 1..], "pkce-verifier");
        } else {
            panic!("Should find null separator");
        }
    }

    #[test]
    fn test_redirect_uri_verifier_extraction() {
        // With verifier
        let uri_with = "https://sid.example.com/callback\0pkce-verifier-xyz";
        if let Some(idx) = uri_with.find('\0') {
            assert_eq!(&uri_with[..idx], "https://sid.example.com/callback");
            assert_eq!(&uri_with[idx + 1..], "pkce-verifier-xyz");
        }

        // Without verifier
        let uri_without = "https://sid.example.com/callback";
        assert!(uri_without.find('\0').is_none());
    }
}
