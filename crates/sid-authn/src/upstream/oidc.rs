// SPDX-License-Identifier: AGPL-3.0-only
//! Generic OIDC Provider Client.
//!
//! Implements `UpstreamIdpProvider` for any standard OIDC provider, and for
//! plain OAuth2 providers that only offer UserInfo. For OIDC the signed-in
//! identity is the ID Token, validated as OpenID Connect Core 1.0 §3.1.3.7
//! requires; UserInfo only adds claims for the same subject (§5.3.2).

use std::collections::HashMap;
use std::fmt;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sid_core::models::{MappedClaims, UpstreamProtocol, UpstreamProvider, UpstreamProviderId};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::UpstreamIdpProvider;
use sid_plugin::upstream::{AuthorizationRequest, PendingAuthorization};

/// The path a discovery URL ends with (OpenID Connect Discovery 1.0 §4).
const DISCOVERY_SUFFIX: &str = "/.well-known/openid-configuration";

/// The asymmetric algorithms an ID Token may be signed with. `none` and the
/// HMAC algorithms are refused: a token this client accepts is one only the
/// provider's published keys could have signed.
const ASYMMETRIC: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Clock skew allowed on `exp` and `iat`, seconds.
const LEEWAY: u64 = 60;

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
    /// The provider's signing keys (JWK Set); required for OIDC.
    pub jwks_uri: Option<String>,
    /// The algorithms the provider signs ID Tokens with.
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

/// Token response from the token endpoint.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    id_token: Option<String>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// What an ID Token is checked against.
#[derive(Debug, Clone, Copy)]
pub struct IdTokenExpectation<'a> {
    /// The provider's issuer, exactly.
    pub issuer: &'a str,
    /// This client's id: an audience, and the authorized party when there
    /// are several.
    pub client_id: &'a str,
    /// The nonce of the authorization request.
    pub nonce: &'a str,
    /// The algorithms the provider advertises; none advertised admits every
    /// asymmetric algorithm.
    pub algorithms: &'a [String],
    /// Now, Unix seconds.
    pub now: u64,
}

/// Validate the ID Token `token` against `keys` and `expected` (OpenID
/// Connect Core 1.0 §3.1.3.7, steps 2 to 11) and return its claims.
pub fn validate_id_token(
    token: &str,
    keys: &JwkSet,
    expected: &IdTokenExpectation<'_>,
) -> SidResult<HashMap<String, serde_json::Value>> {
    let refused = |why: &str| SidError::AuthenticationFailed(format!("ID Token refused: {why}"));
    let header = jsonwebtoken::decode_header(token).map_err(|_| refused("malformed"))?;
    // Steps 6 to 8: an asymmetric algorithm the provider advertises.
    if !ASYMMETRIC.contains(&header.alg) {
        return Err(refused("not an asymmetric signature algorithm"));
    }
    let advertised = expected.algorithms.is_empty()
        || expected
            .algorithms
            .iter()
            .any(|a| a.parse::<Algorithm>().ok() == Some(header.alg));
    if !advertised {
        return Err(refused("an algorithm the provider does not advertise"));
    }
    let jwk = match &header.kid {
        Some(kid) => keys.find(kid).ok_or_else(|| refused("unknown key id"))?,
        // Without a key id only a single published key is unambiguous.
        None => match keys.keys.as_slice() {
            [only] => only,
            _ => return Err(refused("no key id and several keys")),
        },
    };
    let key = DecodingKey::from_jwk(jwk).map_err(|_| refused("unusable key"))?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[expected.issuer]);
    validation.set_audience(&[expected.client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = LEEWAY;
    let claims =
        jsonwebtoken::decode::<HashMap<String, serde_json::Value>>(token, &key, &validation)
            .map_err(|e| refused(&format!("{:?}", e.kind())))?
            .claims;

    // Step 10: an issue time no later than now.
    let iat = claims
        .get("iat")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| refused("no issue time"))?;
    if iat > expected.now + LEEWAY {
        return Err(refused("issued in the future"));
    }
    // Steps 4 and 5: several audiences name this client as the authorized
    // party; an authorized party is this client.
    let several = claims
        .get("aud")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|a| a.len() > 1);
    match claims.get("azp").map(|v| v.as_str()) {
        Some(Some(azp)) if azp == expected.client_id => {}
        Some(_) => return Err(refused("another authorized party")),
        None if several => return Err(refused("several audiences without an authorized party")),
        None => {}
    }
    // Step 11: the nonce of this request.
    if claims.get("nonce").and_then(serde_json::Value::as_str) != Some(expected.nonce) {
        return Err(refused("another nonce"));
    }
    if claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(refused("no subject"));
    }
    Ok(claims)
}

/// Generic OIDC provider client.
///
/// Created from an `UpstreamProvider` config + decrypted client secret.
pub struct OidcProviderClient {
    provider_id: UpstreamProviderId,
    protocol: UpstreamProtocol,
    client_id: String,
    client_secret: SecretBox<String>,
    discovery: OidcDiscovery,
    scopes: Vec<String>,
    http: Client,
}

impl OidcProviderClient {
    /// Create from an UpstreamProvider config and decrypted secret.
    ///
    /// An OIDC provider is configured by its discovery URL, whose document
    /// must name that same issuer; a plain OAuth2 provider may name its
    /// endpoints instead.
    pub async fn from_provider(
        provider: &UpstreamProvider,
        decrypted_secret: String,
    ) -> SidResult<Self> {
        let http = sid_plugin::client_builder()
            .map_err(|e| SidError::Internal(format!("HTTP client error: {e}")))?
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| SidError::Internal(format!("HTTP client error: {e}")))?;

        let discovery = match (&provider.discovery_url, provider.protocol) {
            (Some(discovery_url), _) => Self::fetch_discovery(&http, discovery_url).await?,
            (None, UpstreamProtocol::Oidc) => {
                return Err(SidError::Validation(
                    "an OIDC provider is configured by its discovery_url".into(),
                ));
            }
            (None, UpstreamProtocol::OAuth2) => OidcDiscovery {
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
                jwks_uri: None,
                id_token_signing_alg_values_supported: Vec::new(),
            },
        };
        if provider.protocol == UpstreamProtocol::Oidc && discovery.jwks_uri.is_none() {
            return Err(SidError::Validation(
                "the OIDC provider's discovery names no jwks_uri".into(),
            ));
        }

        Ok(Self {
            provider_id: provider.id,
            protocol: provider.protocol,
            client_id: provider.client_id.clone(),
            client_secret: SecretBox::new(Box::new(decrypted_secret)),
            discovery,
            scopes: provider.scopes.clone(),
            http,
        })
    }

    /// Fetch the discovery document at `discovery_url`. Its issuer must be
    /// the URL the discovery URL names (OpenID Connect Discovery 1.0 §4.3).
    async fn fetch_discovery(http: &Client, discovery_url: &str) -> SidResult<OidcDiscovery> {
        let named = discovery_url
            .strip_suffix(DISCOVERY_SUFFIX)
            .ok_or_else(|| {
                SidError::Validation(format!("a discovery_url ends with {DISCOVERY_SUFFIX}"))
            })?;
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

        let discovery = resp
            .json::<OidcDiscovery>()
            .await
            .map_err(|e| SidError::Internal(format!("OIDC discovery parse failed: {e}")))?;
        check_discovered_issuer(named, &discovery.issuer)?;
        Ok(discovery)
    }

    /// The provider's current signing keys.
    async fn fetch_keys(&self) -> SidResult<JwkSet> {
        let uri = self
            .discovery
            .jwks_uri
            .as_ref()
            .ok_or_else(|| SidError::Internal("no jwks_uri available".into()))?;
        let resp = self
            .http
            .get(uri)
            .send()
            .await
            .map_err(|e| SidError::Internal(format!("JWKS request failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(SidError::Internal(format!(
                "JWKS returned {}",
                resp.status()
            )));
        }
        resp.json::<JwkSet>()
            .await
            .map_err(|e| SidError::Internal(format!("JWKS parse failed: {e}")))
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

/// A discovery document's `issuer` must be exactly the issuer its URL names
/// (OpenID Connect Discovery 1.0 §4.3).
fn check_discovered_issuer(named: &str, discovered: &str) -> SidResult<()> {
    if named == discovered {
        Ok(())
    } else {
        Err(SidError::Validation(format!(
            "the discovery document names issuer {discovered}, not {named}"
        )))
    }
}

/// 32 random bytes, base64url without padding.
fn random_token() -> String {
    use rand::TryRng;
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("the operating system random source is available");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The S256 challenge of `verifier` (RFC 7636 §4.2).
fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// `claims` from UserInfo merged under the validated ID Token's `id_token`
/// claims: the UserInfo response must be about the same subject (OpenID
/// Connect Core 1.0 §5.3.2), and the ID Token's own claims win.
fn merge_userinfo(
    mut id_token: HashMap<String, serde_json::Value>,
    userinfo: HashMap<String, serde_json::Value>,
) -> SidResult<HashMap<String, serde_json::Value>> {
    if userinfo.get("sub") != id_token.get("sub") {
        return Err(SidError::AuthenticationFailed(
            "the UserInfo subject is not the ID Token's".into(),
        ));
    }
    for (name, value) in userinfo {
        id_token.entry(name).or_insert(value);
    }
    Ok(id_token)
}

#[async_trait]
impl UpstreamIdpProvider for OidcProviderClient {
    fn protocol(&self) -> UpstreamProtocol {
        self.protocol
    }

    fn provider_id(&self) -> UpstreamProviderId {
        self.provider_id
    }

    async fn authorization_request(
        &self,
        redirect_uri: &str,
        scopes: &[String],
    ) -> SidResult<AuthorizationRequest> {
        let code_verifier = random_token();
        let code_challenge = pkce_challenge(&code_verifier);
        let state = random_token();
        let oidc = self.protocol == UpstreamProtocol::Oidc;
        let nonce = oidc.then(random_token);

        // Provider default scopes and the requested ones; an OIDC request
        // carries `openid` (OpenID Connect Core 1.0 §3.1.2.1).
        let mut all_scopes: Vec<&str> = Vec::new();
        if oidc {
            all_scopes.push("openid");
        }
        for s in self.scopes.iter().chain(scopes) {
            if !all_scopes.contains(&s.as_str()) {
                all_scopes.push(s.as_str());
            }
        }
        let scope_str = all_scopes.join(" ");

        let mut params = vec![
            ("response_type", "code"),
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("scope", scope_str.as_str()),
            ("state", state.as_str()),
            ("code_challenge", code_challenge.as_str()),
            ("code_challenge_method", "S256"),
        ];
        if let Some(nonce) = &nonce {
            params.push(("nonce", nonce.as_str()));
        }

        let url = reqwest::Url::parse_with_params(&self.discovery.authorization_endpoint, &params)
            .map_err(|e| SidError::Internal(format!("Failed to build auth URL: {e}")))?;

        Ok(AuthorizationRequest {
            url: url.to_string(),
            state,
            code_verifier,
            nonce,
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        pending: &PendingAuthorization<'_>,
    ) -> SidResult<MappedClaims> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", pending.redirect_uri),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.expose_secret().as_str()),
            ("code_verifier", pending.code_verifier),
        ];

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

        let claims = match self.protocol {
            UpstreamProtocol::Oidc => {
                // OpenID Connect Core 1.0 §3.1.3.3: the response carries an
                // ID Token, the one identity this sign-in establishes.
                let id_token = token_resp.id_token.as_deref().ok_or_else(|| {
                    SidError::AuthenticationFailed("the token response carries no ID Token".into())
                })?;
                let nonce = pending.nonce.ok_or_else(|| {
                    SidError::Internal("an OIDC sign-in without its nonce".into())
                })?;
                let keys = self.fetch_keys().await?;
                let validated = validate_id_token(
                    id_token,
                    &keys,
                    &IdTokenExpectation {
                        issuer: &self.discovery.issuer,
                        client_id: &self.client_id,
                        nonce,
                        algorithms: &self.discovery.id_token_signing_alg_values_supported,
                        now: jsonwebtoken::get_current_timestamp(),
                    },
                )?;
                if self.discovery.userinfo_endpoint.is_some() {
                    let userinfo = self.fetch_userinfo(&token_resp.access_token).await?;
                    merge_userinfo(validated, userinfo)?
                } else {
                    validated
                }
            }
            UpstreamProtocol::OAuth2 => self.fetch_userinfo(&token_resp.access_token).await?,
        };

        let mut mapped = MappedClaims::from_oidc_userinfo(&claims);
        if mapped.upstream_subject.is_empty() {
            return Err(SidError::AuthenticationFailed(
                "the provider named no subject".into(),
            ));
        }
        // The configured provider's issuer, never one the claims assert.
        mapped.upstream_issuer = Some(self.discovery.issuer.clone());
        Ok(mapped)
    }
}

#[cfg(test)]
mod tests;
