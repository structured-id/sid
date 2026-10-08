// SPDX-License-Identifier: AGPL-3.0-only
//! RFC 7523 Client Assertion JWT validation.
//!
//! Validates `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
//! JWTs for Private Key JWT client authentication.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sid_core::models::ClientKeySet;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::cache::{CacheBackend, CacheError};
use std::sync::Arc;
use std::time::Duration;

/// Expected assertion type for RFC 7523.
pub const JWT_BEARER_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Maximum assertion lifetime (5 minutes).
const MAX_ASSERTION_LIFETIME_SECS: u64 = 300;

/// RFC 7523 JWT assertion claims.
#[derive(Debug, Deserialize)]
pub struct AssertionClaims {
    /// Issuer — must equal client_id.
    pub iss: String,
    /// Subject — must equal client_id.
    pub sub: String,
    /// Audience — must include token endpoint URL.
    pub aud: AssertionAud,
    /// Expiration time.
    pub exp: u64,
    /// JWT ID — unique, used for replay prevention.
    pub jti: String,
    /// Issued at (optional per spec, validated if present).
    pub iat: Option<u64>,
}

/// Audience can be a string or array of strings per JWT spec.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AssertionAud {
    Single(String),
    Multiple(Vec<String>),
}

impl AssertionAud {
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(s) => s == expected,
            Self::Multiple(v) => v.iter().any(|s| s == expected),
        }
    }
}

/// Seen assertion JTIs (RFC 7523 §3 item 7), in the cache every replica shares.
pub struct AssertionJtiCache {
    ttl: Duration,
    cache: Arc<dyn CacheBackend>,
}

impl AssertionJtiCache {
    pub fn new(cache: Arc<dyn CacheBackend>) -> Self {
        Self {
            ttl: Duration::from_secs(MAX_ASSERTION_LIFETIME_SECS * 2),
            cache,
        }
    }

    /// Record a JTI: `Ok(false)` if it was already used (replay). An
    /// unreachable cache is an error, so a replay is never let through.
    pub async fn check_and_record(&self, jti: &str) -> Result<bool, CacheError> {
        self.cache
            .set_nx(&format!("jti:assertion:{jti}"), b"1", self.ttl)
            .await
    }
}

/// Map algorithm string from credential to jsonwebtoken Algorithm.
fn parse_algorithm(alg: &str) -> SidResult<Algorithm> {
    match alg {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        _ => Err(SidError::AuthenticationFailed(format!(
            "unsupported algorithm: {}",
            alg
        ))),
    }
}

/// Validate a client assertion JWT (RFC 7523).
///
/// - `assertion`: the raw JWT string
/// - `client_id`: expected issuer/subject
/// - `token_endpoint_url`: expected audience
/// - `public_key_pem`: PEM-encoded public key from credential
/// - `algorithm`: signing algorithm (RS256, ES256, EdDSA)
/// - `jti_cache`: replay prevention cache
pub async fn validate_client_assertion(
    assertion: &str,
    client_id: &str,
    token_endpoint_url: &str,
    public_key_pem: &str,
    algorithm: &str,
    jti_cache: &AssertionJtiCache,
) -> SidResult<AssertionClaims> {
    // Parse header to verify algorithm matches.
    let header = decode_header(assertion)
        .map_err(|e| SidError::AuthenticationFailed(format!("invalid assertion JWT: {}", e)))?;

    let expected_alg = parse_algorithm(algorithm)?;
    if header.alg != expected_alg {
        return Err(SidError::AuthenticationFailed(format!(
            "algorithm mismatch: expected {}, got {:?}",
            algorithm, header.alg
        )));
    }

    // Build decoding key from PEM.
    let decoding_key = pem_key(expected_alg, public_key_pem)?;
    verify(
        assertion,
        client_id,
        token_endpoint_url,
        &decoding_key,
        expected_alg,
        jti_cache,
    )
    .await
}

/// Validate a client assertion JWT (RFC 7523) signed by one of a client's
/// registered keys (RFC 7591 §2 `jwks`). The header's `kid` names the key;
/// it may be left out only when the client registered a single key.
pub async fn validate_client_assertion_with_keys(
    assertion: &str,
    client_id: &str,
    token_endpoint_url: &str,
    keys: &ClientKeySet,
    jti_cache: &AssertionJtiCache,
) -> SidResult<AssertionClaims> {
    let refused = |why: &str| SidError::AuthenticationFailed(why.to_owned());
    let header = decode_header(assertion)
        .map_err(|e| SidError::AuthenticationFailed(format!("invalid assertion JWT: {e}")))?;
    let key = match (&header.kid, keys.keys()) {
        (Some(kid), _) => keys.key(kid),
        (None, [only]) => Some(only),
        (None, _) => None,
    }
    .ok_or_else(|| refused("no registered key matches the assertion"))?;
    // A key that names its algorithm verifies only that one (RFC 7517 §4.4).
    let alg = algorithm_name(header.alg)?;
    if key
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|registered| registered != alg)
    {
        return Err(refused("the assertion's algorithm is not its key's"));
    }
    let jwk: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(serde_json::Value::Object(key.clone()))
            .map_err(|e| SidError::AuthenticationFailed(format!("registered key unusable: {e}")))?;
    let decoding_key = DecodingKey::from_jwk(&jwk)
        .map_err(|e| SidError::AuthenticationFailed(format!("registered key unusable: {e}")))?;
    verify(
        assertion,
        client_id,
        token_endpoint_url,
        &decoding_key,
        header.alg,
        jti_cache,
    )
    .await
}

/// Validate a proof that the caller holds the private half of one of `keys`:
/// a JWT signed by the key its `kid` header names, whose `iss` and `sub` are
/// that `kid`, for `audience`, short-lived and used once, under the same
/// checks as a client assertion (RFC 7523 §3). For a caller that does not yet
/// know its client identifier, only which key it holds.
pub async fn validate_key_proof(
    proof: &str,
    audience: &str,
    keys: &ClientKeySet,
    jti_cache: &AssertionJtiCache,
) -> SidResult<()> {
    let kid = decode_header(proof)
        .map_err(|e| SidError::AuthenticationFailed(format!("invalid key proof: {e}")))?
        .kid
        .ok_or_else(|| SidError::AuthenticationFailed("key proof names no key".into()))?;
    validate_client_assertion_with_keys(proof, &kid, audience, keys, jti_cache)
        .await
        .map(|_| ())
}

/// The name of `alg` when it is one a client may sign assertions with; a
/// symmetric or `none` algorithm is refused.
fn algorithm_name(alg: Algorithm) -> SidResult<&'static str> {
    Ok(match alg {
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::PS256 => "PS256",
        Algorithm::PS384 => "PS384",
        Algorithm::PS512 => "PS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        Algorithm::EdDSA => "EdDSA",
        _ => {
            return Err(SidError::AuthenticationFailed(
                "unsupported algorithm".into(),
            ));
        }
    })
}

/// The verification key of `alg` from a PEM public key.
fn pem_key(expected_alg: Algorithm, public_key_pem: &str) -> SidResult<DecodingKey> {
    Ok(match expected_alg {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).map_err(|e| {
                SidError::AuthenticationFailed(format!("invalid RSA public key: {}", e))
            })?
        }
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(public_key_pem.as_bytes())
            .map_err(|e| SidError::AuthenticationFailed(format!("invalid EC public key: {}", e)))?,
        Algorithm::EdDSA => DecodingKey::from_ed_pem(public_key_pem.as_bytes()).map_err(|e| {
            SidError::AuthenticationFailed(format!("invalid EdDSA public key: {}", e))
        })?,
        _ => {
            return Err(SidError::AuthenticationFailed(
                "unsupported algorithm".into(),
            ));
        }
    })
}

/// Verify `assertion` with `decoding_key` under `alg`, then its claims
/// (RFC 7523 §3): issued by and about `client_id`, for `token_endpoint_url`,
/// unexpired, and used once.
async fn verify(
    assertion: &str,
    client_id: &str,
    token_endpoint_url: &str,
    decoding_key: &DecodingKey,
    expected_alg: Algorithm,
    jti_cache: &AssertionJtiCache,
) -> SidResult<AssertionClaims> {
    // Validate signature and claims.
    let mut validation = Validation::new(expected_alg);
    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "jti"]);
    // We validate iss/sub/aud manually for better error messages.
    validation.validate_aud = false;

    let token_data =
        decode::<AssertionClaims>(assertion, decoding_key, &validation).map_err(|e| {
            SidError::AuthenticationFailed(format!("assertion verification failed: {}", e))
        })?;

    let claims = token_data.claims;

    // The replay record outlives only an assertion expiring within the
    // accepted lifetime; a later `exp` could be replayed once it is gone
    // (RFC 7523 §3 item 7 lets the server bound how far ahead `exp` is).
    let now = u64::try_from(chrono::Utc::now().timestamp())
        .map_err(|_| SidError::Internal("system clock before the epoch".into()))?;
    if claims.exp > now + MAX_ASSERTION_LIFETIME_SECS {
        return Err(SidError::AuthenticationFailed(
            "assertion expires too far in the future".into(),
        ));
    }

    // RFC 7523 §3: iss MUST equal client_id.
    if claims.iss != client_id {
        return Err(SidError::AuthenticationFailed(format!(
            "assertion iss '{}' does not match client_id '{}'",
            claims.iss, client_id
        )));
    }

    // RFC 7523 §3: sub MUST equal client_id.
    if claims.sub != client_id {
        return Err(SidError::AuthenticationFailed(format!(
            "assertion sub '{}' does not match client_id '{}'",
            claims.sub, client_id
        )));
    }

    // RFC 7523 §3: aud MUST include the token endpoint URL.
    if !claims.aud.contains(token_endpoint_url) {
        return Err(SidError::AuthenticationFailed(
            "assertion aud does not include token endpoint".into(),
        ));
    }

    // JTI replay prevention.
    if claims.jti.is_empty() {
        return Err(SidError::AuthenticationFailed(
            "assertion jti is empty".into(),
        ));
    }
    let first_use = jti_cache.check_and_record(&claims.jti).await.map_err(|e| {
        tracing::error!(error = %e, "assertion replay cache unavailable");
        SidError::Internal("assertion replay cache unavailable".into())
    })?;
    if !first_use {
        return Err(SidError::AuthenticationFailed(
            "assertion jti already used (replay detected)".into(),
        ));
    }

    Ok(claims)
}

#[cfg(test)]
mod tests;
