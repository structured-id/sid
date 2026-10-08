// SPDX-License-Identifier: AGPL-3.0-only
//! DPoP (Demonstrating Proof-of-Possession) validation service.
//!
//! RFC 9449: validates DPoP proof JWTs and provides JWK thumbprints
//! for sender-constrained access tokens.
//!
//! CE behavior: opt-in. If client sends DPoP header, validate and bind.
//! If not, issue standard Bearer token (backwards compatible).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use sid_core::models::dpop::{DPopBinding, DPopProof};
use sid_plugin::cache::CacheBackend;

use std::sync::Arc;
use std::time::Duration;

/// DPoP validation errors.
#[derive(Debug, thiserror::Error)]
pub enum DPopError {
    #[error("invalid DPoP proof: {0}")]
    InvalidProof(String),

    #[error("DPoP proof replay detected")]
    ReplayDetected,

    #[error("DPoP replay cache unavailable")]
    ReplayCacheUnavailable,

    #[error("DPoP proof expired (max age: {max_age}s)")]
    Expired { max_age: u32 },

    #[error("DPoP htm mismatch: expected {expected}, got {got}")]
    MethodMismatch { expected: String, got: String },

    #[error("DPoP htu mismatch")]
    UriMismatch,

    /// `ath` missing or not the hash of the presented token (RFC 9449 §4.3).
    #[error("DPoP ath does not match the access token")]
    AccessTokenHashMismatch,

    /// The proof key is not the key the token is bound to (RFC 9449 §7.1).
    #[error("DPoP proof key does not match the token binding")]
    KeyMismatch,
}

/// `ath` of an access token: base64url SHA-256 of its ASCII form (RFC 9449 §4.2).
pub fn access_token_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

/// A proof whose signature, method, URI and age were checked.
struct CheckedProof {
    jti: String,
    ath: Option<String>,
    jwk: serde_json::Value,
}

/// DPoP proof validator with JTI replay detection (RFC 9449 §11.1) in the
/// cache every replica shares.
pub struct DPopValidator {
    max_age: Duration,
    cache: Arc<dyn CacheBackend>,
}

impl std::fmt::Debug for DPopValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DPopValidator")
            .field("max_age", &self.max_age)
            .finish_non_exhaustive()
    }
}

/// DPoP JWT header (JOSE header with embedded JWK).
#[derive(serde::Deserialize)]
struct DPopJoseHeader {
    typ: Option<String>,
    alg: String,
    jwk: serde_json::Value,
}

/// DPoP JWT payload claims.
#[derive(serde::Deserialize)]
struct DPopPayload {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    ath: Option<String>,
}

impl DPopValidator {
    /// Create a new validator with replay window = `DPopProof::MAX_AGE_SECONDS` (60s).
    pub fn new(cache: Arc<dyn CacheBackend>) -> Self {
        let max_age = Duration::from_secs(DPopProof::MAX_AGE_SECONDS as u64);
        Self { max_age, cache }
    }

    /// Validate a DPoP proof JWT string.
    ///
    /// On success, returns a `DPopBinding` containing the JWK thumbprint (jkt)
    /// which should be embedded in the access token's `cnf` claim.
    pub async fn validate(
        &self,
        proof_jwt: &str,
        expected_method: &str,
        expected_url: &str,
    ) -> Result<DPopBinding, DPopError> {
        let proof = Self::check(proof_jwt, expected_method, expected_url)?;
        let thumbprint = compute_jwk_thumbprint(&proof.jwk)?;
        self.first_use(&proof.jti).await?;
        Ok(DPopBinding::new(thumbprint))
    }

    /// Validate the proof that accompanies a DPoP-bound `access_token` at a
    /// protected resource: besides the checks of [`Self::validate`], `ath`
    /// must be the token's hash (RFC 9449 §4.3 step 12) and the proof key the
    /// one the token is bound to, `bound_jkt` from its `cnf` (RFC 9449 §7.1).
    pub async fn validate_for_resource(
        &self,
        proof_jwt: &str,
        method: &str,
        url: &str,
        access_token: &str,
        bound_jkt: &str,
    ) -> Result<(), DPopError> {
        let proof = Self::check(proof_jwt, method, url)?;
        if proof.ath.as_deref() != Some(access_token_hash(access_token).as_str()) {
            return Err(DPopError::AccessTokenHashMismatch);
        }
        if compute_jwk_thumbprint(&proof.jwk)? != bound_jkt {
            return Err(DPopError::KeyMismatch);
        }
        self.first_use(&proof.jti).await
    }

    /// Record the proof's `jti` (insert-or-reject, RFC 9449 §11.1). A replay
    /// cache that cannot be reached rejects the proof: accepting it would
    /// accept replays.
    async fn first_use(&self, jti: &str) -> Result<(), DPopError> {
        let first_use = self
            .cache
            .set_nx(&format!("jti:dpop:{jti}"), b"1", self.max_age)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "DPoP replay cache unavailable");
                DPopError::ReplayCacheUnavailable
            })?;
        if first_use {
            Ok(())
        } else {
            Err(DPopError::ReplayDetected)
        }
    }

    /// The checks that need no shared state: form, signature, method, URI, age.
    fn check(
        proof_jwt: &str,
        expected_method: &str,
        expected_url: &str,
    ) -> Result<CheckedProof, DPopError> {
        // 1. Split JWT into header.payload.signature
        let parts: Vec<&str> = proof_jwt.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(DPopError::InvalidProof("malformed JWT".into()));
        }

        // 2. Decode JOSE header (need JWK before we can verify signature)
        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| DPopError::InvalidProof("invalid base64 in header".into()))?;
        let header: DPopJoseHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| DPopError::InvalidProof(format!("invalid header JSON: {e}")))?;

        // 3. Verify typ = "dpop+jwt"
        match header.typ.as_deref() {
            Some("dpop+jwt") => {}
            other => {
                return Err(DPopError::InvalidProof(format!(
                    "expected typ=dpop+jwt, got {:?}",
                    other
                )));
            }
        }

        // 4. Parse algorithm (must be asymmetric)
        let alg = parse_algorithm(&header.alg)?;

        // The jwk header carries a public key only (RFC 9449 §4.3).
        if header.jwk.get("d").is_some() {
            return Err(DPopError::InvalidProof(
                "jwk header contains private key material".into(),
            ));
        }

        // 5. Build DecodingKey from embedded JWK
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(header.jwk.clone())
            .map_err(|e| DPopError::InvalidProof(format!("invalid JWK: {e}")))?;
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(&jwk)
            .map_err(|e| DPopError::InvalidProof(format!("cannot create key from JWK: {e}")))?;

        // 6. Verify signature and decode claims
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.validate_exp = false; // DPoP uses iat freshness, not exp
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        let token_data = jsonwebtoken::decode::<DPopPayload>(proof_jwt, &decoding_key, &validation)
            .map_err(|e| DPopError::InvalidProof(format!("signature verification failed: {e}")))?;

        let payload = token_data.claims;

        // 7. Verify htm matches expected HTTP method
        if !payload.htm.eq_ignore_ascii_case(expected_method) {
            return Err(DPopError::MethodMismatch {
                expected: expected_method.to_string(),
                got: payload.htm,
            });
        }

        // 8. Verify htu matches expected URL (RFC 9449 §4.3)
        if !same_htu(&payload.htu, expected_url) {
            return Err(DPopError::UriMismatch);
        }

        // 9. Check iat freshness (within MAX_AGE window)
        let now = chrono::Utc::now().timestamp();
        let age = now - payload.iat;
        if age < -5 || age > DPopProof::MAX_AGE_SECONDS as i64 {
            return Err(DPopError::Expired {
                max_age: DPopProof::MAX_AGE_SECONDS,
            });
        }

        Ok(CheckedProof {
            jti: payload.jti,
            ath: payload.ath,
            jwk: header.jwk,
        })
    }
}

/// Parse a JWA algorithm string into `jsonwebtoken::Algorithm`.
/// Only asymmetric algorithms are allowed for DPoP (RFC 9449 §4.2).
fn parse_algorithm(alg: &str) -> Result<jsonwebtoken::Algorithm, DPopError> {
    match alg {
        "ES256" => Ok(jsonwebtoken::Algorithm::ES256),
        "ES384" => Ok(jsonwebtoken::Algorithm::ES384),
        "RS256" => Ok(jsonwebtoken::Algorithm::RS256),
        "RS384" => Ok(jsonwebtoken::Algorithm::RS384),
        "RS512" => Ok(jsonwebtoken::Algorithm::RS512),
        "PS256" => Ok(jsonwebtoken::Algorithm::PS256),
        "PS384" => Ok(jsonwebtoken::Algorithm::PS384),
        "PS512" => Ok(jsonwebtoken::Algorithm::PS512),
        "EdDSA" => Ok(jsonwebtoken::Algorithm::EdDSA),
        "HS256" | "HS384" | "HS512" => Err(DPopError::InvalidProof(
            "symmetric algorithms not allowed for DPoP".into(),
        )),
        other => Err(DPopError::InvalidProof(format!(
            "unsupported algorithm: {other}"
        ))),
    }
}

/// Whether a proof's `htu` names the request URI: compared after syntax- and
/// scheme-based normalization (RFC 3986 §6.2.2, §6.2.3), without query and
/// fragment (RFC 9449 §4.3). An unparsable URI matches nothing.
fn same_htu(htu: &str, request_uri: &str) -> bool {
    let (Ok(a), Ok(b)) = (url::Url::parse(htu), url::Url::parse(request_uri)) else {
        return false;
    };
    a.scheme() == b.scheme()
        && a.host() == b.host()
        && a.port_or_known_default() == b.port_or_known_default()
        && a.path() == b.path()
}

/// Compute JWK Thumbprint per RFC 7638.
///
/// Creates a canonical JSON representation of the required JWK members
/// (sorted alphabetically), then SHA-256 hashes it and base64url-encodes.
fn compute_jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, DPopError> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DPopError::InvalidProof("JWK missing kty".into()))?;

    // RFC 7638 §3.2: required members depend on key type, sorted alphabetically.
    let canonical = match kty {
        "EC" => {
            let crv = get_required_member(jwk, "crv")?;
            let x = get_required_member(jwk, "x")?;
            let y = get_required_member(jwk, "y")?;
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        "RSA" => {
            let e = get_required_member(jwk, "e")?;
            let n = get_required_member(jwk, "n")?;
            format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
        }
        "OKP" => {
            let crv = get_required_member(jwk, "crv")?;
            let x = get_required_member(jwk, "x")?;
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        other => {
            return Err(DPopError::InvalidProof(format!(
                "unsupported JWK key type: {other}"
            )));
        }
    };

    let hash = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

/// Extract a required string member from a JWK JSON object.
fn get_required_member(jwk: &serde_json::Value, name: &str) -> Result<String, DPopError> {
    jwk.get(name)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| DPopError::InvalidProof(format!("JWK missing required member: {name}")))
}

#[cfg(test)]
mod tests;
