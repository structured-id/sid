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
use sid_plugin::SingleUseAdmissions;

use std::sync::Arc;
use std::time::Duration;

/// DPoP validation errors.
#[derive(Debug, thiserror::Error)]
pub enum DPopError {
    #[error("invalid DPoP proof: {0}")]
    InvalidProof(String),

    #[error("DPoP proof replay detected")]
    ReplayDetected,

    #[error("DPoP replay store unavailable")]
    ReplayStoreUnavailable,

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

    /// A SID native proof does not bind the credential, exchange or ceremony
    /// it accompanies.
    #[error("native proof does not bind this request")]
    NativeBindingMismatch,
}

/// JWS `typ` of a SID native proof (native_session.proto): distinct from
/// `dpop+jwt`, so neither proof is accepted as the other.
pub const NATIVE_PROOF_TYPE: &str = "sid-native+jwt";

/// JWS `typ` of an OAuth DPoP proof (RFC 9449 §4.2).
const DPOP_PROOF_TYPE: &str = "dpop+jwt";

/// base64url (no padding) SHA-256 of `bytes`: how a native proof names the
/// credential or ceremony it binds.
pub fn native_digest(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

/// What a SID native proof must bind beyond RFC 9449's claims.
#[derive(Debug, Clone, Copy)]
pub enum NativeProofBinding<'a> {
    /// A refresh: the presented credential (`sid_rt`) and the logical
    /// exchange (`sid_ex`).
    Refresh {
        credential: &'a str,
        exchange: &'a sid_core::models::NativeExchange,
    },
    /// A ceremony completion: the ceremony reference it echoes (`sid_cer`).
    Ceremony { reference: &'a [u8] },
}

/// How far ahead of this server's clock a proof's `iat` may be (RFC 9449
/// §11.1 lets the server bound clock difference).
const FUTURE_IAT_ALLOWANCE_SECS: i64 = 5;

/// The holder of a proof's admission: one original request as its verifier
/// identified it, bound to the request's token, method and URI and to the
/// verifier that confirmed it, so the same `request_id` with anything else
/// changed is another request.
pub fn request_holder(
    request_id: &[u8],
    access_token: &str,
    method: &str,
    uri: &str,
    verifier: &str,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in [
        request_id,
        access_token.as_bytes(),
        method.as_bytes(),
        uri.as_bytes(),
        verifier.as_bytes(),
    ] {
        // Length-prefixed, so no two different requests share a digest input.
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

/// `ath` of an access token: base64url SHA-256 of its ASCII form (RFC 9449 §4.2).
pub fn access_token_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

/// A proof whose signature, method, URI and age were checked.
struct CheckedProof {
    jti: String,
    iat: i64,
    ath: Option<String>,
    jwk: serde_json::Value,
    sid_rt: Option<String>,
    sid_ex: Option<String>,
    sid_cer: Option<String>,
}

/// A proof checked at a resource for its bound token, not yet admitted: what
/// the token's issuer needs to admit it once (RFC 9449 §11.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    /// The proof's `jti`.
    pub jti: String,
    /// The proof's `iat`, seconds since the epoch.
    pub iat: i64,
}

/// DPoP proof validator with JTI replay detection (RFC 9449 §11.1) in the
/// single-use admissions every replica of its verifier shares.
pub struct DPopValidator {
    /// How long a proof's replay record is kept: past every moment it could
    /// still be accepted.
    retention: Duration,
    admissions: Arc<dyn SingleUseAdmissions>,
}

impl std::fmt::Debug for DPopValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DPopValidator")
            .field("retention", &self.retention)
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
    #[serde(default)]
    sid_rt: Option<String>,
    #[serde(default)]
    sid_ex: Option<String>,
    #[serde(default)]
    sid_cer: Option<String>,
}

impl DPopValidator {
    /// Create a new validator whose replay records outlive every proof it
    /// accepts: the proof age `DPopProof::MAX_AGE_SECONDS` past the latest
    /// accepted `iat`.
    pub fn new(admissions: Arc<dyn SingleUseAdmissions>) -> Self {
        let retention = Duration::from_secs(
            u64::from(DPopProof::MAX_AGE_SECONDS) + FUTURE_IAT_ALLOWANCE_SECS.unsigned_abs(),
        );
        Self {
            retention,
            admissions,
        }
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
        let proof = Self::check(proof_jwt, DPOP_PROOF_TYPE, expected_method, expected_url)?;
        let thumbprint = compute_jwk_thumbprint(&proof.jwk)?;
        self.first_use(&thumbprint, expected_url, &proof.jti)
            .await?;
        Ok(DPopBinding::new(thumbprint))
    }

    /// Validate a SID native proof (native_session.proto): RFC 9449's
    /// signature, method, URI and freshness checks under typ
    /// `sid-native+jwt`, the SID claims `binding` names, and the proof's
    /// single use. Returns the proving key's thumbprint; that it is the key
    /// a session is bound to is the caller's check.
    pub async fn validate_native(
        &self,
        proof_jwt: &str,
        method: &str,
        url: &str,
        binding: NativeProofBinding<'_>,
    ) -> Result<DPopBinding, DPopError> {
        let proof = Self::check(proof_jwt, NATIVE_PROOF_TYPE, method, url)?;
        let bound = match binding {
            NativeProofBinding::Refresh {
                credential,
                exchange,
            } => {
                proof.sid_cer.is_none()
                    && proof.sid_rt.as_deref()
                        == Some(native_digest(credential.as_bytes()).as_str())
                    && proof.sid_ex.as_deref()
                        == Some(URL_SAFE_NO_PAD.encode(exchange.as_bytes()).as_str())
            }
            NativeProofBinding::Ceremony { reference } => {
                proof.sid_rt.is_none()
                    && proof.sid_ex.is_none()
                    && proof.sid_cer.as_deref() == Some(native_digest(reference).as_str())
            }
        };
        if !bound {
            return Err(DPopError::NativeBindingMismatch);
        }
        let thumbprint = compute_jwk_thumbprint(&proof.jwk)?;
        self.first_use(&thumbprint, url, &proof.jti).await?;
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
        let proof = Self::verify_for_resource(proof_jwt, method, url, access_token, bound_jkt)?;
        self.first_use(bound_jkt, url, &proof.jti).await
    }

    /// Admit `proof`, verified by a resource-side verifier for a token of
    /// this issuer bound to `jkt`, once for the request `holder` stands for
    /// (RFC 9449 §11.1). `scope` names the issuer and the resource the
    /// request was made to. The same request confirms its admission without
    /// extending it; the proof used for any other request is a replay. The
    /// admission lasts as long as this issuer would still accept the proof.
    pub async fn admit_for_request(
        &self,
        scope: &str,
        jkt: &str,
        proof: &VerifiedProof,
        holder: &[u8],
    ) -> Result<(), DPopError> {
        let now = chrono::Utc::now().timestamp();
        let age = now - proof.iat;
        if age < -FUTURE_IAT_ALLOWANCE_SECS || age > i64::from(DPopProof::MAX_AGE_SECONDS) {
            return Err(DPopError::Expired {
                max_age: DPopProof::MAX_AGE_SECONDS,
            });
        }
        // Accepted until iat + max age; kept past the latest accepted moment.
        let remaining = i64::from(DPopProof::MAX_AGE_SECONDS) + FUTURE_IAT_ALLOWANCE_SECS - age;
        let retention =
            Duration::from_secs(u64::try_from(remaining).expect("an accepted proof has time left"));
        // A thumbprint is base64url and an issuer URL and resource id have no
        // raw space, so the jti after the third space is unambiguous.
        let key = format!("{scope} {jkt} {}", proof.jti);
        let held = self
            .admissions
            .admit_for("dpop-request", &key, holder, retention)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "DPoP replay store unavailable");
                DPopError::ReplayStoreUnavailable
            })?;
        if held {
            Ok(())
        } else {
            Err(DPopError::ReplayDetected)
        }
    }

    /// The checks of [`Self::validate_for_resource`] without the admission:
    /// for a resource outside the token's issuer, which has the issuer admit
    /// the returned proof instead of recording it itself.
    pub fn verify_for_resource(
        proof_jwt: &str,
        method: &str,
        url: &str,
        access_token: &str,
        bound_jkt: &str,
    ) -> Result<VerifiedProof, DPopError> {
        let proof = Self::check(proof_jwt, DPOP_PROOF_TYPE, method, url)?;
        if proof.ath.as_deref() != Some(access_token_hash(access_token).as_str()) {
            return Err(DPopError::AccessTokenHashMismatch);
        }
        if compute_jwk_thumbprint(&proof.jwk)? != bound_jkt {
            return Err(DPopError::KeyMismatch);
        }
        Ok(VerifiedProof {
            jti: proof.jti,
            iat: proof.iat,
        })
    }

    /// Record the proof's `jti` (insert-or-reject, RFC 9449 §11.1), scoped to
    /// the verified key `jkt` and the target `htu` this verifier admits it
    /// for, so a proof by one key never takes another key's `jti`. A replay
    /// store that cannot be reached rejects the proof: accepting it would
    /// accept replays.
    async fn first_use(&self, jkt: &str, htu: &str, jti: &str) -> Result<(), DPopError> {
        // A thumbprint is base64url and a URI has no raw space, so the jti
        // after the second space is unambiguous.
        let key = format!("{jkt} {htu} {jti}");
        let first_use = self
            .admissions
            .admit_once("dpop-jti", &key, self.retention)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "DPoP replay store unavailable");
                DPopError::ReplayStoreUnavailable
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
        typ: &str,
        expected_method: &str,
        expected_url: &str,
    ) -> Result<CheckedProof, DPopError> {
        let (payload, jwk) = verify_key_jws::<DPopPayload>(proof_jwt, typ)?;

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
        if age < -FUTURE_IAT_ALLOWANCE_SECS || age > DPopProof::MAX_AGE_SECONDS as i64 {
            return Err(DPopError::Expired {
                max_age: DPopProof::MAX_AGE_SECONDS,
            });
        }

        Ok(CheckedProof {
            jti: payload.jti,
            iat: payload.iat,
            ath: payload.ath,
            jwk,
            sid_rt: payload.sid_rt,
            sid_ex: payload.sid_ex,
            sid_cer: payload.sid_cer,
        })
    }
}

/// The claims of `jws`, a compact JWS whose protected header names its
/// `typ`, an asymmetric `alg` and `jwk`, the public key it is signed with,
/// and that key: checked form, type, algorithm and signature. Every
/// key-bound proof (DPoP, native, device-key) is read through this check.
pub(crate) fn verify_key_jws<C: serde::de::DeserializeOwned>(
    jws: &str,
    typ: &str,
) -> Result<(C, serde_json::Value), DPopError> {
    // 1. Split JWT into header.payload.signature
    let parts: Vec<&str> = jws.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(DPopError::InvalidProof("malformed JWT".into()));
    }

    // 2. Decode JOSE header (need JWK before we can verify signature)
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| DPopError::InvalidProof("invalid base64 in header".into()))?;
    let header: DPopJoseHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| DPopError::InvalidProof(format!("invalid header JSON: {e}")))?;

    // 3. Verify typ: each proof kind has its own, so none is accepted as
    // another.
    if header.typ.as_deref() != Some(typ) {
        return Err(DPopError::InvalidProof(format!(
            "expected typ={typ}, got {:?}",
            header.typ
        )));
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

    // 6. Verify signature and decode claims; freshness and audience are each
    // proof kind's own claims.
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    let token_data = jsonwebtoken::decode::<C>(jws, &decoding_key, &validation)
        .map_err(|e| DPopError::InvalidProof(format!("signature verification failed: {e}")))?;
    Ok((token_data.claims, header.jwk))
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
pub(crate) fn compute_jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, DPopError> {
    let hash = Sha256::digest(canonical_jwk(jwk)?.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

/// The public key of `jwk` as its RFC 7638 §3.2 required members, sorted,
/// without whitespace: the thumbprint's input, and the one stored form of a
/// public key that carries nothing else.
pub(crate) fn canonical_jwk(jwk: &serde_json::Value) -> Result<String, DPopError> {
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
    Ok(canonical)
}

/// Extract a required string member from a JWK JSON object. Every member the
/// canonical form names is base64url (RFC 7518 §6) or a curve name, so a
/// value with any other character is refused rather than written into the
/// canonical JSON unescaped.
fn get_required_member(jwk: &serde_json::Value, name: &str) -> Result<String, DPopError> {
    jwk.get(name)
        .and_then(|v| v.as_str())
        .filter(|v| {
            !v.is_empty()
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .map(String::from)
        .ok_or_else(|| DPopError::InvalidProof(format!("JWK missing required member: {name}")))
}

#[cfg(test)]
mod tests;
