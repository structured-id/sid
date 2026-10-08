// SPDX-License-Identifier: AGPL-3.0-only
//! DPoP (Demonstrating Proof-of-Possession) domain model.
//!
//! RFC 9449: sender-constrained access tokens via client-generated key pairs.
//! The client proves it holds the private key matching the token's bound public key.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// HTTP method for DPoP proof binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// DPoP proof — JWT header claims sent with each request.
///
/// The client generates a key pair and sends a signed JWT proving
/// possession of the private key. The JWT is bound to the HTTP method
/// and URL of the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPopProof {
    /// Unique identifier for this proof (jti claim). Used for replay prevention.
    pub jti: String,

    /// HTTP method this proof is bound to.
    pub htm: HttpMethod,

    /// HTTP URI this proof is bound to (without query/fragment).
    pub htu: String,

    /// Issued at timestamp.
    pub iat: DateTime<Utc>,

    /// JWK Thumbprint (RFC 7638) of the client's public key.
    pub jwk_thumbprint: String,

    /// Server-provided nonce (optional).
    /// When present, the client must include the nonce in the proof.
    pub nonce: Option<String>,

    /// Access token hash (ath claim).
    /// SHA-256 hash of the access token, base64url-encoded.
    /// Present when the proof accompanies a resource request.
    pub ath: Option<String>,
}

impl DPopProof {
    pub fn new(
        jti: impl Into<String>,
        htm: HttpMethod,
        htu: impl Into<String>,
        jwk_thumbprint: impl Into<String>,
    ) -> Self {
        Self {
            jti: jti.into(),
            htm,
            htu: htu.into(),
            iat: Utc::now(),
            jwk_thumbprint: jwk_thumbprint.into(),
            nonce: None,
            ath: None,
        }
    }

    /// Maximum allowed age for a DPoP proof (CE hardcoded, per FAPI 2.0).
    pub const MAX_AGE_SECONDS: u32 = 60;

    /// JWS algorithms accepted for proofs, as advertised in
    /// `dpop_signing_alg_values_supported` (RFC 9449 §5.1). Asymmetric only.
    pub const SIGNING_ALGORITHMS: &'static [&'static str] = &[
        "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA",
    ];

    /// Whether this proof has expired.
    pub fn is_expired(&self) -> bool {
        let age = Utc::now() - self.iat;
        age.num_seconds() > Self::MAX_AGE_SECONDS as i64
    }
}

/// DPoP-bound token confirmation — stored in the access token's `cnf` claim.
///
/// When a token is issued with DPoP binding, the JWK thumbprint is stored
/// so that resource servers can verify the DPoP proof matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DPopBinding {
    /// JWK Thumbprint of the client's DPoP key (cnf.jkt).
    pub jkt: String,

    /// When this binding was created.
    pub bound_at: DateTime<Utc>,
}

impl DPopBinding {
    pub fn new(jkt: impl Into<String>) -> Self {
        Self {
            jkt: jkt.into(),
            bound_at: Utc::now(),
        }
    }

    /// Verify that a DPoP proof matches this binding.
    pub fn matches_proof(&self, proof: &DPopProof) -> bool {
        self.jkt == proof.jwk_thumbprint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proof() -> DPopProof {
        DPopProof::new(
            "unique-jti-123",
            HttpMethod::Post,
            "https://sid.example.com/token",
            "thumbprint_abc",
        )
    }

    #[test]
    fn test_dpop_proof_new() {
        let proof = make_proof();
        assert_eq!(proof.jti, "unique-jti-123");
        assert_eq!(proof.htm, HttpMethod::Post);
        assert_eq!(proof.htu, "https://sid.example.com/token");
        assert_eq!(proof.jwk_thumbprint, "thumbprint_abc");
        assert!(proof.nonce.is_none());
        assert!(proof.ath.is_none());
        assert!(!proof.is_expired());
    }

    #[test]
    fn test_dpop_proof_expired() {
        let mut proof = make_proof();
        proof.iat = Utc::now() - chrono::Duration::seconds(200);
        assert!(proof.is_expired());
    }

    #[test]
    fn test_dpop_proof_not_expired() {
        let proof = make_proof();
        assert!(!proof.is_expired());
    }

    #[test]
    fn test_dpop_binding() {
        let binding = DPopBinding::new("thumbprint_abc");
        assert_eq!(binding.jkt, "thumbprint_abc");
    }

    #[test]
    fn test_dpop_binding_matches_proof() {
        let binding = DPopBinding::new("thumbprint_abc");
        let proof = make_proof();
        assert!(binding.matches_proof(&proof));
    }

    #[test]
    fn test_dpop_binding_rejects_wrong_proof() {
        let binding = DPopBinding::new("different_thumbprint");
        let proof = make_proof();
        assert!(!binding.matches_proof(&proof));
    }

    #[test]
    fn test_http_method_as_str() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
    }

    #[test]
    fn test_http_method_serde() {
        let m = HttpMethod::Put;
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"PUT\"");
        let parsed: HttpMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, HttpMethod::Put);
    }

    #[test]
    fn test_dpop_proof_serde_roundtrip() {
        let mut proof = make_proof();
        proof.nonce = Some("server-nonce-456".into());
        proof.ath = Some("base64url_hash".into());

        let json = serde_json::to_string(&proof).unwrap();
        let parsed: DPopProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.jti, "unique-jti-123");
        assert_eq!(parsed.nonce.as_deref(), Some("server-nonce-456"));
        assert_eq!(parsed.ath.as_deref(), Some("base64url_hash"));
    }
}
