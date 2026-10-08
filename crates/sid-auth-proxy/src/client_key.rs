// SPDX-License-Identifier: AGPL-3.0-only
//! The BFF's client key: an Ed25519 key whose private half never leaves this
//! process. It signs the BFF's token endpoint assertions (`private_key_jwt`,
//! RFC 7523 §2.2) and its proofs to the connection service; SID holds only
//! the public half, registered from the deployment's configuration.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Lifetime of an assertion or proof: short, well inside the five minutes
/// SID accepts.
const ASSERTION_LIFETIME_SECS: i64 = 60;

/// The BFF's signing key.
pub struct ClientKey {
    encoding: EncodingKey,
    /// The RFC 7638 thumbprint of the public key: the `kid` of every JWT it
    /// signs and of its registered public JWK.
    kid: String,
    public: Value,
}

impl std::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl ClientKey {
    /// The key a PEM-encoded Ed25519 private key (PKCS#8, RFC 8410) holds.
    pub fn from_pem(pem: &[u8]) -> anyhow::Result<Self> {
        let text = std::str::from_utf8(pem)
            .map_err(|_| anyhow::anyhow!("the client key is not PEM text"))?;
        let signing = ed25519_dalek::SigningKey::from_pkcs8_pem(text)
            .map_err(|e| anyhow::anyhow!("not an Ed25519 private key in PKCS#8 PEM: {e}"))?;
        let encoding = EncodingKey::from_ed_pem(pem)
            .map_err(|e| anyhow::anyhow!("not an Ed25519 private key in PKCS#8 PEM: {e}"))?;
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
        // RFC 7638 §3.2: the required members of an OKP key (RFC 8037 §2) in
        // lexicographic order, no whitespace, hashed with SHA-256.
        let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        let public = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "kid": kid,
            "use": "sig",
            "alg": "EdDSA",
        });
        Ok(Self {
            encoding,
            kid,
            public,
        })
    }

    /// A new random key and its PKCS#8 PEM encoding.
    pub fn generate() -> anyhow::Result<(Self, String)> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("random seed: {e}"))?;
        let pem = ed25519_dalek::SigningKey::from_bytes(&seed)
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("encoding the client key: {e}"))?;
        Ok((Self::from_pem(pem.as_bytes())?, pem.to_string()))
    }

    /// The key's id.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public JWK Set SID registers for this key (RFC 7517 §5).
    pub fn public_jwks(&self) -> Value {
        json!({ "keys": [self.public.clone()] })
    }

    /// A JWT this key signs with `iss` and `sub` both `issuer` for
    /// `audience`, expiring shortly and naming a fresh `jti`: an RFC 7523 §3
    /// client assertion when `issuer` is the client id, a connection proof
    /// when it is the key's own id.
    pub fn sign(&self, issuer: &str, audience: &str) -> anyhow::Result<String> {
        let now = chrono::Utc::now().timestamp();
        let mut jti = [0u8; 16];
        getrandom::fill(&mut jti).map_err(|e| anyhow::anyhow!("jti: {e}"))?;
        let claims = json!({
            "iss": issuer,
            "sub": issuer,
            "aud": audience,
            "iat": now,
            "exp": now + ASSERTION_LIFETIME_SECS,
            "jti": URL_SAFE_NO_PAD.encode(jti),
        });
        let header = Header {
            kid: Some(self.kid.clone()),
            ..Header::new(Algorithm::EdDSA)
        };
        jsonwebtoken::encode(&header, &claims, &self.encoding)
            .map_err(|e| anyhow::anyhow!("signing: {e}"))
    }
}

#[cfg(test)]
mod tests;
