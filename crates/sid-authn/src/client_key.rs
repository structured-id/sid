// SPDX-License-Identifier: AGPL-3.0-only
//! A client's signing key: what a confidential client authenticates with at
//! its issuer's token endpoint (`private_key_jwt`, RFC 7523 §2.2) and what a
//! relying party proves its registration with. The private half never leaves
//! the process; the issuer holds only the public half.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rand::TryRng;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Lifetime of an assertion or proof (RFC 7523 §3 item 4): long enough to
/// reach the token endpoint, far below the five minutes the issuer accepts.
pub const ASSERTION_LIFETIME_SECS: i64 = 60;

/// Why a key cannot be loaded or cannot sign.
#[derive(Debug, thiserror::Error)]
pub enum ClientKeyError {
    #[error("not a {algorithm} private key in PKCS#8 PEM: {reason}")]
    NotAKey {
        algorithm: &'static str,
        reason: String,
    },
    #[error("unsupported signing algorithm {0}")]
    Unsupported(String),
    #[error("signing: {0}")]
    Signing(#[from] jsonwebtoken::errors::Error),
}

/// A client's signing key.
pub struct ClientKey {
    encoding: EncodingKey,
    algorithm: Algorithm,
    /// The JWS `kid` of every JWT it signs; absent for a client that
    /// registered a single key and names none.
    kid: Option<String>,
    /// The public JWK the issuer registers, when this process derives it.
    public: Option<Value>,
}

impl std::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKey")
            .field("algorithm", &self.algorithm)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl ClientKey {
    /// The Ed25519 key a PEM-encoded PKCS#8 private key (RFC 8410) holds,
    /// named by the RFC 7638 thumbprint of its public half, which is also
    /// the `kid` of the public JWK the issuer registers.
    pub fn ed25519_from_pem(pem: &SecretString) -> Result<Self, ClientKeyError> {
        let not_a_key = |reason: String| ClientKeyError::NotAKey {
            algorithm: "Ed25519",
            reason,
        };
        let text = pem.expose_secret();
        let signing = ed25519_dalek::SigningKey::from_pkcs8_pem(text)
            .map_err(|e| not_a_key(e.to_string()))?;
        let encoding =
            EncodingKey::from_ed_pem(text.as_bytes()).map_err(|e| not_a_key(e.to_string()))?;
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
            algorithm: Algorithm::EdDSA,
            kid: Some(kid),
            public: Some(public),
        })
    }

    /// A new random Ed25519 key and its PKCS#8 PEM encoding.
    pub fn generate_ed25519() -> Result<(Self, SecretString), ClientKeyError> {
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        rand::rngs::SysRng
            .try_fill_bytes(seed.as_mut())
            .expect("the operating system random source is available");
        let pem = ed25519_dalek::SigningKey::from_bytes(&seed)
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| ClientKeyError::NotAKey {
                algorithm: "Ed25519",
                reason: e.to_string(),
            })?;
        let pem = SecretString::from(pem.as_str());
        Ok((Self::ed25519_from_pem(&pem)?, pem))
    }

    /// The key a PKCS#8 PEM private key of the JWS `algorithm` (`EdDSA`,
    /// `ES256` or `RS256`) holds, sending `kid` when the client registered
    /// several keys.
    pub fn from_pem(
        pem: &SecretString,
        algorithm: &str,
        kid: Option<String>,
    ) -> Result<Self, ClientKeyError> {
        let bytes = pem.expose_secret().as_bytes();
        let (encoding, algorithm, name) = match algorithm {
            "EdDSA" => (EncodingKey::from_ed_pem(bytes), Algorithm::EdDSA, "EdDSA"),
            "ES256" => (EncodingKey::from_ec_pem(bytes), Algorithm::ES256, "ES256"),
            "RS256" => (EncodingKey::from_rsa_pem(bytes), Algorithm::RS256, "RS256"),
            other => return Err(ClientKeyError::Unsupported(other.to_owned())),
        };
        let encoding = encoding.map_err(|e| ClientKeyError::NotAKey {
            algorithm: name,
            reason: e.to_string(),
        })?;
        Ok(Self {
            encoding,
            algorithm,
            kid,
            public: None,
        })
    }

    /// The key's id, when it sends one.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The public JWK Set the issuer registers for this key (RFC 7517 §5),
    /// when this process derived its public half.
    pub fn public_jwks(&self) -> Option<Value> {
        self.public
            .as_ref()
            .map(|public| json!({ "keys": [public.clone()] }))
    }

    /// A JWT this key signs with `iss` and `sub` both `issuer` for
    /// `audience`, expiring within [`ASSERTION_LIFETIME_SECS`] and naming a
    /// fresh random `jti`: an RFC 7523 §3 client assertion when `issuer` is
    /// the client id, a registration proof when it is the key's own id.
    pub fn sign(&self, issuer: &str, audience: &str) -> Result<String, ClientKeyError> {
        let now = chrono::Utc::now().timestamp();
        let mut jti = [0u8; 16];
        rand::rngs::SysRng
            .try_fill_bytes(&mut jti)
            .expect("the operating system random source is available");
        let claims = json!({
            "iss": issuer,
            "sub": issuer,
            "aud": audience,
            "iat": now,
            "exp": now + ASSERTION_LIFETIME_SECS,
            "jti": URL_SAFE_NO_PAD.encode(jti),
        });
        let header = Header {
            kid: self.kid.clone(),
            ..Header::new(self.algorithm)
        };
        Ok(jsonwebtoken::encode(&header, &claims, &self.encoding)?)
    }
}

#[cfg(test)]
mod tests;
