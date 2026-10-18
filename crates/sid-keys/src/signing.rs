// SPDX-License-Identifier: Apache-2.0
//! Asymmetric signing for certificate issuance.
//!
//! An issuer signs through [`CaSigner`], which is bound to one key generation
//! and one complete signature algorithm. The caller passes the exact bytes to
//! sign, for X.509 the DER `TBSCertificate` (RFC 5280 §4.1.1.3), and the signer
//! hashes them as its algorithm specifies: there is no prehashed entry point,
//! so nothing is hashed twice. A signer that cannot sign with its key refuses;
//! it never falls back to another key or algorithm.
//!
//! [`SoftwareP256Signer`] is the pure-Rust implementation: ECDSA P-256 with
//! SHA-256, its key held as PKCS#8 by the caller's custody. A signer backed by
//! hardware or an external service implements the same trait elsewhere and
//! exposes only its public key.

use async_trait::async_trait;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use p256::pkcs8::der::{Decode, asn1::ObjectIdentifier};
use p256::pkcs8::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use secrecy::{ExposeSecret, SecretBox};
use thiserror::Error;
use uuid::Uuid;

/// `ecdsa-with-SHA256` (RFC 5758 §3.2).
pub const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// One issuing key generation: the key a signer is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningKeyId(pub Uuid);

/// Why a signing operation was refused.
#[derive(Debug, Error)]
pub enum SigningError {
    /// The key material is not a key of this signer's algorithm.
    #[error("invalid signing key: {0}")]
    InvalidKey(String),

    /// The key exists but cannot be used now (custody unavailable).
    #[error("signing key {0:?} is unavailable")]
    Unavailable(SigningKeyId),

    /// The provider failed to produce a signature.
    #[error("signing provider error: {0}")]
    Provider(String),
}

/// A signer bound to one key generation and one signature algorithm.
#[async_trait]
pub trait CaSigner: Send + Sync {
    /// The key generation every signature of this signer is made with.
    fn key_id(&self) -> SigningKeyId;

    /// The complete signature `AlgorithmIdentifier`, as the `signature` and
    /// `signatureAlgorithm` fields of a certificate carry it (RFC 5280 §4.1.1.2).
    fn signature_algorithm(&self) -> &AlgorithmIdentifierOwned;

    /// The public key of the signing key.
    fn public_key(&self) -> &SubjectPublicKeyInfoOwned;

    /// Signs `message`, the exact bytes to be signed, and returns the
    /// algorithm's encoded signature value.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError>;
}

/// ECDSA P-256 with SHA-256, the key in this process.
///
/// Signatures are deterministic (RFC 6979) and DER-encoded `(r, s)`, as X.509
/// requires (RFC 5758 §3.2), not the fixed-width form of JOSE.
pub struct SoftwareP256Signer {
    key_id: SigningKeyId,
    key: SigningKey,
    algorithm: AlgorithmIdentifierOwned,
    public_key: SubjectPublicKeyInfoOwned,
}

impl SoftwareP256Signer {
    /// A new random key for `key_id`, with its PKCS#8 encoding for the
    /// caller's custody.
    pub fn generate(key_id: SigningKeyId) -> Result<(Self, SecretBox<Vec<u8>>), SigningError> {
        let key = SigningKey::try_generate_from_rng(&mut rand::rngs::SysRng)
            .map_err(|e| SigningError::Provider(format!("random source: {e}")))?;
        let pkcs8 = key
            .to_pkcs8_der()
            .map_err(|e| SigningError::Provider(format!("PKCS#8 encoding: {e}")))?;
        let pkcs8 = SecretBox::new(Box::new(pkcs8.as_bytes().to_vec()));
        Ok((Self::with_key(key_id, key)?, pkcs8))
    }

    /// The signer of `key_id` over the PKCS#8 key its custody holds.
    pub fn from_pkcs8(
        key_id: SigningKeyId,
        pkcs8: &SecretBox<Vec<u8>>,
    ) -> Result<Self, SigningError> {
        let key = SigningKey::from_pkcs8_der(pkcs8.expose_secret())
            .map_err(|e| SigningError::InvalidKey(e.to_string()))?;
        Self::with_key(key_id, key)
    }

    fn with_key(key_id: SigningKeyId, key: SigningKey) -> Result<Self, SigningError> {
        let document = key
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| SigningError::Provider(format!("public key encoding: {e}")))?;
        let public_key = SubjectPublicKeyInfoOwned::from_der(document.as_bytes())
            .map_err(|e| SigningError::Provider(format!("public key encoding: {e}")))?;
        Ok(Self {
            key_id,
            key,
            // RFC 5758 §3.2: the parameters field is absent.
            algorithm: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256,
                parameters: None,
            },
            public_key,
        })
    }
}

#[async_trait]
impl CaSigner for SoftwareP256Signer {
    fn key_id(&self) -> SigningKeyId {
        self.key_id
    }

    fn signature_algorithm(&self) -> &AlgorithmIdentifierOwned {
        &self.algorithm
    }

    fn public_key(&self) -> &SubjectPublicKeyInfoOwned {
        &self.public_key
    }

    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError> {
        let signature: Signature = self
            .key
            .try_sign(message)
            .map_err(|e| SigningError::Provider(e.to_string()))?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests;
