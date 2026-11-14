// SPDX-License-Identifier: AGPL-3.0-only
//! The key of an installation's site in the federation.
//!
//! In plain words: the site has one key of its own. The platform certifies
//! its public half when it enrolls the site; with the private half the site
//! signs what it states about itself (whom it admits). The key signs
//! nothing else: no certificate, no user's sign-in, no token.
//!
//! The private half is handled here only as bytes its installation keeps
//! sealed. Generating, reading and signing with it need no network and no
//! other party.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rand::TryRng;
use zeroize::Zeroizing;

/// Why a site key could not be made or read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SiteKeyError {
    /// The operating system gave no randomness.
    #[error("no randomness for a site key")]
    Randomness,
    /// The stored bytes are not a P-256 private key (PKCS#8).
    #[error("the stored site key is not a P-256 private key")]
    Malformed,
    /// The key could not be encoded.
    #[error("site key encoding: {0}")]
    Encoding(String),
}

/// A site's P-256 signing key.
pub struct SiteKey(SigningKey);

impl SiteKey {
    /// A new key from the operating system's randomness, as the bytes its
    /// installation seals (PKCS#8 DER).
    pub fn generate() -> Result<Zeroizing<Vec<u8>>, SiteKeyError> {
        // A uniform 32-byte value is a valid scalar except with negligible
        // probability; one that is not is drawn again.
        for _ in 0..8 {
            let mut scalar = Zeroizing::new([0u8; 32]);
            rand::rngs::SysRng
                .try_fill_bytes(scalar.as_mut_slice())
                .map_err(|_| SiteKeyError::Randomness)?;
            if let Ok(key) = SigningKey::from_slice(scalar.as_slice()) {
                return key
                    .to_pkcs8_der()
                    .map(|document| Zeroizing::new(document.as_bytes().to_vec()))
                    .map_err(|e| SiteKeyError::Encoding(e.to_string()));
            }
        }
        Err(SiteKeyError::Randomness)
    }

    /// The key the sealed bytes `pkcs8` hold.
    pub fn read(pkcs8: &[u8]) -> Result<Self, SiteKeyError> {
        SigningKey::from_pkcs8_der(pkcs8)
            .map(Self)
            .map_err(|_| SiteKeyError::Malformed)
    }

    /// The public half (DER `SubjectPublicKeyInfo`): what the platform
    /// certifies and what the site publishes under its domain.
    pub fn public_key(&self) -> Result<Vec<u8>, SiteKeyError> {
        self.0
            .verifying_key()
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|e| SiteKeyError::Encoding(e.to_string()))
    }

    /// The ES256 signature over `input`: 64 bytes `R || S` (RFC 7518 §3.4).
    pub fn sign(&self, input: &[u8]) -> [u8; 64] {
        let signature: Signature = self.0.sign(input);
        signature.to_bytes().into()
    }
}

#[cfg(test)]
mod tests;
