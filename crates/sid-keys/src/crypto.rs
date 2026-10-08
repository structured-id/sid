// SPDX-License-Identifier: Apache-2.0
//! Low-level cryptographic primitives behind one trait.
//!
//! The trait is what a deployment swaps: CE links [`RustCryptoPrimitives`]
//! (pure Rust), regulated deployments link an implementation backed by a
//! validated module or an HSM. Everything above it, key derivation and field
//! encryption included, is written once against the trait.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors from low-level cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("crypto provider error: {0}")]
    Provider(String),
}

/// Low-level cryptographic primitives.
///
/// Abstracts symmetric cryptography, hashing, and key derivation. Used by
/// [`crate::SoftwareKeyManager`], blind index computation, token signing,
/// and other non-OPAQUE crypto operations.
///
/// Implementations:
/// - CE: [`RustCryptoPrimitives`] (`aes-gcm`, `sha2`, `hmac`, `hkdf`)
/// - EE/SaaS: `AwsLcPrimitives` (`aws-lc-rs`, FIPS 140-3 validated)
/// - EE regulated: `Pkcs11Primitives` (PKCS#11 HSM, keys never leave hardware)
pub trait CryptoPrimitives: Send + Sync {
    /// AES-256-GCM authenticated encryption.
    fn aes_256_gcm_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// AES-256-GCM authenticated decryption.
    fn aes_256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// HMAC-SHA256.
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32];

    /// HKDF-SHA256 key derivation.
    fn hkdf_sha256(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, CryptoError>;

    /// PBKDF2-HMAC-SHA256 key derivation from password.
    ///
    /// Used for passphrase-based key derivation (e.g., backup encryption).
    /// NOT for password hashing (use Argon2/OPAQUE for that).
    fn pbkdf2_sha256(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// SHA-256 hash.
    fn sha256(&self, data: &[u8]) -> [u8; 32];

    /// Cryptographically secure random bytes.
    fn random_bytes(&self, buf: &mut [u8]);

    /// Generate a random 12-byte AES-GCM nonce.
    fn random_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        self.random_bytes(&mut nonce);
        nonce
    }

    /// Provider identifier for audit/compliance logging.
    fn provider_id(&self) -> &'static str;

    /// Whether this provider is backed by a FIPS-validated module.
    fn is_fips(&self) -> bool;
}

/// Cryptographic primitives backed by the RustCrypto crates.
///
/// Pure Rust, no C dependencies, not FIPS-validated. Fast and suitable for
/// every deployment that is not subject to a validation requirement.
pub struct RustCryptoPrimitives;

impl RustCryptoPrimitives {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RustCryptoPrimitives {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoPrimitives for RustCryptoPrimitives {
    fn aes_256_gcm_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new(key.into());
        let gcm_nonce = Nonce::from(*nonce);
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };
        cipher
            .encrypt(&gcm_nonce, payload)
            .map_err(|e| CryptoError::Encryption(e.to_string()))
    }

    fn aes_256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new(key.into());
        let gcm_nonce = Nonce::from(*nonce);
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad,
        };
        cipher
            .decrypt(&gcm_nonce, payload)
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    fn hkdf_sha256(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut okm = vec![0u8; output_len];
        hk.expand(info, &mut okm)
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
        Ok(okm)
    }

    fn pbkdf2_sha256(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, iterations, output)
            .map_err(|e| CryptoError::KeyDerivation(format!("PBKDF2-SHA256: {e}")))
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn random_bytes(&self, buf: &mut [u8]) {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(buf);
    }

    fn provider_id(&self) -> &'static str {
        "rustcrypto"
    }

    fn is_fips(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
