// SPDX-License-Identifier: Apache-2.0
//! Protocol-independent symmetric operations selected by the host.

use alloc::{string::String, vec::Vec};

/// A refused cryptographic operation or unavailable backend resource.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Authenticated encryption did not complete.
    #[error("encryption failed: {0}")]
    Encryption(String),
    /// Authenticated decryption did not complete.
    #[error("decryption failed: {0}")]
    Decryption(String),
    /// Derivation parameters or execution were rejected.
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    /// A selected provider could not execute the operation.
    #[error("crypto provider error: {0}")]
    Provider(String),
    /// Secure randomness is unavailable; no replacement bytes are permitted.
    #[error("entropy source failed")]
    Entropy,
}

/// Symmetric/hash/KDF operations, independent of identity and key management.
///
/// The host selects the implementation. These operations neither select a
/// process-global provider nor authorize a protocol or compliance claim.
pub trait CryptoPrimitives: Send + Sync {
    /// Encrypts with the supplied AES-256-GCM key, unique nonce and AAD.
    fn aes_256_gcm_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Returns plaintext only after authenticating the ciphertext and AAD.
    fn aes_256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Computes HMAC-SHA256 with the supplied secret key.
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32];

    /// Derives at most 255 SHA-256 blocks, rejecting excessive length before allocation.
    fn hkdf_sha256(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Derives into nonempty caller storage, refusing zero iterations before mutation.
    fn pbkdf2_sha256(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// Computes SHA-256 over the supplied bytes.
    fn sha256(&self, data: &[u8]) -> [u8; 32];

    /// Fills bytes from the selected CSPRNG, returning failure without a fallback.
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), CryptoError>;

    /// Generates an AES-GCM nonce only after secure entropy succeeds.
    fn random_nonce(&self) -> Result<[u8; 12], CryptoError> {
        let mut nonce = [0; 12];
        self.random_bytes(&mut nonce)?;
        Ok(nonce)
    }

    /// Identifies the implementation for diagnostics, not authorization.
    fn provider_id(&self) -> &'static str;

    /// Reports the selected module build; deployment qualification is separate.
    fn is_fips(&self) -> bool;
}

#[cfg(any(feature = "primitives", feature = "aws-lc"))]
pub(crate) fn validate_hkdf_length(length: usize) -> Result<(), CryptoError> {
    // RFC 5869 section 2.3 limits L to 255 * HashLen before expansion.
    if length > 255 * 32 {
        return Err(CryptoError::KeyDerivation(
            "HKDF-SHA256 output exceeds 8160 bytes".into(),
        ));
    }
    Ok(())
}

#[cfg(any(feature = "primitives", feature = "aws-lc"))]
pub(crate) fn validate_pbkdf2_parameters(
    iterations: u32,
    length: usize,
) -> Result<(), CryptoError> {
    // RFC 8018 section 5.2 defines both c and dkLen as positive integers.
    if iterations == 0 || length == 0 {
        return Err(CryptoError::KeyDerivation(
            "PBKDF2 iteration count and output length must be positive".into(),
        ));
    }
    Ok(())
}

#[cfg(all(test, any(feature = "primitives", feature = "aws-lc")))]
mod tests;
