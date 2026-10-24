// SPDX-License-Identifier: Apache-2.0
//! aws-lc symmetric adapter; module qualification belongs to the deployment.

use alloc::{vec, vec::Vec};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::{digest, hmac};

use crate::{CryptoError, CryptoPrimitives};

/// Host-selected aws-lc primitives, with an explicit optional FIPS module build.
#[derive(Debug, Default)]
pub struct AwsLcPrimitives;

impl AwsLcPrimitives {
    /// Creates a stateless adapter without selecting any global provider.
    pub const fn new() -> Self {
        Self
    }
}

impl CryptoPrimitives for AwsLcPrimitives {
    fn aes_256_gcm_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| CryptoError::Encryption("AES-256-GCM key rejected".into()))?;
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| CryptoError::Encryption("AES-GCM nonce rejected".into()))?;
        let mut output = plaintext.to_vec();
        LessSafeKey::new(key)
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut output)
            .map_err(|_| CryptoError::Encryption("AES-GCM authentication failed".into()))?;
        Ok(output)
    }

    fn aes_256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| CryptoError::Decryption("AES-256-GCM key rejected".into()))?;
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| CryptoError::Decryption("AES-GCM nonce rejected".into()))?;
        let mut output = ciphertext.to_vec();
        let length = LessSafeKey::new(key)
            .open_in_place(nonce, Aad::from(aad), &mut output)
            .map_err(|_| CryptoError::Decryption("AES-GCM authentication failed".into()))?
            .len();
        output.truncate(length);
        Ok(output)
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data);
        let mut output = [0; 32];
        output.copy_from_slice(tag.as_ref());
        output
    }

    fn hkdf_sha256(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        crate::operations::validate_hkdf_length(output_len)?;
        let salt = aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA256, salt);
        let extracted = salt.extract(ikm);
        let parts = [info];
        let expanded = extracted
            .expand(&parts, HkdfLength(output_len))
            .map_err(|_| CryptoError::KeyDerivation("HKDF expansion rejected".into()))?;
        let mut output = vec![0; output_len];
        expanded
            .fill(&mut output)
            .map_err(|_| CryptoError::KeyDerivation("HKDF output rejected".into()))?;
        Ok(output)
    }

    fn pbkdf2_sha256(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        crate::operations::validate_pbkdf2_parameters(iterations, output.len())?;
        let iterations = core::num::NonZeroU32::new(iterations)
            .expect("validated PBKDF2 iterations are nonzero");
        aws_lc_rs::pbkdf2::derive(
            aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            salt,
            password,
            output,
        );
        Ok(())
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let digest = digest::digest(&digest::SHA256, data);
        let mut output = [0; 32];
        output.copy_from_slice(digest.as_ref());
        output
    }

    fn random_bytes(&self, bytes: &mut [u8]) -> Result<(), CryptoError> {
        aws_lc_rs::rand::fill(bytes).map_err(|_| CryptoError::Entropy)
    }

    fn provider_id(&self) -> &'static str {
        "aws-lc-rs"
    }

    fn is_fips(&self) -> bool {
        cfg!(feature = "fips")
    }
}

struct HkdfLength(usize);

impl aws_lc_rs::hkdf::KeyType for HkdfLength {
    fn len(&self) -> usize {
        self.0
    }
}
