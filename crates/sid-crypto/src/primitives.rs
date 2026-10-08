// SPDX-License-Identifier: AGPL-3.0-only
//! Cryptographic primitives backed by aws-lc-rs.
//!
//! The pure-Rust implementation and the trait itself live in `sid-keys`, which
//! carries no dependency on this crate or any other part of the engine. What
//! remains here is the hardware-accelerated backend and its verification
//! against the pure-Rust one.

// ── aws-lc-rs backend (BoringSSL) ──

#[cfg(feature = "aws-lc")]
mod aws_lc_impl {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    use aws_lc_rs::digest;
    use aws_lc_rs::hmac;

    use sid_keys::{CryptoError, CryptoPrimitives};

    /// Cryptographic primitives backed by aws-lc-rs (BoringSSL fork).
    ///
    /// Uses AES-NI / SHA-NI / ARM crypto hardware instructions for
    /// significantly higher throughput than pure-Rust implementations.
    ///
    /// When compiled with `fips` feature, uses the FIPS 140-3 validated
    /// aws-lc module with startup self-tests.
    pub struct AwsLcPrimitives;

    impl AwsLcPrimitives {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for AwsLcPrimitives {
        fn default() -> Self {
            Self::new()
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
            let unbound_key = UnboundKey::new(&AES_256_GCM, key)
                .map_err(|_| CryptoError::Encryption("failed to create AES-256-GCM key".into()))?;
            let sealing_key = LessSafeKey::new(unbound_key);
            let aead_nonce = Nonce::try_assume_unique_for_key(nonce)
                .map_err(|_| CryptoError::Encryption("invalid nonce".into()))?;

            let mut in_out = plaintext.to_vec();
            sealing_key
                .seal_in_place_append_tag(aead_nonce, Aad::from(aad), &mut in_out)
                .map_err(|_| CryptoError::Encryption("AES-256-GCM seal failed".into()))?;

            Ok(in_out)
        }

        fn aes_256_gcm_decrypt(
            &self,
            key: &[u8; 32],
            nonce: &[u8; 12],
            ciphertext: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            let unbound_key = UnboundKey::new(&AES_256_GCM, key)
                .map_err(|_| CryptoError::Decryption("failed to create AES-256-GCM key".into()))?;
            let opening_key = LessSafeKey::new(unbound_key);
            let aead_nonce = Nonce::try_assume_unique_for_key(nonce)
                .map_err(|_| CryptoError::Decryption("invalid nonce".into()))?;

            let mut in_out = ciphertext.to_vec();
            let plaintext = opening_key
                .open_in_place(aead_nonce, Aad::from(aad), &mut in_out)
                .map_err(|_| CryptoError::Decryption("AES-256-GCM open failed".into()))?;

            Ok(plaintext.to_vec())
        }

        fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
            let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
            let tag = hmac::sign(&signing_key, data);
            let mut result = [0u8; 32];
            result.copy_from_slice(tag.as_ref());
            result
        }

        fn hkdf_sha256(
            &self,
            ikm: &[u8],
            salt: &[u8],
            info: &[u8],
            output_len: usize,
        ) -> Result<Vec<u8>, CryptoError> {
            use aws_lc_rs::hkdf;

            let hkdf_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
            let prk = hkdf_salt.extract(ikm);

            let info_refs = [info];
            let okm = prk
                .expand(&info_refs, HkdfOutputLen(output_len))
                .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;

            let mut output = vec![0u8; output_len];
            okm.fill(&mut output)
                .map_err(|_| CryptoError::KeyDerivation("HKDF fill failed".into()))?;

            Ok(output)
        }

        fn pbkdf2_sha256(
            &self,
            password: &[u8],
            salt: &[u8],
            iterations: u32,
            output: &mut [u8],
        ) -> Result<(), CryptoError> {
            use std::num::NonZeroU32;
            let iters = NonZeroU32::new(iterations)
                .ok_or_else(|| CryptoError::KeyDerivation("iterations must be > 0".into()))?;
            aws_lc_rs::pbkdf2::derive(
                aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
                iters,
                salt,
                password,
                output,
            );
            Ok(())
        }

        fn sha256(&self, data: &[u8]) -> [u8; 32] {
            let hash = digest::digest(&digest::SHA256, data);
            let mut result = [0u8; 32];
            result.copy_from_slice(hash.as_ref());
            result
        }

        fn random_bytes(&self, buf: &mut [u8]) {
            aws_lc_rs::rand::fill(buf).expect("system random should not fail");
        }

        fn provider_id(&self) -> &'static str {
            "aws-lc-rs"
        }

        fn is_fips(&self) -> bool {
            cfg!(feature = "fips")
        }
    }

    /// Helper type for aws-lc-rs HKDF output length specification.
    struct HkdfOutputLen(usize);

    impl aws_lc_rs::hkdf::KeyType for HkdfOutputLen {
        fn len(&self) -> usize {
            self.0
        }
    }
}

#[cfg(feature = "aws-lc")]
pub use aws_lc_impl::AwsLcPrimitives;

#[cfg(all(test, feature = "aws-lc"))]
mod tests;
