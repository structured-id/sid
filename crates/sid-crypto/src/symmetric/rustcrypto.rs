// SPDX-License-Identifier: Apache-2.0
//! Explicit RustCrypto symmetric adapter over the common operation contract.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use alloc::{format, string::ToString, vec, vec::Vec};
use getrandom::rand_core::TryCryptoRng;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{CryptoError, CryptoPrimitives};

/// Pure-Rust symmetric primitives, selected explicitly by the host.
#[derive(Debug, Default)]
pub struct RustCryptoPrimitives;

impl RustCryptoPrimitives {
    /// Creates a stateless adapter without selecting any global provider.
    pub const fn new() -> Self {
        Self
    }
}

fn fill_entropy(rng: &mut impl TryCryptoRng, bytes: &mut [u8]) -> Result<(), CryptoError> {
    rng.try_fill_bytes(bytes).map_err(|_| CryptoError::Entropy)
}

impl CryptoPrimitives for RustCryptoPrimitives {
    fn aes_256_gcm_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Aes256Gcm::new(key.into())
            .encrypt(
                &Nonce::from(*nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|error| CryptoError::Encryption(error.to_string()))
    }

    fn aes_256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Aes256Gcm::new(key.into())
            .decrypt(
                &Nonce::from(*nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|error| CryptoError::Decryption(error.to_string()))
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
            .expect("HMAC-SHA256 accepts every key length");
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
        crate::operations::validate_hkdf_length(output_len)?;
        let hkdf = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut output = vec![0; output_len];
        hkdf.expand(info, &mut output)
            .map_err(|error| CryptoError::KeyDerivation(error.to_string()))?;
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
        pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, iterations, output)
            .map_err(|error| CryptoError::KeyDerivation(format!("PBKDF2-SHA256: {error}")))
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    fn random_bytes(&self, bytes: &mut [u8]) -> Result<(), CryptoError> {
        fill_entropy(&mut getrandom::SysRng, bytes)
    }

    fn provider_id(&self) -> &'static str {
        "rustcrypto"
    }

    fn is_fips(&self) -> bool {
        false
    }
}
