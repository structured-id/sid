// SPDX-License-Identifier: AGPL-3.0-only
//! Recovery key derivation and data_key encryption/decryption.
//!
//! Flow: BIP-39 mnemonic → PBKDF2(600K) → HKDF → AES-256-GCM key
//! Used to encrypt/decrypt data_key backup for password reset recovery.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const PBKDF2_ITERATIONS: u32 = 600_000;
const PBKDF2_SALT: &[u8] = b"sid-recovery-v1";
const HKDF_INFO: &[u8] = b"data-key-wrap";
const NONCE_SIZE: usize = 12;

/// Errors from recovery key operations.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryKeyError {
    #[error("PBKDF2 derivation failed")]
    Pbkdf2Failed,
    #[error("HKDF expansion failed")]
    HkdfFailed,
    #[error("AES-GCM encryption failed")]
    EncryptFailed,
    #[error("AES-GCM decryption failed (wrong key or corrupted data)")]
    DecryptFailed,
    #[error("encrypted backup too short (missing nonce)")]
    BackupTooShort,
}

/// Derive a 256-bit recovery key from a BIP-39 mnemonic string.
///
/// Steps: mnemonic → PBKDF2(600K, SHA-256) → HKDF-SHA256 → 32-byte key
pub fn derive_recovery_key(mnemonic: &str) -> Result<[u8; 32], RecoveryKeyError> {
    // Step 1: PBKDF2 — slow KDF (600K iterations, ~1s)
    let mut seed = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        mnemonic.as_bytes(),
        PBKDF2_SALT,
        PBKDF2_ITERATIONS,
        &mut seed,
    )
    .map_err(|_| RecoveryKeyError::Pbkdf2Failed)?;

    // Step 2: HKDF — domain-separate the key
    let hkdf = Hkdf::<Sha256>::new(None, &seed);
    let mut recovery_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut recovery_key)
        .map_err(|_| RecoveryKeyError::HkdfFailed)?;

    seed.zeroize();
    Ok(recovery_key)
}

/// Compute SHA-256(seed) for server-side verification.
///
/// The server stores this hash to verify the user's mnemonic during recovery
/// WITHOUT storing the seed itself.
pub fn compute_seed_hash(mnemonic: &str) -> Result<[u8; 32], RecoveryKeyError> {
    let mut seed = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        mnemonic.as_bytes(),
        PBKDF2_SALT,
        PBKDF2_ITERATIONS,
        &mut seed,
    )
    .map_err(|_| RecoveryKeyError::Pbkdf2Failed)?;

    let hash = Sha256::digest(seed);
    seed.zeroize();
    Ok(hash.into())
}

/// Encrypt data_key with recovery key (AES-256-GCM).
///
/// Returns: nonce (12 bytes) || ciphertext+tag
pub fn encrypt_data_key(
    recovery_key: &[u8; 32],
    data_key: &[u8],
) -> Result<Vec<u8>, RecoveryKeyError> {
    let cipher =
        Aes256Gcm::new_from_slice(recovery_key).map_err(|_| RecoveryKeyError::EncryptFailed)?;

    // Random nonce (12 bytes)
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, data_key)
        .map_err(|_| RecoveryKeyError::EncryptFailed)?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data_key with recovery key (AES-256-GCM).
///
/// Input: nonce (12 bytes) || ciphertext+tag (from encrypt_data_key)
pub fn decrypt_data_key(
    recovery_key: &[u8; 32],
    encrypted: &[u8],
) -> Result<Vec<u8>, RecoveryKeyError> {
    if encrypted.len() < NONCE_SIZE + 16 {
        // 16 = AES-GCM tag size
        return Err(RecoveryKeyError::BackupTooShort);
    }

    let cipher =
        Aes256Gcm::new_from_slice(recovery_key).map_err(|_| RecoveryKeyError::DecryptFailed)?;

    // Length is checked above, so the conversion cannot fail.
    let nonce =
        Nonce::try_from(&encrypted[..NONCE_SIZE]).map_err(|_| RecoveryKeyError::DecryptFailed)?;
    let ciphertext = &encrypted[NONCE_SIZE..];

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| RecoveryKeyError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_deterministic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let key1 = derive_recovery_key(mnemonic).unwrap();
        let key2 = derive_recovery_key(mnemonic).unwrap();
        assert_eq!(key1, key2);
        assert_ne!(key1, [0u8; 32]); // not all zeros
    }

    #[test]
    fn different_mnemonics_different_keys() {
        let k1 = derive_recovery_key("word1 word2 word3").unwrap();
        let k2 = derive_recovery_key("word4 word5 word6").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_recovery_key("test mnemonic phrase").unwrap();
        let data_key = b"this-is-a-32-byte-data-key-1234";

        let encrypted = encrypt_data_key(&key, data_key).unwrap();
        assert_ne!(encrypted.as_slice(), data_key.as_slice());
        assert!(encrypted.len() > data_key.len()); // nonce + tag overhead

        let decrypted = decrypt_data_key(&key, &encrypted).unwrap();
        assert_eq!(decrypted, data_key);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let key1 = derive_recovery_key("correct phrase").unwrap();
        let key2 = derive_recovery_key("wrong phrase").unwrap();
        let data_key = b"secret-data-key";

        let encrypted = encrypt_data_key(&key1, data_key).unwrap();
        let result = decrypt_data_key(&key2, &encrypted);
        assert!(matches!(result, Err(RecoveryKeyError::DecryptFailed)));
    }

    #[test]
    fn corrupted_ciphertext_fails_decrypt() {
        let key = derive_recovery_key("test phrase").unwrap();
        let data_key = b"my-data-key";

        let mut encrypted = encrypt_data_key(&key, data_key).unwrap();
        // Flip a bit in the ciphertext (after nonce)
        encrypted[NONCE_SIZE + 2] ^= 0x01;
        let result = decrypt_data_key(&key, &encrypted);
        assert!(matches!(result, Err(RecoveryKeyError::DecryptFailed)));
    }

    #[test]
    fn too_short_backup_fails() {
        let key = [0u8; 32];
        let result = decrypt_data_key(&key, &[0u8; 10]);
        assert!(matches!(result, Err(RecoveryKeyError::BackupTooShort)));
    }

    #[test]
    fn seed_hash_deterministic() {
        let mnemonic = "test recovery mnemonic";
        let h1 = compute_seed_hash(mnemonic).unwrap();
        let h2 = compute_seed_hash(mnemonic).unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn seed_hash_differs_from_key() {
        let mnemonic = "test recovery mnemonic";
        let key = derive_recovery_key(mnemonic).unwrap();
        let hash = compute_seed_hash(mnemonic).unwrap();
        assert_ne!(key, hash);
    }

    #[test]
    fn encrypt_32_byte_aes_key() {
        // Real-world: encrypt a 32-byte AES-256 data_key
        let recovery_key = derive_recovery_key("real world mnemonic test").unwrap();
        let data_key: Vec<u8> = (0..32).collect();

        let encrypted = encrypt_data_key(&recovery_key, &data_key).unwrap();
        // nonce (12) + ciphertext (32) + tag (16) = 60 bytes
        assert_eq!(encrypted.len(), 12 + 32 + 16);

        let decrypted = decrypt_data_key(&recovery_key, &encrypted).unwrap();
        assert_eq!(decrypted, data_key);
    }
}
