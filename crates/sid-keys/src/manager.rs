// SPDX-License-Identifier: Apache-2.0
//! Versioned keys over a host-supplied master secret.
//!
//! The application holds the master secret; this crate never reads a file, an
//! environment variable or a vault of its own. Each key version is derived from
//! that secret with HKDF-SHA256 over parameters that are not secret and are
//! stored with the data, so any process holding the same master reconstructs
//! every retained version and can decrypt what earlier processes wrote.
//!
//! Rotation is lazy: a field encrypted under an older version still decrypts,
//! and the caller re-encrypts it with [`KeyManager::rotate`] when it next reads
//! it, so no batch job walks the database.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::crypto::CryptoPrimitives;
use crate::field::EncryptedField;

/// Errors from key management operations.
#[derive(Debug, Error)]
pub enum KeyManagerError {
    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("key not found for version {0}")]
    KeyNotFound(u32),

    #[error("key manager not initialized")]
    NotInitialized,

    #[error("invalid key versions: {0}")]
    InvalidVersions(String),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("key manager error: {0}")]
    Other(String),
}

pub type KeyManagerResult<T> = Result<T, KeyManagerError>;

/// How a key version is derived from the master secret.
///
/// Stored with the parameters rather than assumed, so that a version written by
/// an older build is re-derived the way it was written, and a future algorithm
/// cannot silently reinterpret an existing salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyDerivation {
    /// HKDF-SHA256 with the stored salt and context as `info`.
    HkdfSha256,
}

/// Non-secret parameters of one key version.
///
/// These are stored alongside the encrypted data: losing them makes the version
/// unrecoverable even with the master secret, which is why a version number
/// alone is not enough to restore a deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVersionParams {
    /// Version number, as recorded in every field this key encrypts.
    pub version: u32,
    /// Random salt for the derivation. Not secret.
    pub salt: Vec<u8>,
    /// Derivation algorithm.
    pub algorithm: KeyDerivation,
    /// Derivation context, used as HKDF `info` (for example `"key-v2"`).
    pub context: String,
}

impl KeyVersionParams {
    /// Parameters for one version, derived with HKDF-SHA256.
    pub fn new(version: u32, salt: Vec<u8>, context: impl Into<String>) -> Self {
        Self {
            version,
            salt,
            algorithm: KeyDerivation::HkdfSha256,
            context: context.into(),
        }
    }
}

/// Encrypts and decrypts stored fields under a versioned key.
///
/// Context binding prevents ciphertext swap attacks between records: the
/// context is the AAD, so a ciphertext moved to another record fails to
/// decrypt rather than yielding another record's secret.
#[async_trait]
pub trait KeyManager: Send + Sync {
    /// Encrypt a plaintext value with context binding.
    ///
    /// Context should uniquely identify the field and record, e.g. "totp:{profile_id}".
    async fn encrypt(&self, plaintext: &[u8], context: &str) -> KeyManagerResult<EncryptedField>;

    /// Decrypt a previously encrypted field.
    ///
    /// Uses the key version recorded in the field to find the correct key.
    async fn decrypt(&self, field: &EncryptedField) -> KeyManagerResult<Vec<u8>>;

    /// Re-encrypt a field with the current key version.
    ///
    /// Called during lazy rotation: if `field.key_version < current_key_version()`,
    /// the caller should call `rotate()` and persist the result.
    async fn rotate(&self, field: &EncryptedField) -> KeyManagerResult<EncryptedField> {
        let plaintext = self.decrypt(field).await?;
        self.encrypt(&plaintext, &field.context).await
    }

    /// Current key version. Fields encrypted with older versions need rotation.
    fn current_key_version(&self) -> u32;

    /// Whether a field was encrypted with an older key version.
    fn needs_rotation(&self, field: &EncryptedField) -> bool {
        field.key_version < self.current_key_version()
    }
}

/// Key manager for software-held keys.
///
/// Every version is derived from the master secret the host supplies, so the
/// manager holds no key material the host did not give it and reads nothing
/// from disk. It protects a database dump taken without the master secret; it
/// does not protect a compromised process, where the derived keys are in
/// memory by necessity.
pub struct SoftwareKeyManager {
    /// Derived keys by version. Each is zeroed on drop and prints `[REDACTED]`.
    keys: BTreeMap<u32, SecretBox<[u8; 32]>>,
    /// Highest version present: the one new encryptions use.
    current: u32,
    /// Cryptographic backend.
    crypto: Arc<dyn CryptoPrimitives>,
}

impl SoftwareKeyManager {
    /// Derive every version from the master secret.
    ///
    /// The master is used here and not retained: after construction the manager
    /// holds only the derived keys, so the secret with the longest life has the
    /// shortest residence in this process.
    pub fn new(
        master: SecretBox<[u8; 32]>,
        versions: Vec<KeyVersionParams>,
        crypto: Arc<dyn CryptoPrimitives>,
    ) -> KeyManagerResult<Self> {
        if versions.is_empty() {
            return Err(KeyManagerError::NotInitialized);
        }

        let mut keys = BTreeMap::new();
        for params in &versions {
            if params.version == 0 {
                return Err(KeyManagerError::InvalidVersions(
                    "version 0 is not a version: numbering starts at 1".into(),
                ));
            }
            if keys.contains_key(&params.version) {
                return Err(KeyManagerError::InvalidVersions(format!(
                    "version {} appears twice",
                    params.version
                )));
            }

            let KeyDerivation::HkdfSha256 = params.algorithm;
            let mut derived = crypto
                .hkdf_sha256(
                    master.expose_secret(),
                    &params.salt,
                    params.context.as_bytes(),
                    32,
                )
                .map_err(|e| KeyManagerError::KeyDerivation(e.to_string()))?;

            let mut key = [0u8; 32];
            key.copy_from_slice(&derived);
            derived.zeroize();
            keys.insert(params.version, SecretBox::new(Box::new(key)));
        }

        let current = *keys
            .keys()
            .next_back()
            .expect("versions is non-empty, checked above");

        Ok(Self {
            keys,
            current,
            crypto,
        })
    }

    /// Key for a specific version.
    fn get_key(&self, version: u32) -> KeyManagerResult<&[u8; 32]> {
        self.keys
            .get(&version)
            .map(|k| k.expose_secret())
            .ok_or(KeyManagerError::KeyNotFound(version))
    }

    /// Versions this manager can decrypt, ascending.
    pub fn known_versions(&self) -> Vec<u32> {
        self.keys.keys().copied().collect()
    }
}

#[async_trait]
impl KeyManager for SoftwareKeyManager {
    async fn encrypt(&self, plaintext: &[u8], context: &str) -> KeyManagerResult<EncryptedField> {
        let version = self.current;
        let key = self.get_key(version)?;
        let nonce = self.crypto.random_nonce();

        let ciphertext = self
            .crypto
            .aes_256_gcm_encrypt(key, &nonce, plaintext, context.as_bytes())
            .map_err(|e| KeyManagerError::Encryption(e.to_string()))?;

        Ok(EncryptedField {
            ciphertext,
            nonce,
            key_version: version,
            context: context.to_string(),
        })
    }

    async fn decrypt(&self, field: &EncryptedField) -> KeyManagerResult<Vec<u8>> {
        let key = self.get_key(field.key_version)?;

        self.crypto
            .aes_256_gcm_decrypt(
                key,
                &field.nonce,
                &field.ciphertext,
                field.context.as_bytes(),
            )
            .map_err(|e| KeyManagerError::Decryption(e.to_string()))
    }

    fn current_key_version(&self) -> u32 {
        self.current
    }
}

#[cfg(test)]
mod tests;
