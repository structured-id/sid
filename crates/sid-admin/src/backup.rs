// SPDX-License-Identifier: AGPL-3.0-only
//! Backup & Restore for StructuredID CE.
//!
//! Coordinated snapshots: database + key material + configuration.
//! AES-256-GCM encrypted archive with integrity verification.
//!
//! Supports full backup and GDPR profile export.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sid_crypto::CryptoPrimitives;
use std::collections::HashMap;
use uuid::Uuid;

/// Unique backup identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BackupId(pub String);

impl BackupId {
    pub fn new() -> Self {
        Self(format!("bk-{}", Uuid::now_v7()))
    }
}

impl Default for BackupId {
    fn default() -> Self {
        Self::new()
    }
}

/// Backup type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupType {
    /// Full coordinated snapshot (all components).
    Full,
    /// Profile-scoped export (GDPR Art. 20).
    ProfileExport,
}

/// Backup status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupStatus {
    /// Backup in progress.
    InProgress,
    /// Completed and verified.
    Verified,
    /// Verification failed.
    Failed,
    /// Restored from this backup.
    Restored,
}

/// Components included in a backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BackupComponent {
    /// PostgreSQL database dump.
    Database,
    /// Cryptographic key material (encrypted).
    KeyStore,
    /// Configuration files (sid.yaml, policies).
    Configuration,
    /// Certificates (CA chain, CRL).
    Certificates,
}

/// Backup manifest — metadata about a backup archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Unique backup ID.
    pub id: BackupId,
    /// When the backup was created.
    pub created_at: DateTime<Utc>,
    /// Backup type.
    pub backup_type: BackupType,
    /// Current status.
    pub status: BackupStatus,
    /// Components included.
    pub components: Vec<BackupComponent>,
    /// SID version that created this backup.
    pub sid_version: String,
    /// SHA-256 checksums for each component file.
    pub checksums: HashMap<String, String>,
    /// Total uncompressed size in bytes.
    pub size_bytes: u64,
    /// Encryption algorithm used.
    pub encryption: EncryptionInfo,
}

/// Encryption metadata for the backup archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    /// Algorithm (always AES-256-GCM for CE).
    pub algorithm: String,
    /// Key derivation function.
    pub kdf: String,
    /// KDF iterations.
    pub kdf_iterations: u32,
    /// Salt (hex-encoded).
    pub salt: String,
    /// Nonce (hex-encoded).
    pub nonce: String,
}

impl EncryptionInfo {
    /// Default CE encryption parameters.
    pub fn aes256gcm(salt: &[u8], nonce: &[u8]) -> Self {
        Self {
            algorithm: "AES-256-GCM".to_string(),
            kdf: "PBKDF2-SHA256".to_string(),
            kdf_iterations: 600_000,
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
        }
    }
}

/// Backup creation request.
#[derive(Debug, Clone)]
pub struct CreateBackupRequest {
    /// Output file path.
    pub output_path: String,
    /// Backup type.
    pub backup_type: BackupType,
    /// Components to include (empty = all).
    pub components: Vec<BackupComponent>,
}

/// Backup restore request.
#[derive(Debug, Clone)]
pub struct RestoreBackupRequest {
    /// Path to the backup archive.
    pub backup_path: String,
    /// Explicit destructive confirmation.
    pub confirm_destructive: bool,
}

/// Backup verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Whether the backup is valid.
    pub valid: bool,
    /// Backup manifest (if readable).
    pub manifest: Option<BackupManifest>,
    /// Verification errors.
    pub errors: Vec<String>,
    /// Component-level verification.
    pub component_checks: Vec<ComponentCheck>,
}

/// Per-component verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentCheck {
    pub component: BackupComponent,
    pub checksum_valid: bool,
    pub size_bytes: u64,
}

/// Backup errors.
#[derive(Debug, Clone)]
pub enum BackupError {
    /// Backup already in progress (advisory lock held).
    ConcurrentBackup,
    /// Output path is not writable.
    OutputNotWritable(String),
    /// Database connection failed.
    DatabaseError(String),
    /// Encryption error.
    EncryptionError(String),
    /// Secure randomness failed before creating ciphertext or opening the archive.
    EntropyUnavailable,
    /// Backup archive is corrupt.
    CorruptArchive(String),
    /// Restore not confirmed.
    NotConfirmed,
    /// Version mismatch.
    VersionMismatch { backup: String, current: String },
    /// IO error.
    IoError(String),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConcurrentBackup => write!(f, "another backup is already in progress"),
            Self::OutputNotWritable(p) => write!(f, "output path not writable: {p}"),
            Self::DatabaseError(e) => write!(f, "database error: {e}"),
            Self::EncryptionError(e) => write!(f, "encryption error: {e}"),
            Self::EntropyUnavailable => write!(f, "secure entropy is unavailable"),
            Self::CorruptArchive(e) => write!(f, "corrupt backup archive: {e}"),
            Self::NotConfirmed => {
                write!(f, "restore requires --confirm-destructive flag")
            }
            Self::VersionMismatch { backup, current } => {
                write!(f, "version mismatch: backup={backup}, current={current}")
            }
            Self::IoError(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for BackupError {}

/// AES-256-GCM encryption/decryption for backup archives.
///
/// All cryptographic operations are delegated to the `CryptoPrimitives` trait.
///
/// Key derived from passphrase via PBKDF2-SHA256 (600,000 iterations).
pub struct BackupCrypto<'a> {
    crypto: &'a dyn CryptoPrimitives,
    /// Work factor of the key derivation.
    ///
    /// A field rather than a constant so a test can exercise the format and
    /// the failure paths without paying the cost that is the whole point of
    /// the function: 600,000 iterations is deliberate in production and a
    /// stall in an unoptimized test build. `new` is the production cost and
    /// is the only constructor outside tests.
    iterations: u32,
}

/// PBKDF2 iteration count for key derivation.
const PBKDF2_ITERATIONS: u32 = 600_000;
/// AES-256-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;
/// PBKDF2 salt size in bytes.
const SALT_SIZE: usize = 16;

/// Result of encryption: ciphertext + crypto parameters needed for decryption.
pub struct EncryptedData {
    /// AES-256-GCM ciphertext (includes 16-byte auth tag).
    pub ciphertext: Vec<u8>,
    /// PBKDF2 salt.
    pub salt: [u8; SALT_SIZE],
    /// AES-256-GCM nonce.
    pub nonce: [u8; NONCE_SIZE],
}

impl<'a> BackupCrypto<'a> {
    /// Create a new BackupCrypto with the given crypto primitives backend.
    pub fn new(crypto: &'a dyn CryptoPrimitives) -> Self {
        Self {
            crypto,
            iterations: PBKDF2_ITERATIONS,
        }
    }

    /// The same thing with a cheaper key derivation, for tests.
    #[cfg(test)]
    fn with_iterations(crypto: &'a dyn CryptoPrimitives, iterations: u32) -> Self {
        Self { crypto, iterations }
    }

    /// Derive a 256-bit key from a passphrase using PBKDF2-SHA256.
    pub fn derive_key(&self, passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], BackupError> {
        let mut key = [0u8; 32];
        self.crypto
            .pbkdf2_sha256(passphrase, salt, self.iterations, &mut key)
            .map_err(|e| BackupError::EncryptionError(format!("key derivation: {e}")))?;
        Ok(key)
    }

    /// Encrypt data using AES-256-GCM with a derived key.
    ///
    /// Returns encrypted data with salt and nonce needed for decryption.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        passphrase: &[u8],
    ) -> Result<EncryptedData, BackupError> {
        let mut salt = [0u8; SALT_SIZE];
        self.crypto
            .random_bytes(&mut salt)
            .map_err(|_| BackupError::EntropyUnavailable)?;
        let nonce_bytes = self
            .crypto
            .random_nonce()
            .map_err(|_| BackupError::EntropyUnavailable)?;

        let key = self.derive_key(passphrase, &salt)?;
        let ciphertext = self
            .crypto
            .aes_256_gcm_encrypt(&key, &nonce_bytes, plaintext, b"sid-backup")
            .map_err(|e| BackupError::EncryptionError(e.to_string()))?;

        Ok(EncryptedData {
            ciphertext,
            salt,
            nonce: nonce_bytes,
        })
    }

    /// Decrypt data using AES-256-GCM with a passphrase, salt, and nonce.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        passphrase: &[u8],
        salt: &[u8],
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<Vec<u8>, BackupError> {
        let key = self.derive_key(passphrase, salt)?;
        self.crypto
            .aes_256_gcm_decrypt(&key, nonce, ciphertext, b"sid-backup")
            .map_err(|_| {
                BackupError::EncryptionError(
                    "decryption failed (wrong passphrase or corrupt data)".to_string(),
                )
            })
    }

    /// Write an encrypted backup file: `[4-byte magic][16-byte salt][12-byte nonce][manifest JSON length u32][manifest JSON][ciphertext]`.
    pub fn write_backup(
        &self,
        path: &std::path::Path,
        manifest: &BackupManifest,
        payload: &[u8],
        passphrase: &[u8],
    ) -> Result<(), BackupError> {
        use std::io::Write;

        let encrypted = self.encrypt(payload, passphrase)?;

        let manifest_json = serde_json::to_vec(manifest)
            .map_err(|e| BackupError::IoError(format!("manifest serialization: {e}")))?;

        let mut file = std::fs::File::create(path)
            .map_err(|e| BackupError::OutputNotWritable(e.to_string()))?;

        // Magic bytes: "SID\x01"
        file.write_all(b"SID\x01")
            .map_err(|e| BackupError::IoError(e.to_string()))?;
        file.write_all(&encrypted.salt)
            .map_err(|e| BackupError::IoError(e.to_string()))?;
        file.write_all(&encrypted.nonce)
            .map_err(|e| BackupError::IoError(e.to_string()))?;

        let manifest_len = (manifest_json.len() as u32).to_le_bytes();
        file.write_all(&manifest_len)
            .map_err(|e| BackupError::IoError(e.to_string()))?;
        file.write_all(&manifest_json)
            .map_err(|e| BackupError::IoError(e.to_string()))?;
        file.write_all(&encrypted.ciphertext)
            .map_err(|e| BackupError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Read an encrypted backup file and decrypt the payload.
    ///
    /// Returns `(manifest, decrypted_payload)`.
    pub fn read_backup(
        &self,
        path: &std::path::Path,
        passphrase: &[u8],
    ) -> Result<(BackupManifest, Vec<u8>), BackupError> {
        use std::io::Read;

        let mut file =
            std::fs::File::open(path).map_err(|e| BackupError::IoError(e.to_string()))?;

        // Read magic
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)
            .map_err(|e| BackupError::CorruptArchive(format!("cannot read magic: {e}")))?;
        if &magic != b"SID\x01" {
            return Err(BackupError::CorruptArchive(
                "invalid magic bytes".to_string(),
            ));
        }

        // Read salt + nonce
        let mut salt = [0u8; SALT_SIZE];
        file.read_exact(&mut salt)
            .map_err(|e| BackupError::CorruptArchive(format!("cannot read salt: {e}")))?;
        let mut nonce = [0u8; NONCE_SIZE];
        file.read_exact(&mut nonce)
            .map_err(|e| BackupError::CorruptArchive(format!("cannot read nonce: {e}")))?;

        // Read manifest
        let mut manifest_len_bytes = [0u8; 4];
        file.read_exact(&mut manifest_len_bytes).map_err(|e| {
            BackupError::CorruptArchive(format!("cannot read manifest length: {e}"))
        })?;
        let manifest_len = u32::from_le_bytes(manifest_len_bytes) as usize;

        let mut manifest_json = vec![0u8; manifest_len];
        file.read_exact(&mut manifest_json)
            .map_err(|e| BackupError::CorruptArchive(format!("cannot read manifest: {e}")))?;
        let manifest: BackupManifest = serde_json::from_slice(&manifest_json)
            .map_err(|e| BackupError::CorruptArchive(format!("invalid manifest JSON: {e}")))?;

        // Read ciphertext
        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext)
            .map_err(|e| BackupError::IoError(e.to_string()))?;

        let plaintext = self.decrypt(&ciphertext, passphrase, &salt, &nonce)?;

        Ok((manifest, plaintext))
    }
}

/// CE Backup Service.
///
/// Coordinates backup creation, verification, and restore.
/// Full backups include: database, key store, configuration, certificates.
pub struct BackupService;

impl BackupService {
    /// Create a new backup manifest for a full backup.
    pub fn create_manifest(backup_type: BackupType) -> BackupManifest {
        let components = match backup_type {
            BackupType::Full => vec![
                BackupComponent::Database,
                BackupComponent::KeyStore,
                BackupComponent::Configuration,
                BackupComponent::Certificates,
            ],
            BackupType::ProfileExport => vec![BackupComponent::Database],
        };

        BackupManifest {
            id: BackupId::new(),
            created_at: Utc::now(),
            backup_type,
            status: BackupStatus::InProgress,
            components,
            sid_version: env!("CARGO_PKG_VERSION").to_string(),
            checksums: HashMap::new(),
            size_bytes: 0,
            encryption: EncryptionInfo {
                algorithm: "AES-256-GCM".to_string(),
                kdf: "PBKDF2-SHA256".to_string(),
                kdf_iterations: 600_000,
                salt: String::new(),
                nonce: String::new(),
            },
        }
    }

    /// Verify a backup manifest for completeness.
    pub fn verify_manifest(manifest: &BackupManifest) -> VerifyResult {
        let mut errors = Vec::new();
        let mut component_checks = Vec::new();

        // Check version compatibility.
        let current_version = env!("CARGO_PKG_VERSION");
        if manifest.sid_version != current_version {
            // Major version must match.
            let backup_major = manifest.sid_version.split('.').next().unwrap_or("0");
            let current_major = current_version.split('.').next().unwrap_or("0");
            if backup_major != current_major {
                errors.push(format!(
                    "major version mismatch: backup={}, current={}",
                    manifest.sid_version, current_version
                ));
            }
        }

        // Verify all expected components have checksums.
        for component in &manifest.components {
            let key = format!("{component:?}");
            let has_checksum = manifest.checksums.contains_key(&key);
            if !has_checksum {
                errors.push(format!("missing checksum for {key}"));
            }
            component_checks.push(ComponentCheck {
                component: *component,
                checksum_valid: has_checksum,
                size_bytes: 0,
            });
        }

        // Check encryption info is populated.
        if manifest.encryption.salt.is_empty() || manifest.encryption.nonce.is_empty() {
            errors.push("encryption salt or nonce is empty".to_string());
        }

        VerifyResult {
            valid: errors.is_empty(),
            manifest: Some(manifest.clone()),
            errors,
            component_checks,
        }
    }

    /// Validate a restore request before proceeding.
    pub fn validate_restore(request: &RestoreBackupRequest) -> Result<(), BackupError> {
        if !request.confirm_destructive {
            return Err(BackupError::NotConfirmed);
        }

        // Check backup file exists (basic path validation).
        if request.backup_path.is_empty() {
            return Err(BackupError::IoError("backup path is empty".to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
