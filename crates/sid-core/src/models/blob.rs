// SPDX-License-Identifier: AGPL-3.0-only
//! Encrypted profile blob types for blind vault storage.
//!
//! Blobs are opaque ciphertext (typically <1MB) encrypted by their owner (the
//! user or the organization).
//! The storage layer never decrypts them — only stores and retrieves.
//!
//! Used in SaaS blind vault (Level 1/2) and EE self-hosted blob storage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An encrypted profile blob with optimistic concurrency control.
///
/// The owner re-encrypts the blob on every field change.
/// Version is used for optimistic locking on `put_blob`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// AES-256-GCM encrypted profile data.
    pub ciphertext: Vec<u8>,

    /// GCM nonce (96-bit / 12 bytes).
    pub nonce: [u8; 12],

    /// Optimistic concurrency version — monotonically increasing.
    /// `put_blob` fails if `expected_version` doesn't match current.
    pub version: u64,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Metadata about a stored blob (without downloading full ciphertext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMeta {
    /// Optimistic concurrency version.
    pub version: u64,

    /// Size of the encrypted blob in bytes.
    pub size_bytes: u64,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,

    /// Where this blob is currently stored.
    pub storage_status: BlobStorageStatus,
}

/// Where an encrypted profile blob lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobStorageStatus {
    /// Stored in this instance's DB (CE Level 1, EE self-hosted).
    Local,

    /// Stored in SaaS blind vault.
    SaasVault,

    /// Detached — stored elsewhere by its owner (future).
    External,

    /// Crypto-shredded (account closure).
    Deleted,
}

/// Errors from blob operations.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// Optimistic locking conflict: expected version doesn't match current.
    #[error("version conflict: expected {expected}, found {actual}")]
    VersionConflict { expected: u64, actual: u64 },

    /// Blob not found for the given profile.
    #[error("blob not found")]
    NotFound,

    /// Storage backend error.
    #[error("blob storage error: {0}")]
    Storage(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_storage_status_serde_roundtrip() {
        let statuses = vec![
            BlobStorageStatus::Local,
            BlobStorageStatus::SaasVault,
            BlobStorageStatus::External,
            BlobStorageStatus::Deleted,
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: BlobStorageStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn test_blob_storage_status_snake_case() {
        assert_eq!(
            serde_json::to_string(&BlobStorageStatus::SaasVault).unwrap(),
            "\"saas_vault\""
        );
        assert_eq!(
            serde_json::to_string(&BlobStorageStatus::Local).unwrap(),
            "\"local\""
        );
    }

    #[test]
    fn test_encrypted_blob_serde() {
        let blob = EncryptedBlob {
            ciphertext: vec![1, 2, 3, 4, 5],
            nonce: [42; 12],
            version: 7,
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&blob).unwrap();
        let deserialized: EncryptedBlob = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, 7);
        assert_eq!(deserialized.nonce, [42; 12]);
        assert_eq!(deserialized.ciphertext, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_blob_meta_serde() {
        let meta = BlobMeta {
            version: 3,
            size_bytes: 1024,
            updated_at: Utc::now(),
            storage_status: BlobStorageStatus::SaasVault,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: BlobMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, 3);
        assert_eq!(deserialized.size_bytes, 1024);
        assert_eq!(deserialized.storage_status, BlobStorageStatus::SaasVault);
    }

    #[test]
    fn test_blob_error_display() {
        let err = BlobError::VersionConflict {
            expected: 5,
            actual: 6,
        };
        assert_eq!(err.to_string(), "version conflict: expected 5, found 6");

        let err = BlobError::NotFound;
        assert_eq!(err.to_string(), "blob not found");

        let err = BlobError::Storage("connection refused".into());
        assert_eq!(err.to_string(), "blob storage error: connection refused");
    }
}
