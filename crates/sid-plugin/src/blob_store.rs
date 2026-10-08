// SPDX-License-Identifier: AGPL-3.0-only
//! Blob store abstraction for encrypted profile blobs (blind vault).
//!
//! Blobs are opaque ciphertext — the storage layer never decrypts them.
//! The blob's owner (the user or the organization) holds the encryption key;
//! storage just stores and retrieves.
//!
//! Implementations:
//! - PostgreSQL: `profile_blobs` table with BYTEA column (TOAST auto-externalizes >2KB)
//! - MongoDB: `profile_blobs` collection with Binary field (sharded by profile_id)
//!
//! Optimistic concurrency: `put_blob` requires `expected_version` to match
//! current version, preventing lost updates from concurrent writes.
//!
//! Reference: Prudnikov, D. (2026). "Content-Addressed Blind Attestation System
//! for Encrypted Structured Data with Storage-Independent Signature Validity."
//! doi:[10.5281/zenodo.19387694](https://doi.org/10.5281/zenodo.19387694)

use async_trait::async_trait;
use sid_core::models::{BlobError, BlobMeta, EncryptedBlob, ProfileId};

/// Storage backend for encrypted profile blobs.
///
/// All operations are keyed by `ProfileId`. Each profile has at most one blob.
/// Blob updates use optimistic locking via version numbers.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Download encrypted blob for sync to device.
    ///
    /// Returns `None` if no blob exists for this profile.
    async fn get_blob(&self, profile_id: &ProfileId) -> Result<Option<EncryptedBlob>, BlobError>;

    /// Upload encrypted blob (the owner re-encrypts on field change).
    ///
    /// Returns new version number. Fails with `BlobError::VersionConflict`
    /// if `expected_version` doesn't match current (optimistic lock).
    ///
    /// For initial upload, use `expected_version = 0`.
    async fn put_blob(
        &self,
        profile_id: &ProfileId,
        blob: EncryptedBlob,
        expected_version: u64,
    ) -> Result<u64, BlobError>;

    /// Remove blob (detach operation or account closure).
    ///
    /// After deletion, `get_blob` returns `None` and `blob_metadata`
    /// returns status `Deleted` until fully purged.
    async fn delete_blob(&self, profile_id: &ProfileId) -> Result<(), BlobError>;

    /// Blob metadata without downloading full ciphertext.
    ///
    /// Returns `None` if no blob exists for this profile.
    async fn blob_metadata(&self, profile_id: &ProfileId) -> Result<Option<BlobMeta>, BlobError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sid_core::models::BlobStorageStatus;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory blob store for testing.
    struct InMemoryBlobStore {
        blobs: Mutex<HashMap<ProfileId, EncryptedBlob>>,
    }

    impl InMemoryBlobStore {
        fn new() -> Self {
            Self {
                blobs: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BlobStore for InMemoryBlobStore {
        async fn get_blob(
            &self,
            profile_id: &ProfileId,
        ) -> Result<Option<EncryptedBlob>, BlobError> {
            let blobs = self.blobs.lock().unwrap();
            Ok(blobs.get(profile_id).cloned())
        }

        async fn put_blob(
            &self,
            profile_id: &ProfileId,
            blob: EncryptedBlob,
            expected_version: u64,
        ) -> Result<u64, BlobError> {
            let mut blobs = self.blobs.lock().unwrap();
            let current_version = blobs.get(profile_id).map(|b| b.version).unwrap_or(0);

            if expected_version != current_version {
                return Err(BlobError::VersionConflict {
                    expected: expected_version,
                    actual: current_version,
                });
            }

            let new_version = current_version + 1;
            let stored = EncryptedBlob {
                version: new_version,
                ..blob
            };
            blobs.insert(*profile_id, stored);
            Ok(new_version)
        }

        async fn delete_blob(&self, profile_id: &ProfileId) -> Result<(), BlobError> {
            let mut blobs = self.blobs.lock().unwrap();
            blobs.remove(profile_id);
            Ok(())
        }

        async fn blob_metadata(
            &self,
            profile_id: &ProfileId,
        ) -> Result<Option<BlobMeta>, BlobError> {
            let blobs = self.blobs.lock().unwrap();
            Ok(blobs.get(profile_id).map(|b| BlobMeta {
                version: b.version,
                size_bytes: b.ciphertext.len() as u64,
                updated_at: b.updated_at,
                storage_status: BlobStorageStatus::Local,
            }))
        }
    }

    fn make_blob(data: &[u8], version: u64) -> EncryptedBlob {
        EncryptedBlob {
            ciphertext: data.to_vec(),
            nonce: [0; 12],
            version,
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_put_and_get_blob() {
        let store = InMemoryBlobStore::new();
        let pid = ProfileId::generate();

        // Initial upload (expected_version = 0)
        let blob = make_blob(b"encrypted-profile-data", 0);
        let new_ver = store.put_blob(&pid, blob, 0).await.unwrap();
        assert_eq!(new_ver, 1);

        // Retrieve
        let retrieved = store.get_blob(&pid).await.unwrap().unwrap();
        assert_eq!(retrieved.ciphertext, b"encrypted-profile-data");
        assert_eq!(retrieved.version, 1);
    }

    #[tokio::test]
    async fn test_get_nonexistent_returns_none() {
        let store = InMemoryBlobStore::new();
        let pid = ProfileId::generate();
        assert!(store.get_blob(&pid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_optimistic_locking_conflict() {
        let store = InMemoryBlobStore::new();
        let pid = ProfileId::generate();

        // Initial upload
        store.put_blob(&pid, make_blob(b"v1", 0), 0).await.unwrap();

        // Try to update with wrong version
        let result = store.put_blob(&pid, make_blob(b"v2", 0), 0).await;
        assert!(matches!(result, Err(BlobError::VersionConflict { .. })));
    }

    #[tokio::test]
    async fn test_optimistic_locking_success() {
        let store = InMemoryBlobStore::new();
        let pid = ProfileId::generate();

        // Upload v1
        let v1 = store.put_blob(&pid, make_blob(b"v1", 0), 0).await.unwrap();
        assert_eq!(v1, 1);

        // Upload v2 with correct expected version
        let v2 = store.put_blob(&pid, make_blob(b"v2", 0), 1).await.unwrap();
        assert_eq!(v2, 2);

        // Verify content updated
        let blob = store.get_blob(&pid).await.unwrap().unwrap();
        assert_eq!(blob.ciphertext, b"v2");
        assert_eq!(blob.version, 2);
    }

    #[tokio::test]
    async fn test_delete_blob() {
        let store = InMemoryBlobStore::new();
        let pid = ProfileId::generate();

        store
            .put_blob(&pid, make_blob(b"data", 0), 0)
            .await
            .unwrap();
        assert!(store.get_blob(&pid).await.unwrap().is_some());

        store.delete_blob(&pid).await.unwrap();
        assert!(store.get_blob(&pid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_blob_metadata() {
        let store = InMemoryBlobStore::new();
        let pid = ProfileId::generate();

        // No blob → None
        assert!(store.blob_metadata(&pid).await.unwrap().is_none());

        // Upload → metadata available
        store
            .put_blob(&pid, make_blob(b"12345", 0), 0)
            .await
            .unwrap();
        let meta = store.blob_metadata(&pid).await.unwrap().unwrap();
        assert_eq!(meta.version, 1);
        assert_eq!(meta.size_bytes, 5);
        assert_eq!(meta.storage_status, BlobStorageStatus::Local);
    }

    #[tokio::test]
    async fn test_delete_nonexistent_blob_is_ok() {
        let store = InMemoryBlobStore::new();
        let pid = ProfileId::generate();
        // Should not error
        store.delete_blob(&pid).await.unwrap();
    }

    #[tokio::test]
    async fn test_blob_store_object_safety() {
        let store: Box<dyn BlobStore> = Box::new(InMemoryBlobStore::new());
        let pid = ProfileId::generate();
        store
            .put_blob(&pid, make_blob(b"test", 0), 0)
            .await
            .unwrap();
        let blob = store.get_blob(&pid).await.unwrap().unwrap();
        assert_eq!(blob.ciphertext, b"test");
    }

    #[tokio::test]
    async fn test_blob_store_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryBlobStore>();
    }

    #[tokio::test]
    async fn test_multiple_profiles_independent() {
        let store = InMemoryBlobStore::new();
        let pid1 = ProfileId::generate();
        let pid2 = ProfileId::generate();

        store
            .put_blob(&pid1, make_blob(b"alice", 0), 0)
            .await
            .unwrap();
        store
            .put_blob(&pid2, make_blob(b"bob", 0), 0)
            .await
            .unwrap();

        let alice = store.get_blob(&pid1).await.unwrap().unwrap();
        let bob = store.get_blob(&pid2).await.unwrap().unwrap();
        assert_eq!(alice.ciphertext, b"alice");
        assert_eq!(bob.ciphertext, b"bob");

        // Delete alice doesn't affect bob
        store.delete_blob(&pid1).await.unwrap();
        assert!(store.get_blob(&pid1).await.unwrap().is_none());
        assert!(store.get_blob(&pid2).await.unwrap().is_some());
    }
}
