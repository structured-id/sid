// SPDX-License-Identifier: AGPL-3.0-only
//! What every `BlobStore` owes: a profile's blob reads back as written, a
//! write must name the version it replaces, and a delete is visible in the
//! metadata. `backend` holds the profiles the blobs belong to.

use sid_core::models::{
    AuditEntry, BlobError, BlobStorageStatus, EncryptedBlob, Profile, ProfileId,
};
use sid_plugin::blob_store::BlobStore;
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

fn blob(ciphertext: &[u8], nonce: u8) -> EncryptedBlob {
    EncryptedBlob {
        ciphertext: ciphertext.to_vec(),
        nonce: [nonce; 12],
        version: 0,
        updated_at: chrono::Utc::now(),
    }
}

async fn owner(backend: &dyn StorageBackend) -> ProfileId {
    let profile = Profile::new(Some(format!("blob-{}", Uuid::now_v7())));
    backend
        .create_profile(&profile, AuditEntry::system("test", "blob").into())
        .await
        .unwrap();
    profile.id
}

/// The first write is version 1 and reads back as written.
pub async fn put_and_get(backend: &dyn StorageBackend, store: &dyn BlobStore) {
    let profile = owner(backend).await;
    assert_eq!(
        store
            .put_blob(&profile, blob(b"sealed", 42), 0)
            .await
            .unwrap(),
        1
    );
    let read = store.get_blob(&profile).await.unwrap().unwrap();
    assert_eq!(read.ciphertext, b"sealed");
    assert_eq!(read.version, 1);
    assert_eq!(read.nonce, [42; 12]);
}

/// A write naming the current version succeeds; one naming a replaced
/// version conflicts, so a concurrent writer cannot be overwritten blindly.
pub async fn write_names_the_version_it_replaces(
    backend: &dyn StorageBackend,
    store: &dyn BlobStore,
) {
    let profile = owner(backend).await;
    store.put_blob(&profile, blob(b"v1", 0), 0).await.unwrap();
    assert_eq!(
        store.put_blob(&profile, blob(b"v2", 1), 1).await.unwrap(),
        2
    );
    let stale = store.put_blob(&profile, blob(b"stale", 2), 1).await;
    assert!(
        matches!(stale, Err(BlobError::VersionConflict { .. })),
        "{stale:?}"
    );
    assert_eq!(
        store.get_blob(&profile).await.unwrap().unwrap().ciphertext,
        b"v2"
    );
}

/// A deleted blob no longer reads, and its metadata says it was deleted.
pub async fn delete_is_visible_in_metadata(backend: &dyn StorageBackend, store: &dyn BlobStore) {
    let profile = owner(backend).await;
    store.put_blob(&profile, blob(b"gone", 0), 0).await.unwrap();
    let meta = store.blob_metadata(&profile).await.unwrap().unwrap();
    assert_eq!(meta.version, 1);
    assert_eq!(meta.storage_status, BlobStorageStatus::Local);

    store.delete_blob(&profile).await.unwrap();
    assert!(store.get_blob(&profile).await.unwrap().is_none());
    let meta = store.blob_metadata(&profile).await.unwrap().unwrap();
    assert_eq!(meta.storage_status, BlobStorageStatus::Deleted);
}

/// A profile without a blob has neither a blob nor metadata.
pub async fn absent_blob_reads_as_none(store: &dyn BlobStore) {
    let profile = ProfileId::generate();
    assert!(store.get_blob(&profile).await.unwrap().is_none());
    assert!(store.blob_metadata(&profile).await.unwrap().is_none());
}
