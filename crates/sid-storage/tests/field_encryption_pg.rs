// SPDX-License-Identifier: AGPL-3.0-only
//! Field encryption through the real database.
//!
//! The unit tests of `sid-keys` prove the cipher and the key schedule. What
//! they cannot prove is that an encrypted field survives the round trip a
//! deployment actually performs: written to a column, read back by another
//! process that derived its keys from the same master, and re-encrypted under
//! a newer version while the old ciphertext is still readable.
//!
//! Run with: cargo nextest run -p sid-storage --test field_encryption_pg

use std::sync::Arc;

use secrecy::SecretBox;
use sid_core::models::{AuditEntry, UpstreamProtocol, UpstreamProvider};
use sid_keys::{
    EncryptedField, KeyManager, KeyManagerError, KeyVersionParams, RustCryptoPrimitives,
    SoftwareKeyManager,
};
use sid_plugin::storage::StorageBackend;
use sid_storage::PostgresBackend;

fn database_url() -> String {
    std::env::var("SID_STORAGE_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid_storage_test".to_string())
}

async fn setup() -> PostgresBackend {
    let backend = PostgresBackend::new(&database_url(), None)
        .await
        .expect("Failed to connect to PostgreSQL. Is the database running?");

    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("Failed to run migrations");

    backend
}

/// The master secret a host supplies. The same bytes in every test, because
/// the point is what a second process holding the same master can read.
fn master() -> SecretBox<[u8; 32]> {
    SecretBox::new(Box::new([0x5Au8; 32]))
}

fn other_master() -> SecretBox<[u8; 32]> {
    SecretBox::new(Box::new([0xA5u8; 32]))
}

fn params_v1() -> KeyVersionParams {
    KeyVersionParams::new(1, vec![0x11; 16], "key-v1")
}

fn params_v2() -> KeyVersionParams {
    KeyVersionParams::new(2, vec![0x22; 16], "key-v2")
}

fn manager(versions: Vec<KeyVersionParams>) -> SoftwareKeyManager {
    SoftwareKeyManager::new(master(), versions, Arc::new(RustCryptoPrimitives::new()))
        .expect("versions are valid")
}

/// A provider row whose client secret is encrypted under `km`.
async fn stored_provider(
    backend: &PostgresBackend,
    km: &SoftwareKeyManager,
    secret: &[u8],
) -> UpstreamProvider {
    let name = format!("test-{}", uuid::Uuid::now_v7());
    let context = format!("upstream:{name}");
    let encrypted = km
        .encrypt(secret, &context)
        .await
        .expect("encryption succeeds");

    let provider = UpstreamProvider::new(name, UpstreamProtocol::Oidc, "client-id", encrypted);
    backend
        .create_upstream_provider(&provider, AuditEntry::system("test", "setup").into())
        .await
        .expect("provider is stored");

    provider
}

async fn load(backend: &PostgresBackend, provider: &UpstreamProvider) -> UpstreamProvider {
    backend
        .get_upstream_provider(provider.id)
        .await
        .expect("storage read succeeds")
        .expect("provider exists")
}

/// The ordinary path: what one process encrypts and stores, a process that
/// starts later with the same master and the same stored parameters reads.
#[tokio::test]
async fn test_secret_survives_the_database_round_trip() {
    let backend = setup().await;
    let writer = manager(vec![params_v1()]);

    let provider = stored_provider(&backend, &writer, b"upstream-client-secret").await;
    let loaded = load(&backend, &provider).await;

    // The column holds ciphertext, not the secret.
    assert_ne!(
        loaded.client_secret.ciphertext.as_slice(),
        b"upstream-client-secret"
    );
    assert_eq!(loaded.client_secret.key_version, 1);

    let reader = manager(vec![params_v1()]);
    let plaintext = reader
        .decrypt(&loaded.client_secret)
        .await
        .expect("the same master re-derives the key");
    assert_eq!(plaintext, b"upstream-client-secret");
}

/// A database dump without the master secret yields nothing usable.
#[tokio::test]
async fn test_another_master_cannot_read_a_stored_secret() {
    let backend = setup().await;
    let writer = manager(vec![params_v1()]);

    let provider = stored_provider(&backend, &writer, b"secret-under-one-master").await;
    let loaded = load(&backend, &provider).await;

    let intruder = SoftwareKeyManager::new(
        other_master(),
        vec![params_v1()],
        Arc::new(RustCryptoPrimitives::new()),
    )
    .expect("versions are valid");

    let result = intruder.decrypt(&loaded.client_secret).await;
    assert!(matches!(result, Err(KeyManagerError::Decryption(_))));
}

/// Losing the stored parameters loses the version: the master alone is not a key.
#[tokio::test]
async fn test_a_replaced_salt_cannot_read_a_stored_secret() {
    let backend = setup().await;
    let writer = manager(vec![params_v1()]);

    let provider = stored_provider(&backend, &writer, b"secret-under-one-salt").await;
    let loaded = load(&backend, &provider).await;

    let wrong_salt = manager(vec![KeyVersionParams::new(1, vec![0xEE; 16], "key-v1")]);
    let result = wrong_salt.decrypt(&loaded.client_secret).await;
    assert!(matches!(result, Err(KeyManagerError::Decryption(_))));
}

/// Lazy rotation as a deployment performs it: read under the old version,
/// re-encrypt under the current one, write back, read again.
#[tokio::test]
async fn test_lazy_rotation_through_storage() {
    let backend = setup().await;

    // Written when only version 1 existed.
    let old_writer = manager(vec![params_v1()]);
    let provider = stored_provider(&backend, &old_writer, b"rotating-secret").await;

    // The process that reads it now also holds version 2.
    let current = manager(vec![params_v1(), params_v2()]);
    let mut loaded = load(&backend, &provider).await;
    assert!(current.needs_rotation(&loaded.client_secret));

    let rotated = current
        .rotate(&loaded.client_secret)
        .await
        .expect("rotation succeeds");
    assert_eq!(rotated.key_version, 2);

    loaded.client_secret = rotated;
    assert!(
        backend
            .update_upstream_provider(&loaded, AuditEntry::system("test", "rotate").into())
            .await
            .expect("rotated provider is stored"),
        "the provider read back is updated"
    );

    let after = load(&backend, &provider).await;
    assert_eq!(after.client_secret.key_version, 2);
    assert!(!current.needs_rotation(&after.client_secret));
    assert_eq!(
        current
            .decrypt(&after.client_secret)
            .await
            .expect("current version reads it"),
        b"rotating-secret"
    );

    // A process still on version 1 no longer reads the rotated row, which is
    // what makes destroying an old version meaningful.
    let stale = manager(vec![params_v1()]);
    assert!(matches!(
        stale.decrypt(&after.client_secret).await,
        Err(KeyManagerError::KeyNotFound(2))
    ));
}

/// A ciphertext moved to another row decrypts to nothing: the context is the
/// AAD, and the context names the record it belongs to.
#[tokio::test]
async fn test_a_secret_moved_to_another_row_is_refused() {
    let backend = setup().await;
    let km = manager(vec![params_v1()]);

    let alice = stored_provider(&backend, &km, b"alice-secret").await;
    let bob_stored = stored_provider(&backend, &km, b"bob-secret").await;
    let mut bob = load(&backend, &bob_stored).await;

    // Swap the stored ciphertext, keeping bob's own context.
    let alice_loaded = load(&backend, &alice).await;
    let bobs_context = bob.client_secret.context.clone();
    bob.client_secret = EncryptedField {
        context: bobs_context,
        ..alice_loaded.client_secret.clone()
    };
    assert!(
        backend
            .update_upstream_provider(&bob, AuditEntry::system("test", "swap").into())
            .await
            .expect("row is stored")
    );

    let tampered = load(&backend, &bob).await;
    let result = km.decrypt(&tampered.client_secret).await;
    assert!(matches!(result, Err(KeyManagerError::Decryption(_))));

    // Alice's own row is untouched by the attempt.
    let alice_after = load(&backend, &alice).await;
    assert_eq!(
        km.decrypt(&alice_after.client_secret)
            .await
            .expect("alice still reads her own secret"),
        b"alice-secret"
    );
}

/// A row whose ciphertext was altered in the database fails to decrypt rather
/// than returning something.
#[tokio::test]
async fn test_a_tampered_ciphertext_is_refused() {
    let backend = setup().await;
    let km = manager(vec![params_v1()]);

    let stored = stored_provider(&backend, &km, b"integrity-checked").await;
    let mut provider = load(&backend, &stored).await;
    provider.client_secret.ciphertext[0] ^= 0x01;
    assert!(
        backend
            .update_upstream_provider(&provider, AuditEntry::system("test", "tamper").into())
            .await
            .expect("row is stored")
    );

    let loaded = load(&backend, &provider).await;
    let result = km.decrypt(&loaded.client_secret).await;
    assert!(matches!(result, Err(KeyManagerError::Decryption(_))));
}
