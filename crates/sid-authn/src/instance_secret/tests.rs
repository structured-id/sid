// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::test_support::key_manager;
use sid_storage::sqlite::SqliteBackend;
use std::convert::Infallible;

async fn storage() -> SqliteBackend {
    SqliteBackend::new_in_memory()
        .await
        .expect("in-memory SQLite")
}

fn fresh(value: u8) -> impl FnOnce() -> Result<Zeroizing<Vec<u8>>, Infallible> {
    move || Ok(Zeroizing::new(vec![value; 32]))
}

/// The first start creates the value; later starts get it back and never
/// create another.
#[tokio::test]
async fn first_start_creates_and_later_starts_reuse() {
    let (storage, keys) = (storage().await, key_manager());
    let secret = InstanceSecret::CaptchaKey;
    let first = load_or_create(&storage, keys.as_ref(), secret, fresh(1))
        .await
        .unwrap();
    let again = load_or_create(&storage, keys.as_ref(), secret, fresh(2))
        .await
        .unwrap();
    assert_eq!(*first, vec![1u8; 32]);
    assert_eq!(*again, vec![1u8; 32]);
}

/// Replicas starting together end up with one value.
#[tokio::test]
async fn concurrent_starts_agree() {
    let (storage, keys) = (storage().await, key_manager());
    let secret = InstanceSecret::CaptchaKey;
    let (a, b) = tokio::join!(
        load_or_create(&storage, keys.as_ref(), secret, fresh(3)),
        load_or_create(&storage, keys.as_ref(), secret, fresh(4)),
    );
    assert_eq!(*a.unwrap(), *b.unwrap());
}

/// The database holds the value only sealed.
#[tokio::test]
async fn value_is_stored_sealed() {
    let (storage, keys) = (storage().await, key_manager());
    let secret = InstanceSecret::CaptchaKey;
    load_or_create(&storage, keys.as_ref(), secret, fresh(5))
        .await
        .unwrap();
    let stored = storage.get_instance_secret(secret).await.unwrap().unwrap();
    assert!(sealed_secret::is_sealed(&stored));
    assert!(!stored.windows(32).any(|w| w == [5u8; 32]));
}

/// A value sealed for another secret is refused, never used in its place.
#[tokio::test]
async fn value_sealed_for_another_secret_is_refused() {
    let (storage, keys) = (storage().await, key_manager());
    let foreign = sealed_secret::seal(
        keys.as_ref(),
        &context(InstanceSecret::OpaqueServerSetup),
        &[6u8; 32],
    )
    .await
    .unwrap();
    storage
        .insert_instance_secret(
            InstanceSecret::CaptchaKey,
            &foreign,
            AuditEntry::system("test", "secret").into(),
        )
        .await
        .unwrap();

    let err = load_or_create(
        &storage,
        keys.as_ref(),
        InstanceSecret::CaptchaKey,
        fresh(7),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        InstanceSecretError::Sealed(SealedSecretError::ContextMismatch)
    ));
}
