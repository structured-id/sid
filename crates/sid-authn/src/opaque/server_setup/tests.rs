// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::opaque::PallasOpaque;
use crate::sealed_secret::{self, SealedSecretError};
use crate::test_support::key_manager;
use sid_core::models::AuditEntry;
use sid_storage::sqlite::SqliteBackend;

async fn storage() -> SqliteBackend {
    SqliteBackend::new_in_memory()
        .await
        .expect("in-memory SQLite")
}

/// A restart loads the setup stored by the first start, byte for byte, so
/// password records registered before it still verify.
#[tokio::test]
async fn restart_loads_the_stored_setup() {
    let (storage, keys, pallas) = (storage().await, key_manager(), PallasOpaque::new());
    let first = load_or_create(&storage, keys.as_ref(), &pallas)
        .await
        .unwrap();
    let again = load_or_create(&storage, keys.as_ref(), &pallas)
        .await
        .unwrap();
    assert_eq!(first.0, again.0);
}

/// Replicas starting at the same time end up with one setup.
#[tokio::test]
async fn concurrent_starts_agree_on_one_setup() {
    let (storage, keys, pallas) = (storage().await, key_manager(), PallasOpaque::new());
    let (a, b) = tokio::join!(
        load_or_create(&storage, keys.as_ref(), &pallas),
        load_or_create(&storage, keys.as_ref(), &pallas),
    );
    assert_eq!(a.unwrap().0, b.unwrap().0);
}

/// The database holds the setup only sealed: a dump alone does not yield it.
#[tokio::test]
async fn setup_is_stored_sealed() {
    let (storage, keys, pallas) = (storage().await, key_manager(), PallasOpaque::new());
    let setup = load_or_create(&storage, keys.as_ref(), &pallas)
        .await
        .unwrap();
    let stored = storage
        .get_instance_secret(InstanceSecret::OpaqueServerSetup)
        .await
        .unwrap()
        .unwrap();
    assert!(sealed_secret::is_sealed(&stored));
    assert!(!stored.windows(setup.0.len()).any(|w| w == setup.0));
}

/// A sealed value bound to another record is refused rather than used as the
/// setup, and nothing replaces it.
#[tokio::test]
async fn value_sealed_for_another_record_is_refused() {
    let (storage, keys, pallas) = (storage().await, key_manager(), PallasOpaque::new());
    let foreign = sealed_secret::seal(keys.as_ref(), "totp:someone", &[7u8; 64])
        .await
        .unwrap();
    storage
        .insert_instance_secret(
            InstanceSecret::OpaqueServerSetup,
            &foreign,
            AuditEntry::system("test", "setup").into(),
        )
        .await
        .unwrap();

    let err = load_or_create(&storage, keys.as_ref(), &pallas)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        ServerSetupError::Stored(InstanceSecretError::Sealed(
            SealedSecretError::ContextMismatch
        ))
    ));
}

/// A replica holding a different master secret cannot open the setup and
/// fails to start instead of serving logins that could never succeed.
#[tokio::test]
async fn different_master_secret_fails_to_start() {
    let (storage, pallas) = (storage().await, PallasOpaque::new());
    load_or_create(&storage, key_manager().as_ref(), &pallas)
        .await
        .unwrap();
    let other: std::sync::Arc<dyn KeyManager> = std::sync::Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([9u8; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![1u8; 16], "key-v1")],
            std::sync::Arc::new(sid_keys::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    );

    let err = load_or_create(&storage, other.as_ref(), &pallas)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        ServerSetupError::Stored(InstanceSecretError::Sealed(_))
    ));
}
