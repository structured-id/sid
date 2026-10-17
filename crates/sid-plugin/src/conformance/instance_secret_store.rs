// SPDX-License-Identifier: AGPL-3.0-only
//! [`InstanceSecretStore`] scenarios: the first stored value of a secret is
//! the one every replica reads. Secrets are store-wide, so each scenario runs
//! against a store of its own that has none stored yet.

use sid_core::models::{AuditEntry, InstanceSecret, MutationContext};

use crate::InstanceSecretStore;

fn ctx() -> MutationContext {
    AuditEntry::system("conformance", "instance_secret").into()
}

/// A secret reads as absent until stored, then as stored.
pub async fn secret_is_absent_until_stored(store: &dyn InstanceSecretStore) {
    let secret = InstanceSecret::CaptchaKey;
    assert_eq!(store.get_instance_secret(secret).await.unwrap(), None);
    assert!(
        store
            .insert_instance_secret(secret, b"first", ctx())
            .await
            .unwrap()
    );
    assert_eq!(
        store.get_instance_secret(secret).await.unwrap(),
        Some(b"first".to_vec())
    );
}

/// A second insert stores nothing: the first value is kept for ever.
pub async fn first_value_is_kept(store: &dyn InstanceSecretStore) {
    let secret = InstanceSecret::OpaqueServerSetup;
    assert!(
        store
            .insert_instance_secret(secret, b"first", ctx())
            .await
            .unwrap()
    );
    assert!(
        !store
            .insert_instance_secret(secret, b"second", ctx())
            .await
            .unwrap()
    );
    assert_eq!(
        store.get_instance_secret(secret).await.unwrap(),
        Some(b"first".to_vec())
    );
}

/// Replicas starting together: of concurrent inserts exactly one is
/// stored, and every reader gets that one.
pub async fn concurrent_inserts_agree(store: &dyn InstanceSecretStore) {
    let secret = InstanceSecret::CaptchaKey;
    let (a, b) = tokio::join!(
        store.insert_instance_secret(secret, b"a", ctx()),
        store.insert_instance_secret(secret, b"b", ctx()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a ^ b, "exactly one insert is stored: {a} {b}");
    let winner: &[u8] = if a { b"a" } else { b"b" };
    assert_eq!(
        store.get_instance_secret(secret).await.unwrap(),
        Some(winner.to_vec())
    );
}
