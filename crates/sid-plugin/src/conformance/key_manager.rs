// SPDX-License-Identifier: AGPL-3.0-only
//! What every [`KeyManager`] owes the fields it protects, whoever holds its
//! keys. A harness gives the same key source at three moments: `earlier` holds
//! one version, `current` holds that version and a newer one, `without_earlier`
//! holds only the newer one.

use sid_keys::{KeyManager, KeyManagerError};

const RECORD: &str = "totp:conformance-a";
const ANOTHER_RECORD: &str = "totp:conformance-b";

/// A field opens only for the record it was sealed for, under every operation.
pub async fn expected_context_is_enforced(manager: &dyn KeyManager) {
    let field = manager.encrypt(b"secret", RECORD).await.unwrap();
    assert_eq!(manager.decrypt(&field, RECORD).await.unwrap(), b"secret");
    assert!(matches!(
        manager.decrypt(&field, ANOTHER_RECORD).await,
        Err(KeyManagerError::ContextMismatch)
    ));
    assert!(matches!(
        manager.rotate(&field, ANOTHER_RECORD).await,
        Err(KeyManagerError::ContextMismatch)
    ));
}

/// A field of a retained version still opens, is reported stale and rotates
/// to the current version without changing its content or its record.
pub async fn retained_versions_decrypt_and_rotate(
    earlier: &dyn KeyManager,
    current: &dyn KeyManager,
) {
    assert!(current.current_key_version() > earlier.current_key_version());
    let field = earlier.encrypt(b"secret", RECORD).await.unwrap();
    assert_eq!(field.key_version, earlier.current_key_version());
    assert_eq!(current.decrypt(&field, RECORD).await.unwrap(), b"secret");
    assert!(current.needs_rotation(&field));

    let rotated = current.rotate(&field, RECORD).await.unwrap();
    assert_eq!(rotated.key_version, current.current_key_version());
    assert!(!current.needs_rotation(&rotated));
    assert_eq!(current.decrypt(&rotated, RECORD).await.unwrap(), b"secret");
    assert!(matches!(
        current.decrypt(&rotated, ANOTHER_RECORD).await,
        Err(KeyManagerError::ContextMismatch)
    ));
}

/// A version no longer held fails by name: nothing decrypts under another key,
/// and rotation cannot pass over the missing one.
pub async fn missing_key_fails(earlier: &dyn KeyManager, without_earlier: &dyn KeyManager) {
    let field = earlier.encrypt(b"secret", RECORD).await.unwrap();
    let version = field.key_version;
    assert!(matches!(
        without_earlier.decrypt(&field, RECORD).await,
        Err(KeyManagerError::KeyNotFound(v)) if v == version
    ));
    assert!(matches!(
        without_earlier.rotate(&field, RECORD).await,
        Err(KeyManagerError::KeyNotFound(v)) if v == version
    ));
}
