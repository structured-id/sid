use super::*;
use crate::crypto::RustCryptoPrimitives;

fn crypto() -> Arc<dyn CryptoPrimitives> {
    Arc::new(RustCryptoPrimitives::new())
}

fn master() -> SecretBox<[u8; 32]> {
    SecretBox::new(Box::new([0x42u8; 32]))
}

fn other_master() -> SecretBox<[u8; 32]> {
    SecretBox::new(Box::new([0x17u8; 32]))
}

fn params_v1() -> KeyVersionParams {
    KeyVersionParams::new(1, vec![0xA1; 16], "key-v1")
}

fn params_v2() -> KeyVersionParams {
    KeyVersionParams::new(2, vec![0xB2; 16], "key-v2")
}

fn manager_v1() -> SoftwareKeyManager {
    SoftwareKeyManager::new(master(), vec![params_v1()], crypto()).unwrap()
}

fn manager_v1_v2() -> SoftwareKeyManager {
    SoftwareKeyManager::new(master(), vec![params_v1(), params_v2()], crypto()).unwrap()
}

// -- Construction --

#[test]
fn test_new_rejects_empty_versions() {
    let result = SoftwareKeyManager::new(master(), vec![], crypto());
    assert!(matches!(result, Err(KeyManagerError::NotInitialized)));
}

#[test]
fn test_new_rejects_version_zero() {
    let params = KeyVersionParams::new(0, vec![1, 2, 3], "key-v0");
    let result = SoftwareKeyManager::new(master(), vec![params], crypto());
    assert!(matches!(result, Err(KeyManagerError::InvalidVersions(_))));
}

#[test]
fn test_new_rejects_duplicate_version() {
    let result = SoftwareKeyManager::new(master(), vec![params_v1(), params_v1()], crypto());
    assert!(matches!(result, Err(KeyManagerError::InvalidVersions(_))));
}

#[test]
fn test_current_version_is_the_highest_not_the_last_given() {
    // Order of the list must not decide which key encrypts: the highest version does.
    let km = SoftwareKeyManager::new(master(), vec![params_v2(), params_v1()], crypto()).unwrap();
    assert_eq!(km.current_key_version(), 2);
}

#[test]
fn test_known_versions_are_ascending() {
    let km = SoftwareKeyManager::new(master(), vec![params_v2(), params_v1()], crypto()).unwrap();
    assert_eq!(km.known_versions(), vec![1, 2]);
}

#[test]
fn test_non_contiguous_versions_are_accepted() {
    // A deployment that destroyed version 2 still decrypts 1 and writes 3.
    let params_v3 = KeyVersionParams::new(3, vec![0xC3; 16], "key-v3");
    let km = SoftwareKeyManager::new(master(), vec![params_v1(), params_v3], crypto()).unwrap();
    assert_eq!(km.known_versions(), vec![1, 3]);
    assert_eq!(km.current_key_version(), 3);
}

// -- Encrypt / decrypt --

#[tokio::test]
async fn test_encrypt_decrypt_roundtrip() {
    let km = manager_v1();
    let field = km.encrypt(b"totp-secret", "totp:alice").await.unwrap();

    assert_eq!(field.key_version, 1);
    assert_eq!(field.context, "totp:alice");
    assert_ne!(field.ciphertext.as_slice(), b"totp-secret");

    let plaintext = km.decrypt(&field).await.unwrap();
    assert_eq!(plaintext, b"totp-secret");
}

#[tokio::test]
async fn test_encrypt_empty_plaintext() {
    let km = manager_v1();
    let field = km.encrypt(b"", "empty").await.unwrap();
    assert!(km.decrypt(&field).await.unwrap().is_empty());
}

#[tokio::test]
async fn test_each_encryption_uses_a_fresh_nonce() {
    let km = manager_v1();
    let a = km.encrypt(b"same", "ctx").await.unwrap();
    let b = km.encrypt(b"same", "ctx").await.unwrap();

    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);
}

// -- Context binding (anti-swap) --

#[tokio::test]
async fn test_context_swap_is_rejected() {
    let km = manager_v1();
    let mut field = km.encrypt(b"alice-secret", "totp:alice").await.unwrap();

    // Move the ciphertext onto another record by relabelling it.
    field.context = "totp:bob".into();

    let result = km.decrypt(&field).await;
    assert!(matches!(result, Err(KeyManagerError::Decryption(_))));
}

#[tokio::test]
async fn test_ciphertext_tamper_is_rejected() {
    let km = manager_v1();
    let mut field = km.encrypt(b"secret", "ctx").await.unwrap();
    field.ciphertext[0] ^= 0x01;

    let result = km.decrypt(&field).await;
    assert!(matches!(result, Err(KeyManagerError::Decryption(_))));
}

#[tokio::test]
async fn test_nonce_tamper_is_rejected() {
    let km = manager_v1();
    let mut field = km.encrypt(b"secret", "ctx").await.unwrap();
    field.nonce[0] ^= 0x01;

    let result = km.decrypt(&field).await;
    assert!(matches!(result, Err(KeyManagerError::Decryption(_))));
}

#[tokio::test]
async fn test_unknown_version_is_named_in_the_error() {
    let km = manager_v1();
    let mut field = km.encrypt(b"secret", "ctx").await.unwrap();
    field.key_version = 9;

    let result = km.decrypt(&field).await;
    assert!(matches!(result, Err(KeyManagerError::KeyNotFound(9))));
}

#[tokio::test]
async fn test_version_zero_is_not_a_key() {
    let km = manager_v1();
    let mut field = km.encrypt(b"secret", "ctx").await.unwrap();
    field.key_version = 0;

    let result = km.decrypt(&field).await;
    assert!(matches!(result, Err(KeyManagerError::KeyNotFound(0))));
}

// -- Key separation --

#[tokio::test]
async fn test_another_master_cannot_decrypt() {
    let km = manager_v1();
    let field = km.encrypt(b"secret", "ctx").await.unwrap();

    let other = SoftwareKeyManager::new(other_master(), vec![params_v1()], crypto()).unwrap();
    let result = other.decrypt(&field).await;
    assert!(matches!(result, Err(KeyManagerError::Decryption(_))));
}

#[tokio::test]
async fn test_a_different_salt_yields_a_different_key() {
    let km = manager_v1();
    let field = km.encrypt(b"secret", "ctx").await.unwrap();

    // Same master, same version number, salt lost and replaced: the key is gone.
    let wrong_salt = KeyVersionParams::new(1, vec![0xFF; 16], "key-v1");
    let other = SoftwareKeyManager::new(master(), vec![wrong_salt], crypto()).unwrap();
    let result = other.decrypt(&field).await;
    assert!(matches!(result, Err(KeyManagerError::Decryption(_))));
}

#[tokio::test]
async fn test_a_different_context_yields_a_different_key() {
    let km = manager_v1();
    let field = km.encrypt(b"secret", "ctx").await.unwrap();

    let wrong_context = KeyVersionParams::new(1, vec![0xA1; 16], "key-v1-other");
    let other = SoftwareKeyManager::new(master(), vec![wrong_context], crypto()).unwrap();
    let result = other.decrypt(&field).await;
    assert!(matches!(result, Err(KeyManagerError::Decryption(_))));
}

// -- Re-derivation in another process --

#[tokio::test]
async fn test_every_retained_version_re_derives_from_the_same_master() {
    // What one process wrote under each version, a process that starts later
    // with the same master and the same stored parameters must read.
    let first = manager_v1_v2();

    let under_v2 = first.encrypt(b"current", "ctx:current").await.unwrap();
    let mut under_v1 = first.encrypt(b"older", "ctx:older").await.unwrap();
    under_v1 = {
        // Produce a genuine v1 ciphertext by encrypting with a v1-only manager.
        let v1_only = manager_v1();
        let f = v1_only.encrypt(b"older", &under_v1.context).await.unwrap();
        assert_eq!(f.key_version, 1);
        f
    };

    let second = manager_v1_v2();
    assert_eq!(second.decrypt(&under_v2).await.unwrap(), b"current");
    assert_eq!(second.decrypt(&under_v1).await.unwrap(), b"older");
}

// -- Lazy rotation --

#[tokio::test]
async fn test_needs_rotation_reports_stale_versions_only() {
    let km = manager_v1_v2();

    let current = km.encrypt(b"x", "ctx").await.unwrap();
    assert!(!km.needs_rotation(&current));

    let stale = manager_v1().encrypt(b"x", "ctx").await.unwrap();
    assert!(km.needs_rotation(&stale));
}

#[tokio::test]
async fn test_rotate_moves_a_field_to_the_current_version() {
    let km = manager_v1_v2();
    let stale = manager_v1().encrypt(b"payload", "ctx:rot").await.unwrap();
    assert_eq!(stale.key_version, 1);

    let rotated = km.rotate(&stale).await.unwrap();

    assert_eq!(rotated.key_version, 2);
    assert_eq!(rotated.context, "ctx:rot");
    assert_ne!(rotated.ciphertext, stale.ciphertext);
    assert_eq!(km.decrypt(&rotated).await.unwrap(), b"payload");
    assert!(!km.needs_rotation(&rotated));
}

#[tokio::test]
async fn test_rotate_preserves_context_binding() {
    let km = manager_v1_v2();
    let stale = manager_v1()
        .encrypt(b"payload", "totp:alice")
        .await
        .unwrap();

    let mut rotated = km.rotate(&stale).await.unwrap();
    rotated.context = "totp:bob".into();

    let result = km.decrypt(&rotated).await;
    assert!(matches!(result, Err(KeyManagerError::Decryption(_))));
}

#[tokio::test]
async fn test_rotate_fails_on_a_field_whose_version_is_unknown() {
    let km = manager_v1_v2();
    let mut field = km.encrypt(b"payload", "ctx").await.unwrap();
    field.key_version = 42;

    let result = km.rotate(&field).await;
    assert!(matches!(result, Err(KeyManagerError::KeyNotFound(42))));
}

#[tokio::test]
async fn test_rotate_on_a_current_field_is_a_fresh_encryption() {
    let km = manager_v1_v2();
    let field = km.encrypt(b"payload", "ctx").await.unwrap();

    let again = km.rotate(&field).await.unwrap();

    assert_eq!(again.key_version, field.key_version);
    assert_ne!(again.nonce, field.nonce);
    assert_eq!(km.decrypt(&again).await.unwrap(), b"payload");
}

// -- Stored parameters --

#[test]
fn test_key_version_params_serde_roundtrip() {
    let params = params_v2();
    let json = serde_json::to_string(&params).unwrap();
    let back: KeyVersionParams = serde_json::from_str(&json).unwrap();

    assert_eq!(back.version, params.version);
    assert_eq!(back.salt, params.salt);
    assert_eq!(back.algorithm, params.algorithm);
    assert_eq!(back.context, params.context);
}

#[test]
fn test_key_derivation_is_named_in_the_stored_form() {
    // The algorithm travels with the parameters, so a future one cannot be read
    // into an old salt by default.
    let json = serde_json::to_string(&KeyDerivation::HkdfSha256).unwrap();
    assert_eq!(json, "\"hkdf_sha256\"");
}

// -- Object safety --

#[tokio::test]
async fn test_key_manager_is_object_safe() {
    let km: Box<dyn KeyManager> = Box::new(manager_v1());
    let field = km.encrypt(b"through-the-trait", "ctx").await.unwrap();
    assert_eq!(km.decrypt(&field).await.unwrap(), b"through-the-trait");
}

#[test]
fn test_software_key_manager_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SoftwareKeyManager>();
}
