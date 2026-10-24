// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use secrecy::ExposeSecret;
use sid_crypto::RustCryptoPrimitives;

struct FailedEntropy;

impl CryptoPrimitives for FailedEntropy {
    fn random_bytes(&self, _: &mut [u8]) -> Result<(), sid_crypto::CryptoError> {
        Err(sid_crypto::CryptoError::Entropy)
    }

    fn aes_256_gcm_encrypt(
        &self,
        _: &[u8; 32],
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
    ) -> Result<Vec<u8>, sid_crypto::CryptoError> {
        panic!("encryption must not start after entropy failure")
    }

    fn aes_256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        data: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, sid_crypto::CryptoError> {
        RustCryptoPrimitives::new().aes_256_gcm_decrypt(key, nonce, data, aad)
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        RustCryptoPrimitives::new().hmac_sha256(key, data)
    }

    fn hkdf_sha256(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, sid_crypto::CryptoError> {
        RustCryptoPrimitives::new().hkdf_sha256(ikm, salt, info, length)
    }

    fn pbkdf2_sha256(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8],
    ) -> Result<(), sid_crypto::CryptoError> {
        RustCryptoPrimitives::new().pbkdf2_sha256(password, salt, iterations, output)
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        RustCryptoPrimitives::new().sha256(data)
    }

    fn provider_id(&self) -> &'static str {
        "failed-entropy-test"
    }
    fn is_fips(&self) -> bool {
        false
    }
}

struct Versions(Vec<KeyVersionParams>);

#[async_trait::async_trait]
impl KeyVersionStore for Versions {
    async fn versions(&self) -> sid_core::Result<Vec<KeyVersionParams>> {
        Ok(self.0.clone())
    }

    async fn insert(&self, _: &KeyVersionParams, _: AuditEntry) -> sid_core::Result<bool> {
        panic!("no version can be inserted without entropy")
    }
}

/// Failed host entropy must not create a master file or publish a key version.
#[tokio::test]
async fn host_entropy_failure_prevents_key_creation() {
    let path = temp_path("master.key");
    assert!(matches!(
        load_or_create_master(&path, &FailedEntropy),
        Err(FieldKeyError::Crypto(sid_crypto::CryptoError::Entropy))
    ));
    assert!(!path.parent().unwrap().exists());
    assert!(matches!(
        load_or_create_versions(&Versions(Vec::new()), &FailedEntropy).await,
        Err(FieldKeyError::Crypto(sid_crypto::CryptoError::Entropy))
    ));
}

/// Existing keys must retain the host's backend through actual encryption.
#[tokio::test]
async fn key_manager_keeps_the_host_selected_backend() {
    let path = temp_path("master.key");
    load_or_create_master(&path, &RustCryptoPrimitives::new()).unwrap();
    let store = Versions(vec![KeyVersionParams::new(1, vec![7; 32], "test-version")]);
    let manager = field_key_manager(&store, &path, Arc::new(FailedEntropy))
        .await
        .unwrap();
    assert!(matches!(
        manager.encrypt(b"secret", "test-context").await,
        Err(sid_keys::KeyManagerError::Crypto(
            sid_crypto::CryptoError::Entropy
        ))
    ));
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir()
        .join(format!("sid-field-keys-{}", uuid::Uuid::now_v7().simple()))
        .join(name)
}

/// A missing master file is created once; later starts read the same secret.
#[test]
fn master_is_created_once_and_reused() {
    let path = temp_path("master.key");
    let crypto = RustCryptoPrimitives::new();
    let first = load_or_create_master(&path, &crypto).unwrap();
    let second = load_or_create_master(&path, &crypto).unwrap();
    assert_eq!(first.expose_secret(), second.expose_secret());
    assert_ne!(first.expose_secret(), &[0u8; 32]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "master key must be owner-only, got {mode:o}"
        );
    }
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

/// A master file of the wrong length is refused rather than padded or cut.
#[test]
fn master_of_wrong_length_is_refused() {
    let path = temp_path("short.key");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, [7u8; 31]).unwrap();
    let err = load_or_create_master(&path, &RustCryptoPrimitives::new()).unwrap_err();
    assert!(matches!(err, FieldKeyError::Length(_)), "{err:?}");
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
