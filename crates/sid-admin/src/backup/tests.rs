// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use sid_crypto::RustCryptoPrimitives;

struct EntropyFailure {
    fail_on: usize,
    calls: std::sync::atomic::AtomicUsize,
}

impl CryptoPrimitives for EntropyFailure {
    fn random_bytes(&self, output: &mut [u8]) -> Result<(), sid_crypto::CryptoError> {
        let call = self
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if call == self.fail_on {
            return Err(sid_crypto::CryptoError::Entropy);
        }
        output.fill(0x35);
        Ok(())
    }

    fn aes_256_gcm_encrypt(
        &self,
        _: &[u8; 32],
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
    ) -> Result<Vec<u8>, sid_crypto::CryptoError> {
        panic!("encryption must not run after entropy failure")
    }

    fn aes_256_gcm_decrypt(
        &self,
        _: &[u8; 32],
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
    ) -> Result<Vec<u8>, sid_crypto::CryptoError> {
        panic!("decryption is outside this scenario")
    }

    fn hmac_sha256(&self, _: &[u8], _: &[u8]) -> [u8; 32] {
        panic!("HMAC is outside this scenario")
    }

    fn hkdf_sha256(
        &self,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: usize,
    ) -> Result<Vec<u8>, sid_crypto::CryptoError> {
        panic!("HKDF is outside this scenario")
    }

    fn pbkdf2_sha256(
        &self,
        _: &[u8],
        _: &[u8],
        _: u32,
        _: &mut [u8],
    ) -> Result<(), sid_crypto::CryptoError> {
        panic!("derivation must not run after entropy failure")
    }

    fn sha256(&self, _: &[u8]) -> [u8; 32] {
        panic!("hashing is outside this scenario")
    }

    fn provider_id(&self) -> &'static str {
        "entropy-failure-test"
    }
    fn is_fips(&self) -> bool {
        false
    }
}

/// Salt and nonce failures must preserve an existing archive and return a typed error.
#[test]
fn entropy_failure_does_not_open_the_archive() {
    for fail_on in [1, 2] {
        let dir = std::env::temp_dir().join(format!("sid-backup-entropy-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("archive");
        std::fs::write(&path, b"existing archive").unwrap();
        let crypto = EntropyFailure {
            fail_on,
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let result = BackupCrypto::new(&crypto).write_backup(
            &path,
            &BackupService::create_manifest(BackupType::Full),
            b"data",
            b"passphrase",
        );
        assert!(matches!(result, Err(BackupError::EntropyUnavailable)));
        assert_eq!(
            crypto.calls.load(std::sync::atomic::Ordering::Relaxed),
            fail_on
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"existing archive");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

fn test_crypto() -> RustCryptoPrimitives {
    RustCryptoPrimitives::new()
}

/// Enough iterations to be the same derivation, few enough that an
/// unoptimized build runs it in milliseconds. These tests check the
/// format, determinism and the failure paths, none of which depend on
/// the work factor; `test_the_shipped_cost_is_the_configured_one` pins
/// the number production actually uses.
const CHEAP_ITERATIONS: u32 = 16;

fn cheap_crypto(crypto: &RustCryptoPrimitives) -> BackupCrypto<'_> {
    BackupCrypto::with_iterations(crypto, CHEAP_ITERATIONS)
}

#[test]
fn test_backup_id_unique() {
    let id1 = BackupId::new();
    let id2 = BackupId::new();
    assert_ne!(id1, id2);
    assert!(id1.0.starts_with("bk-"));
}

#[test]
fn test_create_full_manifest() {
    let manifest = BackupService::create_manifest(BackupType::Full);
    assert_eq!(manifest.backup_type, BackupType::Full);
    assert_eq!(manifest.status, BackupStatus::InProgress);
    assert_eq!(manifest.components.len(), 4);
    assert!(manifest.components.contains(&BackupComponent::Database));
    assert!(manifest.components.contains(&BackupComponent::KeyStore));
    assert!(
        manifest
            .components
            .contains(&BackupComponent::Configuration)
    );
    assert!(manifest.components.contains(&BackupComponent::Certificates));
    assert_eq!(manifest.encryption.algorithm, "AES-256-GCM");
}

#[test]
fn test_create_profile_export_manifest() {
    let manifest = BackupService::create_manifest(BackupType::ProfileExport);
    assert_eq!(manifest.backup_type, BackupType::ProfileExport);
    assert_eq!(manifest.components, vec![BackupComponent::Database]);
}

#[test]
fn test_verify_manifest_valid() {
    let mut manifest = BackupService::create_manifest(BackupType::Full);
    manifest.status = BackupStatus::Verified;
    manifest.encryption = EncryptionInfo::aes256gcm(b"saltsalt", b"noncenonce12");

    // Add checksums for all components.
    for component in &manifest.components {
        manifest
            .checksums
            .insert(format!("{component:?}"), "sha256:abc123".to_string());
    }

    let result = BackupService::verify_manifest(&manifest);
    assert!(result.valid, "errors: {:?}", result.errors);
}

#[test]
fn test_verify_manifest_missing_checksum() {
    let manifest = BackupService::create_manifest(BackupType::Full);
    // No checksums, no encryption info.
    let result = BackupService::verify_manifest(&manifest);
    assert!(!result.valid);
    assert!(!result.errors.is_empty());
}

#[test]
fn test_verify_manifest_empty_encryption() {
    let mut manifest = BackupService::create_manifest(BackupType::Full);
    for component in &manifest.components.clone() {
        manifest
            .checksums
            .insert(format!("{component:?}"), "sha256:abc".to_string());
    }
    // encryption.salt and nonce are empty.
    let result = BackupService::verify_manifest(&manifest);
    assert!(!result.valid);
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("encryption salt or nonce"))
    );
}

#[test]
fn test_validate_restore_not_confirmed() {
    let request = RestoreBackupRequest {
        backup_path: "/backups/test.tar.enc".to_string(),
        confirm_destructive: false,
    };
    let err = BackupService::validate_restore(&request).unwrap_err();
    assert!(err.to_string().contains("confirm-destructive"));
}

#[test]
fn test_validate_restore_empty_path() {
    let request = RestoreBackupRequest {
        backup_path: String::new(),
        confirm_destructive: true,
    };
    let err = BackupService::validate_restore(&request).unwrap_err();
    assert!(err.to_string().contains("empty"));
}

#[test]
fn test_validate_restore_ok() {
    let request = RestoreBackupRequest {
        backup_path: "/backups/test.tar.enc".to_string(),
        confirm_destructive: true,
    };
    assert!(BackupService::validate_restore(&request).is_ok());
}

#[test]
fn test_manifest_serde_roundtrip() {
    let mut manifest = BackupService::create_manifest(BackupType::Full);
    manifest.encryption = EncryptionInfo::aes256gcm(b"salt1234", b"nonce1234567");
    manifest
        .checksums
        .insert("Database".to_string(), "sha256:deadbeef".to_string());

    let json = serde_json::to_string(&manifest).unwrap();
    let deserialized: BackupManifest = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.id, manifest.id);
    assert_eq!(deserialized.backup_type, BackupType::Full);
    assert_eq!(deserialized.encryption.algorithm, "AES-256-GCM");
    assert_eq!(
        deserialized.checksums.get("Database"),
        Some(&"sha256:deadbeef".to_string())
    );
}

#[test]
fn test_encryption_info_aes256gcm() {
    let info = EncryptionInfo::aes256gcm(b"salt", b"nonce");
    assert_eq!(info.algorithm, "AES-256-GCM");
    assert_eq!(info.kdf, "PBKDF2-SHA256");
    assert_eq!(info.kdf_iterations, 600_000);
    assert_eq!(info.salt, hex::encode(b"salt"));
    assert_eq!(info.nonce, hex::encode(b"nonce"));
}

// ── BackupCrypto tests ───────────────────────────────────────

/// The work factor is the point of a passphrase KDF, so the number
/// production runs is asserted rather than assumed, and the manifest
/// records the same one.
#[test]
fn test_the_shipped_cost_is_the_configured_one() {
    assert_eq!(PBKDF2_ITERATIONS, 600_000);
    let crypto = test_crypto();
    assert_eq!(BackupCrypto::new(&crypto).iterations, PBKDF2_ITERATIONS);
    assert_eq!(
        EncryptionInfo::aes256gcm(b"s", b"n").kdf_iterations,
        PBKDF2_ITERATIONS,
        "a manifest must name the cost its data was derived with"
    );
}

#[test]
fn test_derive_key_deterministic() {
    let key1 = cheap_crypto(&test_crypto())
        .derive_key(b"passphrase", b"salt1234salt1234")
        .unwrap();
    let key2 = cheap_crypto(&test_crypto())
        .derive_key(b"passphrase", b"salt1234salt1234")
        .unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn test_derive_key_different_passphrases() {
    let key1 = cheap_crypto(&test_crypto())
        .derive_key(b"pass1", b"salt1234salt1234")
        .unwrap();
    let key2 = cheap_crypto(&test_crypto())
        .derive_key(b"pass2", b"salt1234salt1234")
        .unwrap();
    assert_ne!(key1, key2);
}

#[test]
fn test_derive_key_different_salts() {
    let key1 = cheap_crypto(&test_crypto())
        .derive_key(b"passphrase", b"salt1234salt1234")
        .unwrap();
    let key2 = cheap_crypto(&test_crypto())
        .derive_key(b"passphrase", b"salt5678salt5678")
        .unwrap();
    assert_ne!(key1, key2);
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let plaintext = b"SID backup data: profiles, credentials, sessions";
    let passphrase = b"strong-passphrase-for-test";

    let enc = cheap_crypto(&test_crypto())
        .encrypt(plaintext, passphrase)
        .unwrap();
    assert_ne!(enc.ciphertext, plaintext);

    let decrypted = cheap_crypto(&test_crypto())
        .decrypt(&enc.ciphertext, passphrase, &enc.salt, &enc.nonce)
        .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_produces_different_ciphertexts() {
    let plaintext = b"same data";
    let passphrase = b"passphrase";

    let enc1 = cheap_crypto(&test_crypto())
        .encrypt(plaintext, passphrase)
        .unwrap();
    let enc2 = cheap_crypto(&test_crypto())
        .encrypt(plaintext, passphrase)
        .unwrap();
    // Different salt + nonce each time = different ciphertext.
    assert_ne!(enc1.ciphertext, enc2.ciphertext);
}

#[test]
fn test_decrypt_wrong_passphrase_fails() {
    let enc = cheap_crypto(&test_crypto())
        .encrypt(b"secret", b"correct-pass")
        .unwrap();
    let result =
        cheap_crypto(&test_crypto()).decrypt(&enc.ciphertext, b"wrong-pass", &enc.salt, &enc.nonce);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("decryption failed")
    );
}

#[test]
fn test_decrypt_corrupt_data_fails() {
    let mut enc = cheap_crypto(&test_crypto())
        .encrypt(b"secret", b"pass")
        .unwrap();
    // Corrupt a byte.
    if let Some(byte) = enc.ciphertext.last_mut() {
        *byte ^= 0xff;
    }
    let result =
        cheap_crypto(&test_crypto()).decrypt(&enc.ciphertext, b"pass", &enc.salt, &enc.nonce);
    assert!(result.is_err());
}

#[test]
fn test_write_read_backup_roundtrip() {
    let dir = std::env::temp_dir().join(format!("sid-backup-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.sid-backup");

    let mut manifest = BackupService::create_manifest(BackupType::Full);
    manifest.encryption = EncryptionInfo::aes256gcm(b"placeholder", b"placeholder1");
    for c in &manifest.components.clone() {
        manifest
            .checksums
            .insert(format!("{c:?}"), "sha256:test".to_string());
    }

    let payload = b"database dump + key material + config";
    let passphrase = b"test-passphrase-123";

    cheap_crypto(&test_crypto())
        .write_backup(&path, &manifest, payload, passphrase)
        .unwrap();
    assert!(path.exists());

    let (read_manifest, decrypted) = cheap_crypto(&test_crypto())
        .read_backup(&path, passphrase)
        .unwrap();
    assert_eq!(decrypted, payload);
    assert_eq!(read_manifest.id, manifest.id);
    assert_eq!(read_manifest.backup_type, BackupType::Full);

    // Cleanup.
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_read_backup_wrong_passphrase() {
    let dir = std::env::temp_dir().join(format!("sid-backup-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test2.sid-backup");

    let manifest = BackupService::create_manifest(BackupType::Full);
    cheap_crypto(&test_crypto())
        .write_backup(&path, &manifest, b"data", b"correct")
        .unwrap();

    let result = cheap_crypto(&test_crypto()).read_backup(&path, b"wrong");
    assert!(result.is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_read_backup_corrupt_magic() {
    let dir = std::env::temp_dir().join(format!("sid-backup-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("corrupt.sid-backup");

    std::fs::write(&path, b"NOT_SID_BACKUP").unwrap();
    let result = cheap_crypto(&test_crypto()).read_backup(&path, b"pass");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid magic"));

    let _ = std::fs::remove_dir_all(&dir);
}
