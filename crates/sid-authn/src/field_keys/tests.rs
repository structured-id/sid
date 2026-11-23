// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_crypto::RustCryptoPrimitives;
use std::sync::Mutex;

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

/// A custody's versions in memory: the first insert of a version wins, as
/// the stores' unique version number makes it.
#[derive(Default)]
struct Versions(Mutex<Vec<KeyVersionParams>>);

impl Versions {
    fn with(versions: Vec<KeyVersionParams>) -> Self {
        Self(Mutex::new(versions))
    }
}

#[async_trait::async_trait]
impl KeyVersionStore for Versions {
    async fn versions(&self) -> sid_core::Result<Vec<KeyVersionParams>> {
        Ok(self.0.lock().unwrap().clone())
    }

    async fn insert(&self, params: &KeyVersionParams, _: AuditEntry) -> sid_core::Result<bool> {
        let mut versions = self.0.lock().unwrap();
        if versions.iter().any(|v| v.version == params.version) {
            return Ok(false);
        }
        versions.push(params.clone());
        Ok(true)
    }
}

/// A custody whose versions cannot be read.
struct Unreadable;

#[async_trait::async_trait]
impl KeyVersionStore for Unreadable {
    async fn versions(&self) -> sid_core::Result<Vec<KeyVersionParams>> {
        Err(sid_core::Error::Internal("the store is unreachable".into()))
    }

    async fn insert(&self, _: &KeyVersionParams, _: AuditEntry) -> sid_core::Result<bool> {
        panic!("nothing is inserted when the versions cannot be read")
    }
}

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir()
        .join(format!("sid-field-keys-{}", uuid::Uuid::now_v7().simple()))
        .join(name)
}

fn rust_crypto() -> Arc<dyn CryptoPrimitives> {
    Arc::new(RustCryptoPrimitives::new())
}

/// Failed host entropy on a clean bootstrap creates no master file and
/// publishes no key version.
#[tokio::test]
async fn host_entropy_failure_prevents_key_creation() {
    let path = temp_path("master.key");
    let store = Versions::default();
    assert!(matches!(
        field_key_manager(&store, &path, Arc::new(FailedEntropy)).await,
        Err(FieldKeyError::Crypto(sid_crypto::CryptoError::Entropy))
    ));
    assert!(!path.parent().unwrap().exists());
    assert!(store.versions().await.unwrap().is_empty());
    assert!(matches!(
        load_or_create_versions(&Versions::default(), &FailedEntropy).await,
        Err(FieldKeyError::Crypto(sid_crypto::CryptoError::Entropy))
    ));
}

/// Existing keys retain the host's backend through actual encryption.
#[tokio::test]
async fn key_manager_keeps_the_host_selected_backend() {
    let path = temp_path("master.key");
    let store = Versions::default();
    field_key_manager(&store, &path, rust_crypto())
        .await
        .unwrap();
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

/// A clean bootstrap creates an owner-only 32-byte master and version 1;
/// later starts read the same master and add no version.
#[tokio::test]
async fn a_clean_bootstrap_creates_the_master_and_its_first_version_once() {
    let path = temp_path("master.key");
    let store = Versions::default();
    field_key_manager(&store, &path, rust_crypto())
        .await
        .unwrap();
    let master = std::fs::read(&path).unwrap();
    assert_eq!(master.len(), MASTER_LEN);
    assert_ne!(master, [0u8; MASTER_LEN]);
    assert_eq!(store.versions().await.unwrap().len(), 1);

    field_key_manager(&store, &path, rust_crypto())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), master);
    assert_eq!(store.versions().await.unwrap().len(), 1);
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
    // Nothing but the master is left beside it.
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        1
    );
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

/// The bug: a lost master beside versions made under it was replaced by a
/// fresh random one. The open now fails naming the master to restore, and
/// writes no file and no version.
#[tokio::test]
async fn a_lost_master_is_reported_and_never_replaced() {
    let path = temp_path("master.key");
    let store = Versions::with(vec![KeyVersionParams::new(1, vec![7; 32], "key-v1")]);
    let err = field_key_manager(&store, &path, rust_crypto())
        .await
        .err()
        .expect("a lost master does not open");
    assert!(
        matches!(&err, FieldKeyError::MasterMissing { path: p } if p == &path.display().to_string()),
        "{err:?}"
    );
    assert!(err.to_string().contains("restore"), "{err}");
    assert!(!path.exists());
    assert!(!path.parent().unwrap().exists());
    assert_eq!(store.versions().await.unwrap().len(), 1);
}

/// A store whose versions cannot be read is reported as such: no master is
/// created or read, whatever the file's state.
#[tokio::test]
async fn unreadable_versions_touch_no_master() {
    let path = temp_path("master.key");
    let err = field_key_manager(&Unreadable, &path, rust_crypto())
        .await
        .err()
        .expect("the versions are required");
    assert!(matches!(err, FieldKeyError::Storage(_)), "{err:?}");
    assert!(!path.parent().unwrap().exists());
}

/// Putting the original master back opens the data encrypted before its
/// loss.
#[tokio::test]
async fn the_restored_master_opens_the_earlier_data() {
    let path = temp_path("master.key");
    let store = Versions::default();
    let keys = field_key_manager(&store, &path, rust_crypto())
        .await
        .unwrap();
    let sealed = keys.encrypt(b"earlier data", "ctx").await.unwrap();
    let backup = std::fs::read(&path).unwrap();

    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        field_key_manager(&store, &path, rust_crypto()).await,
        Err(FieldKeyError::MasterMissing { .. })
    ));
    assert!(!path.exists(), "no substitute was written");

    std::fs::write(&path, &backup).unwrap();
    let restored = field_key_manager(&store, &path, rust_crypto())
        .await
        .unwrap();
    let opened = restored.decrypt(&sealed, "ctx").await.unwrap();
    assert_eq!(opened.as_slice(), b"earlier data");
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

/// Concurrent first starts agree on one master: the first published wins,
/// every other reads it whole, and none replaces it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_bootstraps_agree_on_one_master() {
    let path = temp_path("master.key");
    let store = Arc::new(Versions::default());
    let mut starts = Vec::new();
    for _ in 0..16 {
        let (store, path) = (store.clone(), path.clone());
        starts.push(tokio::spawn(async move {
            let keys = field_key_manager(store.as_ref(), &path, rust_crypto())
                .await
                .unwrap();
            keys.encrypt(b"x", "ctx").await.unwrap()
        }));
    }
    let mut sealed = Vec::new();
    for start in starts {
        sealed.push(start.await.unwrap());
    }
    // Every start's key opens every other start's data: one master, one
    // version.
    let keys = field_key_manager(store.as_ref(), &path, rust_crypto())
        .await
        .unwrap();
    for data in &sealed {
        keys.decrypt(data, "ctx").await.unwrap();
    }
    assert_eq!(store.versions().await.unwrap().len(), 1);
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        1,
        "no staging file is left"
    );
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

/// A master another starter already published is read, never replaced,
/// even before any version exists (a bootstrap interrupted after its
/// master).
#[tokio::test]
async fn a_published_master_is_never_replaced() {
    let path = temp_path("master.key");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, [9u8; MASTER_LEN]).unwrap();
    field_key_manager(&Versions::default(), &path, rust_crypto())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), [9u8; MASTER_LEN]);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

/// A custody whose first version may be recorded only after its master's
/// own directory was synced.
struct RecordsAfterSync {
    versions: Versions,
    dir: std::path::PathBuf,
    synced_before: usize,
}

#[async_trait::async_trait]
impl KeyVersionStore for RecordsAfterSync {
    async fn versions(&self) -> sid_core::Result<Vec<KeyVersionParams>> {
        self.versions.versions().await
    }

    async fn insert(&self, params: &KeyVersionParams, audit: AuditEntry) -> sid_core::Result<bool> {
        assert!(
            dir_syncs_of(&self.dir) > self.synced_before,
            "the first version was recorded before the master's name was durable"
        );
        self.versions.insert(params, audit).await
    }
}

/// The bug: a starter that found the master another starter had just linked
/// (or lost the link to it) went on to record the first version before that
/// name was durable, so a power loss could keep the version and lose the
/// master's name. Whoever records the first version syncs the directory
/// first, whether it published the master or took another's.
#[tokio::test]
async fn the_first_version_follows_a_durable_master_name() {
    for published_by_another in [false, true] {
        let path = temp_path("master.key");
        if published_by_another {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, [9u8; MASTER_LEN]).unwrap();
        }
        let dir = path.parent().unwrap().to_path_buf();
        let store = RecordsAfterSync {
            versions: Versions::default(),
            synced_before: dir_syncs_of(&dir),
            dir,
        };
        field_key_manager(&store, &path, rust_crypto())
            .await
            .unwrap();
        assert_eq!(store.versions.versions().await.unwrap().len(), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

/// An established custody's open syncs no directory: the barrier belongs to
/// the bootstrap alone.
#[tokio::test]
async fn an_established_custody_opens_without_a_directory_sync() {
    let path = temp_path("master.key");
    let store = Versions::default();
    field_key_manager(&store, &path, rust_crypto())
        .await
        .unwrap();
    let dir = path.parent().unwrap();
    let before = dir_syncs_of(dir);
    field_key_manager(&store, &path, rust_crypto())
        .await
        .unwrap();
    assert_eq!(dir_syncs_of(dir), before);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

/// Losing the link to a master another starter published is no error, and
/// leaves their master and no staging file behind.
#[test]
fn a_lost_link_keeps_the_winners_master() {
    let path = temp_path("master.key");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, [9u8; MASTER_LEN]).unwrap();
    publish_master(&path, &RustCryptoPrimitives::new(), 7).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), [9u8; MASTER_LEN]);
    assert!(!staging_path(&path, 7).exists());
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

/// The bug: a staging name already taken was removed as if this call had
/// made it, and the collision was taken for a lost publication. It is now an
/// error naming the staging file, which stays as it was; no master is
/// published.
#[test]
fn a_taken_staging_name_is_left_alone_and_reported() {
    let path = temp_path("master.key");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let foreign = staging_path(&path, 7);
    std::fs::write(&foreign, b"another writer's staging").unwrap();
    let err = publish_master(&path, &RustCryptoPrimitives::new(), 7).unwrap_err();
    assert!(
        matches!(&err, FieldKeyError::Io { path: p, source }
            if p == &foreign.display().to_string()
                && source.kind() == std::io::ErrorKind::AlreadyExists),
        "{err:?}"
    );
    assert_eq!(
        std::fs::read(&foreign).unwrap(),
        b"another writer's staging"
    );
    assert!(!path.exists());
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

/// A master file of the wrong length is refused rather than padded, cut or
/// replaced.
#[tokio::test]
async fn master_of_wrong_length_is_refused() {
    let path = temp_path("short.key");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, [7u8; 31]).unwrap();
    for store in [
        Versions::default(),
        Versions::with(vec![KeyVersionParams::new(1, vec![7; 32], "key-v1")]),
    ] {
        let err = field_key_manager(&store, &path, rust_crypto())
            .await
            .err()
            .expect("a short master does not open");
        assert!(matches!(err, FieldKeyError::Length(_)), "{err:?}");
        assert_eq!(std::fs::read(&path).unwrap(), [7u8; 31]);
    }
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
