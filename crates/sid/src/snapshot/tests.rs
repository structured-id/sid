use std::path::PathBuf;
use std::sync::Arc;

use sid_authn::jwt::AccessTokenTtl;
use sid_storage::sqlite::SqliteBackend;
use url::Url;

use super::*;
use crate::lifecycle::{Engine, EngineParts};
use crate::{Installation, InstallationSettings, Maintenance};

/// A directory of its own for a master key file, removed at the end.
struct KeyDir(PathBuf);

impl KeyDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("sid-snapshot-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn master(&self) -> PathBuf {
        self.0.join("master.key")
    }
}

impl Drop for KeyDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn settings(master: PathBuf) -> InstallationSettings {
    InstallationSettings {
        issuer: Url::parse("https://id.sid.example.com").unwrap(),
        master_key: master,
        crypto: Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        cache: Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        access_token_ttl: AccessTokenTtl::default(),
        management: None,
    }
}

/// The engine of `storage` started and drained, as a host stops it.
async fn drained(storage: &Arc<SqliteBackend>) -> Drained {
    let storage: Arc<dyn StorageBackend> = storage.clone();
    Engine::new(EngineParts {
        storage,
        worker: format!("test-{}", uuid::Uuid::now_v7()),
        handlers: vec![],
        runner: Default::default(),
        maintenance: Maintenance::default(),
    })
    .unwrap()
    .start()
    .drain()
    .await
    .unwrap()
}

// A drained installation exported and imported into an uninitialized store
// opens there as the same installation: its organization, its issuer with
// the same handle and URL and its signing key, which opens under the same
// master key file. A master key other than the source's opens nothing.
#[tokio::test]
async fn a_restored_installation_opens_as_the_same_authority() {
    let crypto = sid_crypto::RustCryptoPrimitives::new();
    let keys = KeyDir::new();
    let source = Arc::new(SqliteBackend::new_in_memory().await.unwrap());
    let opened = Installation::open(source.clone(), settings(keys.master()))
        .await
        .unwrap();
    let proof = drained(&source).await;
    let key = ArchiveKey::from_bytes(&[3; 32]).unwrap();
    let sealed = export(
        &proof,
        source.as_ref(),
        &source.history_keys(),
        &key,
        &crypto,
    )
    .await
    .unwrap();
    assert_eq!(
        manifest(&sealed).unwrap().installation_org,
        Some(opened.organization.id)
    );

    let target = Arc::new(SqliteBackend::new_in_memory().await.unwrap());
    import(
        target.as_ref(),
        &target.history_keys(),
        &sealed,
        &key,
        &crypto,
    )
    .await
    .unwrap();
    assert!(
        verify(
            source.as_ref(),
            &source.history_keys(),
            target.as_ref(),
            &target.history_keys()
        )
        .await
        .unwrap()
        .passed
    );
    let restored = Installation::open(target.clone(), settings(keys.master()))
        .await
        .unwrap();
    assert_eq!(restored.organization, opened.organization);
    assert_eq!(restored.issuer, opened.issuer);

    // A store restored without its master key file does not open: the
    // issuer's key does not open under another one, and no replacement is made.
    let other = KeyDir::new();
    let copy = Arc::new(SqliteBackend::new_in_memory().await.unwrap());
    import(copy.as_ref(), &copy.history_keys(), &sealed, &key, &crypto)
        .await
        .unwrap();
    assert!(
        Installation::open(copy.clone(), settings(other.master()))
            .await
            .is_err()
    );
}

// An opened installation is not an import destination, and an archive does
// not open under another key; nothing is written to the target.
#[tokio::test]
async fn an_initialized_installation_takes_no_archive() {
    let crypto = sid_crypto::RustCryptoPrimitives::new();
    let keys = KeyDir::new();
    let source = Arc::new(SqliteBackend::new_in_memory().await.unwrap());
    Installation::open(source.clone(), settings(keys.master()))
        .await
        .unwrap();
    let key = ArchiveKey::from_bytes(&[3; 32]).unwrap();
    let sealed = export(
        &drained(&source).await,
        source.as_ref(),
        &source.history_keys(),
        &key,
        &crypto,
    )
    .await
    .unwrap();

    let other_keys = KeyDir::new();
    let initialized = Arc::new(SqliteBackend::new_in_memory().await.unwrap());
    let own = Installation::open(initialized.clone(), settings(other_keys.master()))
        .await
        .unwrap();
    assert!(matches!(
        import(
            initialized.as_ref(),
            &initialized.history_keys(),
            &sealed,
            &key,
            &crypto
        )
        .await,
        Err(SnapshotError::Target(_))
    ));
    assert_eq!(
        initialized.instance_organization().await.unwrap(),
        Some(own.organization)
    );

    let blank = Arc::new(SqliteBackend::new_in_memory().await.unwrap());
    let wrong = ArchiveKey::from_bytes(&[4; 32]).unwrap();
    assert!(matches!(
        import(
            blank.as_ref(),
            &blank.history_keys(),
            &sealed,
            &wrong,
            &crypto
        )
        .await,
        Err(SnapshotError::Archive(_))
    ));
    assert!(blank.instance_organization().await.unwrap().is_none());
}
