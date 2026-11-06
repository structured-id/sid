use std::sync::Arc;

use sid_core::models::{BootstrapPolicy, InstanceSecret, Profile, Role, RoleAssignment};
use sid_plugin::StorageBackend;

use super::*;

async fn sqlite() -> Arc<sid_storage::sqlite::SqliteBackend> {
    Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    )
}

/// A master key path of its own, removed with the directory at the end.
struct MasterKey(PathBuf);

impl MasterKey {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("sid-installation-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> PathBuf {
        self.0.join("master.key")
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn settings(master: &MasterKey, management: Option<Management>) -> InstallationSettings {
    InstallationSettings {
        issuer: Url::parse("https://id.sid.example.com").unwrap(),
        master_key: master.path(),
        crypto: Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        cache: Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        access_token_ttl: AccessTokenTtl::default(),
        management,
    }
}

/// Whether a claim is stored.
async fn claim(storage: &dyn StorageBackend) -> Option<()> {
    storage
        .get_instance_secret(InstanceSecret::AdminClaim)
        .await
        .unwrap()
        .map(|_| ())
}

/// Store `root`, an installation administrator as role administration makes
/// one.
async fn store_administrator(storage: &dyn StorageBackend) {
    let root = Profile::new(Some("root"));
    storage
        .create_profile(&root, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    storage
        .create_role(
            &Role::installation_administrator(),
            AuditEntry::system("test", "role").into(),
        )
        .await
        .unwrap();
    storage
        .create_role_assignment(
            &RoleAssignment::new(
                sid_core::models::RoleAssignmentPrincipal::Profile(root.id),
                Role::installation_administrator().id,
            )
            .on_installation(),
            AuditEntry::system("test", "assignment").into(),
        )
        .await
        .unwrap();
}

/// The first open creates the organization named by the issuer's host and
/// its issuer; a later open, as a restart or another replica does, finds the
/// same organization, issuer, resources and keys.
#[tokio::test]
async fn an_installation_reopens_as_it_was_created() {
    let (storage, master) = (sqlite().await, MasterKey::new());
    let first = Installation::open(storage.clone(), settings(&master, None))
        .await
        .unwrap();
    assert_eq!(first.organization.canonical_domain, "id.sid.example.com");
    assert_eq!(first.issuer.recipient_org, first.organization.id);

    let again = Installation::open(storage, settings(&master, None))
        .await
        .unwrap();
    assert_eq!(again.organization.id, first.organization.id);
    assert_eq!(again.issuer.id, first.issuer.id);
    assert_eq!(again.authorization_api.id, first.authorization_api.id);
    assert_eq!(again.enrollment_api.id, first.enrollment_api.id);
    assert_eq!(again.captcha_pow_key, first.captcha_pow_key);
}

/// A store opened under another master key does not open: its sealed issuer
/// key would not open, so nothing would be signed with a key its published
/// set lacks.
#[tokio::test]
async fn another_master_key_does_not_open_the_installation() {
    let storage = sqlite().await;
    let (master, other) = (MasterKey::new(), MasterKey::new());
    Installation::open(storage.clone(), settings(&master, None))
        .await
        .unwrap();
    assert!(
        Installation::open(storage, settings(&other, None))
            .await
            .is_err()
    );
}

/// An issuer without a host names no organization and is refused.
#[tokio::test]
async fn an_issuer_without_a_host_is_refused() {
    let master = MasterKey::new();
    let mut hostless = settings(&master, None);
    hostless.issuer = Url::parse("unix:/run/sid").unwrap();
    assert!(matches!(
        Installation::open(sqlite().await, hostless).await,
        Err(InstallationError::IssuerHost(_))
    ));
}

/// A fresh installation offers its administrator claim; one with an
/// administrator offers none. Opening grants no role.
#[tokio::test]
async fn the_claim_is_open_only_without_an_administrator() {
    let master = MasterKey::new();
    let storage = sqlite().await;
    let installation = Installation::open(storage.clone(), settings(&master, None))
        .await
        .unwrap();
    assert!(installation.admin_claim().await.unwrap().is_some());
    assert!(claim(storage.as_ref()).await.is_some());
    assert!(!storage.admin_exists().await.unwrap());

    let storage = sqlite().await;
    store_administrator(storage.as_ref()).await;
    let installation = Installation::open(storage.clone(), settings(&master, None))
        .await
        .unwrap();
    assert!(installation.admin_claim().await.unwrap().is_none());
    assert!(claim(storage.as_ref()).await.is_none());
}

/// Central management removes a claim offered earlier and offers none, opens
/// again unchanged, and is kept when the host names no management.
#[tokio::test]
async fn a_centrally_managed_installation_offers_no_claim() {
    let master = MasterKey::new();
    let storage = sqlite().await;
    let installation = Installation::open(storage.clone(), settings(&master, None))
        .await
        .unwrap();
    installation.admin_claim().await.unwrap();

    for management in [Some(Management::Central), Some(Management::Central), None] {
        let installation = Installation::open(storage.clone(), settings(&master, management))
            .await
            .unwrap();
        assert!(
            installation.admin_claim().await.unwrap().is_none(),
            "{management:?}"
        );
        assert!(claim(storage.as_ref()).await.is_none(), "{management:?}");
    }
    assert_eq!(
        storage.bootstrap_policy().await.unwrap(),
        BootstrapPolicy::CentrallyManaged
    );
}

/// A centrally managed installation never opens self-managed, and a claimed
/// self-managed one never opens centrally managed; neither refusal changes it.
#[tokio::test]
async fn the_management_of_an_installation_does_not_change() {
    let master = MasterKey::new();
    let storage = sqlite().await;
    Installation::open(
        storage.clone(),
        settings(&master, Some(Management::Central)),
    )
    .await
    .unwrap();
    assert!(matches!(
        Installation::open(
            storage.clone(),
            settings(&master, Some(Management::SelfManaged))
        )
        .await,
        Err(InstallationError::CentrallyManaged)
    ));
    assert_eq!(
        storage.bootstrap_policy().await.unwrap(),
        BootstrapPolicy::CentrallyManaged
    );

    let storage = sqlite().await;
    store_administrator(storage.as_ref()).await;
    assert!(matches!(
        Installation::open(
            storage.clone(),
            settings(&master, Some(Management::Central))
        )
        .await,
        Err(InstallationError::LocalAdministrator)
    ));
    assert_eq!(
        storage.bootstrap_policy().await.unwrap(),
        BootstrapPolicy::SelfManaged
    );
}

/// A store whose administrators cannot be read offers no claim and reports
/// the failure, rather than reading as a fresh installation.
#[tokio::test]
async fn an_unreadable_store_is_reported() {
    let master = MasterKey::new();
    let storage = sqlite().await;
    let installation = Installation::open(storage.clone(), settings(&master, None))
        .await
        .unwrap();
    // The administrators are read from the role assignments.
    sqlx::query("DROP TABLE role_assignments")
        .execute(storage.pool())
        .await
        .unwrap();
    assert!(installation.admin_claim().await.is_err());
}
