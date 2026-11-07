//! An application embedding the packaged engine as an external host would:
//! its own runtime, store, keys and crypto provider, nothing from the
//! workspace that built the archives. The host's store is SQLite or its own
//! CoordiNode database, named by the first argument. Each step states what
//! it shows and fails the process when the engine does otherwise.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use sid::admin::Admin;
use sid::lifecycle::{Drained, Engine, EngineParts};
use sid::sign_in::{SignIn, SignInParts};
use sid::snapshot::{ArchiveKey, Store};
use sid::{Installation, InstallationSettings, Maintenance};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::work_runner::{RetrySchedule, RunnerConfig, WorkHandler, WorkOutcome};
use sid_core::models::{
    AuditEntry, ClaimedWork, NewWork, OperationContext, OperationKey, Profile, ProjectId, WorkKind,
    WorkState,
};
use sid_plugin::storage::StorageBackend;

type Failure = Box<dyn std::error::Error>;

const ISSUER: &str = "https://id.sid.example.com";
const WORK_KIND: &str = "host_probe";

fn check(holds: bool, what: &str) -> Result<(), Failure> {
    if holds {
        println!("verified: {what}");
        Ok(())
    } else {
        Err(format!("not verified: {what}").into())
    }
}

/// The host's files: the database and the master key, under one directory.
struct Host {
    dir: PathBuf,
}

impl Host {
    fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("sid-engine-consumer-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("host directory");
        Self { dir }
    }

    fn database(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn master_key(&self) -> PathBuf {
        self.dir.join("master.key")
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn settings(master_key: &Path) -> InstallationSettings {
    InstallationSettings {
        issuer: url::Url::parse(ISSUER).expect("issuer URL"),
        master_key: master_key.to_path_buf(),
        crypto: Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        cache: Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        access_token_ttl: sid_authn::jwt::AccessTokenTtl::default(),
        management: None,
        sod_warnings: Vec::new(),
    }
}

/// The host's token service, over its own signing key.
fn tokens() -> Result<Arc<JwtService>, Failure> {
    Ok(Arc::new(JwtService::new(
        include_bytes!("../keys/test_ed25519_private.pem"),
        include_bytes!("../keys/test_ed25519_public.pem"),
        ISSUER.to_owned(),
    )?))
}

/// Signing in over the installation's own parts and the host's tokens.
fn sign_in(installation: &Installation, jwt: Arc<JwtService>) -> SignIn {
    let storage = installation.storage.clone();
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let ceremonies: Arc<dyn sid_plugin::CeremonyStateStore> = storage.clone();
    SignIn::new(SignInParts {
        storage,
        jwt,
        revocation: installation.revocation_cache.clone(),
        issuer: ISSUER.to_owned(),
        anomaly: Arc::new(sid_authn::anomaly::AnomalyDetector::ce_default(
            ceremonies.clone(),
        )),
        ip_intelligence: Arc::new(sid_authn::ip_intelligence::IpIntelligenceAggregator::new(
            vec![],
            cache.clone(),
            Duration::from_secs(60),
        )),
        geoip: Arc::new(sid_authn::geoip::GeoIpChain::empty(cache)),
        captcha_gate: sid_authn::captcha::CaptchaGate::new(
            ceremonies,
            installation.key_manager.clone(),
        ),
        captcha_provider: Arc::new(sid_authn::captcha::SidPowProvider::new(
            installation.captcha_pow_key,
            4,
            300,
        )),
        opaque: installation.opaque_router.clone(),
        keys: installation.key_manager.clone(),
    })
}

/// `profile` signed in natively; the caller its verified token names.
async fn caller(
    sign_in: &SignIn,
    jwt: &JwtService,
    profile: &Profile,
) -> Result<(Caller, SecretString), Failure> {
    let signed_in = sign_in
        .sign_in(
            profile,
            sign_in.new_session(profile.id, None),
            sid_authn::sign_in_delivery::CeremonyClient::Native,
            None,
            None,
            None,
            None,
        )
        .await?;
    let sid_authn::sign_in_delivery::Delivery::Bearer { token, .. } = signed_in.delivery else {
        return Err("a native sign-in delivers a bearer token".into());
    };
    let claims = jwt.validate_access_token(token.expose_secret())?;
    Ok((Caller::from_claims(&claims)?, token))
}

async fn stored_profile(storage: &dyn StorageBackend, name: &str) -> Result<Profile, Failure> {
    let profile = Profile::new(Some(name));
    storage
        .create_profile(&profile, AuditEntry::system("host", "profile").into())
        .await?;
    Ok(profile)
}

/// The next keyed call's operation context, named `key`.
async fn operation(storage: &dyn StorageBackend, key: &str) -> Result<OperationContext, Failure> {
    let period = storage
        .current_operation_period(chrono::Utc::now(), chrono::Duration::hours(1))
        .await?
        .period;
    Ok(OperationContext::new(OperationKey::parse(key)?, period))
}

/// The host's own work kind, done at its first attempt.
struct Probe(WorkKind);

#[async_trait::async_trait]
impl WorkHandler for Probe {
    fn kind(&self) -> &WorkKind {
        &self.0
    }

    fn retry_schedule(&self) -> RetrySchedule {
        const RETRY: RetrySchedule = RetrySchedule::new(&[Duration::from_millis(10)]);
        RETRY
    }

    fn on_dead(&self, _: &ClaimedWork, _: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, _: &ClaimedWork) -> WorkOutcome {
        WorkOutcome::Done(None)
    }
}

fn engine(storage: &Arc<dyn StorageBackend>, handlers: Vec<Arc<dyn WorkHandler>>) -> Engine {
    Engine::new(EngineParts {
        storage: storage.clone(),
        worker: format!("host-{}", uuid::Uuid::now_v7()),
        handlers,
        runner: RunnerConfig {
            concurrency: 2,
            lease: Duration::from_secs(30),
            scan_interval: Duration::from_millis(10),
        },
        maintenance: Maintenance::default(),
    })
    .expect("the engine takes its handlers")
}

async fn work_state(
    storage: &Arc<dyn StorageBackend>,
    work: &NewWork,
) -> Result<WorkState, Failure> {
    Ok(storage
        .get_work(work.id)
        .await?
        .ok_or("the work is stored")?
        .state)
}

/// The host's database at a path, with the stores a snapshot reads and
/// writes.
trait HostStore: Sized {
    async fn open(path: &Path) -> Result<Self, Failure>;
    fn backend(&self) -> Arc<dyn StorageBackend>;
    fn store(&self) -> Store<'_>;
}

#[cfg(feature = "sqlite")]
struct SqliteHost {
    backend: Arc<sid_storage::sqlite::SqliteBackend>,
    audit: sid_storage::sqlite::SqliteAuditLog,
    keys: sid_storage::sqlite::SqliteHistoryKeyStore,
}

#[cfg(feature = "sqlite")]
impl HostStore for SqliteHost {
    async fn open(path: &Path) -> Result<Self, Failure> {
        let path = path.to_str().ok_or("a UTF-8 database path")?;
        let backend = Arc::new(sid_storage::sqlite::SqliteBackend::new(path).await?);
        Ok(Self {
            audit: sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone()),
            keys: backend.history_keys(),
            backend,
        })
    }

    fn backend(&self) -> Arc<dyn StorageBackend> {
        self.backend.clone()
    }

    fn store(&self) -> Store<'_> {
        Store {
            storage: self.backend.as_ref(),
            audit: &self.audit,
            history_keys: &self.keys,
        }
    }
}

/// The host's own CoordiNode database in a directory, SID's records in it.
#[cfg(feature = "coordinode")]
struct CoordinodeHost {
    backend: Arc<sid_storage::coordinode::CoordinodeBackend>,
    keys: sid_storage::coordinode::CoordinodeHistoryKeyStore,
}

#[cfg(feature = "coordinode")]
impl HostStore for CoordinodeHost {
    async fn open(path: &Path) -> Result<Self, Failure> {
        let path = path.to_path_buf();
        let db =
            tokio::task::spawn_blocking(move || coordinode_embed::Database::open(path)).await??;
        let backend =
            Arc::new(sid_storage::coordinode::CoordinodeBackend::new(Arc::new(db)).await?);
        Ok(Self {
            keys: backend.history_keys(),
            backend,
        })
    }

    fn backend(&self) -> Arc<dyn StorageBackend> {
        self.backend.clone()
    }

    fn store(&self) -> Store<'_> {
        Store {
            storage: self.backend.as_ref(),
            audit: self.backend.as_ref(),
            history_keys: &self.keys,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Failure> {
    // The host's selection: pure-Rust primitives and JWT provider.
    sid_crypto::jwt::rustcrypto::provider()
        .install_default()
        .map_err(|_| "a JWT provider was installed before the host's")?;
    match std::env::args().nth(1).as_deref() {
        #[cfg(feature = "sqlite")]
        Some("sqlite") => run::<SqliteHost>().await,
        #[cfg(feature = "coordinode")]
        Some("coordinode") => run::<CoordinodeHost>().await,
        other => Err(format!("no host store {other:?} in this build").into()),
    }
}

async fn run<S: HostStore>() -> Result<(), Failure> {
    let crypto = sid_crypto::RustCryptoPrimitives::new();
    let host = Host::new();
    let source = S::open(&host.database("source")).await?;
    let storage = source.backend();

    // Bootstrap: a fresh installation offers its administrator claim.
    let installation = Installation::open(storage.clone(), settings(&host.master_key())).await?;
    let claim = installation
        .admin_claim()
        .await?
        .ok_or("a fresh installation offers its claim")?;
    let jwt = tokens()?;
    let sign_in = sign_in(&installation, jwt.clone());
    let cascade = Arc::new(
        sid_authn::revocation_cascade::RevocationCascadeService::new(
            storage.clone(),
            installation.revocation_cache.clone(),
        ),
    );
    let admin = Admin::new(storage.clone(), cascade, installation.key_manager.clone());
    let authorization = installation.authorization(sid_authz::cedar::CedarService::new());

    let root = stored_profile(storage.as_ref(), "root").await?;
    let (unclaimed, _) = caller(&sign_in, &jwt, &root).await?;
    check(
        authorization
            .installation_administrator(&unclaimed)
            .await
            .is_err(),
        "no administrator before the claim",
    )?;
    admin.claim_instance(&unclaimed, &claim).await?;
    check(
        installation.admin_claim().await?.is_none(),
        "the claim closes once taken",
    )?;

    // Allowed and denied management.
    let (root_caller, _) = caller(&sign_in, &jwt, &root).await?;
    let administrator = authorization
        .installation_administrator(&root_caller)
        .await?;
    let guest = stored_profile(storage.as_ref(), "guest").await?;
    let (guest_caller, guest_token) = caller(&sign_in, &jwt, &guest).await?;
    check(
        authorization
            .installation_administrator(&guest_caller)
            .await
            .is_err(),
        "a signed-in user without the role administers nothing",
    )?;
    let request = || sid_proto::sid::v1::authz::CreateRoleRequest {
        project_id: Some(ProjectId::SYSTEM.into()),
        name: "editor".into(),
        description: None,
        permissions: vec!["documents.write".into()],
    };
    let create = operation(storage.as_ref(), "create-editor").await?;
    let first = authorization
        .create_role(&administrator, create.clone(), request())
        .await?;
    // The answer was lost: the host repeats the same keyed command.
    let replayed = authorization
        .create_role(&administrator, create, request())
        .await?;
    check(
        first.role.as_ref().map(|r| &r.id) == replayed.role.as_ref().map(|r| &r.id),
        "a repeated keyed command answers with its first result",
    )?;

    // Revocation: the guest's sessions end and its token stops at once.
    admin
        .revoke_all_sessions(
            &root_caller,
            operation(storage.as_ref(), "revoke-guest").await?,
            sid_proto::sid::v1::RevokeAllSessionsRequest {
                profile_id: Some(guest.id.into()),
            },
        )
        .await?;
    let guest_claims = jwt.validate_access_token(guest_token.expose_secret())?;
    check(
        sid_authn::caller::check_revocation(&installation.revocation_cache, &guest_claims).await?,
        "a revoked session's token is refused",
    )?;

    // Durable work: committed while no handler runs, kept by a drain, done
    // after a new start.
    let kind = WorkKind::new(WORK_KIND)?;
    let work = NewWork::new(kind.clone(), vec![]);
    storage.enqueue_work(&work, 100).await?;
    engine(&storage, vec![]).start().drain().await?;
    check(
        work_state(&storage, &work).await? == WorkState::Pending,
        "a drain keeps pending work",
    )?;
    let running = engine(&storage, vec![Arc::new(Probe(kind))]).start();
    tokio::time::timeout(Duration::from_secs(10), async {
        while work_state(&storage, &work).await.ok() != Some(WorkState::Completed) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "the restarted engine completes the pending work")?;
    println!("verified: the restarted engine completes the pending work");
    let drained: Drained = running.drain().await?;
    check(
        tokio::spawn(async { 7 }).await? == 7,
        "the host's runtime stays usable after the drain",
    )?;

    // Restart: the host closes its database and reopens it; the store and
    // the master key open the same installation.
    let organization = installation.organization.clone();
    let issuer = installation.issuer.clone();
    drop((sign_in, admin, authorization));
    installation.close().await;
    drop((storage, source));
    let source = S::open(&host.database("source")).await?;
    let reopened = Installation::open(source.backend(), settings(&host.master_key())).await?;
    check(
        reopened.organization == organization && reopened.issuer == issuer,
        "a restart reopens the same installation",
    )?;

    // Snapshot: exported from the drained engine, imported into an
    // uninitialized store without serving, verified, opened as the same
    // authority; an initialized store takes no archive.
    let key = ArchiveKey::from_bytes(&[7; 32])?;
    let sealed = sid::snapshot::export(&drained, source.store(), &key, &crypto).await?;
    let target = S::open(&host.database("target")).await?;
    sid::snapshot::import(target.store(), &sealed, &key, &crypto).await?;
    check(
        sid::snapshot::verify(source.store(), target.store())
            .await?
            .passed,
        "the restored store equals its source",
    )?;
    let restored = Installation::open(target.backend(), settings(&host.master_key())).await?;
    check(
        restored.organization == organization && restored.issuer == issuer,
        "the restored installation opens as the same authority",
    )?;
    check(
        sid::snapshot::import(source.store(), &sealed, &key, &crypto)
            .await
            .is_err(),
        "an initialized store takes no archive",
    )?;
    println!("verified: embedded engine consumer");
    Ok(())
}
