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
use sid::authorization::{Authorization, InstallationAdministrator};
use sid::lifecycle::{Drained, Engine, EngineParts};
use sid::registration::{PendingRegistration, Registration};
use sid::sign_in::completions::Completer;
use sid::sign_in::{AttemptContext, SignIn, SignInParts};
use sid::snapshot::{ArchiveKey, Store};
use sid::{Installation, InstallationSettings, Maintenance};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::opaque::OpaqueRouter;
use sid_authn::work_runner::{RetrySchedule, RunnerConfig, WorkHandler, WorkOutcome};
use sid_core::models::{
    ClaimedWork, Credential, CredentialData, CredentialType, NewWork, OperationContext,
    OperationKey, ProjectId, WorkKind, WorkState,
};
use sid_pake_core::pallas_opaque::PallasCipherSuite;
use sid_plugin::storage::StorageBackend;

type Failure = Box<dyn std::error::Error>;

const ISSUER: &str = "https://id.sid.example.com";
const WORK_KIND: &str = "host_probe";
const ROOT: &str = "root@sid.example.com";
const GUEST: &str = "guest@sid.example.com";

fn check(holds: bool, what: &str) -> Result<(), Failure> {
    if holds {
        println!("verified: {what}");
        Ok(())
    } else {
        Err(format!("not verified: {what}").into())
    }
}

/// The host's files: the databases and the master key, under one directory.
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
        if let Err(e) = std::fs::remove_dir_all(&self.dir) {
            eprintln!("host directory {} left behind: {e}", self.dir.display());
        }
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

/// What a host serves an installation with: sign-in, administration and
/// authorization management over its parts.
struct Served {
    installation: Installation,
    jwt: Arc<JwtService>,
    sign_in: SignIn,
    admin: Admin,
    authorization: Authorization,
    registration: Registration,
}

impl Served {
    fn new(installation: Installation) -> Result<Self, Failure> {
        let jwt = tokens()?;
        let storage = installation.storage.clone();
        let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
            Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
        let ceremonies: Arc<dyn sid_plugin::CeremonyStateStore> = storage.clone();
        let sign_in = SignIn::new(SignInParts {
            storage: storage.clone(),
            jwt: jwt.clone(),
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
        });
        let cascade = Arc::new(
            sid_authn::revocation_cascade::RevocationCascadeService::new(
                storage.clone(),
                installation.revocation_cache.clone(),
            ),
        );
        Ok(Self {
            admin: Admin::new(storage.clone(), cascade, installation.key_manager.clone()),
            authorization: installation.authorization(sid_authz::cedar::CedarService::new()),
            registration: Registration::new(
                storage,
                installation.key_manager.clone(),
                ISSUER.to_owned(),
            ),
            installation,
            jwt,
            sign_in,
        })
    }

    /// Register `principal` with `password` as its client would: an OPAQUE
    /// registration against the installation's server setup, committed as
    /// the account's first credential.
    async fn register(
        &self,
        principal: &str,
        password: &[u8],
        claim: Option<&SecretString>,
        enabled: bool,
    ) -> Result<(), Failure> {
        let pending = self
            .registration
            .begin(principal, claim.map(|c| c.expose_secret()), None, enabled)
            .await?;
        let PendingRegistration::NewAccount { profile_id, .. } = pending else {
            return Err(format!("{principal} is already registered").into());
        };
        let mut credential = Credential::new(
            profile_id,
            CredentialType::Opaque,
            CredentialData::new(Vec::new()),
            None,
        );
        let record = opaque_registration(
            &self.installation.opaque_router,
            &credential.opaque_credential_identifier(),
            password,
        )?;
        credential.data = CredentialData::new(record.data);
        credential.opaque_curve = Some(record.curve as u8);
        self.registration
            .commit(pending, credential, None, None, enabled)
            .await?;
        Ok(())
    }

    /// `principal` signed in natively with `password`; the caller its
    /// verified token names, and the token.
    async fn password_sign_in(
        &self,
        principal: &str,
        password: &[u8],
    ) -> Result<(Caller, SecretString), Failure> {
        let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
        let login = sid_opaque_ke::ClientLogin::<PallasCipherSuite>::start(&mut rng, password)?;
        let started = self
            .sign_in
            .password_start(principal, &login.message.serialize(), None)
            .await?;
        let response = sid_opaque_ke::CredentialResponse::<PallasCipherSuite>::deserialize(
            &started.credential_response,
        )?;
        let finished = login.state.finish(
            &mut rng,
            password,
            response,
            sid_opaque_ke::ClientLoginFinishParameters::default(),
        )?;
        let policy = sid_authn::login_policy::FixedLoginPolicy::of(
            &sid_core::models::security_policy::SecurityPolicy::ce_default(),
        );
        let signed_in = self
            .sign_in
            .password_sign_in(
                &policy,
                &started.login_id,
                &finished.message.serialize(),
                Completer {
                    client: sid_authn::sign_in_delivery::CeremonyClient::Native,
                    client_ip: None,
                    context: AttemptContext::default(),
                },
                None,
            )
            .await?;
        let sid_authn::sign_in_delivery::Delivery::Bearer { token, .. } =
            signed_in.signed_in.delivery
        else {
            return Err("a native sign-in delivers a bearer token".into());
        };
        let claims = self.jwt.validate_access_token(token.expose_secret())?;
        Ok((Caller::from_claims(&claims)?, token))
    }

    /// Stop serving: every part lets go of the store, then the installation
    /// stops what it runs itself.
    async fn close(self) {
        let Self {
            installation,
            jwt,
            sign_in,
            admin,
            authorization,
            registration,
        } = self;
        drop((jwt, sign_in, admin, authorization, registration));
        installation.close().await;
    }

    async fn administrator(&self, password: &[u8]) -> Result<InstallationAdministrator, Failure> {
        let (caller, _) = self.password_sign_in(ROOT, password).await?;
        Ok(self
            .authorization
            .installation_administrator(&caller)
            .await?)
    }
}

/// The client half of an OPAQUE registration against `router`: the record
/// the server keeps.
fn opaque_registration(
    router: &OpaqueRouter,
    credential_identifier: &[u8],
    password: &[u8],
) -> Result<sid_plugin::crypto::StoredCredential, Failure> {
    let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
    let start = sid_opaque_ke::ClientRegistration::<PallasCipherSuite>::start(&mut rng, password)?;
    let (response, _) =
        router.registration_start(&start.message.serialize(), credential_identifier)?;
    let response =
        sid_opaque_ke::RegistrationResponse::<PallasCipherSuite>::deserialize(&response)?;
    let finished = start.state.finish(
        &mut rng,
        password,
        response,
        sid_opaque_ke::ClientRegistrationFinishParameters::default(),
    )?;
    Ok(router.registration_finish(&finished.message.serialize())?)
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

async fn work_state(storage: &dyn StorageBackend, work: &NewWork) -> Result<WorkState, Failure> {
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
    const PASSWORD: &[u8] = b"correct-horse-battery-staple";
    let crypto = sid_crypto::RustCryptoPrimitives::new();
    let host = Host::new();
    let source = S::open(&host.database("source")).await?;
    let served =
        Served::new(Installation::open(source.backend(), settings(&host.master_key())).await?)?;
    let storage = source.backend();

    // Bootstrap: a fresh installation offers its claim; nobody registers
    // without it, and the first account registered with it administers.
    let claim = served
        .installation
        .admin_claim()
        .await?
        .ok_or("a fresh installation offers its claim")?;
    check(
        served.register(GUEST, PASSWORD, None, true).await.is_err(),
        "no registration without the claim before the installation is claimed",
    )?;
    served.register(ROOT, PASSWORD, Some(&claim), false).await?;
    check(
        served.installation.admin_claim().await?.is_none(),
        "the claim closes once taken",
    )?;
    check(
        served
            .password_sign_in(ROOT, b"a wrong password")
            .await
            .is_err(),
        "a wrong password signs nobody in",
    )?;
    let administrator = served.administrator(PASSWORD).await?;
    println!("verified: the claiming account signs in with its password and administers");

    // A registered user without the role is refused administration.
    served.register(GUEST, PASSWORD, None, true).await?;
    let (guest, guest_token) = served.password_sign_in(GUEST, PASSWORD).await?;
    check(
        served
            .authorization
            .installation_administrator(&guest)
            .await
            .is_err(),
        "a signed-in user without the role administers nothing",
    )?;

    // A keyed command repeated after a lost answer gets its first result.
    let request = || sid_proto::sid::v1::authz::CreateRoleRequest {
        project_id: Some(ProjectId::SYSTEM.into()),
        name: "editor".into(),
        description: None,
        permissions: vec!["documents.write".into()],
    };
    let create = operation(storage.as_ref(), "create-editor").await?;
    let first = served
        .authorization
        .create_role(&administrator, create.clone(), request())
        .await?
        .role
        .ok_or("the created role")?;
    let replayed = served
        .authorization
        .create_role(&administrator, create.clone(), request())
        .await?;
    check(
        replayed.role.as_ref().map(|r| &r.id) == Some(&first.id),
        "a repeated keyed command answers with its first result",
    )?;

    // Revocation: the guest's sessions end and its token stops at once.
    let (root, _) = served.password_sign_in(ROOT, PASSWORD).await?;
    served
        .admin
        .revoke_all_sessions(
            &root,
            operation(storage.as_ref(), "revoke-guest").await?,
            sid_proto::sid::v1::RevokeAllSessionsRequest {
                profile_id: Some(guest.profile_id.into()),
            },
        )
        .await?;
    let guest_claims = served
        .jwt
        .validate_access_token(guest_token.expose_secret())?;
    check(
        sid_authn::caller::check_revocation(&served.installation.revocation_cache, &guest_claims)
            .await?,
        "a revoked session's token is refused",
    )?;

    // Durable work committed while no handler runs: a drain keeps it.
    let kind = WorkKind::new(WORK_KIND)?;
    let work = NewWork::new(kind.clone(), vec![]);
    storage.enqueue_work(&work, 100).await?;
    engine(&storage, vec![]).start().drain().await?;
    check(
        work_state(storage.as_ref(), &work).await? == WorkState::Pending,
        "a drain keeps pending work",
    )?;
    check(
        tokio::spawn(async { 7 }).await? == 7,
        "the host's runtime stays usable after the drain",
    )?;

    // Restart: the host closes its installation and database and reopens
    // them; the same installation opens, its work still pending.
    let organization = served.installation.organization.clone();
    let issuer = served.installation.issuer.clone();
    served.close().await;
    drop((storage, source));
    let source = S::open(&host.database("source")).await?;
    let reopened = Installation::open(source.backend(), settings(&host.master_key())).await?;
    check(
        reopened.organization == organization && reopened.issuer == issuer,
        "a restart reopens the same installation",
    )?;
    check(
        work_state(source.backend().as_ref(), &work).await? == WorkState::Pending,
        "pending work survives the restart",
    )?;
    let drained: Drained = engine(&source.backend(), vec![]).start().drain().await?;

    // Snapshot: exported from the drained engine, imported into an
    // uninitialized store without serving, verified and opened as the same
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
    check(
        sid::snapshot::import(source.store(), &sealed, &key, &crypto)
            .await
            .is_err(),
        "an initialized store takes no archive",
    )?;
    reopened.close().await;
    let restored =
        Served::new(Installation::open(target.backend(), settings(&host.master_key())).await?)?;
    check(
        restored.installation.organization == organization
            && restored.installation.issuer == issuer,
        "the restored installation opens as the same authority",
    )?;

    // The restored installation: its pending work runs once its engine
    // starts, its administrator signs in with the same password, and a keyed
    // command repeated there answers with what the source recorded.
    let target_storage = target.backend();
    let running = engine(&target_storage, vec![Arc::new(Probe(kind))]).start();
    tokio::time::timeout(Duration::from_secs(10), async {
        while work_state(target_storage.as_ref(), &work).await.ok() != Some(WorkState::Completed) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "the restored engine completes the work the source left pending")?;
    println!("verified: the restored engine completes the work the source left pending");
    running.drain().await?;
    let administrator = restored.administrator(PASSWORD).await?;
    let again = restored
        .authorization
        .create_role(&administrator, create, request())
        .await?;
    check(
        again.role.as_ref().map(|r| &r.id) == Some(&first.id),
        "a keyed command repeated after the restore answers with its recorded result",
    )?;
    restored.close().await;
    println!("verified: embedded engine consumer");
    Ok(())
}
