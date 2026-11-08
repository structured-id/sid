//! An application embedding the packaged engine as an external host would:
//! its own runtime, store, keys and crypto provider, nothing from the
//! workspace that built the archives. The host's store is SQLite or its own
//! CoordiNode database, named by the first argument. Each step states what
//! it shows and fails the process when the engine does otherwise.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ff::PrimeField;
use group::GroupEncoding;
use pasta_curves::pallas;
use secrecy::{ExposeSecret, SecretString};
use sid::admin::Admin;
use sid::auth_mail::{AuthMailDelivery, MailError, OwedMail};
use sid::authorization::{Authorization, InstallationAdministrator};
use sid::lifecycle::{Drained, Engine, EngineParts};
use sid::password_operation::PasswordOperations;
use sid::registration::Registration;
use sid::sign_in::completions::Completer;
use sid::sign_in::{AttemptContext, SignIn, SignInParts};
use sid::snapshot::{ArchiveKey, Store};
use sid::work::{CeMail, CeWork, CeWorkParts};
use sid::{Installation, InstallationSettings};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::opaque_zkpp::ZkppOpaqueServer;
use sid_authn::opaque_zkpp::setup::{ZkppSettings, spawn_zkpp_server};
use sid_authn::password_operation::{HistoryEvaluation, PasswordHistoryAuthority};
use sid_authn::work_runner::{RetrySchedule, RunnerConfig, WorkHandler, WorkOutcome};
use sid_core::models::security_policy::SecurityPolicy;
use sid_core::models::{
    ClaimedWork, NewWork, OperationContext, OperationKey, ProjectId, WorkKind, WorkState,
};
use sid_pake_core::binding::operation_context;
use sid_pake_core::circuit::{CircuitShape, ZKPP_K};
use sid_pake_core::client::{ComparisonDomain, EvaluatorAnswer};
use sid_pake_core::history::EvaluationProof;
use sid_pake_core::pallas_opaque::PallasCipherSuite;
use sid_pake_core::prover::ZkppProver;
use sid_pake_core::types::CE_DEFAULT_POLICY;
use sid_plugin::history_keys::HistoryKeyStore;
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::authn::{OpaqueZkppRegistrationFinishRequest, PasswordRegistrationProof};

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

/// What a host serves an installation with: sign-in, registration,
/// administration and authorization management over its parts.
struct Served {
    installation: Installation,
    jwt: Arc<JwtService>,
    sign_in: SignIn,
    admin: Admin,
    authorization: Authorization,
    registration: Registration,
    /// The installation's password operations; its history evaluator runs
    /// in the host's process, over the host's database (`history`).
    passwords: PasswordOperations,
    history: Arc<HistoryEvaluation>,
}

/// Whether a registration's finish carries the client's proof.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Proof {
    Made,
    Omitted,
}

/// An application's client of password registration: the ZKPP prover of
/// each history shape it was asked for, under the CE policy.
#[derive(Default)]
struct Client {
    provers: BTreeMap<usize, ZkppProver>,
}

impl Client {
    fn prover(&mut self, history_domains: usize) -> Result<&ZkppProver, Failure> {
        if let std::collections::btree_map::Entry::Vacant(slot) =
            self.provers.entry(history_domains)
        {
            let shape = CircuitShape {
                policy: CE_DEFAULT_POLICY,
                history_domains,
            };
            let params = sid_pake_core::keygen::generate_params(ZKPP_K);
            let pk = sid_pake_core::keygen::generate_pk(&params, shape)
                .map_err(|e| format!("proving key: {e:?}"))?;
            slot.insert(ZkppProver::new(params, pk, shape));
        }
        Ok(&self.provers[&history_domains])
    }
}

/// The installation's ZKPP server, once its verifying keys are made from
/// the parameters cached under `cache`; proofs are required.
async fn zkpp_server(
    installation: &Installation,
    cache: &Path,
) -> Result<Arc<ZkppOpaqueServer>, Failure> {
    let slot = spawn_zkpp_server(
        &installation.opaque_router,
        &ZkppSettings::parse(None, None, None)?,
        cache,
    )?;
    Ok(tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            if let Some(server) = Option::clone(&slot.load_full()) {
                return server;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "the ZKPP verifying keys are made")?)
}

fn array32(bytes: &[u8], what: &str) -> Result<[u8; 32], Failure> {
    Ok(bytes.try_into().map_err(|_| format!("{what}: 32 bytes"))?)
}

fn base(bytes: &[u8], what: &str) -> Result<pallas::Base, Failure> {
    Ok(Option::from(pallas::Base::from_repr(array32(bytes, what)?))
        .ok_or_else(|| format!("{what}: a base-field element"))?)
}

fn scalar(bytes: &[u8], what: &str) -> Result<pallas::Scalar, Failure> {
    Ok(
        Option::from(pallas::Scalar::from_repr(array32(bytes, what)?))
            .ok_or_else(|| format!("{what}: a scalar"))?,
    )
}

fn point(bytes: &[u8], what: &str) -> Result<pallas::Affine, Failure> {
    Ok(
        Option::from(pallas::Affine::from_bytes(&array32(bytes, what)?))
            .ok_or_else(|| format!("{what}: a curve point"))?,
    )
}

impl Served {
    async fn new(
        installation: Installation,
        history: Arc<dyn HistoryKeyStore>,
        master_key: &Path,
    ) -> Result<Self, Failure> {
        let jwt = tokens()?;
        let storage = installation.storage.clone();
        let (passwords, evaluation) = PasswordOperations::with_authority(
            storage.clone(),
            storage.clone(),
            installation.key_manager.clone(),
            installation.organization.id,
            PasswordHistoryAuthority::in_process(
                history,
                master_key,
                Arc::new(sid_crypto::RustCryptoPrimitives::new()),
                None,
            )
            .await?,
        );
        let history = evaluation.ok_or("the history evaluator runs in the host")?;
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
            passwords,
            history,
        })
    }

    /// Register `principal` with `password` as its client would: the
    /// password operation's OPAQUE start, the history evaluation by the
    /// installation's evaluator, the client's proof bound to the operation
    /// and its request (unless `proof` omits it), and the finish that
    /// verifies it and commits the account with its first credential and
    /// history.
    async fn register(
        &self,
        client: &mut Client,
        zkpp: &Arc<ZkppOpaqueServer>,
        principal: &str,
        password: &[u8],
        claim: Option<&SecretString>,
        enabled: bool,
        proof: Proof,
    ) -> Result<(), Failure> {
        let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
        let started = sid_pake_core::client::start_registration(&mut rng, password)?;
        let request = started.request.serialize().to_vec();
        let start = self
            .registration
            .start(
                &self.passwords,
                zkpp,
                principal,
                claim.map(|c| c.expose_secret()),
                None,
                request.clone(),
                enabled,
            )
            .await?;
        let context = start.history.ok_or("the start names its operation")?;
        let operation = sid_authn::password_operation::operation_id(context.operation_id.as_ref())?;
        let asked = sid_pake_core::client::history_request(
            &mut rng,
            base(&context.owner_domain, "owner domain")?,
            password,
        )
        .ok_or("the password fits the circuit")?;
        let answers = self
            .history
            .evaluate(&operation, &asked.blinded.to_bytes())
            .await?;
        let domains = context
            .domains
            .iter()
            .map(|d| {
                Ok(ComparisonDomain {
                    domain: base(&d.comparison_domain, "comparison domain")?,
                    evaluator_public_key: point(&d.evaluator_public_key, "evaluator key")?,
                })
            })
            .collect::<Result<Vec<_>, Failure>>()?;
        let evaluated = answers
            .iter()
            .map(|a| {
                let proof = a.proof.as_ref().ok_or("an evaluation proof")?;
                Ok(EvaluatorAnswer {
                    evaluation: point(&a.evaluated_element, "evaluation")?,
                    proof: EvaluationProof {
                        c: scalar(&proof.challenge, "challenge")?,
                        s: scalar(&proof.response, "response")?,
                    },
                })
            })
            .collect::<Result<Vec<_>, Failure>>()?;
        let history = sid_pake_core::client::verified_history(
            password,
            operation.as_bytes(),
            &asked,
            &domains,
            &evaluated,
        )?;
        let proof = match proof {
            Proof::Made => {
                let bound = client.prover(domains.len())?.prove(
                    password,
                    started.blind(),
                    &operation_context(operation.as_bytes(), &request),
                    &history,
                )?;
                Some(PasswordRegistrationProof {
                    zkpp_proof: bound.snark_proof.0,
                    instances: bound
                        .instances
                        .iter()
                        .map(|i| i.to_repr().to_vec())
                        .collect(),
                    evaluation_proofs: answers.into_iter().filter_map(|a| a.proof).collect(),
                })
            }
            Proof::Omitted => None,
        };
        let record = started
            .state
            .finish(
                &mut rng,
                password,
                sid_opaque_ke::RegistrationResponse::<PallasCipherSuite>::deserialize(
                    &start.registration_response,
                )?,
                sid_opaque_ke::ClientRegistrationFinishParameters::default(),
            )?
            .message
            .serialize()
            .to_vec();
        self.registration
            .finish(
                &self.passwords,
                zkpp.clone(),
                OpaqueZkppRegistrationFinishRequest {
                    operation_id: context.operation_id,
                    registration_record: record,
                    proof,
                },
                SecurityPolicy::ce_default().password.history_max_age_days,
                enabled,
            )
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
            passwords,
            history,
        } = self;
        drop((
            jwt,
            sign_in,
            admin,
            authorization,
            registration,
            passwords,
            history,
        ));
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

/// The host's mail: it records what the engine owes instead of sending it.
#[derive(Default)]
struct HostMail {
    sent: std::sync::Mutex<Vec<(sid::auth_mail::AuthMessage, String)>>,
}

#[async_trait::async_trait]
impl AuthMailDelivery for HostMail {
    async fn deliver(&self, mail: &OwedMail) -> Result<String, MailError> {
        self.sent
            .lock()
            .expect("the mail record")
            .push((mail.message, mail.destination.clone()));
        Ok(uuid::Uuid::now_v7().to_string())
    }
}

/// The installation's engine: the CE work it owes, assembled by the
/// engine library with its in-process history evaluator, and the host's own
/// `extra` handlers.
fn engine(served: &Served, extra: Vec<Arc<dyn WorkHandler>>) -> Engine {
    let installation = &served.installation;
    let storage = installation.storage.clone();
    let mail: Arc<dyn AuthMailDelivery> = Arc::new(HostMail::default());
    let codes = Arc::new(sid_authn::otp::OtpService::new(
        storage.clone(),
        sid_authn::otp::CodeDelivery {
            keys: installation.key_manager.clone(),
            work: storage.clone(),
            capacity: sid_plugin::OWED_WORK_CAPACITY,
        },
    ));
    let cascade = Arc::new(
        sid_authn::revocation_cascade::RevocationCascadeService::new(
            storage.clone(),
            installation.revocation_cache.clone(),
        ),
    );
    let CeWork {
        mut handlers,
        maintenance,
    } = CeWork::assemble(CeWorkParts {
        storage: storage.clone(),
        issuers: installation.issuers.clone(),
        revocation: installation.revocation_cache.clone(),
        event_bus: Arc::new(sid_plugin::event_bus::InProcessEventBus::new()),
        required_receivers: Vec::new(),
        history_evaluation: Some(served.history.clone()),
        issuer: ISSUER.to_owned(),
        closures: Arc::new(sid_authn::account_closure::AccountClosureService::new(
            storage.clone(),
            cascade,
        )),
        mail: CeMail {
            codes: Arc::new(sid::auth_mail::CodeMail::new(codes, mail)),
            magic_links: None,
            resets: None,
        },
        audit_retention: sid::AuditRetention::default(),
        migration_deadline_days: sid::maintenance::DEFAULT_MIGRATION_DEADLINE_DAYS,
        source: "engine-package-consumer".into(),
    })
    .expect("the CE work assembles");
    handlers.extend(extra);
    Engine::new(EngineParts {
        storage,
        worker: format!("host-{}", uuid::Uuid::now_v7()),
        handlers,
        runner: RunnerConfig {
            concurrency: 2,
            lease: Duration::from_secs(30),
            scan_interval: Duration::from_millis(10),
        },
        maintenance,
    })
    .expect("the engine takes its handlers")
}

/// Whether any work of the installation is still owed (pending or claimed).
async fn owed_work(storage: &dyn StorageBackend) -> Result<usize, Failure> {
    Ok(storage
        .export_work()
        .await?
        .iter()
        .filter(|w| matches!(w.record.state, WorkState::Pending | WorkState::Claimed))
        .count())
}

/// The installation's CE work (every kind but the host's own), each with
/// the state it ended in; refused when any piece ended otherwise than
/// completed. The kinds of the completed pieces.
async fn ce_work_completed(
    storage: &dyn StorageBackend,
) -> Result<std::collections::BTreeSet<String>, Failure> {
    let mut completed = std::collections::BTreeSet::new();
    for work in storage.export_work().await? {
        if work.record.kind.as_str() == WORK_KIND {
            continue;
        }
        if work.record.state != WorkState::Completed {
            return Err(format!(
                "CE work {} ({}) ended {:?}: {:?}",
                work.record.id,
                work.record.kind.as_str(),
                work.record.state,
                work.record.last_error
            )
            .into());
        }
        completed.insert(work.record.kind.as_str().to_owned());
    }
    Ok(completed)
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
    /// The password history evaluator's store in the same database.
    fn history_keys(&self) -> Arc<dyn HistoryKeyStore>;
    fn store(&self) -> Store<'_>;
}

#[cfg(feature = "sqlite")]
struct SqliteHost {
    backend: Arc<sid_storage::sqlite::SqliteBackend>,
    audit: sid_storage::sqlite::SqliteAuditLog,
    keys: Arc<sid_storage::sqlite::SqliteHistoryKeyStore>,
}

#[cfg(feature = "sqlite")]
impl HostStore for SqliteHost {
    async fn open(path: &Path) -> Result<Self, Failure> {
        let path = path.to_str().ok_or("a UTF-8 database path")?;
        let backend = Arc::new(sid_storage::sqlite::SqliteBackend::new(path).await?);
        Ok(Self {
            audit: sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone()),
            keys: Arc::new(backend.history_keys()),
            backend,
        })
    }

    fn backend(&self) -> Arc<dyn StorageBackend> {
        self.backend.clone()
    }

    fn history_keys(&self) -> Arc<dyn HistoryKeyStore> {
        self.keys.clone()
    }

    fn store(&self) -> Store<'_> {
        Store {
            storage: self.backend.as_ref(),
            audit: &self.audit,
            history_keys: self.keys.as_ref(),
        }
    }
}

/// The host's own CoordiNode database in a directory, SID's records in it.
#[cfg(feature = "coordinode")]
struct CoordinodeHost {
    backend: Arc<sid_storage::coordinode::CoordinodeBackend>,
    keys: Arc<sid_storage::coordinode::CoordinodeHistoryKeyStore>,
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
            keys: Arc::new(backend.history_keys()),
            backend,
        })
    }

    fn backend(&self) -> Arc<dyn StorageBackend> {
        self.backend.clone()
    }

    fn history_keys(&self) -> Arc<dyn HistoryKeyStore> {
        self.keys.clone()
    }

    fn store(&self) -> Store<'_> {
        Store {
            storage: self.backend.as_ref(),
            audit: self.backend.as_ref(),
            history_keys: self.keys.as_ref(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Failure> {
    // The host's selection: pure-Rust primitives, JWT and TLS providers.
    sid_crypto::jwt::rustcrypto::provider()
        .install_default()
        .map_err(|_| "a JWT provider was installed before the host's")?;
    sid_crypto::tls::rustcrypto::provider()
        .install_default()
        .map_err(|_| "a TLS provider was installed before the host's")?;
    match std::env::args().nth(1).as_deref() {
        #[cfg(feature = "sqlite")]
        Some("sqlite") => run::<SqliteHost>().await,
        #[cfg(feature = "coordinode")]
        Some("coordinode") => run::<CoordinodeHost>().await,
        other => Err(format!("no host store {other:?} in this build").into()),
    }
}

async fn run<S: HostStore>() -> Result<(), Failure> {
    const PASSWORD: &[u8] = b"Embedded-Host-7Engine";
    let crypto = sid_crypto::RustCryptoPrimitives::new();
    let host = Host::new();
    let source = S::open(&host.database("source")).await?;
    let served = Served::new(
        Installation::open(source.backend(), settings(&host.master_key())).await?,
        source.history_keys(),
        &host.master_key(),
    )
    .await?;
    let storage = source.backend();
    let zkpp = zkpp_server(&served.installation, &host.database("zkpp")).await?;
    let mut client = Client::default();

    // Bootstrap: a fresh installation offers its claim; nobody registers
    // without it, and the first account registered with it administers.
    // Every password is installed with the client's proof: one without it
    // is refused.
    let claim = served
        .installation
        .admin_claim()
        .await?
        .ok_or("a fresh installation offers its claim")?;
    check(
        served
            .register(&mut client, &zkpp, GUEST, PASSWORD, None, true, Proof::Made)
            .await
            .is_err(),
        "no registration without the claim before the installation is claimed",
    )?;
    check(
        served
            .register(
                &mut client,
                &zkpp,
                ROOT,
                PASSWORD,
                Some(&claim),
                false,
                Proof::Omitted,
            )
            .await
            .is_err(),
        "a password without its proof is refused",
    )?;
    served
        .register(
            &mut client,
            &zkpp,
            ROOT,
            PASSWORD,
            Some(&claim),
            false,
            Proof::Made,
        )
        .await?;
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
    served
        .register(&mut client, &zkpp, GUEST, PASSWORD, None, true, Proof::Made)
        .await?;
    let passwords = storage
        .list_credentials_by_type(sid_core::models::CredentialType::Opaque, None, 10)
        .await?;
    check(
        passwords.len() == 2
            && passwords
                .iter()
                .all(|c| c.policy_evidence != sid_core::models::PolicyEvidence::Unverified),
        "each installed password carries the evidence of its verified proof",
    )?;
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

    // The CE work the installation committed so far (event relays of the
    // registrations, the guest's session revocation) is settled by the CE
    // handlers the engine assembles; the host's own work, which no handler
    // of this run takes, stays pending through the drain.
    let kind = WorkKind::new(WORK_KIND)?;
    let work = NewWork::new(kind.clone(), vec![]);
    storage.enqueue_work(&work, 100).await?;
    check(
        owed_work(storage.as_ref()).await? > 1,
        "the installation owes CE work besides the host's",
    )?;
    let running = engine(&served, vec![]).start();
    tokio::time::timeout(Duration::from_secs(10), async {
        while owed_work(storage.as_ref()).await.ok() != Some(1) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "the CE handlers settle the CE work")?;
    running.drain().await?;
    let completed = ce_work_completed(storage.as_ref()).await?;
    check(
        completed.contains(sid_core::models::event::EVENT_RELAY_KIND)
            && completed.contains(sid_core::models::SESSION_REVOCATION_KIND),
        &format!(
            "the CE handlers complete every piece of CE work the installation owes: {completed:?}"
        ),
    )?;
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
    drop((storage, source, zkpp));
    let source = S::open(&host.database("source")).await?;
    let reopened = Served::new(
        Installation::open(source.backend(), settings(&host.master_key())).await?,
        source.history_keys(),
        &host.master_key(),
    )
    .await?;
    check(
        reopened.installation.organization == organization
            && reopened.installation.issuer == issuer,
        "a restart reopens the same installation",
    )?;
    check(
        work_state(source.backend().as_ref(), &work).await? == WorkState::Pending,
        "pending work survives the restart",
    )?;
    let drained: Drained = engine(&reopened, vec![]).start().drain().await?;

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
    let restored = Served::new(
        Installation::open(target.backend(), settings(&host.master_key())).await?,
        target.history_keys(),
        &host.master_key(),
    )
    .await?;
    check(
        restored.installation.organization == organization
            && restored.installation.issuer == issuer,
        "the restored installation opens as the same authority",
    )?;

    // The restored installation: its pending work runs once its engine
    // starts, its administrator signs in with the same password, and a keyed
    // command repeated there answers with what the source recorded.
    let target_storage = target.backend();
    let running = engine(&restored, vec![Arc::new(Probe(kind))]).start();
    tokio::time::timeout(Duration::from_secs(10), async {
        while work_state(target_storage.as_ref(), &work).await.ok() != Some(WorkState::Completed) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "the restored engine completes the work the source left pending")?;
    println!("verified: the restored engine completes the work the source left pending");
    running.drain().await?;
    check(
        owed_work(target_storage.as_ref()).await? == 0,
        "the restored installation owes no work",
    )?;
    ce_work_completed(target_storage.as_ref()).await?;
    println!("verified: every piece of CE work of the restored installation completed");
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
