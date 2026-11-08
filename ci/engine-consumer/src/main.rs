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
use sid::devices::DeviceKeyError;
use sid::devices::{DeviceKeys, KeyCaller, LocalAccess};
use sid::lifecycle::{Drained, Engine, EngineParts};
use sid::machines::MachineError;
use sid::machines::Machines;
use sid::oauth::{OAuth, OAuthError, OAuthParts};
use sid::passkey::{Assertion, PasskeyError, Passkeys};
use sid::password_operation::PasswordOperations;
use sid::projects::ProjectError;
use sid::projects::Projects;
use sid::registration::Registration;
use sid::second_factor::{Enroller, FactorCaller, SecondFactorError, SecondFactors};
use sid::sign_in::completions::Completer;
use sid::sign_in::{AttemptContext, SignIn, SignInParts};
use sid::snapshot::{ArchiveKey, Store};
use sid::work::{CeMail, CeWork, CeWorkParts};
use sid::{Installation, InstallationSettings};
use sid_authn::caller::Caller;
use sid_authn::caller::CallerError;
use sid_authn::jwt::JwtService;
use sid_authn::oauth2::TokenError;
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
use sid_proto::sid::v1::attestation::{
    AttestationStatus as DeviceAttestationStatus, DeviceEnrollmentChallenge,
    DeviceEnrollmentPurpose, FinishDeviceEnrollmentRequest, GetDeviceAttestationRequest,
    ListDeviceAttestationsRequest, RevokeDeviceKeyRequest, RotateDeviceKeyRequest,
    StartDeviceEnrollmentRequest,
};
use sid_proto::sid::v1::authn::{OpaqueZkppRegistrationFinishRequest, PasswordRegistrationProof};
use sid_proto::sid::v1::{
    AddMachineCredentialRequest, CreateMachineUserRequest, CreateProjectRequest,
    ListMachineCredentialsRequest, MachineCredentialStatus, MachineCredentialType,
    RevokeMachineCredentialRequest, SetResourceAccessRequest,
};

type Failure = Box<dyn std::error::Error>;

const ISSUER: &str = "https://id.sid.example.com";
/// The WebAuthn relying party the issuer's origin belongs to.
const RP_ID: &str = "id.sid.example.com";
const WORK_KIND: &str = "host_probe";
const ROOT: &str = "root@sid.example.com";
const GUEST: &str = "guest@sid.example.com";
/// The redirect URI of the host's own single-page application.
const REDIRECT: &str = "https://app.sid.example.com/callback";
/// The host application's own API, the resource its tokens are for.
const API: &str = "https://api.sid.example.com/orders";

/// `result` is the refusal `expected` names; success or any other failure
/// (a store error, a misconfiguration) fails the run.
fn refused<T, E: std::fmt::Debug>(
    result: Result<T, E>,
    expected: impl FnOnce(&E) -> bool,
    what: &str,
) -> Result<(), Failure> {
    match result {
        Ok(_) => Err(format!("not verified: {what}: it succeeded").into()),
        Err(e) if expected(&e) => {
            println!("verified: {what}");
            Ok(())
        }
        Err(e) => Err(format!("not verified: {what}: refused otherwise: {e:?}").into()),
    }
}

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
    projects: Projects,
    machines: Machines,
    oauth: OAuth,
    devices: DeviceKeys,
    factors: SecondFactors,
    passkeys: Passkeys,
}

/// Whether a registration's finish carries the client's proof.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Proof {
    Made,
    Omitted,
}

/// An application's client of password registration: the ZKPP prover of
/// each history shape it was asked for, under the CE policy, and the
/// password operations it started, each with its owner domain.
#[derive(Default)]
struct Client {
    provers: BTreeMap<usize, ZkppProver>,
    operations: BTreeMap<uuid::Uuid, [u8; 32]>,
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

/// A device's own signing key, as the device's client holds it.
struct DeviceKey {
    private: jsonwebtoken::EncodingKey,
    jwk: serde_json::Value,
}

impl DeviceKey {
    /// An Ed25519 key from its PKCS#8 private and SPKI public PEM.
    fn ed25519(private_pem: &[u8], public_pem: &str) -> Result<Self, Failure> {
        use base64::Engine;
        let body: String = public_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = base64::engine::general_purpose::STANDARD.decode(body)?;
        // The raw 32-byte public key ends the SPKI DER.
        let start = der.len().checked_sub(32).ok_or("an Ed25519 key")?;
        let raw = &der[start..];
        Ok(Self {
            private: jsonwebtoken::EncodingKey::from_ed_pem(private_pem)?,
            jwk: serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
            }),
        })
    }

    fn thumbprint(&self) -> Result<String, Failure> {
        Ok(sid_authn::device_key_proof::stored_key_thumbprint(
            &self.jwk.to_string(),
        )?)
    }

    /// This key's proof over `challenge` at `issuer` for `purpose`, naming
    /// `key` as the proposed key.
    fn proof(
        &self,
        challenge: &DeviceEnrollmentChallenge,
        issuer: &str,
        purpose: &str,
        key: &str,
    ) -> Result<String, Failure> {
        use base64::Engine;
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.typ = Some(sid_authn::device_key_proof::DEVICE_KEY_PROOF_TYPE.to_owned());
        header.jwk = Some(serde_json::from_value(self.jwk.clone())?);
        let device: sid_ids::DeviceId = sid_ids_proto::required(challenge.device_id.as_ref())?;
        let claims = serde_json::json!({
            "chl": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge.challenge),
            "purpose": purpose,
            "iss": issuer,
            "dev": device.to_string(),
            "key": key,
        });
        Ok(jsonwebtoken::encode(&header, &claims, &self.private)?)
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
            geoip: Arc::new(sid_authn::geoip::GeoIpChain::empty(cache.clone())),
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
        let oauth = OAuth::new(OAuthParts {
            storage: storage.clone(),
            oauth2: Arc::new(sid_authn::oauth2::OAuth2Server::new(jwt.clone())),
            jwt: jwt.clone(),
            issuers: installation.issuers.clone(),
            installation_org: installation.organization.id,
            authz: Arc::new(sid_authz::CeAuthzEngine::new(storage.clone())),
            revocation: installation.revocation_cache.clone(),
            cascade: cascade.clone(),
            cache,
            login_policy: Arc::new(sid_authn::login_policy::FixedLoginPolicy::of(
                &SecurityPolicy::ce_default(),
            )),
            installation_url: ISSUER.to_owned(),
        });
        // One relying party serves second factors and passkey sign-in.
        let webauthn = Arc::new(sid_authn::webauthn::WebAuthnServer::new(
            RP_ID,
            &url::Url::parse(ISSUER)?,
            storage.clone(),
            installation.key_manager.clone(),
        )?);
        Ok(Self {
            passkeys: Passkeys::new(
                webauthn.clone(),
                storage.clone(),
                installation.key_manager.clone(),
            ),
            projects: Projects::new(storage.clone(), installation.issuer.clone()),
            machines: Machines::new(
                storage.clone(),
                installation.revocation_cache.clone(),
                installation.organization.id,
            ),
            oauth,
            devices: DeviceKeys::new(storage.clone(), installation.key_manager.clone()),
            factors: SecondFactors::new(
                webauthn,
                ISSUER.to_owned(),
                storage.clone(),
                installation.key_manager.clone(),
            ),
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
        client.operations.insert(
            uuid::Uuid::from_bytes(*operation.as_bytes()),
            array32(&context.owner_domain, "owner domain")?,
        );
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
        let policy = sid_authn::login_policy::FixedLoginPolicy::of(&SecurityPolicy::ce_default());
        let signed_in = self
            .password_first_factor(&policy, principal, password)
            .await?;
        if !signed_in.second_factors.is_empty() {
            return Err(format!("{principal} owes a second factor").into());
        }
        self.bearer(signed_in.signed_in.delivery)
    }

    /// The caller and token a native sign-in delivers.
    fn bearer(
        &self,
        delivery: sid_authn::sign_in_delivery::Delivery,
    ) -> Result<(Caller, SecretString), Failure> {
        let sid_authn::sign_in_delivery::Delivery::Bearer { token, .. } = delivery else {
            return Err("a native sign-in delivers a bearer token".into());
        };
        let claims = self.jwt.validate_access_token(token.expose_secret())?;
        Ok((Caller::from_claims(&claims)?, token))
    }

    /// `principal`'s native password sign-in with `password` under `policy`,
    /// as far as its first factor takes it.
    async fn password_first_factor(
        &self,
        policy: &dyn sid_authn::login_policy::LoginPolicySource,
        principal: &str,
        password: &[u8],
    ) -> Result<sid::sign_in::FirstFactorSignedIn, Failure> {
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
        let signed_in = self
            .sign_in
            .password_sign_in(
                policy,
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
        Ok(signed_in)
    }

    /// A native passkey sign-in with `key`, for `principal`'s account or,
    /// without one, the account the authenticator's credential names.
    async fn passkey_sign_in(
        &self,
        key: &mut sid_authn::webauthn::soft_authenticator::SoftAuthenticator,
        principal: Option<&str>,
    ) -> Result<sid::sign_in::FirstFactorSignedIn, PasskeyError> {
        let started = self
            .passkeys
            .authentication_start(
                &self.sign_in,
                sid_proto::sid::v1::WebAuthnAuthenticationStartRequest {
                    principal: principal.map(str::to_owned),
                },
            )
            .await?;
        let assertion =
            Assertion::parse(principal.map(str::to_owned), &key.assert(&started.options))?;
        self.passkeys
            .authentication_finish(
                &self.sign_in,
                &sid_authn::login_policy::FixedLoginPolicy::of(&SecurityPolicy::ce_default()),
                assertion,
                sid_authn::sign_in_delivery::CeremonyClient::Native,
                None,
                AttemptContext::default(),
                None,
            )
            .await
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
            projects,
            machines,
            oauth,
            devices,
            factors,
            passkeys,
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
        drop((projects, machines, oauth, devices, factors, passkeys));
        installation.close().await;
    }

    /// A token the machine user `client_id` obtains for itself with its
    /// client secret (RFC 6749 §4.4) for the installation's authorization
    /// API.
    async fn machine_token(
        &self,
        client_id: &str,
        secret: &str,
    ) -> Result<sid_proto::sid::v1::OAuth2TokenResponse, OAuthError> {
        let request = sid_proto::sid::v1::OAuth2TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: Some(client_id.to_owned()),
            client_secret: Some(secret.to_owned()),
            scope: Some(sid_core::models::authz::AUTHZ_CHECK.into()),
            issuer_handle: self.installation.issuer.handle.to_string(),
            resource: vec![
                self.installation
                    .authorization_api
                    .indicator
                    .as_str()
                    .to_owned(),
            ],
            ..Default::default()
        };
        let target = sid_authn::resource::RequestTarget {
            method: "POST".into(),
            uri: format!("{ISSUER}/oauth2/token"),
        };
        self.oauth.token(&request, None, None, &target).await
    }

    /// The authorization code `caller`'s sign-in grants `client_id` for
    /// `openid` at the host's redirect URI, bound to the PKCE challenge of
    /// `verifier` (RFC 7636 §4.2, S256).
    async fn authorization_code(
        &self,
        caller: &Caller,
        client_id: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<String, Failure> {
        use base64::Engine;
        use sha2::Digest;
        let request = sid_proto::sid::v1::OAuth2AuthorizeRequest {
            client_id: client_id.to_owned(),
            redirect_uri: REDIRECT.into(),
            response_type: "code".into(),
            scope: Some("openid".into()),
            state: Some("host-state".into()),
            nonce: Some(nonce.to_owned()),
            code_challenge: Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(verifier.as_bytes())),
            ),
            code_challenge_method: Some("S256".into()),
            issuer_handle: self.installation.issuer.handle.to_string(),
            resource: vec![API.into()],
            ..Default::default()
        };
        let (client, issuer) = self.oauth.authorize_client(&request, None).await?;
        let session = self
            .installation
            .storage
            .get_session(sid_core::models::SessionId::parse(&caller.session_id)?)
            .await?
            .ok_or("the caller's session")?;
        let answer = self
            .oauth
            .authorize_with(&client, &issuer, &session, request)
            .await?;
        match answer.result {
            Some(sid_proto::sid::v1::o_auth2_authorize_response::Result::AuthorizationCode(
                code,
            )) => Ok(code),
            other => Err(format!("no authorization code: {other:?}").into()),
        }
    }

    /// `client_id` redeems `code` with its PKCE `verifier`.
    async fn redeem(
        &self,
        client_id: &str,
        code: &str,
        verifier: &str,
    ) -> Result<sid_proto::sid::v1::OAuth2TokenResponse, OAuthError> {
        self.token(sid_proto::sid::v1::OAuth2TokenRequest {
            grant_type: "authorization_code".into(),
            code: Some(code.to_owned()),
            redirect_uri: Some(REDIRECT.into()),
            client_id: Some(client_id.to_owned()),
            code_verifier: Some(verifier.to_owned()),
            ..Default::default()
        })
        .await
    }

    /// `client_id` exchanges `refresh_token` for new tokens.
    async fn refresh(
        &self,
        client_id: &str,
        refresh_token: &str,
    ) -> Result<sid_proto::sid::v1::OAuth2TokenResponse, OAuthError> {
        self.token(sid_proto::sid::v1::OAuth2TokenRequest {
            grant_type: "refresh_token".into(),
            refresh_token: Some(refresh_token.to_owned()),
            client_id: Some(client_id.to_owned()),
            ..Default::default()
        })
        .await
    }

    /// A token request to the installation's issuer.
    async fn token(
        &self,
        mut request: sid_proto::sid::v1::OAuth2TokenRequest,
    ) -> Result<sid_proto::sid::v1::OAuth2TokenResponse, OAuthError> {
        request.issuer_handle = self.installation.issuer.handle.to_string();
        let target = sid_authn::resource::RequestTarget {
            method: "POST".into(),
            uri: format!("{ISSUER}/oauth2/token"),
        };
        self.oauth.token(&request, None, None, &target).await
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
fn engine(served: &Served, extra: Vec<Arc<dyn WorkHandler>>) -> Result<Engine, Failure> {
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
    // Admissions settle here, over the host's evaluator, once they are due.
    if !handlers
        .iter()
        .any(|h| h.kind().as_str() == sid_core::models::password_history::ENROLLMENT_ADMISSION_KIND)
    {
        return Err("the CE work settles enrollment admissions in the host's process".into());
    }
    handlers.extend(extra);
    Ok(Engine::new(EngineParts {
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
    .expect("the engine takes its handlers"))
}

/// Owed (pending or claimed) work of the installation that is due now, by
/// kind and state; work scheduled for later is not yet owed.
async fn due_work(storage: &dyn StorageBackend) -> Result<Vec<String>, Failure> {
    let now = chrono::Utc::now();
    Ok(storage
        .export_work()
        .await?
        .iter()
        .filter(|w| {
            matches!(w.record.state, WorkState::Pending | WorkState::Claimed)
                && w.record.not_before <= now
        })
        .map(|w| format!("{} ({:?})", w.record.kind.as_str(), w.record.state))
        .collect())
}

/// Whether `work` is the enrollment admission of one of `operations` as the
/// engine records it: its kind, the operation's id, the operation and its
/// owner domain in the payload, and the due time the admission sets.
fn is_admission(
    work: &sid_core::models::WorkSnapshot,
    operations: &BTreeMap<uuid::Uuid, [u8; 32]>,
) -> bool {
    let record = &work.record;
    let Some(owner_domain) = operations.get(&record.id.0) else {
        return false;
    };
    let Ok(admission) = sid_core::models::EnrollmentAdmission::from_work(&work.payload) else {
        return false;
    };
    record.kind.as_str() == sid_core::models::password_history::ENROLLMENT_ADMISSION_KIND
        && admission.operation == record.id.0
        && admission.owner_domain == *owner_domain
        && admission.work().not_before == Some(record.not_before)
}

/// The installation's CE work (every kind but the host's own) as it stands:
/// the kinds of the completed pieces, and the operations whose enrollment
/// admission is scheduled (pending, not yet due). Refused when any other
/// piece ended, or is owed, otherwise than completed.
async fn ce_work_settled(
    storage: &dyn StorageBackend,
    operations: &BTreeMap<uuid::Uuid, [u8; 32]>,
) -> Result<
    (
        std::collections::BTreeSet<String>,
        std::collections::BTreeSet<uuid::Uuid>,
    ),
    Failure,
> {
    let now = chrono::Utc::now();
    let mut completed = std::collections::BTreeSet::new();
    let mut scheduled = std::collections::BTreeSet::new();
    for work in storage.export_work().await? {
        let record = &work.record;
        if record.kind.as_str() == WORK_KIND {
            continue;
        }
        match record.state {
            WorkState::Completed => {
                completed.insert(record.kind.as_str().to_owned());
            }
            WorkState::Pending if record.not_before > now && is_admission(&work, operations) => {
                scheduled.insert(record.id.0);
            }
            state => {
                return Err(format!(
                    "CE work {} ({}) stands {state:?}: {:?}",
                    record.id,
                    record.kind.as_str(),
                    record.last_error
                )
                .into());
            }
        }
    }
    Ok((completed, scheduled))
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

    // While its sign-in is live, a user without the role creates neither a
    // project nor a machine user: refused for its role.
    let denied = |e: &CallerError| matches!(e, CallerError::Denied);
    refused(
        served
            .projects
            .create_project(
                &guest,
                operation(storage.as_ref(), "guest-project").await?,
                CreateProjectRequest {
                    name: "denied".into(),
                    ..Default::default()
                },
            )
            .await,
        |e| matches!(e, ProjectError::Caller(e) if denied(e)),
        "a user without the role creates no project",
    )?;
    refused(
        served
            .machines
            .create_machine_user(
                &guest,
                operation(storage.as_ref(), "guest-machine").await?,
                CreateMachineUserRequest {
                    project_id: Some(ProjectId::SYSTEM.into()),
                    display_name: "denied".into(),
                    ..Default::default()
                },
            )
            .await,
        |e| matches!(e, MachineError::Caller(e) if denied(e)),
        "a user without the role creates no machine user",
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

    // Projects and machine identities: the administrator creates a project
    // and a machine user in it.
    let project = served
        .projects
        .create_project(
            &root,
            operation(storage.as_ref(), "create-project").await?,
            CreateProjectRequest {
                name: "orders".into(),
                ..Default::default()
            },
        )
        .await?;
    let machine = served
        .machines
        .create_machine_user(
            &root,
            operation(storage.as_ref(), "create-machine").await?,
            CreateMachineUserRequest {
                project_id: project.id.clone(),
                display_name: "orders-worker".into(),
                ..Default::default()
            },
        )
        .await?
        .machine_user
        .ok_or("the created machine user")?;
    let added = served
        .machines
        .add_machine_credential(
            &root,
            operation(storage.as_ref(), "machine-secret").await?,
            AddMachineCredentialRequest {
                machine_user_id: machine.id.clone(),
                credential_type: MachineCredentialType::ClientSecret as i32,
                ..Default::default()
            },
        )
        .await?;
    let kid = added.credential.ok_or("the added credential")?.kid;
    let api = &served.installation.authorization_api;
    refused(
        served
            .machine_token(&machine.client_id, &added.client_secret)
            .await,
        |e| {
            matches!(
                e,
                OAuthError::Target(sid_authn::target::TargetRefusal::NotPermitted)
            )
        },
        "a machine user without access to a resource gets no token for it",
    )?;
    served
        .projects
        .set_resource_access(
            &root,
            operation(storage.as_ref(), "machine-access").await?,
            SetResourceAccessRequest {
                client_id: machine.client_id.clone(),
                resource_id: Some(api.id.into()),
                scopes: vec![sid_core::models::authz::AUTHZ_CHECK.into()],
            },
        )
        .await?;
    let issued = served
        .machine_token(&machine.client_id, &added.client_secret)
        .await?;
    let verifier = sid_authn::resource_token::ResourceTokenVerifier::new(
        served.installation.issuers.clone(),
        served.installation.issuer.clone(),
        api.indicator.clone(),
    )
    .await?;
    let machine_claims = verifier.verify(&issued.access_token).await?;
    // The resource's verifier holds the installation's issuers: it lets go
    // before the host closes the store.
    drop(verifier);
    let machine_id: sid_ids::MachineUserId = sid_ids_proto::required(machine.id.as_ref())?;
    check(
        machine_claims.sub == machine_id.to_string()
            && !sid_authn::caller::check_revocation(
                &served.installation.revocation_cache,
                &machine_claims,
            )
            .await?,
        "the machine user's own token verifies at the resource as the machine user",
    )?;
    refused(
        served
            .machine_token(&machine.client_id, "not-the-secret")
            .await,
        |e| matches!(e, OAuthError::ClientRefused),
        "a wrong client secret gets no token",
    )?;
    // Revoking the credential stops its issued token and every new one.
    served
        .machines
        .revoke_machine_credential(
            &root,
            RevokeMachineCredentialRequest {
                machine_user_id: machine.id.clone(),
                kid: kid.clone(),
            },
        )
        .await?;
    check(
        sid_authn::caller::check_revocation(&served.installation.revocation_cache, &machine_claims)
            .await?,
        "a revoked machine credential stops its issued token",
    )?;
    refused(
        served
            .machine_token(&machine.client_id, &added.client_secret)
            .await,
        |e| matches!(e, OAuthError::ClientRefused),
        "a revoked machine credential obtains no new token",
    )?;

    // Device keys: the owner's own sign-in enrolls a new device's key through
    // the ceremony and rotates it with both keys' proofs; a proof by another
    // key binds nothing, a revoked sign-in starts nothing, and a revoked key
    // is no longer live.
    let issuer = served.installation.issuer.canonical_url.clone();
    let first_key = DeviceKey::ed25519(
        include_bytes!("../keys/device_a_ed25519_private.pem"),
        include_str!("../keys/device_a_ed25519_public.pem"),
    )?;
    let second_key = DeviceKey::ed25519(
        include_bytes!("../keys/device_b_ed25519_private.pem"),
        include_str!("../keys/device_b_ed25519_public.pem"),
    )?;
    let owner = KeyCaller::from(&root);
    let enroll = || StartDeviceEnrollmentRequest {
        purpose: DeviceEnrollmentPurpose::Enroll as i32,
        device_type: sid_proto::sid::v1::identity::DeviceType::Desktop as i32,
        display_name: Some("Laptop".into()),
        ..Default::default()
    };
    refused(
        served
            .devices
            .start_enrollment(
                &mut LocalAccess(&guest),
                &KeyCaller::from(&guest),
                &issuer,
                enroll(),
            )
            .await,
        |e| matches!(e, DeviceKeyError::Denied),
        "a revoked sign-in starts no device-key ceremony",
    )?;
    let challenge = served
        .devices
        .start_enrollment(&mut LocalAccess(&root), &owner, &issuer, enroll())
        .await?;
    let finish = |proof: String| FinishDeviceEnrollmentRequest {
        enrollment_id: challenge.enrollment_id.clone(),
        proof,
        ..Default::default()
    };
    refused(
        served
            .devices
            .finish_enrollment(
                &mut LocalAccess(&root),
                &owner,
                Some(operation(storage.as_ref(), "enroll-foreign").await?),
                finish(second_key.proof(
                    &challenge,
                    &issuer,
                    "enroll",
                    &first_key.thumbprint()?,
                )?),
            )
            .await,
        |e| matches!(e, DeviceKeyError::Proof(_)),
        "a proof by another key binds nothing",
    )?;
    served
        .devices
        .finish_enrollment(
            &mut LocalAccess(&root),
            &owner,
            Some(operation(storage.as_ref(), "enroll-device").await?),
            finish(first_key.proof(&challenge, &issuer, "enroll", &first_key.thumbprint()?)?),
        )
        .await?;
    let device = challenge.device_id.clone();
    // The thumbprint of the device's live key; none when it has no live
    // key, any other failure fails the run.
    let live_key = || async {
        match served
            .devices
            .get_attestation(
                &mut LocalAccess(&root),
                &owner,
                GetDeviceAttestationRequest {
                    device_id: device.clone(),
                },
            )
            .await
        {
            Ok(a) => Ok::<_, Failure>(Some(sid_authn::device_key_proof::stored_key_thumbprint(
                &a.public_jwk,
            )?)),
            Err(DeviceKeyError::NoAttestation(_)) => Ok(None),
            Err(e) => Err(format!("device key: {e:?}").into()),
        }
    };
    check(
        live_key().await? == Some(first_key.thumbprint()?),
        "the enrolled device's live key is the proven one",
    )?;
    let rotation = served
        .devices
        .start_enrollment(
            &mut LocalAccess(&root),
            &owner,
            &issuer,
            StartDeviceEnrollmentRequest {
                purpose: DeviceEnrollmentPurpose::Rotate as i32,
                device_id: device.clone(),
                ..Default::default()
            },
        )
        .await?;
    let next = second_key.thumbprint()?;
    served
        .devices
        .rotate_key(
            &mut LocalAccess(&root),
            &owner,
            Some(operation(storage.as_ref(), "rotate-device").await?),
            RotateDeviceKeyRequest {
                enrollment_id: rotation.enrollment_id.clone(),
                new_key_proof: second_key.proof(&rotation, &issuer, "rotate-new", &next)?,
                current_key_proof: first_key.proof(&rotation, &issuer, "rotate-current", &next)?,
                ..Default::default()
            },
        )
        .await?;
    check(
        live_key().await? == Some(next),
        "a rotation approved by the current key installs the new one",
    )?;
    served
        .devices
        .revoke_key(
            &mut LocalAccess(&root),
            &owner,
            Some(operation(storage.as_ref(), "revoke-device").await?),
            RevokeDeviceKeyRequest {
                device_id: device.clone(),
            },
        )
        .await?;
    check(
        live_key().await?.is_none(),
        "a revoked device key is no longer live",
    )?;

    // OAuth: a public application's client gets an authorization code under
    // the administrator's sign-in, redeems it once with its PKCE verifier,
    // and refreshes; a redeemed code and a rotated refresh token are refused.
    let app = served
        .projects
        .create_application(
            &root,
            operation(storage.as_ref(), "create-app").await?,
            sid_proto::sid::v1::CreateApplicationRequest {
                project_id: project.id.clone(),
                name: "orders-app".into(),
                client: Some(sid_proto::sid::v1::ClientRoleSettings {
                    r#type: sid_proto::sid::v1::ApplicationType::Spa as i32,
                    redirect_uris: vec![REDIRECT.into()],
                    ..Default::default()
                }),
                resource: Some(sid_proto::sid::v1::ResourceRoleSettings {
                    indicator: API.into(),
                    scopes: vec!["orders.read".into()],
                }),
                ..Default::default()
            },
        )
        .await?
        .response
        .application
        .ok_or("the created application")?;
    let api_resource = app.resource.ok_or("the application's resource")?;
    let app = app.client.ok_or("the application's client")?;
    served
        .projects
        .set_resource_access(
            &root,
            operation(storage.as_ref(), "app-access").await?,
            SetResourceAccessRequest {
                client_id: app.client_id.clone(),
                resource_id: api_resource.id.clone(),
                scopes: vec!["orders.read".into()],
            },
        )
        .await?;
    let verifier = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
    };
    let nonce = uuid::Uuid::now_v7().to_string();
    let code = served
        .authorization_code(&root, &app.client_id, &verifier, &nonce)
        .await?;
    let redeemed = served.redeem(&app.client_id, &code, &verifier).await?;
    // The access token is for the API (its audience), issued to the
    // requesting client; the ID token is for the client (its audience),
    // with the request's nonce and the same subject (RFC 9068 §3, OIDC Core
    // §3.1.3.7).
    let api_tokens = sid_authn::resource_token::ResourceTokenVerifier::new(
        served.installation.issuers.clone(),
        served.installation.issuer.clone(),
        sid_core::models::ResourceIndicator::parse(API)?,
    )
    .await?;
    let access = api_tokens.verify(&redeemed.access_token).await?;
    check(
        access.client_id.as_deref() == Some(app.client_id.as_str()),
        "the access token verifies at the API, issued to the requesting client",
    )?;
    let id_token = redeemed.id_token.as_deref().ok_or("an ID token")?;
    // The client's own validation (OIDC Core §3.1.3.7): the issuer's
    // signature and `iss`, an ID token, for this client, with its nonce.
    let id_claims = served
        .installation
        .issuers
        .verifier(&served.installation.issuer)
        .await?
        .validate_id_token(id_token, &app.client_id, &nonce)?;
    check(
        id_claims.sub == access.sub,
        "the ID token validates for the client with its nonce and the access token's subject",
    )?;
    let invalid_grant = |e: &OAuthError| matches!(e, OAuthError::Token { error, .. } if *error == TokenError::InvalidGrant);
    let rotated = redeemed.refresh_token.clone().ok_or("a refresh token")?;
    let second = served.refresh(&app.client_id, &rotated).await?;
    let current = second
        .refresh_token
        .clone()
        .ok_or("a rotated refresh token")?;
    check(current != rotated, "a refresh rotates the refresh token")?;
    let refreshed = api_tokens.verify(&second.access_token).await?;
    check(
        refreshed.client_id == access.client_id && refreshed.sub == access.sub,
        "a refresh keeps the grant's target, client and subject",
    )?;
    drop(api_tokens);
    // A client that lost the answer retries within the rotation's grace
    // window and is answered; after it, the rotated token is a replay.
    served.refresh(&app.client_id, &rotated).await?;
    println!("verified: a refresh retried within its grace window is answered");
    tokio::time::sleep(Duration::from_secs(
        (sid_core::models::refresh_token::DEFAULT_GRACE_WINDOW_SECS + 1).try_into()?,
    ))
    .await;
    refused(
        served.refresh(&app.client_id, &rotated).await,
        invalid_grant,
        "a rotated refresh token presented after its grace window is refused",
    )?;
    refused(
        served.refresh(&app.client_id, &current).await,
        invalid_grant,
        "the replay ends its family: the current refresh token is refused too",
    )?;
    refused(
        served.redeem(&app.client_id, &code, &verifier).await,
        invalid_grant,
        "a redeemed code is refused",
    )?;
    let fresh_code = served
        .authorization_code(&root, &app.client_id, &verifier, &nonce)
        .await?;
    refused(
        served
            .redeem(&app.client_id, &fresh_code, "not-the-verifier")
            .await,
        invalid_grant,
        "a code redeemed with a wrong PKCE verifier is refused",
    )?;

    // A second factor: the guest signs in again, enrolls a TOTP
    // authenticator under that sign-in and receives recovery codes; from then
    // on its password alone completes no sign-in, a wrong or spent code
    // completes none, the next code does, and a recovery code is spent once.
    let (guest, guest_token) = served.password_sign_in(GUEST, PASSWORD).await?;
    let enroller = Enroller::Session(guest.clone());
    let totp = served
        .factors
        .totp_enrollment_start(&served.sign_in, &enroller)
        .await?;
    let enrollment_code = sid_authn::generate_current_totp(&totp.shared_secret);
    let enrolled = served
        .factors
        .totp_enrollment_finish(&served.sign_in, &enroller, &enrollment_code)
        .await?;
    check(
        !enrolled.recovery_codes.is_empty(),
        "a first second factor comes with recovery codes",
    )?;
    let failed = |e: &SecondFactorError| matches!(e, SecondFactorError::AuthenticationFailed);
    // The CE baseline makes MFA optional: setup is voluntary, the enabled
    // protection is not skippable.
    let policy = sid_authn::login_policy::FixedLoginPolicy::of(&SecurityPolicy::ce_default());
    let pending = served
        .password_first_factor(&policy, GUEST, PASSWORD)
        .await?;
    check(
        !pending.second_factors.is_empty(),
        "under optional MFA, once TOTP is enabled the password alone completes no sign-in",
    )?;
    // A policy requiring MFA asks an account without a factor to enroll one,
    // not for a factor it does not have.
    let required = sid_authn::login_policy::FixedLoginPolicy::of(&{
        let mut policy = SecurityPolicy::ce_default();
        policy.auth.mfa_enforcement = sid_core::models::security_policy::MfaEnforcement::Required;
        policy
    });
    let unenrolled = served
        .password_first_factor(&required, ROOT, PASSWORD)
        .await?;
    check(
        unenrolled.second_factors.is_empty() && !unenrolled.enrollable_factors.is_empty(),
        "under required MFA an account without a factor is offered its enrollment",
    )?;
    let pending_session = || async {
        Ok::<_, Failure>(
            served
                .installation
                .storage
                .get_session(pending.signed_in.session_id)
                .await?
                .ok_or("the pending sign-in")?,
        )
    };
    refused(
        served
            .factors
            .verify_totp(
                &served.sign_in,
                &policy,
                FactorCaller::Pending(
                    pending_session().await?,
                    sid_authn::sign_in_delivery::CeremonyClient::Native,
                ),
                None,
                None,
                "000000",
            )
            .await,
        failed,
        "a wrong TOTP code completes no sign-in",
    )?;
    refused(
        served
            .factors
            .verify_totp(
                &served.sign_in,
                &policy,
                FactorCaller::Pending(
                    pending_session().await?,
                    sid_authn::sign_in_delivery::CeremonyClient::Native,
                ),
                None,
                None,
                &enrollment_code,
            )
            .await,
        failed,
        "the code spent by the enrollment completes no sign-in",
    )?;
    let completed = served
        .factors
        .verify_totp(
            &served.sign_in,
            &policy,
            FactorCaller::Pending(
                pending_session().await?,
                sid_authn::sign_in_delivery::CeremonyClient::Native,
            ),
            None,
            None,
            &sid_authn::generate_next_totp(&totp.shared_secret),
        )
        .await?;
    let (second_factor, second_token) = served.bearer(completed.delivery)?;
    let second_claims = served
        .jwt
        .validate_access_token(second_token.expose_secret())?;
    check(
        second_factor.profile_id == guest.profile_id
            && second_claims.amr.iter().any(|m| m == "otp"),
        "the next code completes the sign-in with the second factor recorded",
    )?;
    // A recovery code is spent once on the signed-in session.
    let verified = sid_authn::caller::Verified {
        claims: served
            .jwt
            .validate_access_token(guest_token.expose_secret())?,
        caller: guest.clone(),
        source: sid_authn::caller::TokenSource::Installation,
    };
    let code = enrolled.recovery_codes.first().ok_or("a recovery code")?;
    let spent = served
        .factors
        .verify_recovery_code(&served.sign_in, &verified, code)
        .await?;
    check(
        spent.remaining_codes == i32::try_from(enrolled.recovery_codes.len() - 1).ok(),
        "a recovery code is spent, one fewer remains",
    )?;
    refused(
        served
            .factors
            .verify_recovery_code(&served.sign_in, &verified, code)
            .await,
        failed,
        "a spent recovery code is refused",
    )?;

    // A passkey: the guest binds one under its two-factor sign-in and from
    // then on signs in with it alone, naming its account or letting the
    // authenticator name it; an assertion that does not verify signs in
    // nobody.
    let mut key = sid_authn::webauthn::soft_authenticator::SoftAuthenticator::new(ISSUER, RP_ID);
    let options = served
        .passkeys
        .registration_start(&served.sign_in, &second_factor)
        .await?;
    served
        .passkeys
        .registration_finish(
            &served.sign_in,
            &second_factor,
            sid_proto::sid::v1::WebAuthnRegistrationFinishRequest {
                credential: key.register(&options.options),
                label: Some("Laptop".into()),
            },
        )
        .await?;
    for principal in [Some(GUEST), None] {
        let signed_in = served.passkey_sign_in(&mut key, principal).await?;
        check(
            signed_in.second_factors.is_empty(),
            "a user-verified passkey completes the sign-in without another factor",
        )?;
        let (passkey_caller, passkey_token) = served.bearer(signed_in.signed_in.delivery)?;
        let claims = served
            .jwt
            .validate_access_token(passkey_token.expose_secret())?;
        check(
            passkey_caller.profile_id == guest.profile_id
                && claims.amr.iter().any(|m| m == "hwk" || m == "swk"),
            "the passkey signs in its own account with the key method recorded",
        )?;
    }
    key.behavior.corrupt_signature = true;
    refused(
        served.passkey_sign_in(&mut key, Some(GUEST)).await,
        |e| matches!(e, PasskeyError::AuthenticationFailed),
        "an assertion whose signature does not verify signs in nobody",
    )?;
    key.behavior.corrupt_signature = false;

    // The CE work the installation committed so far (event relays of the
    // registrations, the guest's session revocation) is settled by the CE
    // handlers the engine assembles; the host's own work, which no handler
    // of this run takes, stays pending through the drain.
    let kind = WorkKind::new(WORK_KIND)?;
    let work = NewWork::new(kind.clone(), vec![]);
    storage.enqueue_work(&work, 100).await?;
    check(
        due_work(storage.as_ref()).await?.len() > 1,
        "the installation owes CE work besides the host's",
    )?;
    let running = engine(&served, vec![])?.start();
    if tokio::time::timeout(Duration::from_secs(10), async {
        while due_work(storage.as_ref()).await.map(|w| w.len()).ok() != Some(1) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_err()
    {
        let owed = due_work(storage.as_ref()).await?;
        return Err(format!("the CE handlers settle the CE work; still owed: {owed:?}").into());
    }
    running.drain().await?;
    let (completed, scheduled) = ce_work_settled(storage.as_ref(), &client.operations).await?;
    check(
        completed.contains(sid_core::models::event::EVENT_RELAY_KIND)
            && completed.contains(sid_core::models::SESSION_REVOCATION_KIND),
        &format!(
            "the CE handlers complete every piece of CE work the installation owes: {completed:?}"
        ),
    )?;
    // Each registration operation's enrollment admission settles once the
    // operation can no longer commit; until then it is scheduled, and it
    // travels with the installation.
    check(
        client.operations.len() == 3 && scheduled.iter().eq(client.operations.keys()),
        "each registration operation leaves exactly its enrollment admission scheduled",
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
    let drained: Drained = engine(&reopened, vec![])?.start().drain().await?;

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
    let running = engine(&restored, vec![Arc::new(Probe(kind))])?.start();
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
        due_work(target_storage.as_ref()).await?.is_empty(),
        "the restored installation owes no due work",
    )?;
    check(
        ce_work_settled(target_storage.as_ref(), &client.operations)
            .await?
            .1
            == scheduled,
        "the restored installation keeps the source's scheduled work, every other piece completed",
    )?;
    let administrator = restored.administrator(PASSWORD).await?;
    // Revocations made before the snapshot hold after the restore: the
    // credential and the device key are restored revoked.
    let (restored_root, _) = restored.password_sign_in(ROOT, PASSWORD).await?;
    let credentials = restored
        .machines
        .list_machine_credentials(
            &restored_root,
            ListMachineCredentialsRequest {
                machine_user_id: machine.id.clone(),
            },
        )
        .await?
        .credentials;
    check(
        credentials
            .iter()
            .any(|c| c.kid == kid && c.status == MachineCredentialStatus::Revoked as i32),
        "the restored installation keeps the machine credential revoked",
    )?;
    check(
        sid_authn::caller::check_revocation(
            &restored.installation.revocation_cache,
            &machine_claims,
        )
        .await?,
        "the restored installation stops the revoked credential's token",
    )?;
    refused(
        restored
            .machine_token(&machine.client_id, &added.client_secret)
            .await,
        |e| matches!(e, OAuthError::ClientRefused),
        "the restored installation issues no token for the revoked credential",
    )?;
    let restored_owner = KeyCaller::from(&restored_root);
    let bindings = restored
        .devices
        .list_attestations(
            &mut LocalAccess(&restored_root),
            &restored_owner,
            ListDeviceAttestationsRequest {
                profile_id: Some(restored_root.profile_id.into()),
            },
        )
        .await?
        .attestations;
    check(
        bindings
            .iter()
            .filter(|b| b.device_id == device)
            .all(|b| b.status == DeviceAttestationStatus::Revoked as i32)
            && bindings.iter().any(|b| b.device_id == device),
        "the restored installation keeps the device's keys revoked",
    )?;
    refused(
        restored
            .devices
            .get_attestation(
                &mut LocalAccess(&restored_root),
                &restored_owner,
                GetDeviceAttestationRequest {
                    device_id: device.clone(),
                },
            )
            .await,
        |e| matches!(e, DeviceKeyError::NoAttestation(_)),
        "the restored device has no live key",
    )?;
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
