// SPDX-License-Identifier: AGPL-3.0-only
//! A SID issuer served over gRPC on a loopback port, for the tests of a
//! service that verifies its tokens through `sid_auth::receiver`.
//!
//! It is the server's own token endpoint, authorization API and issuer
//! registry, provisioned as a server start provisions them, over a real
//! storage engine (SQLite in memory). The service under test reaches it only
//! over the network, with public trust material and its own credential, as
//! it does in a deployment. Fixtures are written to the issuer's store the
//! way its management APIs store them.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::machine_user::{MachineCredentialType, MachineOwner, MachineUserCredential};
use sid_core::models::{
    AUTHZ_CHECK, AuditEntry, MachineUser, OidcIssuer, Profile, ProjectId, ProtectedResource,
    ResourceAccess, ResourceId, ResourceIndicator, Role, RoleAssignment, RoleAssignmentPrincipal,
    Session,
};
use sid_plugin::StorageBackend;
use sid_plugin::cache::CacheBackend;

/// The installation's public URL.
pub const INSTALLATION: &str = "https://sid.example.com";

/// A service that asks the authorization API about its callers.
pub struct Checker {
    pub client_id: String,
    pub secret: String,
    /// Trusted to confirm the DPoP proofs it checked on its own resources.
    pub confirms_proofs: bool,
}

/// What exists before the issuer starts serving.
#[derive(Default)]
pub struct Setup {
    /// Resource indicators to register, each a protected resource of the
    /// installation's issuer.
    pub resources: Vec<String>,
    /// Services that may ask about callers, each holding the checker role on
    /// every registered resource.
    pub checkers: Vec<Checker>,
}

/// What the replicas of one installation share: issuers started on the same
/// one are its replicas, and an issuer started again on it is the
/// installation after a restart.
#[derive(Clone)]
pub struct Installation {
    /// The SQLite database URL the replicas keep their state in.
    pub store: String,
    /// The cache they share (single-use admissions, ceremony state), as
    /// replicas share their cache server.
    pub cache: Arc<dyn CacheBackend>,
}

impl Installation {
    /// An installation keeping its state in the SQLite file `path`.
    pub fn at(path: &std::path::Path) -> Self {
        Self {
            store: format!("sqlite://{}", path.display()),
            cache: Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        }
    }
}

/// An access token from a stored sign-in.
pub struct Issued {
    pub token: String,
    pub session: Session,
    /// The token's `sub`.
    pub subject: String,
}

/// The running issuer.
pub struct TestIssuer {
    pub storage: Arc<dyn StorageBackend>,
    /// The password-history evaluator's store, in the same database.
    pub history_keys: Arc<dyn sid_plugin::history_keys::HistoryKeyStore>,
    /// The installation's issuer.
    pub issuer: OidcIssuer,
    issuers: Arc<sid_authn::issuer::IssuerRegistry>,
    jwt: Arc<JwtService>,
    resources: Vec<ProtectedResource>,
    auth: Arc<sid_server::grpc::auth_service::AuthServiceImpl>,
    addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    serving: Option<tokio::task::JoinHandle<()>>,
}

fn audit(action: &str) -> sid_core::models::MutationContext {
    AuditEntry::system(action, "test-issuer").into()
}

/// The code an authenticator holding `seed` shows now (RFC 6238 as the
/// issuer verifies it), for a client signing in to an account
/// [`TestIssuer::enroll_totp`] protected.
pub fn totp_code(seed: &[u8]) -> String {
    sid_authn::generate_current_totp(seed)
}

/// The field-encryption key manager of the test installation.
fn key_manager() -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([0x5Au8; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![0x01; 32], "key-v1")],
            Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        )
        .expect("test key manager"),
    )
}

impl TestIssuer {
    /// Provision the issuer as a server start does, create `setup`, and
    /// serve it.
    pub async fn start(setup: Setup) -> Self {
        Self::start_in(setup, None).await
    }

    /// A replica of `installation`, provisioned and serving as [`start`]
    /// does. Every replica takes the installation's same `setup`, as
    /// replicas run with one configuration: the first creates its records,
    /// the others and a restarted one find them.
    ///
    /// [`start`]: Self::start
    pub async fn replica(setup: Setup, installation: &Installation) -> Self {
        Self::start_in(setup, Some(installation)).await
    }

    async fn start_in(setup: Setup, installation: Option<&Installation>) -> Self {
        let backend = match installation {
            Some(installation) => {
                sid_storage::sqlite::SqliteBackend::new(&installation.store).await
            }
            None => sid_storage::sqlite::SqliteBackend::new_in_memory().await,
        }
        .expect("SQLite storage");
        let audit_log: Arc<dyn sid_plugin::audit::AuditLog> = Arc::new(
            sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone()),
        );
        let history_keys: Arc<dyn sid_plugin::history_keys::HistoryKeyStore> =
            Arc::new(backend.history_keys());
        let storage: Arc<dyn StorageBackend> = Arc::new(backend);
        storage
            .ensure_system_project(audit("project.ensure_system"))
            .await
            .expect("system project");
        let keys = key_manager();
        let organization = sid_authn::instance_org::ensure(storage.as_ref(), "sid.example.com")
            .await
            .expect("installation organization");
        let issuer = sid_authn::issuer::ensure_local_issuer(
            storage.as_ref(),
            keys.as_ref(),
            &url::Url::parse(INSTALLATION).unwrap(),
            organization.id,
        )
        .await
        .expect("installation issuer");
        let api = sid_authn::issuer::ensure_authorization_api_resource(storage.as_ref(), &issuer)
            .await
            .expect("authorization API resource");
        sid_authz::builtin::ensure_permission_checker_role(storage.as_ref())
            .await
            .expect("permission checker role");
        let issuers = Arc::new(sid_authn::issuer::IssuerRegistry::new(
            storage.clone(),
            keys.clone(),
        ));
        let jwt = Arc::new(
            JwtService::new(
                include_bytes!("../../sid-authn/tests/fixtures/test_ed25519_private.pem"),
                include_bytes!("../../sid-authn/tests/fixtures/test_ed25519_public.pem"),
                INSTALLATION.to_string(),
            )
            .expect("token service"),
        );

        // A replica of an installation starts with the installation's setup
        // too, as replicas run with one configuration: the records the first
        // created are found, never created twice.
        let mut resources = Vec::new();
        for indicator in &setup.resources {
            let parsed = ResourceIndicator::parse(indicator).expect("a resource indicator");
            let found = storage
                .protected_resource_by_indicator(issuer.id, &parsed)
                .await
                .expect("resource lookup");
            resources.push(match found {
                Some(resource) => resource,
                None => register(storage.as_ref(), &issuer, organization.id, indicator).await,
            });
        }
        let checker_role = Role::permission_checker();
        let mut verifiers = Vec::new();
        for checker in &setup.checkers {
            if let Some(machine) = storage
                .get_machine_user_by_client_id(&checker.client_id)
                .await
                .expect("checker lookup")
            {
                if checker.confirms_proofs {
                    verifiers.push(verifier_entry(&machine, &resources));
                }
                continue;
            }
            let machine = MachineUser::new(
                ProjectId::SYSTEM,
                &checker.client_id,
                &checker.client_id,
                MachineOwner::System,
            );
            storage
                .create_machine_user(&machine, audit("machine_user.create"))
                .await
                .expect("checker");
            storage
                .add_machine_credential(
                    &MachineUserCredential::new(
                        machine.id,
                        format!("kid_{}", checker.client_id),
                        MachineCredentialType::ClientSecret,
                        sid_authn::bearer_secret::verifier_of(&checker.secret),
                    ),
                    None,
                    audit("machine_user.credential"),
                )
                .await
                .expect("checker credential");
            storage
                .set_resource_access(
                    &ResourceAccess {
                        client_id: checker.client_id.clone(),
                        resource_id: api.id,
                        scopes: vec![AUTHZ_CHECK.into()],
                        created_at: chrono::Utc::now(),
                    },
                    audit("resource_access.set"),
                )
                .await
                .expect("authorization API access");
            for resource in &resources {
                storage
                    .create_role_assignment(
                        &RoleAssignment::new(
                            RoleAssignmentPrincipal::MachineUser(machine.id),
                            checker_role.id,
                        )
                        .on_resource(resource.id),
                        audit("role_assignment.create"),
                    )
                    .await
                    .expect("checker role");
            }
            if checker.confirms_proofs {
                verifiers.push(verifier_entry(&machine, &resources));
            }
        }
        let verifiers = sid_authz::request_verifier::RequestVerifiers::from_json(&format!(
            r#"{{"verifiers": [{}]}}"#,
            verifiers.join(", ")
        ))
        .expect("request verifiers");

        let cache: Arc<dyn CacheBackend> = match installation {
            Some(installation) => installation.cache.clone(),
            None => Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        };
        let revocation = Arc::new(RevocationCache::recorded_in(
            std::time::Duration::from_secs(900),
            cache.clone(),
            storage.clone(),
        ));
        let service_tokens = Arc::new(
            sid_authn::resource_token::ResourceTokenVerifier::new(
                issuers.clone(),
                issuer.clone(),
                api.indicator.clone(),
            )
            .await
            .expect("authorization API token verifier"),
        );
        let authz = Arc::new(
            sid_server::grpc::authz_service::AuthzServiceImpl::new(
                Arc::new(sid_authz::CeAuthzEngine::new(storage.clone())),
                storage.clone(),
                sid_authz::cedar::CedarService::new(),
                Arc::new(AtomicBool::new(false)),
                jwt.clone(),
                revocation.clone(),
                audit_log,
            )
            .with_service_tokens(service_tokens)
            .with_request_verifiers(verifiers),
        );
        let auth = auth_service(
            storage.clone(),
            cache,
            jwt.clone(),
            revocation,
            issuers.clone(),
            organization.id,
            keys.clone(),
            sid_authn::password_operation::PasswordHistoryAuthority::InProcess {
                store: history_keys.clone(),
                history_keys: keys,
            },
        );
        let oidc = sid_server::grpc::oidc_issuer_service::OidcIssuerServiceImpl::new(
            issuers.clone(),
            storage.clone(),
            authz.clone(),
        );
        let routes = tonic::service::Routes::new(
            sid_proto::sid::v1::auth_service_server::AuthServiceServer::from_arc(auth.clone()),
        )
        .add_service(sid_proto::sid::v1::authz_service_server::AuthzServiceServer::from_arc(authz))
        .add_service(
            sid_proto::sid::v1::oidc_issuer_service_server::OidcIssuerServiceServer::new(oidc),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback port");
        let addr = listener.local_addr().expect("local address");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_routes(routes)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        stopped.await.ok();
                    },
                )
                .await
                .expect("test issuer");
        });
        Self {
            storage,
            history_keys,
            issuer,
            issuers,
            jwt,
            resources,
            auth,
            addr,
            stop: Some(stop),
            serving: Some(serving),
        }
    }

    /// The gRPC address services reach the issuer at.
    pub fn upstream(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The registered resource `indicator`.
    pub fn resource(&self, indicator: &str) -> &ProtectedResource {
        self.resources
            .iter()
            .find(|r| r.indicator.as_str() == indicator)
            .expect("a resource registered at start")
    }

    /// The receiver configuration of a service protecting `resource`,
    /// addressed at `origin`, asking as `checker` whose secret is in
    /// `secret_file`.
    pub fn receiver_config(
        &self,
        resource: &str,
        origin: &str,
        checker: &str,
        secret_file: &std::path::Path,
    ) -> sid_auth::config::ReceiverConfig {
        sid_auth::config::ReceiverConfig {
            upstream: self.upstream(),
            issuer_url: INSTALLATION.into(),
            resource: resource.into(),
            origin: origin.into(),
            checker: self.client_config(checker, secret_file),
        }
    }

    /// The configuration of the registered client `client_id` of this
    /// issuer, authenticating with the secret in `secret_file`.
    pub fn client_config(
        &self,
        client_id: &str,
        secret_file: &std::path::Path,
    ) -> sid_infra::client_credential::ClientCredentialConfig {
        sid_infra::client_credential::ClientCredentialConfig {
            issuer: self.issuer.canonical_url.clone(),
            client_id: client_id.into(),
            authentication: sid_infra::client_credential::ClientAuthentication::ClientSecretBasic {
                secret_file: secret_file.display().to_string(),
            },
        }
    }

    /// A stored Profile, under a name of its own.
    pub async fn profile(&self) -> Profile {
        let profile = Profile::new(Some(&format!("operator-{}", uuid::Uuid::now_v7().simple())));
        self.storage
            .create_profile(&profile, audit("profile.create"))
            .await
            .expect("profile");
        profile
    }

    /// A stored role named `name` holding `permissions`.
    pub async fn role(&self, name: &str, permissions: &[&str]) -> Role {
        let mut role = Role::new(ProjectId::SYSTEM, name, name);
        role.permissions = permissions.iter().map(|p| (*p).to_owned()).collect();
        self.storage
            .create_role(&role, audit("role.create"))
            .await
            .expect("role");
        role
    }

    /// A system machine user `client_id` authenticating with `secret`,
    /// allowed to obtain client credentials tokens for the resource
    /// `indicator`. What it may do there is what its grants allow.
    pub async fn machine(&self, client_id: &str, secret: &str, indicator: &str) -> MachineUser {
        let machine = MachineUser::new(
            ProjectId::SYSTEM,
            client_id,
            client_id,
            MachineOwner::System,
        );
        self.storage
            .create_machine_user(&machine, audit("machine_user.create"))
            .await
            .expect("machine user");
        self.storage
            .add_machine_credential(
                &MachineUserCredential::new(
                    machine.id,
                    format!("kid_{client_id}"),
                    MachineCredentialType::ClientSecret,
                    sid_authn::bearer_secret::verifier_of(secret),
                ),
                None,
                audit("machine_user.credential"),
            )
            .await
            .expect("machine credential");
        self.storage
            .set_resource_access(
                &ResourceAccess {
                    client_id: client_id.into(),
                    resource_id: self.resource(indicator).id,
                    scopes: vec![],
                    created_at: chrono::Utc::now(),
                },
                audit("resource_access.set"),
            )
            .await
            .expect("resource access");
        machine
    }

    /// Assign `role` to `machine` on the resource `indicator`.
    pub async fn grant_machine(&self, machine: &MachineUser, role: &Role, indicator: &str) {
        self.storage
            .create_role_assignment(
                &RoleAssignment::new(RoleAssignmentPrincipal::MachineUser(machine.id), role.id)
                    .on_resource(self.resource(indicator).id),
                audit("role_assignment.create"),
            )
            .await
            .expect("grant");
    }

    /// Assign `role` to `profile` on the resource `indicator`.
    pub async fn grant(&self, profile: &Profile, role: &Role, indicator: &str) {
        self.storage
            .create_role_assignment(
                &RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile.id), role.id)
                    .on_resource(self.resource(indicator).id),
                audit("role_assignment.create"),
            )
            .await
            .expect("grant");
    }

    /// Let the checker `client_id` inspect tokens issued for every registered
    /// resource (RFC 7662): the token inspector role on each, a permission of
    /// its own beside the checker's.
    pub async fn grant_inspection(&self, client_id: &str) {
        let role = sid_authz::builtin::ensure_token_inspector_role(self.storage.as_ref())
            .await
            .expect("token inspector role");
        let machine = self
            .storage
            .get_machine_user_by_client_id(client_id)
            .await
            .expect("machine user lookup")
            .expect("a registered checker");
        for resource in &self.resources {
            self.storage
                .create_role_assignment(
                    &RoleAssignment::new(RoleAssignmentPrincipal::MachineUser(machine.id), role.id)
                        .on_resource(resource.id),
                    audit("role_assignment.create"),
                )
                .await
                .expect("inspection");
        }
    }

    /// Make `profile` the installation's administrator: the built-in role,
    /// assigned across the installation, as the first claim assigns it.
    pub async fn administrator(&self, profile: &Profile) {
        let role =
            sid_authz::builtin::ensure_installation_administrator_role(self.storage.as_ref())
                .await
                .expect("installation administrator role");
        self.storage
            .create_role_assignment(
                &RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile.id), role.id)
                    .on_installation(),
                audit("role_assignment.create"),
            )
            .await
            .expect("installation administrator");
    }

    /// An access token of `profile` for the resource `indicator`, from a
    /// stored sign-in; bound to the key `jkt` when given. Its subject is
    /// pairwise, never the ProfileId.
    pub async fn token(&self, profile: &Profile, indicator: &str, jkt: Option<&str>) -> Issued {
        let session = Session::new(
            profile.id,
            None,
            chrono::Utc::now() + chrono::Duration::hours(1),
        );
        self.storage
            .create_session(&session, audit("session.create"))
            .await
            .expect("session");
        let binding = jkt.map(sid_core::models::dpop::DPopBinding::new);
        let signer = self.issuers.signer(&self.issuer).await.expect("signer");
        let pairwise = uuid::Uuid::now_v7().to_string();
        let client = console(self.resource(indicator));
        let token = self
            .jwt
            .access_token_signed_by(
                signer.as_ref(),
                sid_authn::jwt::TokenAudience::Resource {
                    indicator,
                    client_id: &client,
                },
                &pairwise,
                None,
                &profile.roles,
                &session,
                &[],
                binding.as_ref(),
                None,
            )
            .expect("access token");
        Issued {
            token,
            session,
            subject: pairwise,
        }
    }

    /// End `session`, as a sign-out does.
    pub async fn end(&self, session: &Session) {
        self.storage
            .delete_session(
                session.id,
                &sid_core::models::SessionEnd::new(
                    sid_core::models::RevocationReason::UserRequested,
                    "test",
                ),
                audit("session.end"),
            )
            .await
            .expect("end session");
    }

    /// Register `principal` (an email address) with `password` through the
    /// issuer's password registration; returns the Profile it created. On an
    /// installation not claimed yet the account registers with the open
    /// claim token, as its first administrator does; afterwards it registers
    /// as the installation's registration policy admits.
    pub async fn password_account(&self, principal: &str, password: &[u8]) -> Profile {
        use secrecy::ExposeSecret;
        use sid_proto::sid::v1::auth_service_server::AuthService;
        use sid_proto::sid::v1::{
            OpaqueZkppRegistrationFinishRequest, OpaqueZkppRegistrationStartRequest,
        };
        let claim_token =
            sid_authn::admin_claim::open_claim(self.storage.as_ref(), key_manager().as_ref())
                .await
                .expect("installation claim")
                .map(|token| token.expose_secret().to_owned());
        let started = password::start_registration(password);
        let prepared = self
            .auth
            .opaque_zkpp_registration_start(tonic::Request::new(
                OpaqueZkppRegistrationStartRequest {
                    principal: principal.to_owned(),
                    registration_request: started.request.clone(),
                    claim_token,
                    invite_code: None,
                },
            ))
            .await
            .expect("registration start")
            .into_inner();
        let operation_id = prepared
            .history
            .expect("the registration's history context")
            .operation_id;
        let record =
            password::finish_registration(started, password, &prepared.registration_response);
        self.auth
            .opaque_zkpp_registration_finish(tonic::Request::new(
                OpaqueZkppRegistrationFinishRequest {
                    operation_id,
                    registration_record: record,
                    proof: None,
                },
            ))
            .await
            .expect("registration finish");
        // The account is found as a sign-in finds it: by the principal's
        // resolution key, not by the spelling the caller typed.
        let key = sid_authn::normalize::normalize_principal(principal)
            .expect("a principal the registration admitted")
            .normalized;
        let holder = self
            .storage
            .get_principal_by_value(sid_core::models::PrincipalType::Email, &key)
            .await
            .expect("principal lookup")
            .and_then(|p| p.assigned_profile_id)
            .expect("the registered principal's profile");
        self.storage
            .get_profile(holder)
            .await
            .expect("profile lookup")
            .expect("the registered profile")
    }

    /// Enroll an authenticator app for `profile`: an active TOTP credential
    /// stored as enrollment stores it, its seed sealed under the account's
    /// TOTP context with the installation's field key. Returns the seed, from
    /// which a client computes the codes (RFC 6238, SHA-1, 6 digits, 30 s).
    /// The account's sign-ins then owe this factor.
    pub async fn enroll_totp(&self, profile: &Profile) -> Vec<u8> {
        use sid_core::models::{Credential, CredentialData, CredentialType};
        let seed = sid_authn::generate_secret();
        let sealed = sid_authn::sealed_secret::seal(
            key_manager().as_ref(),
            &sid_authn::sealed_secret::totp_context(profile.id),
            &seed,
        )
        .await
        .expect("seal the TOTP seed");
        self.storage
            .create_credential(
                &Credential::new(
                    profile.id,
                    CredentialType::Totp,
                    CredentialData::new(sealed),
                    None,
                ),
                audit("credential.totp_enrolled"),
            )
            .await
            .expect("store the TOTP credential");
        seed
    }

    /// Start a password sign-in of `principal` and answer the issuer's
    /// challenge as the client does; returns the finish request the client
    /// sends next. Its `login_id` is the reference a native proof of the
    /// sign-in binds (`sid_cer`).
    pub async fn start_password_login(
        &self,
        principal: &str,
        password: &[u8],
    ) -> sid_proto::sid::v1::OpaqueLoginFinishRequest {
        use sid_proto::sid::v1::auth_service_server::AuthService;
        use sid_proto::sid::v1::{OpaqueLoginFinishRequest, OpaqueLoginStartRequest};
        let login = password::start_login(password);
        let started = self
            .auth
            .opaque_login_start(tonic::Request::new(OpaqueLoginStartRequest {
                principal: principal.to_owned(),
                credential_request: login.request.clone(),
            }))
            .await
            .expect("login start")
            .into_inner();
        OpaqueLoginFinishRequest {
            principal: principal.to_owned(),
            credential_finalization: password::finish_login(
                login,
                password,
                &started.credential_response,
            ),
            login_id: started.login_id,
        }
    }

    /// Stop serving and wait until the issuer is unreachable: its listener
    /// is closed and its connections are gone.
    pub async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.send(()).ok();
        }
        if let Some(serving) = self.serving.take() {
            serving.await.expect("test issuer stopped");
        }
    }
}

impl Drop for TestIssuer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.send(()).ok();
        }
    }
}

/// The request-verifier entry trusting `machine` to confirm DPoP proofs on
/// `resources`.
fn verifier_entry(machine: &MachineUser, resources: &[ProtectedResource]) -> String {
    let listed: Vec<String> = resources
        .iter()
        .map(|r| format!("\"{}\"", r.indicator.as_str()))
        .collect();
    format!(
        r#"{{"subject": "machine:{}", "resources": [{}], "profiles": ["dpop"]}}"#,
        machine.id,
        listed.join(", ")
    )
}

/// The client that signs users in to `resource`'s application: the
/// console its users reach the service through.
fn console(resource: &ProtectedResource) -> String {
    format!("console-{}", resource.id)
}

/// Register the protected resource `indicator` of `issuer` with its
/// application and that application's sign-in client, in the issuer's
/// organization `org`, as the application API stores them.
async fn register(
    storage: &dyn StorageBackend,
    issuer: &OidcIssuer,
    org: sid_core::models::OrgId,
    indicator: &str,
) -> ProtectedResource {
    use sid_core::models::{
        ApplicationType, EnforcementMode, LoginStrategy, OAuth2Client, SubjectType,
        TokenEndpointAuthMethod,
    };
    let now = chrono::Utc::now();
    let app = sid_core::models::Application {
        id: sid_core::models::ApplicationId::generate(),
        project_id: ProjectId::SYSTEM,
        name: indicator.to_owned(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let resource = ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(app.id),
        issuer_id: issuer.id,
        indicator: ResourceIndicator::parse(indicator).expect("a resource indicator"),
        scopes: vec![],
        state: sid_core::models::ResourceState::Active,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let client = OAuth2Client {
        client_id: console(&resource),
        project_id: ProjectId::SYSTEM,
        application_id: app.id,
        default_resource: Some(resource.id),
        application_type: ApplicationType::Spa,
        client_secret_hash: None,
        jwks: None,
        redirect_uris: vec![format!("{}/callback", indicator.trim_end_matches('/'))],
        allowed_scopes: vec!["openid".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        client_name: indicator.to_owned(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: TokenEndpointAuthMethod::None,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: now,
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: None,
        required_amr: vec![],
        enforcement_mode: EnforcementMode::Audit,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        login_strategy: LoginStrategy::LocalFirst,
        show_federation_button: false,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: Some(org),
        revision: 0,
        created_at: now,
    };
    storage
        .create_application(
            &app,
            Some(&client),
            Some(&resource),
            audit("application.create"),
        )
        .await
        .expect("resource");
    resource
}

/// The authentication service, as a server start builds it; only its token
/// endpoint is used here.
#[allow(clippy::too_many_arguments)]
fn auth_service(
    storage: Arc<dyn StorageBackend>,
    cache: Arc<dyn CacheBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    issuers: Arc<sid_authn::issuer::IssuerRegistry>,
    org: sid_core::models::OrgId,
    keys: Arc<dyn sid_keys::KeyManager>,
    password_history: sid_authn::password_operation::PasswordHistoryAuthority,
) -> Arc<sid_server::grpc::auth_service::AuthServiceImpl> {
    use sid_authn::opaque::{OpaqueRouter, P256Opaque, PallasOpaque, RistrettoOpaque};
    use sid_plugin::crypto::{CurveId, OpaqueOperations};
    let primary = Box::new(PallasOpaque::new());
    // Every issuer of the test installation derives the same OPAQUE server
    // setup, so a registration or a login started at one replica finishes at
    // another, as an installation's replicas share theirs.
    let setup = primary
        .create_setup(Some(b"sid-test-issuer OPAQUE server setup"))
        .expect("OPAQUE setup");
    let mut verifiers: std::collections::HashMap<CurveId, Box<dyn OpaqueOperations>> =
        std::collections::HashMap::new();
    verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
    verifiers.insert(CurveId::Pallas, Box::new(PallasOpaque::new()));
    verifiers.insert(CurveId::P256, Box::new(P256Opaque::new()));
    let opaque_router = Arc::new(OpaqueRouter::new(primary, verifiers, setup));
    let zkpp = Arc::new(
        sid_authn::opaque_zkpp::ZkppOpaqueServer::new(
            &opaque_router,
            vec![],
            sid_authn::opaque_zkpp::ZkppConfig {
                require_proof: false,
                policy_version: 1,
            },
        )
        .expect("ZKPP server"),
    );
    let webauthn = Arc::new(
        sid_authn::webauthn::WebAuthnServer::new(
            "sid.example.com",
            &url::Url::parse(INSTALLATION).unwrap(),
            storage.clone(),
            keys.clone(),
        )
        .expect("WebAuthn"),
    );
    let cascade = Arc::new(
        sid_authn::revocation_cascade::RevocationCascadeService::new(
            storage.clone(),
            revocation.clone(),
        ),
    );
    Arc::new(sid_server::grpc::auth_service::AuthServiceImpl::new(
        storage.clone(),
        Arc::new(sid_authn::oauth2::OAuth2Server::new(jwt.clone())),
        webauthn,
        jwt,
        opaque_router,
        Arc::new(arc_swap::ArcSwap::from_pointee(Some(zkpp))),
        revocation,
        sid_server::feature_flags::FeatureFlagService::disabled(),
        None,
        Arc::new(sid_authn::otp::OtpService::new(
            storage.clone(),
            sid_authn::otp::CodeDelivery {
                keys: keys.clone(),
                work: storage.clone(),
                capacity: sid_plugin::OWED_WORK_CAPACITY,
            },
        )),
        issuers,
        org,
        INSTALLATION.to_string(),
        Arc::new(sid_authn::captcha::SidPowProvider::new([0u8; 32], 4, 300)),
        cache.clone(),
        Arc::new(sid_authn::ip_intelligence::IpIntelligenceAggregator::new(
            vec![],
            cache.clone(),
            std::time::Duration::from_secs(60),
        )),
        Arc::new(sid_authn::geoip::GeoIpChain::empty(cache)),
        keys,
        cascade,
        Arc::new(sid_authz::CeAuthzEngine::new(storage)),
        password_history,
    ))
}

mod password;

#[cfg(test)]
mod tests;
