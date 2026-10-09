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
use sid_core::models::machine_user::{MachineCredentialType, MachineUserCredential, OwnerType};
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
    /// The installation's issuer.
    pub issuer: OidcIssuer,
    issuers: Arc<sid_authn::issuer::IssuerRegistry>,
    jwt: Arc<JwtService>,
    resources: Vec<ProtectedResource>,
    addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    serving: Option<tokio::task::JoinHandle<()>>,
}

fn audit(action: &str) -> sid_core::models::MutationContext {
    AuditEntry::system(action, "test-issuer").into()
}

/// The field-encryption key manager of the test installation.
fn key_manager() -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([0x5Au8; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![0x01; 32], "key-v1")],
            Arc::new(sid_keys::RustCryptoPrimitives::new()),
        )
        .expect("test key manager"),
    )
}

impl TestIssuer {
    /// Provision the issuer as a server start does, create `setup`, and
    /// serve it.
    pub async fn start(setup: Setup) -> Self {
        let backend = sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .expect("SQLite storage");
        let audit_log: Arc<dyn sid_plugin::audit::AuditLog> = Arc::new(
            sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone()),
        );
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

        let mut resources = Vec::new();
        for indicator in &setup.resources {
            resources.push(register(storage.as_ref(), &issuer, organization.id, indicator).await);
        }
        let checker_role = Role::permission_checker();
        let mut verifiers = Vec::new();
        for checker in &setup.checkers {
            let machine = MachineUser::new(
                ProjectId::system(),
                &checker.client_id,
                &checker.client_id,
                OwnerType::System,
                "system",
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
                let listed: Vec<String> = resources
                    .iter()
                    .map(|r| format!("\"{}\"", r.indicator.as_str()))
                    .collect();
                verifiers.push(format!(
                    r#"{{"subject": "machine:{}", "resources": [{}], "profiles": ["dpop"]}}"#,
                    machine.id,
                    listed.join(", ")
                ));
            }
        }
        let verifiers = sid_authz::request_verifier::RequestVerifiers::from_json(&format!(
            r#"{{"verifiers": [{}]}}"#,
            verifiers.join(", ")
        ))
        .expect("request verifiers");

        let cache: Arc<dyn CacheBackend> = Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
        let revocation = Arc::new(RevocationCache::new(
            std::time::Duration::from_secs(900),
            cache.clone(),
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
        let authz = sid_authz::grpc::AuthzServiceImpl::new(
            Arc::new(sid_authz::CeAuthzEngine::new(storage.clone())),
            storage.clone(),
            sid_authz::cedar::CedarService::new(),
            Arc::new(AtomicBool::new(false)),
            jwt.clone(),
            revocation.clone(),
            audit_log,
        )
        .with_service_tokens(service_tokens)
        .with_request_verifiers(verifiers);
        let auth = auth_service(
            storage.clone(),
            cache,
            jwt.clone(),
            revocation,
            issuers.clone(),
            organization.id,
            keys,
        );
        let oidc = sid_server::grpc::oidc_issuer_service::OidcIssuerServiceImpl::new(
            issuers.clone(),
            storage.clone(),
        );
        let routes = tonic::service::Routes::new(
            sid_proto::sid::v1::auth_service_server::AuthServiceServer::from_arc(auth),
        )
        .add_service(sid_proto::sid::v1::authz_service_server::AuthzServiceServer::new(authz))
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
            issuer,
            issuers,
            jwt,
            resources,
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
        cache_url: Option<String>,
    ) -> sid_auth::config::ReceiverConfig {
        sid_auth::config::ReceiverConfig {
            upstream: self.upstream(),
            issuer_url: INSTALLATION.into(),
            resource: resource.into(),
            origin: origin.into(),
            cache_url,
            checker: self.client_config(checker, secret_file),
        }
    }

    /// The configuration of the registered client `client_id` of this
    /// issuer, authenticating with the secret in `secret_file`.
    pub fn client_config(
        &self,
        client_id: &str,
        secret_file: &std::path::Path,
    ) -> sid_authn::client_credential::ClientCredentialConfig {
        sid_authn::client_credential::ClientCredentialConfig {
            issuer: self.issuer.canonical_url.clone(),
            client_id: client_id.into(),
            authentication: sid_authn::client_credential::ClientAuthentication::ClientSecretBasic {
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
        let mut role = Role::new(ProjectId::system(), name, name);
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
            ProjectId::system(),
            client_id,
            client_id,
            OwnerType::System,
            "system",
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

    /// An access token of `profile` for the resource `indicator`, from a
    /// stored sign-in; bound to the key `jkt` when given. Its subject is
    /// pairwise, never the ProfileId.
    pub async fn token(&self, profile: &Profile, indicator: &str, jkt: Option<&str>) -> Issued {
        let session = Session::new(
            profile.id,
            "127.0.0.1".into(),
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
                profile,
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
        project_id: ProjectId::system(),
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
        project_id: ProjectId::system(),
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
fn auth_service(
    storage: Arc<dyn StorageBackend>,
    cache: Arc<dyn CacheBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    issuers: Arc<sid_authn::issuer::IssuerRegistry>,
    org: sid_core::models::OrgId,
    keys: Arc<dyn sid_keys::KeyManager>,
) -> Arc<sid_server::grpc::auth_service::AuthServiceImpl> {
    use sid_authn::opaque::{OpaqueRouter, P256Opaque, PallasOpaque, RistrettoOpaque};
    use sid_plugin::crypto::{CurveId, OpaqueOperations};
    let primary = Box::new(PallasOpaque::new());
    let setup = primary.create_setup(None).expect("OPAQUE setup");
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
            cache.clone(),
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
        sid_authn::otp::OtpService::new(cache.clone()),
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
    ))
}

#[cfg(test)]
mod tests;
