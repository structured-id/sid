// SPDX-License-Identifier: AGPL-3.0-only
//! Shared test infrastructure for sid-server integration tests.
//!
//! Provides MockStorage (in-memory StorageBackend) and helper functions
//! to construct gRPC service instances for testing.

#![allow(dead_code)]

pub mod mock_storage;
pub mod oauth_client;
pub mod opaque_client;
pub mod zkpp_client;

use sid_authn::account_closure::AccountClosureService;
use sid_authn::data_export::DataExportService;
use sid_authn::jwt::JwtService;
use sid_authn::magic_link::MagicLinkService;
use sid_authn::oauth2::OAuth2Server;
use sid_authn::opaque::{OpaqueRouter, P256Opaque, PallasOpaque, RistrettoOpaque};
use sid_authn::opaque_zkpp::{ZkppConfig, ZkppOpaqueServer};
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_authn::webauthn::WebAuthnServer;
use sid_core::models::{Profile, ProfileId, Session};
use sid_pake_core::verifier::ZkppVerifier;
use sid_plugin::StorageBackend;
use sid_plugin::audit::{AuditLog, VerifyResult};
use sid_plugin::cache::NoCacheBackend;
use sid_plugin::crypto::{CurveId, OpaqueOperations};
use sid_plugin::event_bus::InProcessEventBus;
use sid_server::feature_flags::FeatureFlagService;
use sid_server::grpc::{
    admin_service::AdminServiceImpl,
    auth_service::AuthServiceImpl,
    flow_service::{FlowActionServiceImpl, FlowConfigServiceImpl},
    identity_service::IdentityServiceImpl,
    project_service::ProjectServiceImpl,
    security_service::SecurityServiceImpl,
};
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

use chrono::{Duration, Utc};
use mock_storage::MockStorage;

/// No-op audit log for tests that don't need audit verification.
struct NoOpAuditLog;

#[async_trait::async_trait]
impl AuditLog for NoOpAuditLog {
    async fn log(
        &self,
        _chain_id: &str,
        _entry: sid_core::models::audit::AuditEntry,
    ) -> Result<sid_core::models::audit::AuditRecord, sid_core::models::audit::AuditError> {
        Err(sid_core::models::audit::AuditError::WriteFailed(
            "NoOpAuditLog".into(),
        ))
    }

    async fn query(
        &self,
        _chain_id: &str,
        _from: Option<chrono::DateTime<chrono::Utc>>,
        _to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<sid_core::models::audit::AuditRecord>, sid_core::models::audit::AuditError>
    {
        Ok(vec![])
    }

    async fn verify_chain(
        &self,
        _chain_id: &str,
    ) -> Result<VerifyResult, sid_core::models::audit::AuditError> {
        Ok(VerifyResult {
            valid: true,
            records_verified: 0,
            first_broken_record: None,
        })
    }

    async fn list_chain_ids(&self) -> Result<Vec<String>, sid_core::models::audit::AuditError> {
        Ok(vec![])
    }
}

/// A shared cache whose DPoP replay records cannot be written, every other
/// key served by the cache it wraps: a proof's single use cannot be recorded.
#[allow(dead_code)]
pub struct NoReplayRecord(pub Arc<dyn sid_plugin::cache::CacheBackend>);

#[async_trait::async_trait]
impl sid_plugin::cache::CacheBackend for NoReplayRecord {
    async fn get(&self, key: &str) -> sid_plugin::cache::CacheResult<Option<Vec<u8>>> {
        self.0.get(key).await
    }
    async fn set(
        &self,
        key: &str,
        value: &[u8],
        ttl: std::time::Duration,
    ) -> sid_plugin::cache::CacheResult<()> {
        self.0.set(key, value, ttl).await
    }
    async fn delete(&self, key: &str) -> sid_plugin::cache::CacheResult<()> {
        self.0.delete(key).await
    }
    async fn take(&self, key: &str) -> sid_plugin::cache::CacheResult<Option<Vec<u8>>> {
        self.0.take(key).await
    }
    async fn exists(&self, key: &str) -> sid_plugin::cache::CacheResult<bool> {
        self.0.exists(key).await
    }
    async fn set_nx(
        &self,
        key: &str,
        value: &[u8],
        ttl: std::time::Duration,
    ) -> sid_plugin::cache::CacheResult<bool> {
        if key.starts_with("jti:dpop:") {
            return Err(sid_plugin::cache::CacheError::Connection("down".into()));
        }
        self.0.set_nx(key, value, ttl).await
    }
    async fn incr(
        &self,
        key: &str,
        ttl: std::time::Duration,
    ) -> sid_plugin::cache::CacheResult<u64> {
        self.0.incr(key, ttl).await
    }
    async fn publish(&self, channel: &str, message: &[u8]) -> sid_plugin::cache::CacheResult<()> {
        self.0.publish(channel, message).await
    }
    async fn subscribe(
        &self,
        channel: &str,
    ) -> sid_plugin::cache::CacheResult<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
        self.0.subscribe(channel).await
    }
    async fn health_check(&self) -> sid_plugin::cache::CacheResult<()> {
        self.0.health_check().await
    }
}

/// The shared cache of the test stack (Redis 63799).
#[allow(dead_code)]
pub async fn test_redis() -> Arc<dyn sid_plugin::cache::CacheBackend> {
    let url =
        std::env::var("SID_TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:63799".into());
    sid_infra::shared_cache(Some(&url))
        .await
        .expect("the test stack's Redis")
}

/// An audit log keeping the entries written to it, in order, with their
/// chains, for tests asserting what was recorded.
#[derive(Default)]
#[allow(dead_code)]
pub struct RecordingAuditLog {
    entries: std::sync::Mutex<Vec<(String, sid_core::models::audit::AuditEntry)>>,
}

#[allow(dead_code)]
impl RecordingAuditLog {
    /// A shared, empty log.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Every `(chain, entry)` written so far.
    pub fn entries(&self) -> Vec<(String, sid_core::models::audit::AuditEntry)> {
        self.entries.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl AuditLog for RecordingAuditLog {
    async fn log(
        &self,
        chain_id: &str,
        entry: sid_core::models::audit::AuditEntry,
    ) -> Result<sid_core::models::audit::AuditRecord, sid_core::models::audit::AuditError> {
        let record = sid_core::models::audit::AuditRecord {
            id: uuid::Uuid::now_v7().to_string(),
            timestamp: Utc::now(),
            chain_id: chain_id.to_owned(),
            sequence: 0,
            actor_id: entry.actor_id.clone(),
            actor_type: entry.actor_type,
            action: entry.action.clone(),
            resource: entry.resource.clone(),
            outcome: entry.outcome,
            metadata: entry.metadata.clone(),
            ip_address: entry.ip_address.clone(),
            device_id: entry.device_id.clone(),
            prev_hash: String::new(),
            hash: String::new(),
        };
        self.entries
            .lock()
            .unwrap()
            .push((chain_id.to_owned(), entry));
        Ok(record)
    }

    async fn query(
        &self,
        _chain_id: &str,
        _from: Option<chrono::DateTime<chrono::Utc>>,
        _to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<sid_core::models::audit::AuditRecord>, sid_core::models::audit::AuditError>
    {
        Ok(vec![])
    }

    async fn verify_chain(
        &self,
        _chain_id: &str,
    ) -> Result<VerifyResult, sid_core::models::audit::AuditError> {
        Ok(VerifyResult {
            valid: true,
            records_verified: 0,
            first_broken_record: None,
        })
    }

    async fn list_chain_ids(&self) -> Result<Vec<String>, sid_core::models::audit::AuditError> {
        Ok(vec![])
    }
}

pub fn test_jwt() -> Arc<JwtService> {
    Arc::new(test_jwt_service())
}

/// The installation's token service of every test server.
pub fn test_jwt_service() -> JwtService {
    let private_pem = include_bytes!("../../../sid-authn/tests/fixtures/test_ed25519_private.pem");
    let public_pem = include_bytes!("../../../sid-authn/tests/fixtures/test_ed25519_public.pem");
    JwtService::new(
        private_pem,
        public_pem,
        "https://sid.example.com".to_string(),
    )
    .expect("JWT creation failed")
}

/// An empty revocation cache, as a freshly started server has.
pub fn test_revocation() -> Arc<RevocationCache> {
    Arc::new(RevocationCache::new(
        std::time::Duration::from_secs(900),
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
    ))
}

/// A WebAuthn server keeping its ceremony state in `cache`.
pub fn test_webauthn(cache: Arc<dyn sid_plugin::cache::CacheBackend>) -> Arc<WebAuthnServer> {
    let origin = Url::parse("https://sid.example.com").unwrap();
    Arc::new(
        WebAuthnServer::new("sid.example.com", &origin, cache, test_key_manager())
            .expect("WebAuthn creation failed"),
    )
}

pub fn test_opaque_router() -> Arc<OpaqueRouter> {
    let primary = Box::new(PallasOpaque::new());
    let setup = primary.create_setup(None).unwrap();
    opaque_router(primary, setup)
}

/// An OPAQUE router whose server setup is the one stored in `storage`, as a
/// server process loads it on start.
#[allow(dead_code)]
pub async fn stored_opaque_router(storage: &dyn StorageBackend) -> Arc<OpaqueRouter> {
    let primary = Box::new(PallasOpaque::new());
    let setup = sid_authn::opaque::server_setup::load_or_create(
        storage,
        test_key_manager().as_ref(),
        primary.as_ref(),
    )
    .await
    .expect("stored OPAQUE setup");
    opaque_router(primary, setup)
}

fn opaque_router(
    primary: Box<PallasOpaque>,
    setup: sid_plugin::crypto::OpaqueSetupHandle,
) -> Arc<OpaqueRouter> {
    let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
    verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
    verifiers.insert(CurveId::Pallas, Box::new(PallasOpaque::new()));
    verifiers.insert(CurveId::P256, Box::new(P256Opaque::new()));
    Arc::new(OpaqueRouter::new(primary, verifiers, setup))
}

pub fn test_profile() -> Profile {
    Profile::new(Some("alice"))
}

/// The password whose legacy hash [`LEGACY_HASH`] is.
pub const LEGACY_PASSWORD: &str = "right";
/// bcrypt hash (cost 4) of [`LEGACY_PASSWORD`], as an imported legacy password.
pub const LEGACY_HASH: &str = "$2b$04$eRzmeciDokem1Nq176hkIuDFn./QFPLjp9ODMCuBml/ZVTjW1sHg2";

/// A legacy password credential of `profile`: [`LEGACY_PASSWORD`].
pub fn legacy_password(profile: ProfileId) -> sid_core::models::Credential {
    sid_core::models::Credential::new(
        profile,
        sid_core::models::CredentialType::LegacyHash,
        LEGACY_HASH.as_bytes().to_vec(),
        None,
    )
}

/// Whether signing in as `principal` reaches `profile`. The profile gets a
/// legacy password and a migration start is tried with it: only a route to
/// a profile holding that password verifies it (the empty OPAQUE request is
/// then the first thing refused); anything else is refused like an unknown
/// account. Every probed profile keeps the password, so after probing one
/// profile a `true` for another only proves a route to one of them.
pub async fn routes_to(svc: &TestServices, principal: &str, profile: ProfileId) -> bool {
    use sid_proto::sid::v1::auth_service_server::AuthService;

    svc.storage
        .create_credential(
            &legacy_password(profile),
            sid_core::models::AuditEntry::system("test", "setup").into(),
        )
        .await
        .expect("legacy password stored");
    let answer = svc
        .auth
        .legacy_migrate_start(tonic::Request::new(
            sid_proto::sid::v1::LegacyMigrateStartRequest {
                principal: principal.to_string(),
                password: LEGACY_PASSWORD.to_string(),
                opaque_registration_request: vec![],
            },
        ))
        .await;
    match answer {
        Err(status) if status.code() == tonic::Code::InvalidArgument => true,
        Err(status) if status.code() == tonic::Code::Unauthenticated => false,
        other => panic!("unexpected migration start answer: {other:?}"),
    }
}

pub fn test_client() -> sid_core::models::OAuth2Client {
    sid_core::models::OAuth2Client {
        client_id: "test-client".to_string(),
        project_id: sid_core::models::ProjectId::system(),
        application_id: sid_core::models::ApplicationId::generate(),
        default_resource: None,
        application_type: sid_core::models::ApplicationType::Spa,
        client_secret_hash: None,
        jwks: None,
        redirect_uris: vec!["https://app.sid.example.com/callback".to_string()],
        allowed_scopes: vec!["openid".into(), "profile".into(), "email".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        client_name: "Test App".to_string(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: sid_core::models::TokenEndpointAuthMethod::None,
        response_types: vec!["code".into()],
        subject_type: sid_core::models::SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: Utc::now(),
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: None,
        required_amr: vec![],
        enforcement_mode: sid_core::models::EnforcementMode::Audit,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        login_strategy: sid_core::models::LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: Some(test_org()),
        revision: 0,
        created_at: Utc::now(),
    }
}

/// Store `client` as the client role of an application of its own, the way
/// an administrator registers one.
#[allow(dead_code)]
pub async fn store_client(
    storage: &dyn sid_plugin::StorageBackend,
    client: &sid_core::models::OAuth2Client,
) -> sid_core::Result<()> {
    let app = sid_core::models::Application {
        id: client.application_id,
        project_id: client.project_id,
        name: client.client_name.clone(),
        system: None,
        revision: 0,
        created_at: client.created_at,
        updated_at: client.created_at,
    };
    storage
        .create_application(
            &app,
            Some(client),
            None,
            sid_core::models::AuditEntry::system("test", "application").into(),
        )
        .await
}

/// Issue a bearer token for a profile with given scopes.
pub fn issue_token(jwt: &JwtService, profile: &Profile, scopes: &[String]) -> String {
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        Utc::now() + Duration::hours(1),
    );
    jwt.issue_access_token(
        &profile.id.to_string(),
        Some(&profile.id.to_string()),
        profile,
        &session,
        scopes,
        None,
        None,
    )
    .unwrap()
}

/// An access token the installation's OIDC issuer gives the test client for
/// `profile`, as the token endpoint issues it (no `pid`, issuer `iss`, the
/// issuer's UserInfo resource as `aud`, the client as `client_id`).
#[allow(dead_code)]
pub async fn issue_application_token(
    svc: &TestServices,
    profile: &Profile,
    scopes: &[String],
) -> String {
    issue_application_token_to(svc, profile, scopes, "test-client").await
}

/// The OAuth `error` code a refusal carries in its ErrorInfo metadata
/// (RFC 6749 §5.2).
#[allow(dead_code)]
pub fn oauth_error(status: &tonic::Status) -> Option<String> {
    tonic_types::StatusExt::get_details_error_info(status)
        .and_then(|info| info.metadata.get("oauthError").cloned())
}

/// The ErrorInfo reason a refusal carries.
#[allow(dead_code)]
pub fn error_reason(status: &tonic::Status) -> Option<String> {
    tonic_types::StatusExt::get_details_error_info(status).map(|info| info.reason)
}

/// Client id of [`confidential_client`].
#[allow(dead_code)]
pub const CONFIDENTIAL_CLIENT: &str = "confidential-client";
/// Secret of [`confidential_client`].
#[allow(dead_code)]
pub const CONFIDENTIAL_SECRET: &str = "confidential-client-secret";

/// A confidential client of the installation's issuer, registered for HTTP
/// Basic (the RFC 7591 §2 default).
#[allow(dead_code)]
pub fn confidential_client() -> sid_core::models::OAuth2Client {
    let mut client = test_client();
    client.client_id = CONFIDENTIAL_CLIENT.into();
    client.application_id = sid_core::models::ApplicationId::generate();
    client.application_type = sid_core::models::ApplicationType::Web;
    client.client_secret_hash = Some(
        OAuth2Server::hash_client_secret(CONFIDENTIAL_SECRET)
            .unwrap()
            .into_bytes(),
    );
    client.token_endpoint_auth_method =
        sid_core::models::TokenEndpointAuthMethod::ClientSecretBasic;
    client
}

/// `message` sent by `client_id` authenticating with HTTP Basic `secret`
/// (RFC 6749 §2.3.1).
#[allow(dead_code)]
pub fn as_client<T>(message: T, client_id: &str, secret: &str) -> tonic::Request<T> {
    use base64::Engine;
    let credentials =
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
    let mut request = tonic::Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        format!("Basic {credentials}").parse().unwrap(),
    );
    request
}

/// Whether `token` is an access token the installation's issuer vouches for
/// now: signed by it for a client, unexpired and unrevoked.
#[allow(dead_code)]
pub async fn token_active(svc: &TestServices, token: &str) -> bool {
    let verifier = svc.issuers.verifier(&svc.issuer).await.unwrap();
    match verifier.validate_access_token(token) {
        Ok(claims) => !sid_authn::caller::check_revocation(&svc.revocation_cache, &claims)
            .await
            .unwrap(),
        Err(_) => false,
    }
}

/// An access token the installation's OIDC issuer gives `client_id` for
/// `profile`, as the token endpoint issues it for the issuer's UserInfo
/// resource.
#[allow(dead_code)]
pub async fn issue_application_token_to(
    svc: &TestServices,
    profile: &Profile,
    scopes: &[String],
    client_id: &str,
) -> String {
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        Utc::now() + Duration::hours(1),
    );
    // A real grant is redeemed from a stored session; its token lives only
    // as long as that session.
    svc.storage
        .create_session(
            &session,
            sid_core::models::AuditEntry::system("test", "session").into(),
        )
        .await
        .unwrap();
    let signer = svc.issuers.signer(&svc.issuer).await.unwrap();
    let userinfo = sid_authn::issuer::userinfo_endpoint(&svc.issuer.canonical_url);
    svc.jwt
        .access_token_signed_by(
            signer.as_ref(),
            sid_authn::jwt::TokenAudience::Resource {
                indicator: &userinfo,
                client_id,
            },
            &profile.id.to_string(),
            None,
            profile,
            &session,
            scopes,
            None,
            None,
        )
        .unwrap()
}

/// The installation issuer's UserInfo resource, which the test clients use
/// as their default token target.
#[allow(dead_code)]
pub async fn userinfo_resource(svc: &TestServices) -> sid_core::models::ResourceId {
    userinfo(svc).await.id
}

async fn userinfo(svc: &TestServices) -> sid_core::models::ProtectedResource {
    let indicator = sid_core::models::ResourceIndicator::parse(
        &sid_authn::issuer::userinfo_endpoint(&svc.issuer.canonical_url),
    )
    .unwrap();
    svc.storage
        .protected_resource_by_indicator(svc.issuer.id, &indicator)
        .await
        .unwrap()
        .expect("the UserInfo resource is provisioned")
}

/// Give `principal` the built-in token inspector role on `resource`, as an
/// administrator assigns it; returns the stored assignment.
#[allow(dead_code)]
pub async fn grant_inspection(
    svc: &TestServices,
    principal: sid_core::models::RoleAssignmentPrincipal,
    resource: sid_core::models::ResourceId,
) -> sid_core::models::RoleAssignment {
    let role = svc
        .storage
        .list_roles(sid_core::models::ProjectId::system())
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.key == sid_core::models::TOKEN_INSPECTOR_ROLE)
        .expect("the token inspector role is provisioned");
    let assignment =
        sid_core::models::RoleAssignment::new(principal, role.id).on_resource(resource);
    svc.storage
        .create_role_assignment(
            &assignment,
            sid_core::models::AuditEntry::system("test", "inspection").into(),
        )
        .await
        .unwrap();
    assignment
}

/// Give every client stored so far the UserInfo resource, as the services
/// do at start for the clients stored before them.
#[allow(dead_code)]
pub async fn open_userinfo_to_clients(svc: &TestServices) {
    svc.mock_storage.open_to_every_client(&userinfo(svc).await);
}

/// Issue a bearer token for a profile using a specific session.
/// Returns (token, session) so the session can be stored in MockStorage.
pub fn issue_token_with_session(
    jwt: &JwtService,
    profile: &Profile,
    scopes: &[String],
    session: Session,
) -> (String, Session) {
    let token = jwt
        .issue_access_token(
            &profile.id.to_string(),
            Some(&profile.id.to_string()),
            profile,
            &session,
            scopes,
            None,
            None,
        )
        .unwrap();
    (token, session)
}

/// A session of `profile` authenticated `minutes_ago` at `level`.
#[allow(dead_code)]
pub fn authenticated_session(
    profile: &Profile,
    level: sid_core::models::AuthLevel,
    minutes_ago: i64,
) -> Session {
    let mut session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        Utc::now() + Duration::hours(24),
    );
    session.assurance_level = level;
    session.authenticated_at = Utc::now() - Duration::minutes(minutes_ago);
    session
}

/// Store `session` and issue its bearer token, so handlers that read the
/// caller's session find it.
#[allow(dead_code)]
pub async fn stored_session_token(
    svc: &TestServices,
    profile: &Profile,
    session: Session,
) -> String {
    svc.storage
        .create_session(
            &session,
            sid_core::models::AuditEntry::system("test", "session").into(),
        )
        .await
        .unwrap();
    issue_token_with_session(&svc.jwt, profile, &["openid".to_string()], session).0
}

/// A fresh password session of `profile`, stored, as its bearer token.
#[allow(dead_code)]
pub async fn fresh_token(svc: &TestServices, profile: &Profile) -> String {
    let session = authenticated_session(profile, sid_core::models::AuthLevel::Basic, 0);
    stored_session_token(svc, profile, session).await
}

/// Issue a bearer token for an admin profile.
pub fn issue_admin_token(jwt: &JwtService, profile_id: ProfileId) -> String {
    let mut admin_profile = Profile::new(Some("admin"));
    admin_profile.id = profile_id;
    admin_profile.roles = vec!["admin".to_string()];
    issue_token(
        jwt,
        &admin_profile,
        &["openid".to_string(), "profile".to_string()],
    )
}

/// The field-encryption key manager every test server uses.
pub fn test_key_manager() -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([0x5Au8; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![0x01; 32], "key-v1")],
            Arc::new(sid_keys::RustCryptoPrimitives::new()),
        )
        .expect("test key manager"),
    )
}

/// A TOTP seed in the form the server stores it for `profile_id`.
#[allow(dead_code)]
pub async fn sealed_totp_seed(profile_id: ProfileId, seed: &[u8]) -> Vec<u8> {
    sid_authn::sealed_secret::seal(
        test_key_manager().as_ref(),
        &sid_authn::sealed_secret::totp_context(profile_id),
        seed,
    )
    .await
    .expect("seal test seed")
}

/// The installation organization of every test server: applications the
/// services register, and test clients built by hand, belong to it.
#[allow(dead_code)]
pub fn test_org() -> sid_core::models::OrgId {
    sid_core::models::OrgId::parse("0192f3a4-7c1e-7b2a-8000-00000000c0de").unwrap()
}

/// Optional server capabilities a test enables.
struct Options {
    /// The ZKPP verifiers and configuration; the server is built on the
    /// services' own OPAQUE router, as a server start builds it. None leaves
    /// ZKPP off.
    zkpp: Option<(Vec<ZkppVerifier>, ZkppConfig)>,
    magic_links: bool,
}

/// What the authentication service is built from besides its storage and
/// shared cache.
pub struct AuthOptions {
    pub opaque_router: Arc<OpaqueRouter>,
    pub jwt: Arc<JwtService>,
    pub oauth2: Arc<OAuth2Server>,
    pub webauthn: Arc<WebAuthnServer>,
    pub revocation_cache: Arc<RevocationCache>,
    pub feature_flags: FeatureFlagService,
    pub magic_link: Option<Arc<MagicLinkService>>,
    /// The ZKPP verifiers (one per history-domain count) and configuration;
    /// None or no verifier verifies no proof.
    pub zkpp: Option<(Vec<ZkppVerifier>, ZkppConfig)>,
    pub issuers: Arc<sid_authn::issuer::IssuerRegistry>,
    /// The installation organization.
    pub org: sid_core::models::OrgId,
    pub cascade: Arc<RevocationCascadeService>,
}

/// The authentication service over `storage` and `cache`, as a server start
/// builds it.
pub fn auth_service(
    storage: Arc<dyn StorageBackend>,
    cache: Arc<dyn sid_plugin::cache::CacheBackend>,
    options: AuthOptions,
) -> Arc<AuthServiceImpl> {
    let AuthOptions {
        opaque_router,
        jwt,
        oauth2,
        webauthn,
        revocation_cache,
        feature_flags,
        magic_link,
        zkpp,
        issuers,
        org,
        cascade,
    } = options;
    // Registration, change and reset run their OPAQUE on the ZKPP server
    // whether or not proofs are verified, as a server start builds it:
    // without a verifier every password installs policy-unverified.
    let (verifiers, config) = match zkpp {
        Some((verifiers, config)) => (verifiers, config),
        None => (
            vec![],
            ZkppConfig {
                require_proof: false,
                policy_version: 1,
            },
        ),
    };
    let zkpp =
        Arc::new(ZkppOpaqueServer::new(&opaque_router, verifiers, config).expect("ZKPP server"));
    let opaque_zkpp: Arc<arc_swap::ArcSwap<Option<Arc<ZkppOpaqueServer>>>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(Some(zkpp)));

    let otp_service = sid_authn::otp::OtpService::new(cache.clone());
    Arc::new(
        AuthServiceImpl::new(
            storage.clone(),
            oauth2,
            webauthn,
            jwt,
            opaque_router,
            opaque_zkpp,
            revocation_cache,
            feature_flags,
            magic_link,
            otp_service,
            issuers,
            org,
            "https://sid.example.com".to_string(),
            // A 4-bit proof of work, so a test solves a challenge in a few hashes.
            Arc::new(sid_authn::captcha::SidPowProvider::new([0u8; 32], 4, 300)),
            cache.clone(),
            Arc::new(sid_authn::ip_intelligence::IpIntelligenceAggregator::new(
                vec![],
                cache.clone(),
                std::time::Duration::from_secs(60),
            )),
            Arc::new(sid_authn::geoip::GeoIpChain::empty(cache)),
            test_key_manager(),
            cascade,
            Arc::new(sid_authz::CeAuthzEngine::new(storage)),
        )
        .with_sign_in_page(&url::Url::parse(SIGN_IN_PAGE).unwrap()),
    )
}

/// The browser sign-in page of every test server, on the issuer's site.
#[allow(dead_code)]
pub const SIGN_IN_PAGE: &str = "https://login.sid.example.com/sign-in";

/// Its origin, as a browser sends it in `Origin`.
#[allow(dead_code)]
pub const SIGN_IN_ORIGIN: &str = "https://login.sid.example.com";

/// Build all gRPC service implementations sharing the same storage.
pub struct TestServices {
    pub admin: AdminServiceImpl,
    /// Shared, as the server shares it with the OIDC provider endpoints.
    pub auth: Arc<AuthServiceImpl>,
    /// The password history evaluator, co-located as CE serves it.
    pub evaluator: sid_server::grpc::password_operation::PasswordHistoryEvaluatorImpl,
    /// Shared, so a test can also serve it over the network.
    pub identity: Arc<IdentityServiceImpl>,
    /// Shared, as the server shares it with the OIDC provider endpoints.
    pub project: Arc<ProjectServiceImpl>,
    #[allow(dead_code)]
    pub machine_user: sid_server::grpc::machine_user_service::MachineUserServiceImpl,
    #[allow(dead_code)]
    pub upstream: sid_server::grpc::upstream_service::UpstreamServiceImpl,
    pub flow_config: FlowConfigServiceImpl,
    pub flow_action: FlowActionServiceImpl,
    pub security: SecurityServiceImpl,
    pub account: sid_server::grpc::account_service::AccountServiceImpl,
    pub storage: Arc<dyn StorageBackend>,
    pub mock_storage: Arc<MockStorage>,
    #[allow(dead_code)]
    pub cache: Arc<dyn sid_plugin::cache::CacheBackend>,
    pub jwt: Arc<JwtService>,
    pub event_bus: Arc<dyn sid_plugin::event_bus::EventBus>,
    #[allow(dead_code)]
    pub revocation_cache: Arc<RevocationCache>,
    #[allow(dead_code)]
    pub feature_flags: FeatureFlagService,
    /// The installation organization's OIDC issuer, provisioned as a server
    /// start provisions it.
    #[allow(dead_code)]
    pub issuer: sid_core::models::OidcIssuer,
    #[allow(dead_code)]
    pub issuers: Arc<sid_authn::issuer::IssuerRegistry>,
    #[allow(dead_code)]
    pub oidc_issuer: sid_server::grpc::oidc_issuer_service::OidcIssuerServiceImpl,
}

impl TestServices {
    pub fn new(storage: MockStorage) -> Self {
        Self::with_feature_flags(storage, FeatureFlagService::disabled())
    }

    /// TestServices with ZKPP accepting registrations without a proof and
    /// verifying none (no verifier, so no Halo2 keygen).
    pub fn with_zkpp_degraded(storage: MockStorage) -> Self {
        Self::with_zkpp_options(
            storage,
            vec![],
            ZkppConfig {
                require_proof: false,
                policy_version: 1,
            },
        )
    }

    /// TestServices whose ZKPP registration and password change verify with
    /// `verifier` under `config`.
    #[allow(dead_code)]
    pub fn with_zkpp(storage: MockStorage, verifier: ZkppVerifier, config: ZkppConfig) -> Self {
        Self::with_zkpp_options(storage, vec![verifier], config)
    }

    /// TestServices verifying operations with one or more history domains,
    /// one verifier per domain count, as a server start builds them.
    #[allow(dead_code)]
    pub fn with_zkpp_verifiers(
        storage: MockStorage,
        verifiers: Vec<ZkppVerifier>,
        config: ZkppConfig,
    ) -> Self {
        Self::with_zkpp_options(storage, verifiers, config)
    }

    fn with_zkpp_options(
        storage: MockStorage,
        verifiers: Vec<ZkppVerifier>,
        config: ZkppConfig,
    ) -> Self {
        Self::with_options(
            storage,
            FeatureFlagService::disabled(),
            Options {
                zkpp: Some((verifiers, config)),
                magic_links: false,
            },
        )
    }

    /// TestServices with magic links enabled (they are off by default, as in production).
    pub fn with_magic_links(storage: MockStorage) -> Self {
        Self::with_options(
            storage,
            FeatureFlagService::disabled(),
            Options {
                zkpp: None,
                magic_links: true,
            },
        )
    }

    pub fn with_feature_flags(storage: MockStorage, feature_flags: FeatureFlagService) -> Self {
        Self::with_options(
            storage,
            feature_flags,
            Options {
                zkpp: None,
                magic_links: false,
            },
        )
    }

    /// TestServices over `cache` as the shared cache, for tests of a cache
    /// that fails.
    #[allow(dead_code)]
    pub fn with_cache(
        storage: MockStorage,
        cache: Arc<dyn sid_plugin::cache::CacheBackend>,
    ) -> Self {
        Self::assemble(
            Arc::new(storage),
            cache,
            test_opaque_router(),
            FeatureFlagService::disabled(),
            Options {
                zkpp: None,
                magic_links: false,
            },
        )
    }

    fn with_options(
        storage: MockStorage,
        feature_flags: FeatureFlagService,
        options: Options,
    ) -> Self {
        Self::assemble(
            Arc::new(storage),
            Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
            test_opaque_router(),
            feature_flags,
            options,
        )
    }

    /// Two replicas of the services over one database and one shared cache,
    /// each starting as a server process does, as a deployment behind a load
    /// balancer runs them.
    #[allow(dead_code)]
    pub async fn replicas(storage: MockStorage) -> (Self, Self) {
        let storage = Arc::new(storage);
        let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
            Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
        let a = Self::replica(storage.clone(), cache.clone()).await;
        let b = Self::replica(storage, cache).await;
        (a, b)
    }

    /// Another replica over this one's database and cache, started now: a
    /// restart, or a replica added later.
    #[allow(dead_code)]
    pub async fn restarted(&self) -> Self {
        Self::replica(self.mock_storage.clone(), self.cache.clone()).await
    }

    /// One replica starting over `storage` and `cache`: it loads the stored
    /// OPAQUE setup and applies the other replicas' revocations.
    async fn replica(
        storage: Arc<MockStorage>,
        cache: Arc<dyn sid_plugin::cache::CacheBackend>,
    ) -> Self {
        let opaque_router = stored_opaque_router(storage.as_ref()).await;
        let replica = Self::assemble(
            storage,
            cache,
            opaque_router,
            FeatureFlagService::disabled(),
            Options {
                zkpp: None,
                magic_links: false,
            },
        );
        replica
            .revocation_cache
            .listen()
            .await
            .expect("revocation listener");
        replica
    }

    fn assemble(
        mock_storage: Arc<MockStorage>,
        cache_backend: Arc<dyn sid_plugin::cache::CacheBackend>,
        opaque_router: Arc<OpaqueRouter>,
        feature_flags: FeatureFlagService,
        options: Options,
    ) -> Self {
        let Options { zkpp, magic_links } = options;
        let storage: Arc<dyn StorageBackend> = mock_storage.clone();
        // Provisioned as a server start provisions it; a replica over the same
        // store reads the stored one back.
        let issuer = futures::executor::block_on(sid_authn::issuer::ensure_local_issuer(
            storage.as_ref(),
            test_key_manager().as_ref(),
            &url::Url::parse("https://sid.example.com").unwrap(),
            test_org(),
        ))
        .expect("installation issuer");
        // The issuer's UserInfo resource, as a server start provisions it; the
        // clients the test stored sign in with it as their token target.
        let userinfo = futures::executor::block_on(sid_authn::issuer::ensure_userinfo_resource(
            storage.as_ref(),
            &issuer,
        ))
        .expect("UserInfo resource");
        mock_storage.open_to_every_client(&userinfo);
        futures::executor::block_on(sid_authz::builtin::ensure_token_inspector_role(
            storage.as_ref(),
        ))
        .expect("token inspector role");
        futures::executor::block_on(sid_authz::builtin::ensure_scim_provisioner_role(
            storage.as_ref(),
        ))
        .expect("SCIM provisioner role");
        futures::executor::block_on(sid_authz::builtin::ensure_permission_checker_role(
            storage.as_ref(),
        ))
        .expect("permission checker role");
        let issuers = Arc::new(sid_authn::issuer::IssuerRegistry::new(
            storage.clone(),
            test_key_manager(),
        ));
        // The services accept the account API's tokens, as a server does.
        let account_api =
            futures::executor::block_on(sid_authn::account_api::AccountApiVerifier::new(
                issuers.clone(),
                issuer.clone(),
                sid_authn::system_integration::account_api_indicator("https://sid.example.com")
                    .unwrap(),
            ))
            .expect("account API verifier");
        let jwt = Arc::new(test_jwt_service().with_account_api(Arc::new(account_api)));
        let oauth2 = Arc::new(OAuth2Server::new(jwt.clone()));
        let webauthn = test_webauthn(cache_backend.clone());
        let revocation_cache = Arc::new(RevocationCache::new(
            std::time::Duration::from_secs(900),
            cache_backend.clone(),
        ));
        let magic_link = magic_links.then(|| Arc::new(MagicLinkService::new(storage.clone())));
        let event_bus: Arc<dyn sid_plugin::event_bus::EventBus> =
            Arc::new(InProcessEventBus::new());
        let cascade_service = Arc::new(RevocationCascadeService::new(
            storage.clone(),
            revocation_cache.clone(),
        ));
        let closure_service = Arc::new(AccountClosureService::new(
            storage.clone(),
            cascade_service.clone(),
        ));
        let data_export = Arc::new(DataExportService::new(
            storage.clone(),
            "/tmp/sid-test-exports".to_string(),
        ));

        let auth = auth_service(
            storage.clone(),
            cache_backend.clone(),
            AuthOptions {
                opaque_router,
                jwt: jwt.clone(),
                oauth2,
                webauthn,
                revocation_cache: revocation_cache.clone(),
                feature_flags: feature_flags.clone(),
                magic_link,
                zkpp,
                issuers: issuers.clone(),
                org: test_org(),
                cascade: cascade_service.clone(),
            },
        );

        let identity = Arc::new(IdentityServiceImpl::new(
            storage.clone(),
            jwt.clone(),
            revocation_cache.clone(),
            feature_flags.clone(),
            cascade_service.clone(),
            closure_service,
            data_export,
        ));

        let project = Arc::new(ProjectServiceImpl::new(
            storage.clone(),
            feature_flags.clone(),
            jwt.clone(),
            revocation_cache.clone(),
            issuer.clone(),
        ));
        let admin = AdminServiceImpl::new(
            storage.clone(),
            jwt.clone(),
            revocation_cache.clone(),
            cascade_service,
            test_key_manager(),
        );
        let flow_config =
            FlowConfigServiceImpl::new(storage.clone(), jwt.clone(), revocation_cache.clone());
        let flow_action =
            FlowActionServiceImpl::new(storage.clone(), jwt.clone(), revocation_cache.clone());
        let audit_log: Arc<dyn AuditLog> = Arc::new(NoOpAuditLog);
        let no_cache: Arc<dyn sid_plugin::cache::CacheBackend> = Arc::new(NoCacheBackend);
        let security = SecurityServiceImpl::new(
            storage.clone(),
            jwt.clone(),
            revocation_cache.clone(),
            audit_log,
            no_cache,
        );
        let account = sid_server::grpc::account_service::AccountServiceImpl::new(
            storage.clone(),
            jwt.clone(),
            revocation_cache.clone(),
        );
        let oidc_issuer = sid_server::grpc::oidc_issuer_service::OidcIssuerServiceImpl::new(
            issuers.clone(),
            storage.clone(),
        );
        let evaluator = auth
            .history_evaluator()
            .expect("the test server co-locates the history evaluator");
        let machine_user = sid_server::grpc::machine_user_service::MachineUserServiceImpl::new(
            storage.clone(),
            jwt.clone(),
            revocation_cache.clone(),
            test_org(),
        );
        let upstream = sid_server::grpc::upstream_service::UpstreamServiceImpl::new(
            storage.clone(),
            test_key_manager(),
            cache_backend.clone(),
            jwt.clone(),
            revocation_cache.clone(),
        );

        Self {
            admin,
            auth,
            evaluator,
            identity,
            project,
            machine_user,
            upstream,
            flow_config,
            flow_action,
            security,
            account,
            storage,
            mock_storage,
            cache: cache_backend,
            jwt,
            event_bus,
            revocation_cache,
            feature_flags,
            issuer,
            oidc_issuer,
            issuers,
        }
    }

    /// Publish the events committed mutations owe, as the work runner does:
    /// owed contestation checks run first (they owe events of their own),
    /// then every event reaches subscribers through its durable relay work.
    pub async fn relay_events(&self) {
        use sid_authn::work_runner::WorkHandler;

        let contest =
            sid_authn::principal_contest::PrincipalContestHandler::new(self.storage.clone());
        let relay = sid_authn::event_relay::EventRelayHandler::new(self.event_bus.clone());
        let handlers: [&dyn WorkHandler; 2] = [&contest, &relay];
        for handler in handlers {
            self.run_owed(handler).await;
        }
    }

    /// Run every due item of `handler`'s kind once; each must succeed.
    async fn run_owed(&self, handler: &dyn sid_authn::work_runner::WorkHandler) {
        use sid_authn::work_runner::WorkOutcome;

        let claimed = self
            .storage
            .claim_work(
                std::slice::from_ref(handler.kind()),
                "test-runner",
                u32::MAX,
                std::time::Duration::from_secs(60),
            )
            .await
            .unwrap();
        for work in claimed {
            match handler.handle(&work).await {
                WorkOutcome::Done(result) => assert!(
                    self.storage
                        .complete_work(work.id, work.generation, result.as_deref())
                        .await
                        .unwrap()
                ),
                other => panic!("owed work {:?} failed: {other:?}", work.id),
            }
        }
    }
}
