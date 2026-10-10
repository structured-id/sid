// SPDX-License-Identifier: AGPL-3.0-only
//! CE server initialization.
//!
//! Reusable initialization logic: a binary calls [`init_ce`] to set up all
//! core components, then adds its own services.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use sid_authn::account_closure::AccountClosureService;
use sid_authn::backchannel_logout::BackChannelLogoutHandler;
use sid_authn::data_export::DataExportService;
use sid_authn::event_relay::EventRelayHandler;
use sid_authn::geoip::build_geoip_chain_from_env;
use sid_authn::ip_intelligence::{
    AllowlistProvider, CloudRangeProvider, FireholProvider, IpIntelligenceAggregator,
    IpIntelligenceProvider, SelfLearnedReputationProvider, TorExitProvider,
};
use sid_authn::jwt::JwtService;
use sid_authn::magic_link::MagicLinkService;
use sid_authn::oauth2::OAuth2Server;
use sid_authn::opaque::{
    OpaqueRouter, P256Opaque, P384Opaque, P521Opaque, PallasOpaque, RistrettoOpaque,
};
use sid_authn::otp::OtpService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_authn::webauthn::WebAuthnServer;
use sid_authn::work_runner::{RunnerConfig, WorkHandler, WorkRunner};
use sid_core::models::AuditEntry;
use sid_plugin::cache::CacheBackend;
use sid_plugin::crypto::{CurveId, OpaqueOperations};
use sid_plugin::event_bus::EventBus;
use sid_plugin::storage::StorageBackend;
use tracing::info;
use url::Url;

use crate::feature_flags::{FeatureFlagConfig, FeatureFlagService};
use crate::grpc::{
    admin_service::AdminServiceImpl, auth_service::AuthServiceImpl,
    identity_service::IdentityServiceImpl, project_service::ProjectServiceImpl,
};
use crate::state::AppState;

use sid_authn::opaque_zkpp::ZkppOpaqueServer;
use sid_authz::cedar::CedarService;
use sid_authz::grpc::AuthzServiceImpl;

// Advisory lock IDs for background tasks (multi-instance coordination).
// Lock 42 is reserved for migrations (migrator.rs).
const LOCK_PAT_AUTO_REVOKE: i64 = 43;
const LOCK_CREDENTIAL_EXPIRY: i64 = 44;
const LOCK_ROLE_EXPIRY: i64 = 45;
const LOCK_QUARANTINE_CLEANUP: i64 = 46;
const LOCK_PROFILE_PURGE: i64 = 47;
const LOCK_MIGRATION_DEADLINE: i64 = 48;
const LOCK_AUDIT_PARTITION: i64 = 49;
const LOCK_PRINCIPAL_EXPIRY: i64 = 50;
const LOCK_ENROLLMENT_COMPACTION: i64 = 51;

/// Namespace of machine-credential alert event ids.
const CREDENTIAL_ALERT_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x9b47_2c1e_65fa_4d38_a0c2_e81f_3d96_7b54);

/// The id of a machine-credential alert: the same alert gets the same id, so
/// a repeated scan relays it once.
fn credential_alert_id(alert: &str) -> String {
    uuid::Uuid::new_v5(&CREDENTIAL_ALERT_NAMESPACE, alert.as_bytes()).to_string()
}

/// All initialized CE components and gRPC services.
pub struct CeComponents {
    pub storage: Arc<dyn StorageBackend>,
    pub jwt: Arc<JwtService>,
    pub oauth2: Arc<OAuth2Server>,
    pub webauthn: Arc<WebAuthnServer>,
    pub opaque_router: Arc<OpaqueRouter>,
    pub opaque_zkpp: Arc<arc_swap::ArcSwap<Option<Arc<ZkppOpaqueServer>>>>,
    pub revocation_cache: Arc<RevocationCache>,
    pub feature_flags: FeatureFlagService,
    pub event_bus: Arc<dyn EventBus>,
    /// The bundled `nats-server` behind `event_bus` in embedded mode; it is
    /// stopped when dropped, so it lives as long as the components.
    pub embedded_nats: Option<Arc<crate::embedded_nats::EmbeddedNats>>,
    pub cache_backend: Arc<dyn CacheBackend>,
    pub app_state: AppState,
    pub issuer: String,
    pub grpc_addr: SocketAddr,
    /// Field encryption for stored secrets every service seals.
    pub key_manager: Arc<dyn sid_keys::KeyManager>,
    /// Ends sessions, tokens and PATs of a profile (shared by every service
    /// that suspends or revokes one).
    pub cascade_service: Arc<RevocationCascadeService>,
    /// Executes account closures whose grace period has ended.
    pub closure_service: Arc<AccountClosureService>,
    /// How long audit records are kept and what happens to them after.
    pub audit_retention: crate::background_tasks::AuditRetention,
    /// The installation's OIDC issuers and their signers.
    pub issuers: Arc<sid_authn::issuer::IssuerRegistry>,
    /// The sign-in page the authorization endpoint sends users to.
    pub login_url: Option<url::Url>,
    /// The one authorization evaluator of this process.
    pub authz_engine: Arc<dyn sid_plugin::AuthzEngine>,
    /// The installation's organization.
    pub organization: sid_core::models::Organization,
    /// The directory the SCIM endpoint serves.
    #[cfg(feature = "scim")]
    pub scim_directory: sid_scim::grpc::ScimDirectory,
    /// Its protected resource registration.
    #[cfg(feature = "scim")]
    pub scim_resource: sid_core::models::ProtectedResource,
    /// The issuer whose tokens the SCIM resource accepts.
    #[cfg(feature = "scim")]
    pub scim_issuer: sid_core::models::OidcIssuer,

    // CE gRPC service implementations
    pub identity_svc: Arc<IdentityServiceImpl>,
    pub auth_svc: Arc<AuthServiceImpl>,
    pub project_svc: Arc<ProjectServiceImpl>,
    pub authz_svc: Arc<AuthzServiceImpl>,
    pub admin_svc: Arc<AdminServiceImpl>,
    pub branding_svc: Arc<crate::grpc::branding_service::BrandingServiceImpl>,
    pub flow_config_svc: Arc<crate::grpc::flow_service::FlowConfigServiceImpl>,
    pub flow_action_svc: Arc<crate::grpc::flow_service::FlowActionServiceImpl>,
    pub enrollment_svc: Arc<crate::grpc::enrollment_service::EnrollmentServiceImpl>,
    pub security_svc: Arc<crate::grpc::security_service::SecurityServiceImpl>,
    pub account_svc: Arc<crate::grpc::account_service::AccountServiceImpl>,
}

/// Whether magic links are enabled, from the `SID_MAGIC_LINKS_ENABLED` value.
///
/// Off unless set to `true`. Any other value is a configuration error, and so is
/// enabling them on a site whose policy requires more than basic assurance: a
/// magic link proves only weak possession of the mailbox.
pub fn magic_links_enabled(
    value: Option<&str>,
    policy: &sid_core::models::SecurityPolicy,
) -> anyhow::Result<bool> {
    let enabled = match value {
        None | Some("false") => false,
        Some("true") => true,
        Some(other) => {
            anyhow::bail!("SID_MAGIC_LINKS_ENABLED must be true or false, got {other:?}")
        }
    };
    if enabled && !policy.permits_magic_links() {
        anyhow::bail!(
            "magic links require basic assurance; the site policy requires {:?}",
            policy.auth.min_acr
        );
    }
    Ok(enabled)
}

/// The sign-in page, from the `SID_LOGIN_URL` value, where the authorization
/// endpoint sends a user who must sign in. Unset or empty means none (the
/// client then gets `login_required`); a value that is not an http(s) URL is
/// a configuration error, and so is a page on another site than the issuer
/// host `issuer`: its ceremonies set the IdP session cookie on that host,
/// which a response to a cross-site request cannot do.
pub fn login_url(value: Option<&str>, issuer: &str) -> anyhow::Result<Option<url::Url>> {
    let Some(value) = value.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let url =
        url::Url::parse(value).with_context(|| format!("SID_LOGIN_URL {value:?} is not a URL"))?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        anyhow::bail!("SID_LOGIN_URL {value:?} is not an http(s) URL with a host");
    }
    let issuer_url =
        url::Url::parse(issuer).with_context(|| format!("SID_ISSUER {issuer:?} is not a URL"))?;
    if !sid_authn::browser_session::same_site(&url, &issuer_url) {
        anyhow::bail!(
            "SID_LOGIN_URL {value:?} is not on the same site as SID_ISSUER {issuer:?}: \
             the sign-in page must share the issuer's scheme and registrable domain"
        );
    }
    Ok(Some(url))
}

/// The account integration's settings from `SID_ACCOUNT_URL` (the account
/// UI's public URL) and `SID_ACCOUNT_CLIENT_JWKS` (a file holding its BFF's
/// public JWK Set). Neither set means the deployment serves no account UI;
/// one without the other, an unreadable key file or an invalid value is a
/// configuration error, never an integration with invented settings.
pub fn account_settings(
    url: Option<&str>,
    jwks_file: Option<&str>,
) -> anyhow::Result<Option<sid_authn::system_integration::AccountSettings>> {
    let (url, jwks_file) = match (
        url.filter(|v| !v.is_empty()),
        jwks_file.filter(|v| !v.is_empty()),
    ) {
        (None, None) => return Ok(None),
        (Some(url), Some(file)) => (url, file),
        _ => anyhow::bail!(
            "SID_ACCOUNT_URL and SID_ACCOUNT_CLIENT_JWKS are set together: the account \
             integration needs its URL and its BFF's public keys"
        ),
    };
    let text = std::fs::read_to_string(jwks_file)
        .with_context(|| format!("SID_ACCOUNT_CLIENT_JWKS {jwks_file:?} cannot be read"))?;
    let keys = sid_core::models::ClientKeySet::from_json(&text)
        .map_err(|e| anyhow::anyhow!("SID_ACCOUNT_CLIENT_JWKS {jwks_file:?}: {e}"))?;
    sid_authn::system_integration::AccountSettings::new(url, keys)
        .map(Some)
        .map_err(|e| anyhow::anyhow!("SID_ACCOUNT_URL: {e}"))
}

/// The installation's domain: the host of its issuer URL.
pub(crate) fn instance_domain(issuer: &str) -> anyhow::Result<String> {
    url::Url::parse(issuer)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .with_context(|| format!("SID_ISSUER {issuer:?} is not a URL with a host"))
}

/// While the instance has no administrator, write its claim token to the log
/// for the operator; a storage failure stops the start.
pub(crate) async fn announce_admin_claim(
    storage: &dyn StorageBackend,
    keys: &dyn sid_keys::KeyManager,
) -> anyhow::Result<()> {
    let claim = sid_authn::admin_claim::open_claim(storage, keys)
        .await
        .context("administrator claim")?;
    if let Some(token) = claim {
        tracing::warn!(
            "No administrator yet. Register and enter this claim token to become the \
             first administrator: {}",
            secrecy::ExposeSecret::expose_secret(&token)
        );
    }
    Ok(())
}

/// Initialize all CE components: storage, crypto, auth, and gRPC services.
///
/// Does NOT start the server — caller assembles the tonic server and serves.
pub async fn init_ce() -> anyhow::Result<CeComponents> {
    let grpc_addr: SocketAddr = std::env::var("SID_GRPC_BIND")
        .unwrap_or_else(|_| "127.0.0.1:50051".to_string())
        .parse()?;

    // ── Storage backend ──

    // The history evaluator's own store over the same database, for a
    // standalone installation that runs the evaluator in process; its tables
    // are created only when it does (`local_history_keys`).
    #[cfg(feature = "storage-pg")]
    let (storage, audit_log, local_history_keys): (
        Arc<dyn StorageBackend>,
        Arc<dyn sid_plugin::audit::AuditLog>,
        LocalHistoryKeys,
    ) = {
        let database_url = std::env::var("SID_DATABASE_URL").expect("SID_DATABASE_URL must be set");
        let schema = std::env::var("SID_STORAGE_POSTGRESQL_SCHEMA").ok();
        if let Some(ref s) = schema {
            info!(
                "Schema isolation enabled: tables will be created in schema '{}'",
                s
            );
        }
        let storage_backend = sid_storage::PostgresBackend::new(&database_url, schema.clone())
            .await
            .expect("Failed to connect to database");

        let audit_log: Arc<dyn sid_plugin::audit::AuditLog> = Arc::new(
            sid_storage::audit_log::PostgresAuditLog::new(storage_backend.pool().clone()),
        );

        let backend = storage_backend.with_audit_log(audit_log.clone());

        sid_storage::migrator::run_migrations(backend.pool(), schema.as_deref())
            .await
            .expect("Migration failed");

        let local_history_keys =
            LocalHistoryKeys::Postgres(sid_storage::PgHistoryKeyStore::new(backend.pool().clone()));
        (Arc::new(backend), audit_log, local_history_keys)
    };

    #[cfg(all(feature = "embedded-dev", not(feature = "storage-pg")))]
    let (storage, audit_log, local_history_keys): (
        Arc<dyn StorageBackend>,
        Arc<dyn sid_plugin::audit::AuditLog>,
        LocalHistoryKeys,
    ) = {
        let db_path =
            std::env::var("SID_SQLITE_PATH").unwrap_or_else(|_| "/var/lib/sid/auth.db".to_string());
        let backend = sid_storage::sqlite::SqliteBackend::new(&db_path)
            .await
            .expect("Failed to initialize SQLite backend");
        let audit_log: Arc<dyn sid_plugin::audit::AuditLog> = Arc::new(
            sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone()),
        );
        let local_history_keys = LocalHistoryKeys::Sqlite(backend.history_keys());
        (Arc::new(backend), audit_log, local_history_keys)
    };

    // Ensure system project exists
    storage
        .ensure_system_project(AuditEntry::system("project.ensure_system", "system").into())
        .await
        .expect("Failed to ensure system project");

    // ── JWT keys ──
    let data_dir = std::env::var("SID_DATA_DIR").unwrap_or_else(|_| "/var/lib/sid".into());
    let jwt_private_key_path = std::env::var("SID_JWT_PRIVATE_KEY_PATH")
        .unwrap_or_else(|_| format!("{}/jwt_private.pem", data_dir));
    let jwt_public_key_path = std::env::var("SID_JWT_PUBLIC_KEY_PATH")
        .unwrap_or_else(|_| format!("{}/jwt_public.pem", data_dir));
    // No default: the issuer names every token and the installation's
    // organization domain, so a guessed one would be wrong everywhere.
    let issuer = std::env::var("SID_ISSUER")
        .ok()
        .filter(|issuer| !issuer.is_empty())
        .context("SID_ISSUER is required")?;
    let instance_domain = instance_domain(&issuer)?;

    // Auto-generate JWT keys if not present
    if !std::path::Path::new(&jwt_private_key_path).exists() {
        tracing::warn!(
            "JWT keys not found at '{}' — generating Ed25519 key pair for development",
            jwt_private_key_path
        );
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            panic!("Cannot create data directory '{}': {}", data_dir, e);
        }
        let output = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                &jwt_private_key_path,
            ])
            .output()
            .expect("Failed to run openssl — is it installed?");
        if !output.status.success() {
            panic!(
                "openssl genpkey failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let output = std::process::Command::new("openssl")
            .args([
                "pkey",
                "-in",
                &jwt_private_key_path,
                "-pubout",
                "-out",
                &jwt_public_key_path,
            ])
            .output()
            .expect("Failed to extract public key");
        if !output.status.success() {
            panic!(
                "openssl pkey failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        info!("Generated JWT key pair at '{}'", data_dir);
        tracing::warn!("Set SID_JWT_PRIVATE_KEY_PATH for production use");
    }

    let private_pem = std::fs::read(&jwt_private_key_path)
        .unwrap_or_else(|_| panic!("Cannot read JWT private key: {}", jwt_private_key_path));
    let public_pem = std::fs::read(&jwt_public_key_path)
        .unwrap_or_else(|_| panic!("Cannot read JWT public key: {}", jwt_public_key_path));

    // A set but malformed or out-of-range lifetime stops startup rather than
    // silently falling back to a default.
    let access_token_ttl = match std::env::var("SID_ACCESS_TOKEN_TTL_MINUTES") {
        Ok(v) => v
            .parse::<u32>()
            .map_err(|e| format!("SID_ACCESS_TOKEN_TTL_MINUTES: {e}"))
            .and_then(|m| {
                sid_authn::jwt::AccessTokenTtl::from_minutes(m)
                    .map_err(|e| format!("SID_ACCESS_TOKEN_TTL_MINUTES: {e}"))
            })
            .unwrap_or_else(|e| panic!("{e}")),
        Err(_) => sid_authn::jwt::AccessTokenTtl::default(),
    };
    let refresh_token_ttl_days: i64 = match std::env::var("SID_REFRESH_TOKEN_TTL_DAYS") {
        Ok(v) => v
            .parse()
            .unwrap_or_else(|e| panic!("SID_REFRESH_TOKEN_TTL_DAYS: {e}")),
        Err(_) => 30,
    };

    // ── Field encryption: master key outside the database, versions inside ──
    let master_key_path =
        std::env::var("SID_MASTER_KEY_FILE").unwrap_or_else(|_| format!("{}/master.key", data_dir));
    let key_manager = crate::field_keys::field_key_manager(
        storage.as_ref(),
        std::path::Path::new(&master_key_path),
    )
    .await
    .unwrap_or_else(|e| panic!("Field-encryption key manager: {e}"));
    // TOTP seeds written before field encryption are sealed before serving.
    let sealed = sid_authn::sealed_secret::seal_plaintext_credentials(
        storage.as_ref(),
        key_manager.as_ref(),
        sid_core::models::CredentialType::Totp,
        |c| sid_authn::sealed_secret::totp_context(c.profile_id),
    )
    .await
    .unwrap_or_else(|e| panic!("Sealing stored TOTP seeds: {e}"));
    if sealed > 0 {
        info!(
            "Sealed {} stored TOTP seed(s) under the key manager",
            sealed
        );
    }
    // OPAQUE envelopes likewise (defense in depth, storage-cache Key Manager).
    let sealed = sid_authn::sealed_secret::seal_plaintext_credentials(
        storage.as_ref(),
        key_manager.as_ref(),
        sid_core::models::CredentialType::Opaque,
        |c| sid_authn::sealed_secret::opaque_context(c.profile_id),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Sealing stored OPAQUE envelopes: {e}"))?;
    if sealed > 0 {
        info!(
            "Sealed {} stored OPAQUE envelope(s) under the key manager",
            sealed
        );
    }
    // The PoW CAPTCHA key every replica signs and checks challenges with.
    let captcha_pow_key =
        sid_authn::captcha::load_or_create_pow_key(storage.as_ref(), key_manager.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("CAPTCHA key: {e}"))?;

    // ── Shared cache: ceremony state, one-time codes, replay and rate state ──
    let cache_backend: Arc<dyn CacheBackend> =
        sid_infra::shared_cache(sid_infra::cache_url_from_env().as_deref())
            .await
            .unwrap_or_else(|e| panic!("Shared cache: {e}"));

    // ── WebAuthn ──
    // RP_ID must match the domain users access (e.g., "structured.id", "localhost").
    // RP_ORIGIN must include the scheme (e.g., "https://structured.id").
    // Defaults are safe for local development. Production MUST set these.
    let rp_id = std::env::var("SID_RP_ID").unwrap_or_else(|_| "localhost".into());
    let rp_origin = std::env::var("SID_RP_ORIGIN").unwrap_or_else(|_| "http://localhost".into());
    let rp_origin_url = Url::parse(&rp_origin)?;
    let webauthn = Arc::new(WebAuthnServer::new(
        &rp_id,
        &rp_origin_url,
        cache_backend.clone(),
        key_manager.clone(),
    )?);

    // ── OPAQUE ──
    let opaque_router = {
        let primary = Box::new(PallasOpaque::new());
        let setup = sid_authn::opaque::server_setup::load_or_create(
            storage.as_ref(),
            key_manager.as_ref(),
            primary.as_ref(),
        )
        .await
        .unwrap_or_else(|e| panic!("OPAQUE server setup: {e}"));
        let mut verifiers: std::collections::HashMap<CurveId, Box<dyn OpaqueOperations>> =
            std::collections::HashMap::new();
        verifiers.insert(CurveId::Ristretto255, Box::new(RistrettoOpaque::new()));
        verifiers.insert(CurveId::Pallas, Box::new(PallasOpaque::new()));
        verifiers.insert(CurveId::P256, Box::new(P256Opaque::new()));
        verifiers.insert(CurveId::P384, Box::new(P384Opaque::new()));
        verifiers.insert(CurveId::P521, Box::new(P521Opaque::new()));
        Arc::new(OpaqueRouter::new(primary, verifiers, setup))
    };

    // ── ZKPP ──
    let opaque_zkpp = init_zkpp(&opaque_router);

    // ── Revocation cache ──
    let revocation_cache = Arc::new(RevocationCache::new(
        access_token_ttl
            .duration()
            .to_std()
            .expect("access token lifetime is positive"),
        cache_backend.clone(),
    ));
    // Revocations made on other replicas reach this one through the shared cache.
    revocation_cache
        .listen()
        .await
        .unwrap_or_else(|e| panic!("Revocation propagation: {e}"));

    // ── Feature flags ──
    let feature_flags = init_feature_flags();

    // ── Telemetry ──
    #[cfg(feature = "telemetry")]
    let _prometheus_registry = {
        let registry = prometheus::Registry::new();
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .build()
            .expect("Prometheus exporter setup");
        let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_reader(exporter)
            .build();
        opentelemetry::global::set_meter_provider(provider);
        info!("Telemetry: Prometheus metrics enabled at /metrics");
        registry
    };
    #[cfg(feature = "telemetry")]
    let sid_metrics = Arc::new(crate::metrics::SidMetrics::init());

    announce_admin_claim(storage.as_ref(), key_manager.as_ref()).await?;

    // The installation's organization, and every application in it.
    let organization = sid_authn::instance_org::ensure(storage.as_ref(), &instance_domain)
        .await
        .context("installation organization")?;
    let assigned = storage
        .assign_unowned_clients(
            organization.id,
            AuditEntry::system(
                "application.organization_assigned",
                organization.id.to_string(),
            )
            .into(),
        )
        .await
        .context("assign applications to the installation organization")?;
    if assigned > 0 {
        info!(assigned, org = %organization.id, "applications assigned to the installation organization");
    }

    // The organization's OIDC issuer; its key must open under this
    // installation's master key, or the start fails rather than signing with
    // a key its published set lacks.
    let issuer_base = Url::parse(&issuer).context("SID_ISSUER is not a URL")?;
    let local_issuer = sid_authn::issuer::ensure_local_issuer(
        storage.as_ref(),
        key_manager.as_ref(),
        &issuer_base,
        organization.id,
    )
    .await
    .context("installation OIDC issuer")?;
    // The issuer's UserInfo resource: the token target OIDC-only clients select.
    sid_authn::issuer::ensure_userinfo_resource(storage.as_ref(), &local_issuer)
        .await
        .context("installation OIDC issuer UserInfo resource")?;
    // The authorization API resource: a permission checker's own token
    // targets it (D054).
    let authorization_api =
        sid_authn::issuer::ensure_authorization_api_resource(storage.as_ref(), &local_issuer)
            .await
            .context("installation authorization API resource")?;
    // The SCIM directory resource: provisioning connectors hold their roles
    // on it and their tokens target it.
    #[cfg(feature = "scim")]
    let scim_resource = sid_authn::issuer::ensure_scim_resource(storage.as_ref(), &local_issuer)
        .await
        .context("installation SCIM directory resource")?;
    #[cfg(feature = "scim")]
    let scim_directory = sid_scim::grpc::ScimDirectory {
        org: organization.id,
        resource: scim_resource.id,
    };
    #[cfg(feature = "scim")]
    let scim_issuer = local_issuer.clone();
    // SID's own account UI, when the deployment serves one: its web client,
    // the account API and the access between them.
    if let Some(account) = account_settings(
        std::env::var("SID_ACCOUNT_URL").ok().as_deref(),
        std::env::var("SID_ACCOUNT_CLIENT_JWKS").ok().as_deref(),
    )? {
        let integration = sid_authn::system_integration::ensure_account_integration(
            storage.as_ref(),
            &local_issuer,
            &issuer,
            &account,
        )
        .await
        .context("account integration")?;
        if integration.is_ready() {
            info!(client_id = %integration.client.client_id, "account integration");
        } else {
            tracing::warn!(
                client_id = %integration.client.client_id,
                "account integration is disabled; the account UI cannot sign in"
            );
        }
    }
    // The built-in role assigned to token inspectors, one resource at a time.
    sid_authz::builtin::ensure_token_inspector_role(storage.as_ref())
        .await
        .context("token inspector role")?;
    // The built-in role assigned to SCIM provisioning connectors.
    sid_authz::builtin::ensure_scim_provisioner_role(storage.as_ref())
        .await
        .context("SCIM provisioner role")?;
    // The built-in role assigned to services that ask about others'
    // permissions, one resource at a time.
    sid_authz::builtin::ensure_permission_checker_role(storage.as_ref())
        .await
        .context("permission checker role")?;
    let issuers = Arc::new(sid_authn::issuer::IssuerRegistry::new(
        storage.clone(),
        key_manager.clone(),
    ));
    issuers
        .signer(&local_issuer)
        .await
        .context("installation OIDC issuer signing key")?;
    info!(issuer = %local_issuer.canonical_url, "installation OIDC issuer");

    // The services accept the installation's own tokens and the account
    // API's, issued by its local issuer for the account resource.
    let account_api = sid_authn::account_api::AccountApiVerifier::new(
        issuers.clone(),
        local_issuer.clone(),
        sid_authn::system_integration::account_api_indicator(&issuer)
            .context("account API indicator")?,
    )
    .await
    .context("account API verifier")?;
    let jwt = Arc::new(
        JwtService::new(&private_pem, &public_pem, issuer.clone())?
            .with_access_token_ttl(access_token_ttl)
            .with_account_api(Arc::new(account_api)),
    );

    // ── OAuth2 ──
    let oauth2 = Arc::new(
        OAuth2Server::new(jwt.clone())
            .with_refresh_token_ttl(chrono::Duration::days(refresh_token_ttl_days)),
    );

    let app_state = AppState {
        storage: storage.clone(),
        oauth2: oauth2.clone(),
        webauthn: webauthn.clone(),
        jwt: jwt.clone(),
        opaque_router: opaque_router.clone(),
        opaque_zkpp: opaque_zkpp.clone(),
        revocation_cache: revocation_cache.clone(),
        wt_cert_hash: None,
        feature_flags: feature_flags.clone(),
        issuer: issuer.clone(),
        #[cfg(feature = "telemetry")]
        metrics: sid_metrics,
    };

    // ── CE gRPC services ──

    let cascade_service = Arc::new(RevocationCascadeService::new(
        storage.clone(),
        revocation_cache.clone(),
    ));

    let closure_service = Arc::new(AccountClosureService::new(
        storage.clone(),
        cascade_service.clone(),
    ));

    let magic_link = magic_links_enabled(
        std::env::var("SID_MAGIC_LINKS_ENABLED").ok().as_deref(),
        &sid_core::models::SecurityPolicy::ce_default(),
    )?
    .then(|| Arc::new(MagicLinkService::new(storage.clone())));

    let export_dir =
        std::env::var("SID_EXPORT_DIR").unwrap_or_else(|_| "/tmp/sid-exports".to_string());
    let data_export = Arc::new(DataExportService::new(storage.clone(), export_dir));

    // Event bus: SID_NATS_URL unset / `embedded` bundles nats-server with
    // JetStream under the data directory, a nats:// or tls:// URL connects to
    // an external cluster. No in-process fallback: a bus that cannot start
    // stops startup, and committed work waits in the database.
    let nats_setting = std::env::var("SID_NATS_URL").ok();
    let nats_mode = crate::embedded_nats::EventBusMode::from_setting(nats_setting.as_deref())?;
    let crate::embedded_nats::ConnectedBus {
        bus: event_bus,
        embedded: embedded_nats,
    } = crate::embedded_nats::connect_event_bus(&nats_mode, std::path::Path::new(&data_dir))
        .await?;

    let identity_svc = Arc::new(IdentityServiceImpl::new(
        storage.clone(),
        jwt.clone(),
        revocation_cache.clone(),
        feature_flags.clone(),
        cascade_service.clone(),
        closure_service.clone(),
        data_export,
    ));

    let otp_service = OtpService::new(cache_backend.clone());

    // ── IP Intelligence: configurable provider chain ──
    // SID_IPINTEL_PROVIDERS: comma-separated list of enabled providers.
    // Default: all providers enabled. Set to empty or "none" to disable all.
    // Valid values: tor, cloud, firehol, self_learned, allowlist
    // Air-gapped deployments: set to "self_learned,allowlist" (no external fetches).
    let enabled_providers: Vec<String> = std::env::var("SID_IPINTEL_PROVIDERS")
        .unwrap_or_else(|_| "tor,cloud,firehol,self_learned,allowlist".to_string())
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && s != "none")
        .collect();

    let mut ip_intel_providers: Vec<Arc<dyn IpIntelligenceProvider>> = Vec::new();

    if enabled_providers.iter().any(|p| p == "tor") {
        let tor_provider = Arc::new(TorExitProvider::new(cache_backend.clone()));
        ip_intel_providers.push(tor_provider);
        info!("IP intelligence: Tor exit provider enabled");
    }

    if enabled_providers.iter().any(|p| p == "cloud") {
        // Azure: optional, URL changes weekly. Configure via SID_IPINTEL_AZURE_URL.
        let cloud_provider = if let Ok(azure_url) = std::env::var("SID_IPINTEL_AZURE_URL") {
            Arc::new(CloudRangeProvider::with_azure(
                cache_backend.clone(),
                azure_url,
            ))
        } else {
            Arc::new(CloudRangeProvider::new(cache_backend.clone()))
        };
        ip_intel_providers.push(cloud_provider);
        info!("IP intelligence: Cloud range provider enabled");
    }

    if enabled_providers.iter().any(|p| p == "firehol") {
        let firehol_provider = Arc::new(FireholProvider::new(cache_backend.clone()));
        ip_intel_providers.push(firehol_provider);
        info!("IP intelligence: FireHOL provider enabled");
    }

    if enabled_providers.iter().any(|p| p == "self_learned") {
        let threshold: f32 = match std::env::var("SID_IPINTEL_REPUTATION_THRESHOLD") {
            Err(_) => 0.7,
            Ok(v) => v
                .parse()
                .ok()
                .filter(|t: &f32| (0.0..=1.0).contains(t))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "SID_IPINTEL_REPUTATION_THRESHOLD must be a number from 0 to 1, got {v:?}"
                    )
                })?,
        };
        let self_learned_provider = Arc::new(SelfLearnedReputationProvider::new(
            storage.clone(),
            threshold,
        ));
        ip_intel_providers.push(self_learned_provider);
        info!("IP intelligence: Self-learned reputation provider enabled (threshold={threshold})");
    }

    if enabled_providers.iter().any(|p| p == "allowlist") {
        let allowlist_provider = Arc::new(AllowlistProvider::new(storage.clone()));
        ip_intel_providers.push(allowlist_provider);
        info!("IP intelligence: Admin allowlist provider enabled");
    }

    if ip_intel_providers.is_empty() {
        info!("IP intelligence: no providers enabled (SID_IPINTEL_PROVIDERS=none)");
    }

    let ip_intelligence = Arc::new(IpIntelligenceAggregator::new(
        ip_intel_providers,
        cache_backend.clone(),
        std::time::Duration::from_secs(300), // 5 min cache for aggregated results
    ));
    // Start from what the replicas already published; failures are logged
    // and the refresh task tries again.
    ip_intelligence.reload_all().await;

    // Background refresh: hourly for all providers.
    // Cloud provider uses 2-day cache TTL internally (effectively daily refresh).
    // Self-learned and allowlist refresh from DB every hour.
    if ip_intelligence.provider_count() > 0 {
        sid_authn::ip_intelligence::spawn_refresh_task(
            ip_intelligence.clone(),
            std::time::Duration::from_secs(3600), // 1 hour
            cache_backend.clone(),
        );
    }

    // ── GeoIP resolution: priority chain with cache ──
    let geoip = Arc::new(build_geoip_chain_from_env(cache_backend.clone()));

    // Proxies in front of this server whose X-Forwarded-For names the client;
    // unset means clients connect directly and headers are ignored.
    let trusted_proxies = sid_authn::client_address::TrustedProxies::parse(
        &std::env::var("SID_TRUSTED_PROXIES").unwrap_or_default(),
    )
    .map_err(|e| anyhow::anyhow!("SID_TRUSTED_PROXIES: {e}"))?;

    // A provider that was asked for and cannot run stops startup.
    let captcha_provider = sid_authn::captcha::build_captcha_provider_from_env(&captcha_pow_key)
        .map_err(|e| anyhow::anyhow!("CAPTCHA: {e}"))?;

    // One authorization evaluator for every service of this process.
    let authz_engine: Arc<dyn sid_plugin::AuthzEngine> =
        Arc::new(sid_authz::CeAuthzEngine::new(storage.clone()));

    let login_url = login_url(std::env::var("SID_LOGIN_URL").ok().as_deref(), &issuer)?;

    let history_authority = password_history_authority(
        |name| std::env::var(name),
        storage.as_ref(),
        || local_history_keys.open(),
        key_manager.clone(),
        &issuer,
    )
    .await
    .context("password history configuration")?;
    let auth_svc = AuthServiceImpl::new(
        storage.clone(),
        oauth2.clone(),
        webauthn.clone(),
        jwt.clone(),
        opaque_router.clone(),
        opaque_zkpp.clone(),
        revocation_cache.clone(),
        feature_flags.clone(),
        magic_link,
        otp_service,
        issuers.clone(),
        organization.id,
        issuer.clone(),
        captcha_provider,
        cache_backend.clone(),
        ip_intelligence,
        geoip,
        key_manager.clone(),
        cascade_service.clone(),
        authz_engine.clone(),
        history_authority,
    )
    .with_trusted_proxies(trusted_proxies);
    let auth_svc = Arc::new(match &login_url {
        Some(page) => auth_svc.with_sign_in_page(page),
        None => auth_svc,
    });

    let project_svc = Arc::new(ProjectServiceImpl::new(
        storage.clone(),
        feature_flags.clone(),
        jwt.clone(),
        revocation_cache.clone(),
        local_issuer.clone(),
    ));

    // Maintenance mode bridge: FeatureFlagService → AtomicBool for sid-authz
    let maintenance_mode = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let mm = maintenance_mode.clone();
        let ff = feature_flags.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                mm.store(
                    ff.is_maintenance_mode().await,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
        });
    }

    let cedar = CedarService::new();
    // The deployment names the services it trusts to confirm checks of
    // original requests; without the setting nobody is trusted.
    let request_verifiers = match std::env::var("SID_AUTHZ_REQUEST_VERIFIERS_FILE") {
        Ok(path) => {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read SID_AUTHZ_REQUEST_VERIFIERS_FILE {path}"))?;
            sid_authz::request_verifier::RequestVerifiers::from_json(&text)
                .with_context(|| format!("SID_AUTHZ_REQUEST_VERIFIERS_FILE {path}"))?
        }
        Err(_) => Default::default(),
    };
    // Permission checkers authenticate with their own tokens for the
    // authorization API.
    let checker_tokens = Arc::new(
        sid_authn::resource_token::ResourceTokenVerifier::new(
            issuers.clone(),
            local_issuer.clone(),
            authorization_api.indicator.clone(),
        )
        .await
        .context("authorization API token verifier")?,
    );
    let authz_svc = Arc::new(
        AuthzServiceImpl::new(
            authz_engine.clone(),
            storage.clone(),
            cedar,
            maintenance_mode,
            jwt.clone(),
            revocation_cache.clone(),
            audit_log.clone(),
        )
        .with_service_tokens(checker_tokens)
        .with_request_verifiers(request_verifiers),
    );

    let admin_svc = Arc::new(AdminServiceImpl::new(
        storage.clone(),
        jwt.clone(),
        revocation_cache.clone(),
        cascade_service.clone(),
        key_manager.clone(),
    ));
    let branding_svc = Arc::new(crate::grpc::branding_service::BrandingServiceImpl::new(
        storage.clone(),
        jwt.clone(),
        revocation_cache.clone(),
    ));
    let flow_config_svc = Arc::new(crate::grpc::flow_service::FlowConfigServiceImpl::new(
        storage.clone(),
        jwt.clone(),
        revocation_cache.clone(),
    ));
    let flow_action_svc = Arc::new(crate::grpc::flow_service::FlowActionServiceImpl::new(
        storage.clone(),
        jwt.clone(),
        revocation_cache.clone(),
    ));
    let enrollment_svc = Arc::new(crate::grpc::enrollment_service::EnrollmentServiceImpl::new(
        storage.clone(),
        jwt.clone(),
        revocation_cache.clone(),
    ));
    let security_svc = Arc::new(crate::grpc::security_service::SecurityServiceImpl::new(
        storage.clone(),
        jwt.clone(),
        revocation_cache.clone(),
        audit_log.clone(),
        cache_backend.clone(),
    ));
    let account_svc = Arc::new(crate::grpc::account_service::AccountServiceImpl::new(
        storage.clone(),
        jwt.clone(),
        revocation_cache.clone(),
    ));

    let audit_retention =
        crate::background_tasks::AuditRetention::from_lookup(|k| std::env::var(k).ok())
            .map_err(|e| anyhow::anyhow!(e))?;

    Ok(CeComponents {
        audit_retention,
        issuers,
        login_url,
        authz_engine,
        organization,
        #[cfg(feature = "scim")]
        scim_directory,
        #[cfg(feature = "scim")]
        scim_resource,
        #[cfg(feature = "scim")]
        scim_issuer,
        storage,
        jwt,
        oauth2,
        webauthn,
        opaque_router,
        opaque_zkpp,
        revocation_cache,
        feature_flags,
        event_bus,
        embedded_nats: embedded_nats.map(Arc::new),
        cache_backend,
        app_state,
        issuer,
        grpc_addr,
        key_manager,
        cascade_service,
        closure_service,
        identity_svc,
        auth_svc,
        project_svc,
        authz_svc,
        admin_svc,
        branding_svc,
        flow_config_svc,
        flow_action_svc,
        enrollment_svc,
        security_svc,
        account_svc,
    })
}

/// This round's lock of background job `job`: `None` when another instance
/// holds it, or when the store cannot be asked (logged; the next round retries).
async fn take_job_lock(
    storage: &dyn sid_plugin::storage::StorageBackend,
    job: i64,
    name: &str,
) -> Option<sid_plugin::storage::JobLock> {
    match storage.try_job_lock(job).await {
        Ok(lock) => lock,
        Err(e) => {
            tracing::warn!(job = name, error = %e, "background job lock unavailable, skipping this round");
            None
        }
    }
}

/// Free a job lock after the job's run. A failed release is logged: the lock
/// frees itself (closed session, lease end), so the job resumes later.
async fn release_job_lock(lock: sid_plugin::storage::JobLock, name: &str) {
    if let Err(e) = lock.release().await {
        tracing::warn!(job = name, error = %e, "background job lock release failed");
    }
}

/// Spawn all CE background tasks, each run by one instance at a time.
pub fn spawn_ce_background_tasks(c: &CeComponents) {
    // Ended first enrollments' records (hourly): their work, aborts and
    // fences are dropped once no step of them can still arrive.
    {
        let storage = c.storage.clone();
        let auth = c.auth_svc.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if let Some(lock) = take_job_lock(
                    &*storage,
                    LOCK_ENROLLMENT_COMPACTION,
                    "enrollment_compaction",
                )
                .await
                {
                    match auth.compact_enrollments().await {
                        Ok(0) => {}
                        Ok(n) => info!("Compacted {} ended enrollment records", n),
                        Err(e) => tracing::warn!("enrollment compaction failed: {}", e),
                    }
                    release_job_lock(lock, "enrollment_compaction").await;
                }
            }
        });
    }

    // PAT auto-revoke (hourly)
    {
        let storage = c.storage.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if let Some(lock) =
                    take_job_lock(&*storage, LOCK_PAT_AUTO_REVOKE, "pat_auto_revoke").await
                {
                    match storage
                        .revoke_unused_pats(
                            sid_core::models::pat::PAT_AUTO_REVOKE_UNUSED_DAYS,
                            AuditEntry::system("pat.auto_revoke_unused", "background_task").into(),
                        )
                        .await
                    {
                        Ok(0) => {}
                        Ok(n) => info!("Auto-revoked {} unused PATs", n),
                        Err(e) => tracing::warn!("PAT auto-revoke failed: {}", e),
                    }
                    release_job_lock(lock, "pat_auto_revoke").await;
                }
            }
        });
    }

    // Machine credential expiry (hourly). Each alert is relayed as durable
    // work whose id follows from the credential (and the day count), so the
    // hourly scan announces an expiry once and each day's warning once.
    {
        let storage = c.storage.clone();
        tokio::spawn(async move {
            let alert_days = sid_core::models::machine_user::CREDENTIAL_ALERT_BEFORE_EXPIRY_DAYS;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let Some(lock) =
                    take_job_lock(&*storage, LOCK_CREDENTIAL_EXPIRY, "credential_expiry").await
                else {
                    continue;
                };
                match storage.list_expiring_machine_credentials(alert_days).await {
                    Ok(creds) => {
                        let now = chrono::Utc::now();
                        for cred in &creds {
                            if let Some(exp) = cred.expires_at {
                                if exp <= now {
                                    let mut event = sid_core::models::event::Event::new(
                                        "sid-server",
                                        sid_core::models::event::event_types::MACHINE_USER_CREDENTIAL_EXPIRED,
                                    )
                                    .with_subject(format!("machine_credential/{}", cred.kid))
                                    .with_data(serde_json::json!({
                                        "kid": cred.kid,
                                        "machine_user_id": cred.machine_user_id,
                                        "expired_at": exp.to_rfc3339(),
                                    }));
                                    event.id =
                                        credential_alert_id(&format!("expired:{}", cred.kid));
                                    if let Err(e) =
                                        sid_authn::event_relay::relay_observed(&*storage, &event)
                                            .await
                                    {
                                        tracing::warn!(
                                            "Failed to relay credential_expired event: {}",
                                            e
                                        );
                                    }
                                    tracing::warn!(
                                        kid = %cred.kid,
                                        machine_user_id = %cred.machine_user_id,
                                        "Machine credential expired, should be revoked"
                                    );
                                } else {
                                    let days_left = (exp - now).num_days();
                                    let mut event = sid_core::models::event::Event::new(
                                        "sid-server",
                                        sid_core::models::event::event_types::MACHINE_USER_CREDENTIAL_EXPIRING,
                                    )
                                    .with_subject(format!("machine_credential/{}", cred.kid))
                                    .with_data(serde_json::json!({
                                        "kid": cred.kid,
                                        "machine_user_id": cred.machine_user_id,
                                        "expires_at": exp.to_rfc3339(),
                                        "days_left": days_left,
                                    }));
                                    event.id = credential_alert_id(&format!(
                                        "expiring:{}:{days_left}",
                                        cred.kid
                                    ));
                                    if let Err(e) =
                                        sid_authn::event_relay::relay_observed(&*storage, &event)
                                            .await
                                    {
                                        tracing::warn!(
                                            "Failed to relay credential_expiring event: {}",
                                            e
                                        );
                                    }
                                    tracing::info!(
                                        kid = %cred.kid,
                                        machine_user_id = %cred.machine_user_id,
                                        days_left = days_left,
                                        "Machine credential expiring soon"
                                    );
                                }
                            }
                        }
                        if !creds.is_empty() {
                            info!(
                                "Credential expiry scan: {} credentials expiring/expired",
                                creds.len()
                            );
                        }
                    }
                    Err(e) => tracing::warn!("Credential expiry scan failed: {}", e),
                }
                release_job_lock(lock, "credential_expiry").await;
            }
        });
    }

    // Role assignment auto-revoke (every 5 minutes). Each warning threshold is
    // announced once per assignment; each removal owes its expired event in
    // the removal's own transaction.
    {
        let storage = c.storage.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let Some(lock) = take_job_lock(&*storage, LOCK_ROLE_EXPIRY, "role_expiry").await
                else {
                    continue;
                };

                let max_window = *sid_core::models::authz::ROLE_EXPIRY_ALERT_HOURS
                    .first()
                    .unwrap_or(&72);
                match storage.list_expiring_role_assignments(max_window).await {
                    Ok(assignments) => {
                        let now = chrono::Utc::now();
                        for a in &assignments {
                            if let Some(exp) = a.expires_at {
                                if exp <= now {
                                    continue;
                                }
                                let hours_left = (exp - now).num_hours();
                                // The thresholds descend: the last one reached
                                // is the tightest warning due now.
                                if let Some(&threshold) =
                                    sid_core::models::authz::ROLE_EXPIRY_ALERT_HOURS
                                        .iter()
                                        .rev()
                                        .find(|&&t| hours_left <= t)
                                {
                                    let event = a.expiring_event(threshold, hours_left);
                                    if let Err(e) =
                                        sid_authn::event_relay::relay_observed(&*storage, &event)
                                            .await
                                    {
                                        tracing::warn!(
                                            "Failed to relay role_expiring event: {}",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => tracing::warn!("Role expiry scan failed: {}", e),
                }

                match storage
                    .cleanup_expired_role_assignments(
                        AuditEntry::system("role_assignment.auto_revoke", "background_task").into(),
                    )
                    .await
                {
                    Ok(removed) if removed.is_empty() => {}
                    Ok(removed) => {
                        info!("Auto-revoked {} expired role assignments", removed.len())
                    }
                    Err(e) => tracing::warn!("Role assignment auto-revoke failed: {}", e),
                }
                release_job_lock(lock, "role_expiry").await;
            }
        });
    }

    // Quarantine cleanup (daily)
    {
        let storage = c.storage.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
            loop {
                interval.tick().await;
                if let Some(lock) =
                    take_job_lock(&*storage, LOCK_QUARANTINE_CLEANUP, "quarantine_cleanup").await
                {
                    crate::background_tasks::cleanup_quarantine(storage.as_ref()).await;
                    release_job_lock(lock, "quarantine_cleanup").await;
                }
            }
        });
    }

    // Account closure lifecycle (hourly, leader-only): closures whose grace
    // period ended are executed, closed profiles are purged at quarantine end.
    {
        let storage = c.storage.clone();
        let closures = c.closure_service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if let Some(lock) =
                    take_job_lock(&*storage, LOCK_PROFILE_PURGE, "profile_purge").await
                {
                    crate::background_tasks::execute_due_closures(storage.as_ref(), &closures)
                        .await;
                    crate::background_tasks::purge_closed_profiles(storage.as_ref()).await;
                    release_job_lock(lock, "profile_purge").await;
                }
            }
        });
    }

    // Migration deadline enforcement (daily)
    {
        let storage = c.storage.clone();
        let deadline_days: i64 = std::env::var("SID_MIGRATION_DEADLINE_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(crate::background_tasks::DEFAULT_MIGRATION_DEADLINE_DAYS);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
            loop {
                interval.tick().await;
                if let Some(lock) =
                    take_job_lock(&*storage, LOCK_MIGRATION_DEADLINE, "migration_deadline").await
                {
                    crate::background_tasks::enforce_migration_deadline(
                        storage.as_ref(),
                        deadline_days,
                    )
                    .await;
                    release_job_lock(lock, "migration_deadline").await;
                }
            }
        });
    }

    // Audit storage maintenance (daily, leader-only): this and next month's
    // storage prepared, months past retention removed when the site chose
    // `delete`.
    {
        let storage = c.storage.clone();
        let retention = c.audit_retention;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
            loop {
                interval.tick().await;
                if let Some(lock) =
                    take_job_lock(&*storage, LOCK_AUDIT_PARTITION, "audit_partition").await
                {
                    if let Err(e) = crate::background_tasks::manage_audit_partitions(
                        storage.as_ref(),
                        retention,
                        chrono::Utc::now(),
                    )
                    .await
                    {
                        tracing::error!(error = %e, "audit storage maintenance failed");
                    }
                    release_job_lock(lock, "audit_partition").await;
                }
            }
        });
    }

    // ── Principal verification expiry (daily, leader-only) ──
    {
        let storage = c.storage.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
            loop {
                interval.tick().await;
                if let Some(lock) =
                    take_job_lock(&*storage, LOCK_PRINCIPAL_EXPIRY, "principal_expiry").await
                {
                    crate::background_tasks::expire_principal_verifications(storage.as_ref()).await;
                    release_job_lock(lock, "principal_expiry").await;
                }
            }
        });
    }
}

/// Start the runner for work the storage commits with a mutation (owed
/// back-channel logouts, relayed events, contestation checks). Every replica
/// runs one; leases keep an attempt on a single replica. Runs until
/// `shutdown` resolves, then lets attempts in flight record their outcome.
pub fn spawn_work_runner(
    c: &CeComponents,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let handlers: Vec<Arc<dyn WorkHandler>> = vec![
        Arc::new(BackChannelLogoutHandler::new(
            c.issuers.clone(),
            c.storage.clone(),
        )),
        Arc::new(EventRelayHandler::new(c.event_bus.clone())),
        Arc::new(sid_authn::principal_contest::PrincipalContestHandler::new(
            c.storage.clone(),
        )),
        c.auth_svc.enrollment_handler(),
    ];
    let worker = format!("sid-server-{}-{}", std::process::id(), uuid::Uuid::now_v7());
    let runner = WorkRunner::new(c.storage.clone(), worker, handlers, RunnerConfig::default())
        .map_err(|e| anyhow::anyhow!("work runner: {e}"))?;
    Ok(tokio::spawn(runner.run(shutdown)))
}

/// The history evaluator's store in this installation's own database, used
/// only when the evaluator runs in this process: its tables are created then.
pub(crate) enum LocalHistoryKeys {
    #[cfg(feature = "storage-pg")]
    Postgres(sid_storage::PgHistoryKeyStore),
    #[cfg(all(feature = "embedded-dev", not(feature = "storage-pg")))]
    Sqlite(sid_storage::sqlite::SqliteHistoryKeyStore),
}

impl LocalHistoryKeys {
    /// The store, its tables created first.
    async fn open(self) -> anyhow::Result<Arc<dyn sid_plugin::history_keys::HistoryKeyStore>> {
        Ok(match self {
            #[cfg(feature = "storage-pg")]
            Self::Postgres(store) => {
                store
                    .migrate()
                    .await
                    .context("history evaluator migrations")?;
                Arc::new(store)
            }
            #[cfg(all(feature = "embedded-dev", not(feature = "storage-pg")))]
            Self::Sqlite(store) => Arc::new(store),
        })
    }
}

/// Where this server's password history evaluator runs. Without
/// `SID_PASSWORD_HISTORY_EVALUATOR` it runs here, over the store `local`
/// opens and sealing history keys with the field keys. With it, this server
/// calls that gRPC address with its own client credential
/// (`SID_PASSWORD_HISTORY_CALLER_*`) for the evaluator's resource
/// (`SID_PASSWORD_HISTORY_EVALUATOR_RESOURCE`), requested from the issuer at
/// `SID_PASSWORD_HISTORY_TOKEN_UPSTREAM`; it then opens no evaluator store
/// and holds no history key.
///
/// The history write cutoff `SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE` is an
/// input to the durable cutoff of each store, raised before anything is
/// served: first this server's own (`storage`), which fences its history
/// commits whether or not the evaluator is reachable, then the in-process
/// evaluator's. An older or unset setting lowers neither; a raise that
/// cannot be committed stops the start. A remote evaluator applies the
/// setting from its own deployment.
async fn password_history_authority<Local>(
    var: impl Fn(&str) -> Result<String, std::env::VarError>,
    storage: &dyn sid_plugin::StorageBackend,
    local: impl FnOnce() -> Local,
    field_keys: Arc<dyn sid_keys::KeyManager>,
    base: &str,
) -> anyhow::Result<crate::grpc::password_operation::PasswordHistoryAuthority>
where
    Local: std::future::Future<
            Output = anyhow::Result<Arc<dyn sid_plugin::history_keys::HistoryKeyStore>>,
        >,
{
    use crate::grpc::password_operation::{PasswordHistoryAuthority, RemoteHistoryEvaluator};
    // A setting that is present but unreadable is refused, never read as
    // unset: that would quietly give this server the history keys.
    let optional = |name: &str| match var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(anyhow::anyhow!("{name} must be Unicode")),
    };
    let required = |name: &str| var(name).map_err(|_| anyhow::anyhow!("{name} is required"));
    let cutoff = history_epoch_cutoff(var("SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE"))?;
    let audit = || AuditEntry::system("password_history.write_cutoff", "password_history");
    if let Some(cutoff) = cutoff {
        let in_force = storage
            .raise_history_write_cutoff(cutoff, audit().into())
            .await
            .context("SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE: credential history cutoff")?;
        info!(%in_force, "password history write cutoff in force for history commits");
    }
    let Some(evaluator) = optional("SID_PASSWORD_HISTORY_EVALUATOR")? else {
        let store = local().await?;
        if let Some(cutoff) = cutoff {
            store
                .raise_write_cutoff(cutoff, audit())
                .await
                .context("SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE: evaluator cutoff")?;
        }
        return Ok(PasswordHistoryAuthority::InProcess {
            store,
            history_keys: field_keys,
        });
    };
    // An invalid RFC 8707 indicator of the evaluator stops the start.
    let resource = sid_core::models::ResourceIndicator::parse(&required(
        "SID_PASSWORD_HISTORY_EVALUATOR_RESOURCE",
    )?)
    .map_err(|e| anyhow::anyhow!("SID_PASSWORD_HISTORY_EVALUATOR_RESOURCE: {e}"))?;
    let token_upstream = required("SID_PASSWORD_HISTORY_TOKEN_UPSTREAM")?;
    let caller = sid_authn::client_credential::ClientCredentialConfig::from_vars(
        "SID_PASSWORD_HISTORY_CALLER",
        |name| var(name).ok().filter(|v| !v.is_empty()),
    )?
    .ok_or_else(|| anyhow::anyhow!("SID_PASSWORD_HISTORY_CALLER_CLIENT_ID is required"))?;
    let lazy = |address: &str| -> anyhow::Result<tonic::transport::Channel> {
        Ok(tonic::transport::Endpoint::from_shared(address.to_owned())
            .with_context(|| format!("gRPC address {address}"))?
            .connect_lazy())
    };
    let credential = Arc::new(
        sid_authn::client_credential::ClientCredential::for_resource(
            &caller,
            base,
            lazy(&token_upstream)?,
            resource.as_str(),
        )?,
    );
    Ok(PasswordHistoryAuthority::Remote(
        RemoteHistoryEvaluator::new(lazy(&evaluator)?, credential),
    ))
}

/// The cutoff before which password-history epochs are replaced, an RFC 3339
/// instant. Unset means none; a malformed or future value stops startup.
fn history_epoch_cutoff(
    input: Result<String, std::env::VarError>,
) -> anyhow::Result<Option<chrono::DateTime<chrono::Utc>>> {
    const NAME: &str = "SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE";
    let value = match input {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{NAME} must be Unicode"),
    };
    let cutoff = chrono::DateTime::parse_from_rfc3339(&value)
        .map_err(|_| anyhow::anyhow!("{NAME} must be an RFC 3339 instant"))?
        .with_timezone(&chrono::Utc);
    // A future cutoff would replace every epoch created until then, again
    // at each operation: it names no compromise that has happened.
    anyhow::ensure!(
        cutoff <= chrono::Utc::now(),
        "{NAME} must not be in the future"
    );
    Ok(Some(cutoff))
}

/// Parse explicit proof settings without treating invalid input as absence.
fn zkpp_settings(
    enabled: Result<String, std::env::VarError>,
    required: Result<String, std::env::VarError>,
    version: Result<String, std::env::VarError>,
) -> anyhow::Result<(bool, sid_authn::opaque_zkpp::ZkppConfig)> {
    fn value(
        name: &str,
        input: Result<String, std::env::VarError>,
    ) -> anyhow::Result<Option<String>> {
        match input {
            Ok(v) => Ok(Some(v)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must be Unicode"),
        }
    }
    fn boolean(name: &str, input: Result<String, std::env::VarError>) -> anyhow::Result<bool> {
        match value(name, input)?.as_deref() {
            None | Some("true" | "1") => Ok(true),
            Some("false" | "0") => Ok(false),
            Some(_) => anyhow::bail!("{name} must be true, false, 1 or 0"),
        }
    }
    let enabled = boolean("SID_ZKPP_ENABLED", enabled)?;
    let require_proof = boolean("SID_ZKPP_REQUIRE_PROOF", required)?;
    anyhow::ensure!(
        enabled || !require_proof,
        "mandatory password proofs require enabled verifiers"
    );
    let policy_version = match value("SID_ZKPP_POLICY_VERSION", version)? {
        None => 1,
        Some(v) => v.parse::<u32>().map_err(|_| {
            anyhow::anyhow!("SID_ZKPP_POLICY_VERSION must be an unsigned policy version")
        })?,
    };
    anyhow::ensure!(
        sid_pake_core::policy::get_policy(sid_pake_core::types::PolicyVersion(policy_version))
            .is_some(),
        "SID_ZKPP_POLICY_VERSION selects an unknown policy"
    );
    Ok((
        enabled,
        sid_authn::opaque_zkpp::ZkppConfig {
            require_proof,
            policy_version,
        },
    ))
}

/// Initialize ZKPP with async keygen on the router's server setup.
/// Password operations return UNAVAILABLE until the verifier is ready.
/// Proofs are mandatory by default; optional setup still verifies every proof.
fn init_zkpp(router: &Arc<OpaqueRouter>) -> Arc<arc_swap::ArcSwap<Option<Arc<ZkppOpaqueServer>>>> {
    let slot: Arc<arc_swap::ArcSwap<Option<Arc<ZkppOpaqueServer>>>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(None));

    let (enabled, config) = zkpp_settings(
        std::env::var("SID_ZKPP_ENABLED"),
        std::env::var("SID_ZKPP_REQUIRE_PROOF"),
        std::env::var("SID_ZKPP_POLICY_VERSION"),
    )
    .unwrap_or_else(|e| panic!("ZKPP configuration: {e}"));
    if !enabled {
        // Registration, change and reset run their OPAQUE on this server
        // whether or not proofs are verified; without verifiers every
        // password installs policy-unverified (D018) and a proof sent
        // anyway is refused. A router this server cannot serve (another
        // primary curve) leaves password operations unavailable.
        match sid_authn::opaque_zkpp::ZkppOpaqueServer::new(
            router,
            vec![],
            sid_authn::opaque_zkpp::ZkppConfig {
                require_proof: false,
                policy_version: config.policy_version,
            },
        ) {
            Ok(server) => slot.store(Arc::new(Some(Arc::new(server)))),
            Err(e) => tracing::warn!("password operations unavailable: {e}"),
        }
        return slot;
    }

    let policy_version = config.policy_version;
    let require_proof = config.require_proof;
    // The verifying key is built for this policy: its minimums are fixed
    // columns of the key, so this is the policy every accepted proof meets.
    let policy =
        sid_pake_core::policy::get_policy(sid_pake_core::types::PolicyVersion(policy_version))
            .unwrap_or_else(|| panic!("SID_ZKPP_POLICY_VERSION={policy_version}: no such policy"));

    // A ZKPP server on the router's setup; a router it cannot serve is a
    // deployment error, found here at start, not after keygen.
    if let Err(e) = sid_authn::opaque_zkpp::ZkppOpaqueServer::new(
        router,
        vec![],
        sid_authn::opaque_zkpp::ZkppConfig {
            require_proof: false,
            policy_version,
        },
    ) {
        panic!("ZKPP: {e}");
    }

    // The SRS depends only on k and is cached; a verifying key per supported
    // number of history comparison domains is derived from it.
    let cache_dir = std::env::var("SID_DATA_DIR").unwrap_or_else(|_| ".sid-data".to_string());
    let cache_path = std::path::Path::new(&cache_dir).join("zkpp");
    info!(
        "ZKPP verifying keys preparing in background (k={}) — non-ZKPP traffic is served meanwhile",
        sid_pake_core::circuit::ZKPP_K
    );
    let slot_clone = slot.clone();
    let router = Arc::clone(router);
    tokio::spawn(async move {
        let start = std::time::Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            let params = match std::fs::File::open(cache_path.join("zkpp_params.bin"))
                .ok()
                .and_then(|mut f| sid_pake_core::keygen::read_params(&mut f).ok())
            {
                Some(params) => params,
                None => {
                    let params =
                        sid_pake_core::keygen::generate_params(sid_pake_core::circuit::ZKPP_K);
                    if let Err(e) = sid_pake_core::keygen::save_params_cache(&cache_path, &params) {
                        tracing::warn!("Failed to cache ZKPP params: {}", e);
                    }
                    params
                }
            };
            (1..=sid_core::models::password_history::MAX_HISTORY_DOMAINS)
                .map(|history_domains| {
                    let shape = sid_pake_core::circuit::CircuitShape {
                        policy,
                        history_domains,
                    };
                    sid_pake_core::keygen::generate_vk(&params, shape).map(|vk| {
                        sid_pake_core::verifier::ZkppVerifier::new(params.clone(), vk, shape)
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .await;

        match result {
            Ok(Ok(verifiers)) => {
                let server =
                    sid_authn::opaque_zkpp::ZkppOpaqueServer::new(&router, verifiers, config)
                        .unwrap_or_else(|e| panic!("ZKPP: {e}"));
                slot_clone.store(Arc::new(Some(Arc::new(server))));
                info!(
                    "ZKPP verifying keys ready ({}s, require_proof={}, policy_version={})",
                    start.elapsed().as_secs(),
                    require_proof,
                    policy_version
                );
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    "ZKPP keygen failed: {:?} — password operations remain unavailable",
                    e
                );
            }
            Err(e) => {
                tracing::error!(
                    "ZKPP keygen task panicked: {} — password operations remain unavailable",
                    e
                );
            }
        }
    });

    slot
}

/// Initialize feature flag service from env vars.
fn init_feature_flags() -> FeatureFlagService {
    if std::env::var("SID_FEATURE_FLAGS_ENABLED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
    {
        let config = FeatureFlagConfig {
            api_url: std::env::var("SID_FEATURE_FLAGS_URL")
                .expect("SID_FEATURE_FLAGS_URL must be set when feature flags enabled"),
            instance_id: std::env::var("SID_FEATURE_FLAGS_INSTANCE_ID")
                .expect("SID_FEATURE_FLAGS_INSTANCE_ID must be set when feature flags enabled"),
            app_name: std::env::var("SID_FEATURE_FLAGS_APP_NAME")
                .unwrap_or_else(|_| "production".into()),
            poll_interval_secs: std::env::var("SID_FEATURE_FLAGS_POLL_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
        };
        info!(
            "Feature flags enabled (url={}, interval={}s)",
            config.api_url, config.poll_interval_secs
        );
        let svc = FeatureFlagService::new(config);
        svc.start_polling();
        svc
    } else {
        FeatureFlagService::disabled()
    }
}

#[cfg(test)]
mod tests;
