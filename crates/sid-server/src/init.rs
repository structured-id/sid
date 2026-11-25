// SPDX-License-Identifier: AGPL-3.0-only
//! CE server initialization.
//!
//! Reusable initialization logic: a binary calls [`init_ce`] to set up all
//! core components, then adds its own services.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use sid_authn::account_closure::AccountClosureService;
use sid_authn::data_export::DataExportService;
use sid_authn::geoip::build_geoip_chain_from_env;
use sid_authn::ip_intelligence::{
    AllowlistProvider, CloudRangeProvider, FireholProvider, IpIntelligenceAggregator,
    IpIntelligenceProvider, SelfLearnedReputationProvider, TorExitProvider,
};
use sid_authn::jwt::JwtService;
use sid_authn::magic_link::MagicLinkService;
use sid_authn::oauth2::OAuth2Server;
use sid_authn::opaque::OpaqueRouter;
use sid_authn::otp::OtpService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_authn::webauthn::WebAuthnServer;
use sid_authn::work_runner::RunnerConfig;
use sid_core::models::AuditEntry;
use sid_plugin::cache::CacheBackend;
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

use crate::grpc::authz_service::AuthzServiceImpl;
use sid_authn::opaque_zkpp::ZkppOpaqueServer;
use sid_authz::cedar::CedarService;

/// Audit retention from `SID_AUDIT_RETENTION_DAYS` (default 365, 1 to 36500)
/// and `SID_AUDIT_RETENTION_ACTION` (`archive`, the default, or `delete`);
/// anything else, including a setting `get` cannot read, is an error, never a
/// silent default.
pub fn audit_retention_from_lookup(
    get: impl Fn(&str) -> anyhow::Result<Option<String>>,
) -> anyhow::Result<sid::AuditRetention> {
    use sid::RetentionAction;
    let days = match get("SID_AUDIT_RETENTION_DAYS")? {
        None => sid::AuditRetention::default().days,
        Some(v) => v
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|d| (1..=36500).contains(d))
            .ok_or_else(|| {
                anyhow::anyhow!("SID_AUDIT_RETENTION_DAYS must be 1 to 36500 days, got {v:?}")
            })?,
    };
    let action = match get("SID_AUDIT_RETENTION_ACTION")?.as_deref().map(str::trim) {
        None | Some("archive") => RetentionAction::Archive,
        Some("delete") => RetentionAction::Delete,
        Some(other) => {
            anyhow::bail!("SID_AUDIT_RETENTION_ACTION must be archive or delete, got {other:?}")
        }
    };
    Ok(sid::AuditRetention { days, action })
}

/// All initialized CE components and gRPC services.
pub struct CeComponents {
    pub storage: Arc<dyn StorageBackend>,
    pub jwt: Arc<JwtService>,
    pub oauth2: Arc<OAuth2Server>,
    pub webauthn: Arc<WebAuthnServer>,
    pub opaque_router: Arc<OpaqueRouter>,
    pub opaque_zkpp: Arc<arc_swap::ArcSwap<Option<Arc<ZkppOpaqueServer>>>>,
    /// When `opaque_zkpp` can serve password operations, reported on the
    /// health service under their own name.
    pub zkpp_ready: sid_authn::opaque_zkpp::setup::ZkppReady,
    pub revocation_cache: Arc<RevocationCache>,
    /// Receives the other replicas' revocations into `revocation_cache`; it
    /// stops when dropped, so it lives as long as the components.
    pub revocation_listener: Arc<sid_authn::revocation_cache::RevocationListener>,
    pub feature_flags: FeatureFlagService,
    pub event_bus: Arc<dyn EventBus>,
    /// The bundled `nats-server` behind `event_bus` in embedded mode; it is
    /// stopped when dropped, so it lives as long as the components.
    pub embedded_nats: Option<Arc<crate::embedded_nats::EmbeddedNats>>,
    /// Over SQLite, this process's bus lock on the file (exclusive with the
    /// in-process bus, shared otherwise), held as long as the components live.
    pub database_lock: Option<Arc<std::fs::File>>,
    /// The receivers every committed fact of their types is owed to, whether
    /// or not they are running (`SID_EVENT_RECEIVERS`).
    pub required_receivers: Vec<sid_core::models::RequiredReceiver>,
    pub cache_backend: Arc<dyn CacheBackend>,
    pub app_state: AppState,
    pub issuer: String,
    /// The installation's browser-facing settings (public URL, console
    /// address, session cookie scope): changed by RealmService, applied by
    /// the cookie issuer and the UI host.
    pub web_settings: Arc<sid::web_settings::WebSettingsAdmin>,
    pub grpc_addr: SocketAddr,
    /// Field encryption for stored secrets every service seals.
    pub key_manager: Arc<dyn sid_keys::KeyManager>,
    /// Ends sessions, tokens and PATs of a profile (shared by every service
    /// that suspends or revokes one).
    pub cascade_service: Arc<RevocationCascadeService>,
    /// Executes account closures whose grace period has ended.
    pub closure_service: Arc<AccountClosureService>,
    /// How long audit records are kept and what happens to them after.
    pub audit_retention: sid::AuditRetention,
    /// Days a profile has to finish its password migration.
    pub migration_deadline_days: i64,
    /// The installation's OIDC issuers and their signers.
    pub issuers: Arc<sid_authn::issuer::IssuerRegistry>,
    /// The sign-in page the authorization endpoint sends users to: the
    /// account UI's, or, set by the host before serving, a source naming the
    /// entry of the interactive branch it serves for the issuer once that
    /// branch is open.
    pub sign_in_page: Arc<dyn crate::grpc::oidc_provider_service::SignInPage>,
    /// The account UI's sign-in page, the one page whose origin runs the
    /// browser ceremonies: the auth service admits them from it and the HTTP
    /// form allows it credentialed CORS. A host's interactive branch replaces
    /// only [`sign_in_page`](Self::sign_in_page), never this.
    pub ceremony_page: Option<url::Url>,
    /// The signing key of the account pages' web client this process
    /// serves itself (see [`CeHost::served_account`]); none without them.
    pub account_client_key: Option<sid_authn::client_key::ClientKey>,
    /// The one authorization evaluator of this process.
    pub authz_engine: Arc<sid_authz::CeAuthzEngine<dyn sid_plugin::StorageBackend>>,
    /// The installation's organization.
    pub organization: sid_core::models::Organization,
    /// The registered connections federated sign-ins arrive through.
    pub entry_connections: Arc<sid::entry_connections::EntryConnections>,
    /// Accepts the Binding Passport and presentation of an identity signed
    /// in through a connection: the classical recipient over the
    /// installation's store, or, set by the host before serving, the one
    /// with the signature checks its edition adds.
    pub identities: Arc<dyn sid_fed::recipient::PresentedIdentities>,
    /// Pages of the host composition at each issuer that a federated entry
    /// may return to, besides an application's authorization: none in CE,
    /// set by the host before serving.
    pub entry_continuations: Vec<crate::grpc::federated_entry_service::HostContinuation>,
    /// Emails requested sign-in links, when magic links are enabled.
    pub magic_link_mail: Option<Arc<sid::auth_mail::MagicLinkMail>>,
    /// Emails requested sign-in codes.
    pub code_mail: Arc<sid::auth_mail::CodeMail>,
    /// Emails requested password reset links, when an account UI opens them.
    pub reset_mail: Option<Arc<sid::auth_mail::ResetMail>>,
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
    /// The installation's public UI settings, in memory: what the pages
    /// follow before anyone signs in.
    pub public_settings: Arc<sid::public_settings::PublicSettings>,
    pub security_svc: Arc<crate::grpc::security_service::SecurityServiceImpl>,
    pub account_svc: Arc<crate::grpc::account_service::AccountServiceImpl>,
    pub upstream_svc: Arc<crate::grpc::upstream_service::UpstreamServiceImpl>,
}

/// The WebAuthn relying party: the ID (`SID_RP_ID`) and origin
/// (`SID_RP_ORIGIN`) given, each defaulting to the `issuer`'s host and
/// origin. An issuer with no host, or a given origin that is not a URL, is a
/// configuration error.
pub fn webauthn_relying_party(
    issuer: &Url,
    rp_id: Option<String>,
    rp_origin: Option<String>,
) -> anyhow::Result<(String, Url)> {
    let rp_id = match rp_id {
        Some(id) => id,
        None => issuer
            .host_str()
            .context("SID_ISSUER has no host to serve as the WebAuthn relying party")?
            .to_owned(),
    };
    let origin = match rp_origin {
        Some(origin) => Url::parse(&origin).context("SID_RP_ORIGIN is not a URL")?,
        None => Url::parse(&issuer.origin().ascii_serialization())
            .context("SID_ISSUER has no origin to serve as the WebAuthn relying party")?,
    };
    Ok((rp_id, origin))
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

/// The mail of requested sign-in links when `links` are enabled. A link
/// opens the verification page of the account pages emailed links open
/// (`mailed`), so enabling them without those is a configuration error:
/// requested links would be owed a mail that can never name a page.
pub fn magic_link_mail(
    links: Option<&Arc<MagicLinkService>>,
    mailed: Option<&sid_authn::system_integration::AccountPages>,
    storage: &Arc<dyn StorageBackend>,
    keys: &Arc<dyn sid_keys::KeyManager>,
) -> anyhow::Result<Option<Arc<sid::auth_mail::MagicLinkMail>>> {
    let Some(links) = links else {
        return Ok(None);
    };
    let Some(mailed) = mailed else {
        anyhow::bail!(
            "SID_MAGIC_LINKS_ENABLED needs account pages that open the links, served beside \
             the account cabinet: set SID_ACCOUNT_URL"
        );
    };
    Ok(Some(Arc::new(sid::auth_mail::MagicLinkMail::new(
        links.clone(),
        mailed.magic_link_page(),
        stored_mail(storage, keys),
    ))))
}

/// The standard authentication mail, sent through the installation's stored
/// email provider.
pub fn stored_mail(
    storage: &Arc<dyn StorageBackend>,
    keys: &Arc<dyn sid_keys::KeyManager>,
) -> Arc<dyn sid::auth_mail::AuthMailDelivery> {
    Arc::new(crate::auth_mail::stored_mail(storage.clone(), keys.clone()))
}

/// Password resets and the mail of their links, when account pages served
/// beside the account cabinet (`mailed`) open the page a link opens; without
/// them none is started: a reset could never be completed, or would let a
/// public page change an account managed by a closed host.
pub fn password_resets(
    mailed: Option<&sid_authn::system_integration::AccountPages>,
    storage: &Arc<dyn StorageBackend>,
    keys: &Arc<dyn sid_keys::KeyManager>,
) -> Option<(
    Arc<sid_authn::password_reset::PasswordResetService>,
    Arc<sid::auth_mail::ResetMail>,
)> {
    let mailed = mailed?;
    let resets = Arc::new(sid_authn::password_reset::PasswordResetService::new(
        storage.clone(),
        keys.clone(),
    ));
    let mail = Arc::new(sid::auth_mail::ResetMail::new(
        resets.clone(),
        mailed.password_reset_page(),
        stored_mail(storage, keys),
    ));
    Some((resets, mail))
}

/// The sign-in page the authorization endpoint sends a user who must sign in
/// to: the sign-in route of the account UI the deployment serves, `None`
/// without one (the client then gets `login_required`). A host serving
/// another interactive branch for its issuer replaces it on the components.
/// An account UI on another site than the issuer host `issuer` is a
/// configuration error: its ceremonies set the IdP session cookie on that
/// host, which a response to a cross-site request cannot do.
pub fn sign_in_page(
    pages: Option<&sid_authn::system_integration::AccountPages>,
    issuer: &str,
) -> anyhow::Result<Option<url::Url>> {
    let Some(pages) = pages else {
        return Ok(None);
    };
    let page = pages.sign_in_page();
    let issuer_url =
        url::Url::parse(issuer).with_context(|| format!("SID_ISSUER {issuer:?} is not a URL"))?;
    if !sid_authn::browser_session::same_site(&page, &issuer_url) {
        anyhow::bail!(
            "the account UI's sign-in page {page} is not on the same site as SID_ISSUER \
             {issuer:?}: it must share the issuer's scheme and registrable domain"
        );
    }
    Ok(Some(page))
}

/// Where the composition serves its account cabinet client: the UI host
/// signing users into account management as the installation's account web
/// client.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AccountClient {
    /// Beside the account pages: `SID_ACCOUNT_URL` and
    /// `SID_ACCOUNT_CLIENT_JWKS` go together, and the pages also open the
    /// emailed sign-in and password reset links.
    #[default]
    Delivered,
    /// Apart from the pages, by a closed host at `SID_ACCOUNT_CLIENT_URL`:
    /// that URL and `SID_ACCOUNT_CLIENT_JWKS` go together, and
    /// `SID_ACCOUNT_URL` alone names the shared ceremony pages. The public
    /// pages open no emailed link: a mailed reset or sign-in link would let a
    /// public page change an account whose management is the closed host's.
    Apart,
}

/// What the account settings configure: the shared account pages, where the
/// account cabinet client is served, and the pages emailed links open.
#[derive(Debug, Clone, Default)]
pub struct Account {
    /// The pages the issuer sends users who must sign in to.
    pub pages: Option<sid_authn::system_integration::AccountPages>,
    /// The account cabinet client's integration, where one is delivered.
    pub integration: Option<sid_authn::system_integration::AccountSettings>,
    /// The pages emailed sign-in and password reset links open: only those
    /// served beside the account cabinet.
    pub mailed: Option<sid_authn::system_integration::AccountPages>,
}

/// The account configuration from `SID_ACCOUNT_URL` (the account pages'
/// public URL, with their mount), `SID_ACCOUNT_CLIENT_URL` (where a closed
/// host serves the account cabinet client, under that URL's path) and
/// `SID_ACCOUNT_CLIENT_JWKS` (a file holding that client's UI host's public
/// JWK Set), as `client` says the composition serves its cabinet. Nothing set
/// means no account UI; a combination the composition does not serve is a
/// configuration error. An unreadable key file or an invalid value is a
/// configuration error, never an integration with invented settings.
pub fn account_settings(
    url: Option<&str>,
    client_url: Option<&str>,
    jwks_file: Option<&str>,
    client: AccountClient,
) -> anyhow::Result<Account> {
    let some = |value: Option<&str>| value.filter(|v| !v.is_empty()).map(str::to_owned);
    let (url, client_url, jwks_file) = (some(url), some(client_url), some(jwks_file));
    let keys = |file: &str| -> anyhow::Result<sid_core::models::ClientKeySet> {
        let text = std::fs::read_to_string(file)
            .with_context(|| format!("SID_ACCOUNT_CLIENT_JWKS {file:?} cannot be read"))?;
        sid_core::models::ClientKeySet::from_json(&text)
            .map_err(|e| anyhow::anyhow!("SID_ACCOUNT_CLIENT_JWKS {file:?}: {e}"))
    };
    match (client, url, client_url, jwks_file) {
        (_, None, None, None) => Ok(Account::default()),
        (AccountClient::Delivered, _, Some(_), _) => anyhow::bail!(
            "SID_ACCOUNT_CLIENT_URL is set, but this composition serves its account cabinet \
             beside the pages of SID_ACCOUNT_URL"
        ),
        (AccountClient::Delivered, Some(url), None, Some(file)) => {
            let integration =
                sid_authn::system_integration::AccountSettings::new(&url, keys(&file)?)
                    .map_err(|e| anyhow::anyhow!("SID_ACCOUNT_URL: {e}"))?;
            Ok(Account {
                pages: Some(integration.pages().clone()),
                mailed: Some(integration.pages().clone()),
                integration: Some(integration),
            })
        }
        (AccountClient::Delivered, _, None, _) => anyhow::bail!(
            "SID_ACCOUNT_URL and SID_ACCOUNT_CLIENT_JWKS are set together: the account \
             integration needs its URL and its UI host's public keys"
        ),
        (AccountClient::Apart, Some(url), None, None) => Ok(Account {
            pages: Some(
                sid_authn::system_integration::AccountPages::new(&url)
                    .map_err(|e| anyhow::anyhow!("SID_ACCOUNT_URL: {e}"))?,
            ),
            integration: None,
            mailed: None,
        }),
        (AccountClient::Apart, Some(url), Some(client_url), Some(file)) => {
            let integration = sid_authn::system_integration::AccountSettings::apart(
                &url,
                &client_url,
                keys(&file)?,
            )
            .map_err(|e| anyhow::anyhow!("SID_ACCOUNT_URL / SID_ACCOUNT_CLIENT_URL: {e}"))?;
            Ok(Account {
                pages: Some(integration.pages().clone()),
                integration: Some(integration),
                mailed: None,
            })
        }
        (AccountClient::Apart, _, _, _) => anyhow::bail!(
            "SID_ACCOUNT_URL names the shared pages; SID_ACCOUNT_CLIENT_URL and \
             SID_ACCOUNT_CLIENT_JWKS, set together beside it, name the account cabinet \
             client its closed host serves"
        ),
    }
}

/// The setting `name` as `read` from the environment: unset is `None`, a
/// value that is no text stops the start like any other invalid value,
/// never read as unset.
pub(crate) fn setting(
    name: &str,
    read: Result<String, std::env::VarError>,
) -> anyhow::Result<Option<String>> {
    match read {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} is not valid Unicode"),
    }
}

/// The environment setting `name`, as [`setting`] reads it.
pub fn env_setting(name: &str) -> anyhow::Result<Option<String>> {
    setting(name, std::env::var(name))
}

/// The installation's management from `SID_INSTALLATION_MANAGEMENT`:
/// `central` or `self`; unset keeps whatever is recorded. Any other value
/// stops the start.
pub(crate) fn management_setting(setting: Option<&str>) -> anyhow::Result<Option<sid::Management>> {
    match setting {
        Some("central") => Ok(Some(sid::Management::Central)),
        Some("self") => Ok(Some(sid::Management::SelfManaged)),
        None => Ok(None),
        Some(other) => {
            anyhow::bail!("SID_INSTALLATION_MANAGEMENT {other:?}: expected `central` or `self`")
        }
    }
}

/// What a host binary supplies to the CE components it composes.
#[derive(Default)]
pub struct CeHost {
    /// Where the login requirements come from; none keeps the installation's
    /// fixed security policy.
    pub login_policy: Option<Arc<dyn sid_authn::login_policy::LoginPolicySource>>,
    /// Makes the proofs of this installation's own Profiles for sign-ins at
    /// other organizations; none issues the Binding subject without a proof.
    pub own_presentations: Option<Arc<dyn sid::oauth::OwnPresentations>>,
    /// Whether this composition delivers an account cabinet client.
    pub account_client: AccountClient,
    /// The account settings the host itself provides; none reads them from
    /// the environment.
    pub account: Option<Account>,
    /// The URL (with its mount) of account pages this process serves itself:
    /// their web client is provisioned with the installation's own key,
    /// shared by every replica, in place of any other account settings.
    pub served_account: Option<String>,
}

/// The store an installation runs over.
struct OpenedStore {
    storage: Arc<dyn StorageBackend>,
    audit_log: Arc<dyn sid_plugin::audit::AuditLog>,
    /// The history evaluator's own store over the same database, for a
    /// standalone installation that runs the evaluator in process; its
    /// tables are created only when it does.
    local_history_keys: LocalHistoryKeys,
    /// The SQLite file this process serves, if any: every server on it holds
    /// its bus lock (see `hold_database`).
    sqlite_file: Option<std::path::PathBuf>,
}

/// The PostgreSQL database the storage settings name, migrated.
#[cfg(feature = "storage-pg")]
async fn open_store() -> anyhow::Result<OpenedStore> {
    let database_url = env_setting("SID_DATABASE_URL")?.context("SID_DATABASE_URL must be set")?;
    let schema = env_setting("SID_STORAGE_POSTGRESQL_SCHEMA")?;
    if let Some(ref s) = schema {
        info!(
            "Schema isolation enabled: tables will be created in schema '{}'",
            s
        );
    }
    let max_connections = env_setting("SID_DATABASE_MAX_CONNECTIONS")?
        .map(|n| {
            n.parse::<u32>()
                .context("SID_DATABASE_MAX_CONNECTIONS must be a whole number")
        })
        .transpose()?;
    let backend =
        sid_storage::PostgresBackend::connect(&database_url, schema.clone(), max_connections)
            .await
            .context("connect to the database")?;

    let audit_log: Arc<dyn sid_plugin::audit::AuditLog> = Arc::new(
        sid_storage::audit_log::PostgresAuditLog::new(backend.pool().clone()),
    );

    // A refused migration changed nothing; its reason is the error's cause.
    sid_storage::migrator::run_migrations(backend.pool(), schema.as_deref())
        .await
        .context("database migrations")?;

    let local_history_keys =
        LocalHistoryKeys::Postgres(sid_storage::PgHistoryKeyStore::new(backend.pool().clone()));
    Ok(OpenedStore {
        storage: Arc::new(backend),
        audit_log,
        local_history_keys,
        sqlite_file: None,
    })
}

/// The SQLite file the storage setting names, migrated.
#[cfg(all(feature = "embedded-dev", not(feature = "storage-pg")))]
async fn open_store() -> anyhow::Result<OpenedStore> {
    let sqlite_setting = env_setting("SID_STORAGE_SQLITE_PATH")?
        .unwrap_or_else(|| "/var/lib/sid/auth.db".to_string());
    let backend = sid_storage::sqlite::SqliteBackend::new(&sqlite_setting)
        .await
        .context("SQLite storage and its migrations")?;
    let audit_log: Arc<dyn sid_plugin::audit::AuditLog> = Arc::new(
        sid_storage::sqlite::SqliteAuditLog::new(backend.writer().clone()),
    );
    let local_history_keys = LocalHistoryKeys::Sqlite(backend.history_keys());
    let sqlite_file = Some(
        sid_storage::sqlite::SqliteBackend::database_file(&sqlite_setting)
            .context("the SQLite file")?,
    );
    Ok(OpenedStore {
        storage: Arc::new(backend),
        audit_log,
        local_history_keys,
        sqlite_file,
    })
}

/// Initialize all CE components: storage, crypto, auth, and gRPC services.
///
/// Does NOT start the server — caller assembles the tonic server and serves.
pub async fn init_ce() -> anyhow::Result<CeComponents> {
    init_ce_with(CeHost::default()).await
}

/// Initialize the CE components with what `host` supplies.
pub async fn init_ce_with(host: CeHost) -> anyhow::Result<CeComponents> {
    let grpc_addr: SocketAddr = env_setting("SID_GRPC_BIND")?
        .unwrap_or_else(|| "127.0.0.1:50051".to_string())
        .parse()?;

    // ── Storage backend ──

    refuse_renamed_setting(env_setting("SID_SQLITE_PATH")?.as_deref())?;

    let OpenedStore {
        storage,
        audit_log,
        local_history_keys,
        sqlite_file,
    } = open_store().await?;

    // ── JWT keys ──
    let data_dir = env_setting("SID_DATA_DIR")?.unwrap_or_else(|| "/var/lib/sid".into());
    let jwt_private_key_path = env_setting("SID_JWT_PRIVATE_KEY_PATH")?
        .unwrap_or_else(|| format!("{}/jwt_private.pem", data_dir));
    let jwt_public_key_path = env_setting("SID_JWT_PUBLIC_KEY_PATH")?
        .unwrap_or_else(|| format!("{}/jwt_public.pem", data_dir));
    // No default: the issuer names every token and the installation's
    // organization domain, so a guessed one would be wrong everywhere.
    let issuer = env_setting("SID_ISSUER")?
        .filter(|issuer| !issuer.is_empty())
        .context("SID_ISSUER is required")?;
    let issuer_base = Url::parse(&issuer).context("SID_ISSUER is not a URL")?;

    if ensure_jwt_key_pair(&jwt_private_key_path, &jwt_public_key_path)? {
        info!("Generated JWT key pair at '{}'", data_dir);
        tracing::warn!("Set SID_JWT_PRIVATE_KEY_PATH for production use");
    }

    let private_pem = std::fs::read(&jwt_private_key_path)
        .unwrap_or_else(|_| panic!("Cannot read JWT private key: {}", jwt_private_key_path));
    let public_pem = std::fs::read(&jwt_public_key_path)
        .unwrap_or_else(|_| panic!("Cannot read JWT public key: {}", jwt_public_key_path));

    // A set but malformed or out-of-range lifetime stops startup rather than
    // silently falling back to a default.
    let access_token_ttl = match env_setting("SID_ACCESS_TOKEN_TTL_MINUTES")? {
        Some(v) => v
            .parse::<u32>()
            .map_err(|e| format!("SID_ACCESS_TOKEN_TTL_MINUTES: {e}"))
            .and_then(|m| {
                sid_authn::jwt::AccessTokenTtl::from_minutes(m)
                    .map_err(|e| format!("SID_ACCESS_TOKEN_TTL_MINUTES: {e}"))
            })
            .unwrap_or_else(|e| panic!("{e}")),
        None => sid_authn::jwt::AccessTokenTtl::default(),
    };
    let refresh_token_ttl_days: i64 = match env_setting("SID_REFRESH_TOKEN_TTL_DAYS")? {
        Some(v) => v
            .parse()
            .unwrap_or_else(|e| panic!("SID_REFRESH_TOKEN_TTL_DAYS: {e}")),
        None => 30,
    };
    let refresh_token_ttl = refresh_token_ttl_days
        .checked_mul(24)
        .and_then(jiff::SignedDuration::try_from_hours)
        .unwrap_or_else(|| {
            panic!("SID_REFRESH_TOKEN_TTL_DAYS: {refresh_token_ttl_days} days is out of range")
        });

    // ── Shared cache: one-time codes, replay and rate state ──
    let cache_backend: Arc<dyn CacheBackend> =
        sid_infra::shared_cache(sid_infra::cache_url_from_env().as_deref())
            .await
            .unwrap_or_else(|e| panic!("Shared cache: {e}"));

    // ── The installation: keys, organization, issuer and their resources ──
    // The master key lives outside the database; the key versions inside.
    let master_key_path =
        env_setting("SID_MASTER_KEY_FILE")?.unwrap_or_else(|| format!("{}/master.key", data_dir));
    let installation = sid::Installation::open(
        storage.clone(),
        sid::InstallationSettings {
            issuer: issuer_base.clone(),
            master_key: master_key_path.clone().into(),
            crypto: Arc::new(sid_crypto::AwsLcPrimitives::new()),
            cache: cache_backend.clone(),
            access_token_ttl,
            management: management_setting(env_setting("SID_INSTALLATION_MANAGEMENT")?.as_deref())?,
            sod_warnings: crate::config::installation_config(
                env_setting("SID_CONFIG_FILE")?.as_deref(),
            )?
            .governance
            .sod_warnings,
        },
    )
    .await
    .context("installation")?;
    if let Some(token) = installation.admin_claim().await? {
        tracing::warn!(
            "No administrator yet. Register and enter this claim token to become the \
             first administrator: {}",
            secrecy::ExposeSecret::expose_secret(&token)
        );
    }
    let sid::Installation {
        key_manager,
        organization,
        issuer: local_issuer,
        authorization_api,
        enrollment_api,
        issuers,
        opaque_router,
        revocation_cache,
        captcha_pow_key,
        sod_warnings,
        revocation_listener,
        ..
    } = installation;

    // ── WebAuthn ──
    // The relying party is the host users reach the installation at: by
    // default the issuer's host and origin, set apart only where sign-in is
    // presented on another host than the issuer.
    let (rp_id, rp_origin_url) = webauthn_relying_party(
        &issuer_base,
        env_setting("SID_RP_ID")?,
        env_setting("SID_RP_ORIGIN")?,
    )?;
    let webauthn = Arc::new(WebAuthnServer::new(
        &rp_id,
        &rp_origin_url,
        storage.clone(),
        key_manager.clone(),
    )?);

    // ── ZKPP ──
    let zkpp_cache_dir = env_setting("SID_DATA_DIR")?.unwrap_or_else(|| ".sid-data".to_string());
    let (opaque_zkpp, zkpp_ready) = init_zkpp(&opaque_router, &zkpp_cache_dir);

    // ── Feature flags ──
    let feature_flags = init_feature_flags()?;

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
    // Account pages served in process sign in with the installation's own
    // client key, created once and read back by every replica.
    let account_client_key = match &host.served_account {
        Some(_) => Some(
            sid_authn::client_key::ClientKey::installation_ed25519(
                storage.as_ref(),
                key_manager.as_ref(),
                sid_core::models::InstanceSecret::AccountClientKey,
            )
            .await
            .context("account client key")?,
        ),
        None => None,
    };
    let served = match (&host.served_account, &account_client_key) {
        (Some(url), Some(key)) => {
            let jwks = key
                .public_jwks()
                .context("the account client key has no public half")?;
            let keys = sid_core::models::ClientKeySet::from_json(&jwks.to_string())
                .map_err(|e| anyhow::anyhow!("account client key: {e}"))?;
            let integration = sid_authn::system_integration::AccountSettings::new(url, keys)
                .map_err(|e| anyhow::anyhow!("account pages {url}: {e}"))?;
            Some(Account {
                pages: Some(integration.pages().clone()),
                mailed: Some(integration.pages().clone()),
                integration: Some(integration),
            })
        }
        _ => None,
    };
    let Account {
        pages: account_pages,
        integration: account,
        mailed: mailed_pages,
    } = match served.or(host.account) {
        Some(account) => account,
        None => account_settings(
            env_setting("SID_ACCOUNT_URL")?.as_deref(),
            env_setting("SID_ACCOUNT_CLIENT_URL")?.as_deref(),
            env_setting("SID_ACCOUNT_CLIENT_JWKS")?.as_deref(),
            host.account_client,
        )?,
    };
    if let Some(account) = &account {
        let integration = sid_authn::system_integration::ensure_account_integration(
            storage.as_ref(),
            &local_issuer,
            &issuer,
            account,
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
    let oauth2 = Arc::new(OAuth2Server::new(jwt.clone()).with_refresh_token_ttl(refresh_token_ttl));

    let app_state = AppState {
        storage: storage.clone(),
        oauth2: oauth2.clone(),
        webauthn: webauthn.clone(),
        jwt: jwt.clone(),
        opaque_router: opaque_router.clone(),
        opaque_zkpp: opaque_zkpp.clone(),
        revocation_cache: revocation_cache.clone(),
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
        env_setting("SID_MAGIC_LINKS_ENABLED")?.as_deref(),
        &sid_core::models::SecurityPolicy::ce_default(),
    )?
    .then(|| Arc::new(MagicLinkService::new(storage.clone(), key_manager.clone())));
    let magic_link_mail = magic_link_mail(
        magic_link.as_ref(),
        mailed_pages.as_ref(),
        &storage,
        &key_manager,
    )?;

    // Under the data directory by default: the installation's volume keeps
    // prepared exports across restarts, which a temporary directory does not.
    let export_dir =
        env_setting("SID_EXPORT_DIR")?.unwrap_or_else(|| format!("{data_dir}/exports"));
    let data_export = Arc::new(DataExportService::new(storage.clone(), export_dir));

    // Event bus: SID_NATS_URL unset / `embedded` bundles nats-server with
    // JetStream under the data directory, a nats:// or tls:// URL connects to
    // an external cluster, `in-process` runs without a broker. The in-process
    // bus is never a fallback: a bus that cannot start stops startup, and
    // committed work waits in the database.
    let nats_setting = env_setting("SID_NATS_URL")?;
    let nats_mode = crate::embedded_nats::EventBusMode::from_setting(nats_setting.as_deref())?;
    // This server is the installation's bootstrap, so it owns the event
    // topology unless the deployment names another owner.
    let crate::embedded_nats::ConnectedBus {
        bus: event_bus,
        embedded: embedded_nats,
    } = crate::embedded_nats::connect_event_bus(
        &nats_mode,
        std::path::Path::new(&data_dir),
        sid_infra::Topology::from_env()?,
        sid_infra::TopologyRole::from_env(sid_infra::TopologyRole::Own)?,
    )
    .await?;
    // Without a broker, replicas sharing PostgreSQL claim committed work from
    // that database under fenced leases; the in-process bus only wakes their
    // workers and feeds this process's live views, which may miss facts
    // another replica handled. A SQLite file serves one engine process, so
    // the in-process bus locks it. Either way it takes over no addressed work
    // it could never hand on.
    let in_process = nats_mode == crate::embedded_nats::EventBusMode::InProcess;
    // The file lock comes first, so no process on another bus can address
    // work between the check and the lock.
    let database_lock = match sqlite_file.as_deref() {
        Some(database) => Some(Arc::new(hold_database(database, in_process)?)),
        None => None,
    };
    if in_process {
        refuse_addressed_history(storage.as_ref()).await?;
    }
    let required_receivers =
        required_receivers(&nats_mode, env_setting("SID_EVENT_RECEIVERS")?.as_deref())?;

    let identity_svc = Arc::new(IdentityServiceImpl::new(
        storage.clone(),
        jwt.clone(),
        revocation_cache.clone(),
        feature_flags.clone(),
        cascade_service.clone(),
        closure_service.clone(),
        data_export,
    ));

    let otp_service = Arc::new(OtpService::new(
        storage.clone(),
        sid_authn::otp::CodeDelivery {
            keys: key_manager.clone(),
        },
    ));
    let code_mail = Arc::new(sid::auth_mail::CodeMail::new(
        otp_service.clone(),
        stored_mail(&storage, &key_manager),
    ));

    // ── IP Intelligence: configurable provider chain ──
    // SID_IPINTEL_PROVIDERS: comma-separated list of enabled providers.
    // Default: all providers enabled. Set to empty or "none" to disable all.
    // Valid values: tor, cloud, firehol, self_learned, allowlist
    // Air-gapped deployments: set to "self_learned,allowlist" (no external fetches).
    let enabled_providers: Vec<String> = env_setting("SID_IPINTEL_PROVIDERS")?
        .unwrap_or_else(|| "tor,cloud,firehol,self_learned,allowlist".to_string())
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && s != "none")
        .collect();

    let mut ip_intel_providers: Vec<Arc<dyn IpIntelligenceProvider>> = Vec::new();

    if enabled_providers.iter().any(|p| p == "tor") {
        let tor_provider = Arc::new(TorExitProvider::new(cache_backend.clone())?);
        ip_intel_providers.push(tor_provider);
        info!("IP intelligence: Tor exit provider enabled");
    }

    if enabled_providers.iter().any(|p| p == "cloud") {
        // Azure: optional, URL changes weekly. Configure via SID_IPINTEL_AZURE_URL.
        let cloud_provider = if let Some(azure_url) = env_setting("SID_IPINTEL_AZURE_URL")? {
            Arc::new(CloudRangeProvider::with_azure(
                cache_backend.clone(),
                azure_url,
            )?)
        } else {
            Arc::new(CloudRangeProvider::new(cache_backend.clone())?)
        };
        ip_intel_providers.push(cloud_provider);
        info!("IP intelligence: Cloud range provider enabled");
    }

    if enabled_providers.iter().any(|p| p == "firehol") {
        let firehol_provider = Arc::new(FireholProvider::new(cache_backend.clone())?);
        ip_intel_providers.push(firehol_provider);
        info!("IP intelligence: FireHOL provider enabled");
    }

    if enabled_providers.iter().any(|p| p == "self_learned") {
        let threshold: f32 = match env_setting("SID_IPINTEL_REPUTATION_THRESHOLD")? {
            None => 0.7,
            Some(v) => v
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
    let geoip = Arc::new(build_geoip_chain_from_env(cache_backend.clone())?);

    // A provider that was asked for and cannot run stops startup.
    let captcha_provider = sid_authn::captcha::build_captcha_provider_from_env(&captcha_pow_key)
        .map_err(|e| anyhow::anyhow!("CAPTCHA: {e}"))?;

    // One authorization evaluator for every service of this process.
    let authz_engine = Arc::new(sid_authz::CeAuthzEngine::new(storage.clone()));

    let ceremony_page = sign_in_page(account_pages.as_ref(), &issuer)?;
    // Named after the installation's issuer, which shares its host with other
    // issuers: never configured, so a rebuilt installation's issuer names its
    // own.
    let browser_cookie =
        sid_authn::browser_session::BrowserCookie::for_issuer(&local_issuer.handle);

    let history_authority = password_history_authority(
        |name| std::env::var(name),
        storage.as_ref(),
        || local_history_keys.open(),
        std::path::Path::new(&master_key_path),
    )
    .await
    .context("password history configuration")?;
    bus_carries_history_evaluator(
        &nats_mode,
        matches!(
            history_authority,
            sid_authn::password_operation::PasswordHistoryAuthority::Remote(_)
        ),
    )?;
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
    .with_browser_cookie(browser_cookie);
    let auth_svc = match host.login_policy {
        Some(source) => auth_svc.with_login_policy(source),
        None => auth_svc,
    };
    let auth_svc = match host.own_presentations {
        Some(presentations) => auth_svc.with_own_presentations(presentations),
        None => auth_svc,
    };
    // The recipient side verifies what other installations present, and
    // the admissions their sites were registered on as clients here.
    let recipient = classical_recipient(storage.clone())?;
    hold_build_platform_cas(&recipient).await?;
    let identities: Arc<dyn sid_fed::recipient::PresentedIdentities> = Arc::new(recipient);
    let auth_svc = auth_svc.with_site_evidence(identities.clone());
    let auth_svc = match &ceremony_page {
        Some(page) => auth_svc.with_sign_in_page(page),
        None => auth_svc,
    };
    let resets = password_resets(mailed_pages.as_ref(), &storage, &key_manager);
    // What the pages follow before anyone signs in: read once here, then
    // kept current by the policy's own commits and a periodic read.
    let public_settings = sid::public_settings::PublicSettings::open(
        storage.clone(),
        sid::public_settings::Served {
            password_reset: resets.is_some(),
        },
    )
    .await
    .context("the installation's public UI settings")?;
    tokio::spawn(sid::public_settings::follow_while_held(
        Arc::downgrade(&public_settings),
        sid::public_settings::DEFAULT_FOLLOW_INTERVAL,
    ));
    let (auth_svc, reset_mail) = match resets {
        Some((resets, mail)) => (auth_svc.with_password_resets(resets), Some(mail)),
        None => (auth_svc, None),
    };
    let auth_svc = Arc::new(auth_svc);
    // Sign-in through upstream providers completes as the other ceremonies
    // do: the same sign-in page, cookie, security rules and session policy.
    let upstream_svc = Arc::new(crate::grpc::upstream_service::UpstreamServiceImpl::new(
        storage.clone(),
        key_manager.clone(),
        jwt.clone(),
        revocation_cache.clone(),
        auth_svc.clone(),
    ));

    // Platform sign-in goes through the registration at the platform this
    // build was made for, never another environment's.
    let build_platform =
        sid_infra::platform_ca::build_platform().context("the build's platform")?;
    let entry_connections = Arc::new(sid::entry_connections::EntryConnections::new(
        storage.clone(),
        key_manager.clone(),
        issuers.clone(),
        sid::entry_connections::PlatformScope::new(
            build_platform.as_ref(),
            &sid_infra::platform_ca::PLATFORMS,
        ),
    ));

    let project_svc = Arc::new(ProjectServiceImpl::new(
        storage.clone(),
        feature_flags.clone(),
        jwt.clone(),
        revocation_cache.clone(),
        local_issuer.clone(),
        Some(sid::projects::SiteRegistrar {
            identities: identities.clone(),
            keys: key_manager.clone(),
            base: issuer_base.clone(),
        }),
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
    let request_verifiers = match env_setting("SID_AUTHZ_REQUEST_VERIFIERS_FILE")? {
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read SID_AUTHZ_REQUEST_VERIFIERS_FILE {path}"))?;
            sid_authz::request_verifier::RequestVerifiers::from_json(&text)
                .with_context(|| format!("SID_AUTHZ_REQUEST_VERIFIERS_FILE {path}"))?
        }
        None => Default::default(),
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
        .with_service_tokens(checker_tokens, organization.id)
        .with_request_verifiers(request_verifiers)
        .with_sod_warnings(sod_warnings),
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
    // Invite-issuing services authenticate with their own tokens for the
    // enrollment API.
    let invite_services = crate::grpc::enrollment_service::InviteServices {
        engine: authz_engine.clone(),
        tokens: Arc::new(
            sid_authn::resource_token::ResourceTokenVerifier::new(
                issuers.clone(),
                local_issuer.clone(),
                enrollment_api.indicator.clone(),
            )
            .await
            .context("enrollment API token verifier")?,
        ),
        resource: enrollment_api.id,
    };
    let enrollment_svc = Arc::new(
        crate::grpc::enrollment_service::EnrollmentServiceImpl::new(
            storage.clone(),
            jwt.clone(),
            revocation_cache.clone(),
        )
        .with_invite_services(invite_services)
        .projected_to(public_settings.clone()),
    );
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

    let audit_retention = audit_retention_from_lookup(env_setting)?;
    let migration_deadline_days = match env_setting("SID_MIGRATION_DEADLINE_DAYS")? {
        Some(v) => v
            .parse()
            .with_context(|| format!("SID_MIGRATION_DEADLINE_DAYS {v:?}"))?,
        None => sid::maintenance::DEFAULT_MIGRATION_DEADLINE_DAYS,
    };

    let web_settings = Arc::new(sid::web_settings::WebSettingsAdmin::new(
        storage.clone(),
        &issuer_base,
    ));

    Ok(CeComponents {
        magic_link_mail,
        code_mail,
        reset_mail,
        audit_retention,
        migration_deadline_days,
        issuers,
        sign_in_page: Arc::new(ceremony_page.clone()),
        ceremony_page,
        account_client_key,
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
        zkpp_ready,
        revocation_cache,
        revocation_listener: Arc::new(revocation_listener),
        feature_flags,
        event_bus,
        embedded_nats: embedded_nats.map(Arc::new),
        database_lock,
        required_receivers,
        cache_backend,
        app_state,
        web_settings,
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
        public_settings,
        security_svc,
        account_svc,
        upstream_svc,
        entry_connections,
        identities,
        entry_continuations: Vec::new(),
    })
}

/// `recipient` refreshing its platform CA set from the publication of the
/// platform this build was made for. The platform is a constant of the
/// build, never a setting of the installation: an operator does not choose
/// whose certificates it trusts. The publication is only the quick way to a
/// newer set between two builds: what the installation already holds keeps
/// deciding without it, and a build made for no platform asks nobody. The
/// platform's discovery records are read beside the publication; without a
/// usable resolver the HTTPS step alone refreshes.
pub fn of_build_platform<V: sid_fed::recipient::Verdict>(
    recipient: sid_fed::recipient::Recipient<V>,
) -> anyhow::Result<sid_fed::recipient::Recipient<V>> {
    use sid_infra::platform_ca::PublishedPlatformCas;
    use sid_infra::platform_ca::discovery::DiscoveryResolver;
    let Some(publication) =
        sid_infra::platform_ca::build_publication().context("the build's platform")?
    else {
        info!("this build names no platform: its platform CA set is refreshed from nowhere");
        return Ok(recipient);
    };
    let mut source = PublishedPlatformCas::new();
    match DiscoveryResolver::new() {
        Ok(discovery) => source = source.with_discovery(Arc::new(discovery)),
        Err(reason) => tracing::warn!(
            %reason,
            "no DNS resolver for the platform CA discovery records; the HTTPS publication alone refreshes the set"
        ),
    }
    info!(%publication, "platform CA publication");
    recipient
        .with_source(publication, Arc::new(source))
        .map_err(|e| anyhow::anyhow!("the build's platform CA publication: {e}"))
}

/// Hold the platform CA set this build carries, so the installation
/// verifies under its platform's certificates from the first start with no
/// network. It is applied as any received set is: one older than the set
/// already held changes nothing, and a generation a newer held set withdrew
/// stays withdrawn. A carried set that cannot be held stops the start: the
/// delivery is broken, and serving without it would refuse every identity
/// without saying why.
pub async fn hold_build_platform_cas<V: sid_fed::recipient::Verdict>(
    recipient: &sid_fed::recipient::Recipient<V>,
) -> anyhow::Result<()> {
    let Some(set) =
        sid_infra::platform_ca::build_platform_cas().context("the build's platform CA set")?
    else {
        info!("this build carries no platform CA set");
        return Ok(());
    };
    let applied = recipient
        .record_platform_cas(&set)
        .await
        .map_err(|e| anyhow::anyhow!("hold the build's platform CA set: {e}"))?;
    info!(
        revision = set.revision,
        ?applied,
        "the build's platform CA set"
    );
    Ok(())
}

/// The recipient a self-managed installation verifies presented identities
/// with: classical signature checks, under the platform CA set held in
/// `storage`.
pub fn classical_recipient(
    storage: Arc<dyn StorageBackend>,
) -> anyhow::Result<sid_fed::recipient::Recipient> {
    // An organization's list missing or past its time is read where the
    // installation is connected to that organization.
    let publications =
        Arc::new(crate::organization_publications::ConnectedPublications::new(storage.clone()));
    of_build_platform(
        sid_fed::recipient::Recipient::new(storage, sid_fed::recipient::ClassicalVerdict)
            .with_organization_publications(publications),
    )
}

/// Make the installation's JWT key pair if neither file exists; `true` when
/// it was made. A pair found whole is kept. Half a pair (one file without
/// the other) is refused before anything is written: generating the
/// missing half would pair it with an unrelated key.
pub(crate) fn ensure_jwt_key_pair(private_path: &str, public_path: &str) -> anyhow::Result<bool> {
    let private = std::path::Path::new(private_path).exists();
    let public = std::path::Path::new(public_path).exists();
    match (private, public) {
        (true, true) => Ok(false),
        (false, false) => {
            tracing::warn!(
                "JWT keys not found at '{private_path}': generating an Ed25519 key pair for development"
            );
            for path in [private_path, public_path] {
                if let Some(dir) = std::path::Path::new(path).parent() {
                    std::fs::create_dir_all(dir)
                        .with_context(|| format!("create key directory {}", dir.display()))?;
                }
            }
            let (private_pem, public_pem) =
                sid_authn::jwt::generate_signing_key_pem().context("generate the JWT key pair")?;
            write_new_key_file(private_path, private_pem.as_bytes(), true)?;
            write_new_key_file(public_path, public_pem.as_bytes(), false)?;
            Ok(true)
        }
        _ => anyhow::bail!(
            "half a JWT key pair: {private_path} {} but {public_path} {}; restore both files, or remove the remaining one to generate a new pair",
            if private { "exists" } else { "is missing" },
            if public { "exists" } else { "is missing" },
        ),
    }
}

/// Write a generated key to a new file at `path`, never over an existing
/// one. A private key is readable by its owner only, so another account on
/// the host cannot read it.
pub(crate) fn write_new_key_file(path: &str, contents: &[u8], private: bool) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .with_context(|| format!("create key file {path}"))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("write key file {path}"))
}

/// The work and maintenance engine of these components: the CE work the
/// engine assembles ([`sid::work::CeWork`]) over this server's parts and
/// mail delivery. Facts are owed to the deployment's required receivers and
/// to `also_required` (receivers this server runs). Every replica runs one;
/// leases keep an attempt on a single replica, job locks a maintenance run on
/// one instance.
pub fn engine(
    c: &CeComponents,
    also_required: &[sid_core::models::RequiredReceiver],
) -> anyhow::Result<sid::Engine> {
    let sid::work::CeWork {
        handlers,
        maintenance,
    } = sid::work::CeWork::assemble(sid::work::CeWorkParts {
        storage: c.storage.clone(),
        organization: c.organization.id,
        issuers: c.issuers.clone(),
        revocation: c.revocation_cache.clone(),
        event_bus: c.event_bus.clone(),
        required_receivers: c
            .required_receivers
            .iter()
            .chain(also_required)
            .cloned()
            .collect(),
        history_evaluation: c.auth_svc.history_evaluation(),
        issuer: c.issuer.clone(),
        closures: c.closure_service.clone(),
        mail: Some(sid::work::CeMail {
            codes: c.code_mail.clone(),
            magic_links: c.magic_link_mail.clone(),
            resets: c.reset_mail.clone(),
        }),
        site_admissions: Some(Arc::new(sid::federation_site::AdmissionPublications::new(
            Arc::new(sid::federation_site::FederationSite::new(
                c.storage.clone(),
                c.key_manager.clone(),
                c.identities.clone(),
                c.organization.id,
            )),
            build_platform_admissions()?,
        ))),
        audit_retention: c.audit_retention,
        migration_deadline_days: c.migration_deadline_days,
        source: "sid-server".into(),
    })?;
    sid::Engine::new(sid::EngineParts {
        storage: c.storage.clone(),
        worker: format!("sid-server-{}-{}", std::process::id(), uuid::Uuid::now_v7()),
        handlers,
        runner: RunnerConfig::default(),
        maintenance,
    })
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// The transport of the site's admission statements to the platform this
/// build was made for; none for a build made for no platform.
fn build_platform_admissions()
-> anyhow::Result<Option<Arc<dyn sid_plugin::site_admission::AdmissionPublisher>>> {
    Ok(
        sid_infra::platform_ca::site_admission::PlatformAdmissions::of_build()
            .context("the build's platform")?
            .map(|platform| {
                Arc::new(platform) as Arc<dyn sid_plugin::site_admission::AdmissionPublisher>
            }),
    )
}

/// The receivers `SID_EVENT_RECEIVERS` names (comma-separated; `none` for a
/// deployment without any), each owed every fact: its own routing decides
/// what it acts on. On the bundled bus (the single-binary installation, which
/// runs no separate receiver) unset names none; on an external bus the
/// deployment must name them, so a missing setting is not read as "none".
/// The in-process bus keeps no addressed work, so it takes none: a named
/// receiver would be owed facts nothing could hand over.
pub(crate) fn required_receivers(
    mode: &crate::embedded_nats::EventBusMode,
    setting: Option<&str>,
) -> anyhow::Result<Vec<sid_core::models::RequiredReceiver>> {
    use crate::embedded_nats::EventBusMode;
    let receivers = match (setting.map(str::trim), mode) {
        (None | Some(""), EventBusMode::Embedded | EventBusMode::InProcess) => Vec::new(),
        (None | Some(""), EventBusMode::External(_)) => anyhow::bail!(
            "SID_EVENT_RECEIVERS is required with an external bus: name the receivers (e.g. sid-notify) or `none`"
        ),
        (Some(list), _) => sid_core::models::RequiredReceiver::parse_list(list)
            .map_err(|e| anyhow::anyhow!("SID_EVENT_RECEIVERS: {e}"))?,
    };
    if *mode == EventBusMode::InProcess && !receivers.is_empty() {
        anyhow::bail!(
            "SID_EVENT_RECEIVERS names receivers, but the in-process bus keeps no addressed work: \
             set SID_NATS_URL to `embedded` or a NATS URL, or SID_EVENT_RECEIVERS to `none`"
        );
    }
    Ok(receivers)
}

/// An installation that ever addressed work to a receiver cannot move to the
/// in-process bus: a delivery recorded done may still wait in the durable
/// bus that accepted it, and the in-process bus never reaches that bus.
pub(crate) async fn refuse_addressed_history(
    work: &dyn sid_plugin::WorkStore,
) -> anyhow::Result<()> {
    let delivery = sid_core::models::WorkKind::new(sid_core::models::event::EVENT_DELIVERY_KIND)
        .expect("the delivery kind is valid");
    if work
        .has_work_of_kind(&delivery)
        .await
        .context("read the stored work before using the in-process bus")?
    {
        anyhow::bail!(
            "this installation has addressed work to receivers, which only a durable bus hands \
             over (some may still wait there): keep SID_NATS_URL `embedded` or a NATS URL"
        );
    }
    Ok(())
}

/// Lock the SQLite file `database` for this process, held while the returned
/// file lives: shared for a server on a durable bus (several may share the
/// file), exclusive for the in-process bus, which reaches its own process
/// only. Either kind excludes the other, so the in-process bus never runs
/// beside another process on the same file, whatever bus that one uses.
pub(crate) fn hold_database(
    database: &std::path::Path,
    exclusive: bool,
) -> anyhow::Result<std::fs::File> {
    let mut path = database.as_os_str().to_owned();
    path.push(".bus.lock");
    let path = std::path::PathBuf::from(path);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let locked = if exclusive {
        file.try_lock()
    } else {
        file.try_lock_shared()
    };
    match locked {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) if exclusive => anyhow::bail!(
            "another process serves {}: the in-process bus serves one process, so set \
             SID_NATS_URL to `embedded` or a NATS URL to run several",
            database.display()
        ),
        Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
            "a process with the in-process bus serves {}: it serves that process alone",
            database.display()
        ),
        Err(std::fs::TryLockError::Error(e)) => {
            Err(anyhow::Error::new(e).context(format!("lock {}", path.display())))
        }
    }
}

/// The SQLite file is named by `SID_STORAGE_SQLITE_PATH`. A set old name
/// `SID_SQLITE_PATH` stops startup in every build, not ignored: ignoring it
/// would open the default file instead of the one it names and start that
/// deployment as a new installation.
pub(crate) fn refuse_renamed_setting(old_sqlite_path: Option<&str>) -> anyhow::Result<()> {
    if old_sqlite_path.is_some() {
        anyhow::bail!(
            "SID_SQLITE_PATH is not read: name the SQLite file in SID_STORAGE_SQLITE_PATH"
        );
    }
    Ok(())
}

/// A separate history evaluator (`remote_evaluator`) reports its cleanup
/// settlements to this server as addressed work, which the in-process bus
/// cannot keep: that pairing stops startup instead of leaving the consumer
/// retrying forever and the relayed cleanup owed.
pub(crate) fn bus_carries_history_evaluator(
    mode: &crate::embedded_nats::EventBusMode,
    remote_evaluator: bool,
) -> anyhow::Result<()> {
    if remote_evaluator && *mode == crate::embedded_nats::EventBusMode::InProcess {
        anyhow::bail!(
            "SID_PASSWORD_HISTORY_EVALUATOR needs a bus that keeps addressed work: \
             set SID_NATS_URL to `embedded` or a NATS URL, or run the evaluator in this process"
        );
    }
    Ok(())
}

/// With a separate history evaluator, consume the cleanup settlements it
/// reports, so the cleanup this server relays stops being owed once settled;
/// runs until `shutdown` resolves. Nothing to consume with the evaluator in
/// process.
pub fn spawn_cleanup_settlements(
    c: &CeComponents,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Option<tokio::task::JoinHandle<()>> {
    let authority = c.auth_svc.cleanup_settlement_authority()?;
    let (bus, storage) = (c.event_bus.clone(), c.storage.clone());
    Some(tokio::spawn(async move {
        let consume = async {
            // The bus reopens a consumer it already has; one it cannot open
            // (the bus unreachable at start) is tried again here. Meanwhile
            // the relayed cleanup stays owed and is relayed again.
            loop {
                match sid_authn::password_operation::consume_cleanup_settlements(
                    bus.as_ref(),
                    storage.clone(),
                    &authority,
                )
                .await
                {
                    Ok(()) => break,
                    Err(e) => {
                        tracing::error!("cleanup settlements are not consumed: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
        };
        tokio::select! {
            () = consume => {}
            () = shutdown => {}
        }
    }))
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
/// opens, sealing history keys under the installation's master secret
/// (`master_key_path`) and the key versions that store records: the
/// evaluator's custody stays its own, so its store moves with its keys. With it, this server
/// calls the separate evaluator's internal listener at that gRPC address,
/// over the deployment's protected internal transport; it then opens no
/// evaluator store and holds no history key.
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
    master_key_path: &std::path::Path,
) -> anyhow::Result<sid_authn::password_operation::PasswordHistoryAuthority>
where
    Local: std::future::Future<
            Output = anyhow::Result<Arc<dyn sid_plugin::history_keys::HistoryKeyStore>>,
        >,
{
    use sid_authn::password_operation::PasswordHistoryAuthority;
    use sid_infra::authn::password_operation::RemoteHistoryEvaluator;
    // A setting that is present but unreadable is refused, never read as
    // unset: that would quietly give this server the history keys.
    let optional = |name: &str| setting(name, var(name));
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
        return PasswordHistoryAuthority::in_process(
            local().await?,
            master_key_path,
            Arc::new(sid_crypto::AwsLcPrimitives::new()),
            cutoff,
        )
        .await
        .context("the in-process password history evaluator");
    };
    // The evaluator's internal listener, which the deployment keeps reachable
    // by this server alone over its protected internal transport.
    let channel = tonic::transport::Endpoint::from_shared(evaluator.clone())
        .with_context(|| format!("SID_PASSWORD_HISTORY_EVALUATOR: gRPC address {evaluator}"))?
        .connect_lazy();
    Ok(PasswordHistoryAuthority::Remote(Arc::new(
        RemoteHistoryEvaluator::new(channel),
    )))
}

/// The cutoff before which password-history epochs are replaced, an RFC 3339
/// instant. Unset means none; a malformed or future value stops startup.
fn history_epoch_cutoff(
    input: Result<String, std::env::VarError>,
) -> anyhow::Result<Option<jiff::Timestamp>> {
    const NAME: &str = "SID_PASSWORD_HISTORY_EPOCH_NOT_BEFORE";
    let Some(value) = setting(NAME, input)? else {
        return Ok(None);
    };
    let cutoff =
        sid_authn::password_operation::parse_history_write_cutoff(&value, jiff::Timestamp::now())
            .context(NAME)?;
    Ok(Some(cutoff))
}

/// Parse explicit proof settings without treating invalid input as absence.
fn zkpp_settings(
    enabled: Result<String, std::env::VarError>,
    skip: Result<String, std::env::VarError>,
    version: Result<String, std::env::VarError>,
) -> anyhow::Result<sid_authn::opaque_zkpp::setup::ZkppSettings> {
    Ok(sid_authn::opaque_zkpp::setup::ZkppSettings::parse(
        setting("SID_ZKPP_ENABLED", enabled)?.as_deref(),
        setting("SID_ZKPP_SKIP_PROOF", skip)?.as_deref(),
        setting("SID_ZKPP_POLICY_VERSION", version)?.as_deref(),
    )?)
}

/// Initialize ZKPP with async keygen on the router's server setup.
/// Password operations return UNAVAILABLE until the verifier is ready.
/// Proofs are mandatory by default; optional setup still verifies every proof.
/// The SRS is cached under `cache_dir`.
fn init_zkpp(
    router: &Arc<OpaqueRouter>,
    cache_dir: &str,
) -> (
    Arc<arc_swap::ArcSwap<Option<Arc<ZkppOpaqueServer>>>>,
    sid_authn::opaque_zkpp::setup::ZkppReady,
) {
    let settings = zkpp_settings(
        std::env::var("SID_ZKPP_ENABLED"),
        std::env::var("SID_ZKPP_SKIP_PROOF"),
        std::env::var("SID_ZKPP_POLICY_VERSION"),
    )
    .unwrap_or_else(|e| panic!("ZKPP configuration: {e}"));
    // Registration, change and reset run their OPAQUE on this server whether
    // or not proofs are verified; a router this server cannot serve is a
    // deployment error found here at start when proofs are verified.
    sid_authn::opaque_zkpp::setup::spawn_zkpp_server(
        router,
        &settings,
        std::path::Path::new(cache_dir),
    )
    .unwrap_or_else(|e| panic!("ZKPP: {e}"))
}

/// Initialize feature flag service from env vars; a set but unreadable or
/// malformed setting stops the start.
fn init_feature_flags() -> anyhow::Result<FeatureFlagService> {
    if env_setting("SID_FEATURE_FLAGS_ENABLED")?.is_some_and(|v| v == "true" || v == "1") {
        let config = FeatureFlagConfig {
            api_url: env_setting("SID_FEATURE_FLAGS_URL")?
                .context("SID_FEATURE_FLAGS_URL must be set when feature flags enabled")?,
            instance_id: env_setting("SID_FEATURE_FLAGS_INSTANCE_ID")?
                .context("SID_FEATURE_FLAGS_INSTANCE_ID must be set when feature flags enabled")?,
            app_name: env_setting("SID_FEATURE_FLAGS_APP_NAME")?
                .unwrap_or_else(|| "production".into()),
            poll_interval_secs: match env_setting("SID_FEATURE_FLAGS_POLL_INTERVAL")? {
                Some(v) => v
                    .parse()
                    .with_context(|| format!("SID_FEATURE_FLAGS_POLL_INTERVAL {v:?}"))?,
                None => 15,
            },
        };
        info!(
            "Feature flags enabled (url={}, interval={}s)",
            config.api_url, config.poll_interval_secs
        );
        let svc = FeatureFlagService::new(config);
        svc.start_polling()?;
        Ok(svc)
    } else {
        Ok(FeatureFlagService::disabled())
    }
}

#[cfg(test)]
mod tests;
