// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's own web UI, served by this process on its HTTP port:
//!
//! - the account pages at `/account/`, with their browser adapter: sign-in
//!   start under `/account/auth/`, its callback and back-channel logout at
//!   the origin's root, the account API under `/account/api/`, as the system
//!   account integration's web client;
//! - the administration console where the installation settings place it
//!   (`/admin/` by default, another prefix, or a sibling host on the same
//!   site), followed from the next request on. The console acts in the
//!   installation's own browser session against its API at `/api`.
//!
//! `SID_UI_DIR` names the directory of the compiled bundles (`account/`,
//! `admin/`); unset, no UI is served. The account client's key is created
//! in `SID_DATA_DIR` on the first start and registered as the account
//! integration's, so the image needs no configuration of its own.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use secrecy::SecretString;
use sid_authn::bff_session::BffSessionStore;
use sid_authn::client_key::ClientKey;
use sid_authn::issuer_directory::IssuerDirectory;
use sid_infra::issuer_client::RpClient;
use sid_infra::issuer_registry::GrpcIssuerSource;
use sid_ui_host::UiBundle;
use sid_ui_host::application_session::ApplicationSessions;
use sid_ui_host::host::{HostUpstream, issuer_channel};
use structured_proxy::hooks::{ExtraRoute, ExtraRouteHandler, RouteRequest, RouteResponse};
use tokio::sync::Mutex;
use tonic::codegen::http;
use tower::{Layer as _, ServiceExt as _};

use crate::init::{Account, CeComponents};
use crate::serve::{MountFactory, MountedService};

/// Where the account pages are served.
pub const ACCOUNT_MOUNT: &str = "/account/";

/// The account pages' session cookie: host-only, apart from the
/// installation's own session cookie.
const ACCOUNT_COOKIE: &str = "__Host-sid_account";

/// A session lasts at most this long, however active.
const SESSION_MAX_AGE: Duration = Duration::from_secs(24 * 3600);
/// A session ends after this long unused.
const SESSION_IDLE: Duration = Duration::from_secs(3600);
/// A started sign-in waits this long for its callback.
const SIGN_IN_TTL: Duration = Duration::from_secs(300);
/// How often expired account sessions and sign-ins are removed.
const PURGE_INTERVAL: Duration = Duration::from_secs(60);

/// The UI prepared before the components start: its bundles and the
/// account client's key.
pub struct Prepared {
    account_dir: PathBuf,
    console_dir: PathBuf,
    key_file: PathBuf,
}

/// The UI `SID_UI_DIR` names, with the account settings it brings: the
/// account pages under the issuer's origin, their web client's key created
/// in `data_dir` on the first start. None when `SID_UI_DIR` is unset.
pub fn prepare(issuer: &str, data_dir: &Path) -> anyhow::Result<Option<(Prepared, Account)>> {
    let Some(dir) = crate::init::env_setting("SID_UI_DIR")? else {
        return Ok(None);
    };
    let dir = PathBuf::from(dir);
    let issuer = url::Url::parse(issuer).context("SID_ISSUER is not a URL")?;
    let account_url = format!("{}{ACCOUNT_MOUNT}", issuer.origin().ascii_serialization());
    let key_file = data_dir.join("account-client.pem");
    let jwks_file = data_dir.join("account-client.jwks.json");
    if !key_file.exists() && !jwks_file.exists() {
        let kid = sid_ui_host::client_key_files::generate(&key_file, &jwks_file)
            .context("account client key")?;
        tracing::info!(%kid, "account client key created");
    }
    let jwks = std::fs::read_to_string(&jwks_file)
        .with_context(|| format!("{jwks_file:?} cannot be read"))?;
    let keys = sid_core::models::ClientKeySet::from_json(&jwks)
        .map_err(|e| anyhow::anyhow!("{jwks_file:?}: {e}"))?;
    let integration = sid_authn::system_integration::AccountSettings::new(&account_url, keys)
        .map_err(|e| anyhow::anyhow!("account pages {account_url}: {e}"))?;
    let account = Account {
        pages: Some(integration.pages().clone()),
        mailed: Some(integration.pages().clone()),
        integration: Some(integration),
    };
    Ok(Some((
        Prepared {
            account_dir: dir.join("account"),
            console_dir: dir.join("admin"),
            key_file,
        },
        account,
    )))
}

/// The deployment's public configuration of a bundle.
fn bundle_config(extra: serde_json::Value) -> Vec<u8> {
    let mut config = serde_json::json!({
        "environment": "standalone",
        "release": env!("CARGO_PKG_VERSION"),
    });
    if let (Some(config), serde_json::Value::Object(extra)) = (config.as_object_mut(), extra) {
        config.extend(extra);
    }
    serde_json::to_vec(&config).expect("a JSON object encodes")
}

/// This process's gRPC port on the loopback.
fn loopback(c: &CeComponents) -> String {
    format!("http://127.0.0.1:{}", c.grpc_addr.port())
}

/// The database the account adapter keeps its sessions in: the
/// installation's own, so replicas sharing it share the sessions.
fn adapter_database() -> anyhow::Result<String> {
    if let Some(url) = crate::init::env_setting("SID_UI_DATABASE_URL")? {
        return Ok(url);
    }
    if let Some(url) = crate::init::env_setting("SID_DATABASE_URL")? {
        return Ok(url);
    }
    let path = crate::init::env_setting("SID_STORAGE_SQLITE_PATH")?
        .unwrap_or_else(|| "/var/lib/sid/auth.db".to_owned());
    Ok(format!("sqlite:{path}"))
}

/// What the UI adds to the server.
pub struct Started {
    /// The HTTP port's routes: the bundles and the sign-in start.
    pub routes: Vec<ExtraRoute>,
    /// The account adapter's service, served among the server's own so its
    /// sign-in callback and back-channel logout at the origin's root reach
    /// it in process.
    pub adapter: Arc<ApplicationSessions>,
    /// The account pages' calls (`/account/api/...`), served in process with
    /// the session's bearer.
    pub account_api: MountFactory,
}

/// Set up the account adapter and return what the server serves of the UI.
pub async fn start(c: &CeComponents, prepared: Prepared) -> anyhow::Result<Started> {
    let grpc = loopback(c);
    let pem = SecretString::from(
        std::fs::read_to_string(&prepared.key_file)
            .with_context(|| format!("{:?} cannot be read", prepared.key_file))?,
    );
    let key = ClientKey::ed25519_from_pem(&pem).context("account client key")?;
    let channel = issuer_channel(&grpc)?;
    let client = RpClient::new(key, c.issuer.clone(), channel.clone())?;
    let store = sid_storage::application_store::ceremony_store(&adapter_database()?)
        .await
        .context("account session store")?;
    tokio::spawn(sid_storage::application_store::purge_expired(
        store.clone(),
        PURGE_INTERVAL,
    ));
    let sessions = Arc::new(ApplicationSessions::new(
        Arc::new(client),
        Arc::new(IssuerDirectory::new(Arc::new(GrpcIssuerSource::new(
            channel,
        )))),
        Arc::new(BffSessionStore::new(
            store,
            SESSION_MAX_AGE,
            SESSION_IDLE,
            SIGN_IN_TTL,
        )),
        c.revocation_cache.clone(),
        ACCOUNT_COOKIE.to_owned(),
    ));
    // The page speaks gRPC-Web; the host answers the adapter itself and
    // calls the installation's own services, in process, with the session's
    // bearer.
    let host_sessions = sessions.clone();
    let account_api: MountFactory = Box::new(move |routes| {
        let api = tower::ServiceBuilder::new()
            .layer(sid_infra::authn::operation::OperationContextLayer)
            .service(routes);
        MountedService::new(
            tonic_web::GrpcWebLayer::new().layer(HostUpstream::new(host_sessions, Some(api))),
        )
    });

    let account = UiBundle::new(
        &prepared.account_dir,
        ACCOUNT_MOUNT,
        &bundle_config(serde_json::json!({})),
    )?;
    let account: Arc<dyn ExtraRouteHandler> = Arc::new(AccountPages {
        bundle: sid_ui_host::router(account),
    });
    let console: Arc<dyn ExtraRouteHandler> = Arc::new(Console {
        dir: prepared.console_dir,
        web: c.web_settings.clone(),
        served: Mutex::new(None),
    });
    let mut routes = Vec::new();
    // The mount itself too: a catch-all matches only a non-empty rest.
    for path in ["/account", "/account/", "/account/{*path}"] {
        routes.push(ExtraRoute::new(http::Method::GET, path, account.clone()));
    }
    for path in ["/", "/{*path}"] {
        routes.push(ExtraRoute::new(http::Method::GET, path, console.clone()));
    }
    Ok(Started {
        routes,
        adapter: sessions,
        account_api,
    })
}

/// The account pages: the bundle, and the adapter's sign-in start sent to
/// where the adapter answers it, at the origin's root.
struct AccountPages {
    bundle: axum::Router,
}

#[async_trait::async_trait]
impl ExtraRouteHandler for AccountPages {
    async fn handle(&self, request: RouteRequest) -> RouteResponse {
        let rest = request
            .uri
            .path()
            .strip_prefix("/account")
            .unwrap_or_default();
        if rest.starts_with("/auth/") {
            // The pages start sign-in under their mount; the adapter's
            // sign-in routes are the origin's (RFC 9110 §15.4.8).
            let query = request
                .uri
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            let mut response = RouteResponse::new(http::StatusCode::TEMPORARY_REDIRECT, "");
            match http::HeaderValue::try_from(format!("{rest}{query}")) {
                Ok(location) => {
                    response.headers.insert(http::header::LOCATION, location);
                    response.headers.insert(
                        http::header::CACHE_CONTROL,
                        http::HeaderValue::from_static("no-store"),
                    );
                    return response;
                }
                Err(_) => return RouteResponse::new(http::StatusCode::BAD_REQUEST, ""),
            }
        }
        serve_router(&self.bundle, request).await
    }
}

/// `request` answered by `router`, read whole: a bundle's files are a few
/// megabytes.
async fn serve_router(router: &axum::Router, request: RouteRequest) -> RouteResponse {
    use http_body_util::BodyExt as _;
    let mut forwarded = http::Request::new(axum::body::Body::from(request.body));
    *forwarded.method_mut() = request.method;
    *forwarded.uri_mut() = request.uri;
    *forwarded.headers_mut() = request.headers;
    let answer = match router.clone().oneshot(forwarded).await {
        Ok(answer) => answer,
        Err(never) => match never {},
    };
    let (parts, body) = answer.into_parts();
    let body = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::error!(error = %e, "cannot read a bundle answer");
            return RouteResponse::new(http::StatusCode::INTERNAL_SERVER_ERROR, "");
        }
    };
    let mut response = RouteResponse::new(parts.status, body);
    response.headers = parts.headers;
    response
}

/// The console where the settings place it now.
struct Console {
    dir: PathBuf,
    web: Arc<sid::web_settings::WebSettingsAdmin>,
    /// The placement served last and the bundle router built for it.
    served: Mutex<Option<Served>>,
}

struct Served {
    revision: u64,
    host: String,
    mount: String,
    public_url: String,
    router: axum::Router,
}

impl Console {
    /// The router of the console's current placement, rebuilt when the
    /// settings changed; none when they cannot be read or the bundle cannot
    /// be served there.
    async fn placed(&self) -> Option<(String, String, axum::Router)> {
        let placed = match self.web.recent().await {
            Ok(placed) => placed,
            Err(e) => {
                tracing::warn!(error = %e, "console placement unreadable");
                return None;
            }
        };
        let host = placed.console_url.host_str().unwrap_or_default().to_owned();
        let mount = placed.console_url.path().to_owned();
        let public_url = placed.public_url.to_string();
        let mut served = self.served.lock().await;
        let reuse = served
            .as_ref()
            .filter(|s| {
                s.revision == placed.revision
                    && s.mount == mount
                    && s.host == host
                    && s.public_url == public_url
            })
            .map(|s| s.router.clone());
        let router = match reuse {
            Some(router) => router,
            None => {
                let config = bundle_config(serde_json::json!({
                    "installationUrl": placed.public_url.as_str(),
                }));
                match UiBundle::new(&self.dir, &mount, &config) {
                    Ok(bundle) => sid_ui_host::router(bundle),
                    Err(e) => {
                        tracing::error!(error = %e, %mount, "console bundle cannot be served");
                        return None;
                    }
                }
            }
        };
        *served = Some(Served {
            revision: placed.revision,
            host: host.clone(),
            mount: mount.clone(),
            public_url,
            router: router.clone(),
        });
        Some((host, mount, router))
    }
}

#[async_trait::async_trait]
impl ExtraRouteHandler for Console {
    async fn handle(&self, request: RouteRequest) -> RouteResponse {
        let not_found = || RouteResponse::new(http::StatusCode::NOT_FOUND, "");
        let Some((host, mount, router)) = self.placed().await else {
            return not_found();
        };
        // The host the browser asked for, without its port; the console's
        // own host only.
        let asked = request
            .headers
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(host_name)
            .unwrap_or_default();
        let path = request.uri.path();
        let under = path.starts_with(&mount) || format!("{path}/") == mount;
        if !asked.eq_ignore_ascii_case(&host) || !under {
            return not_found();
        }
        serve_router(&router, request).await
    }
}

/// The host name of a `Host` header value, without its port; an IPv6
/// literal keeps its brackets, as a URL's host string does (RFC 9110 §7.2).
fn host_name(value: &str) -> &str {
    if value.starts_with('[') {
        return value.find(']').map_or(value, |end| &value[..=end]);
    }
    value.rsplit_once(':').map_or(value, |(name, _)| name)
}

#[cfg(test)]
mod tests;
