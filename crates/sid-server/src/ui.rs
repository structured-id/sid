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
//! `admin/`); unset, no UI is served. The account client's key is the
//! installation's own, created once in its store and read by every replica,
//! so the image needs no configuration of its own.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use sid_authn::bff_session::BffSessionStore;
use sid_authn::issuer_directory::IssuerDirectory;
use sid_infra::issuer_client::RpClient;
use sid_infra::issuer_registry::GrpcIssuerSource;
use sid_ui_host::UiBundle;
use sid_ui_host::application_session::ApplicationSessions;
use sid_ui_host::host::HostUpstream;
use structured_proxy::hooks::{ExtraRoute, ExtraRouteHandler, RouteRequest, RouteResponse};
use tokio::sync::Mutex;
use tonic::codegen::http;
use tower::{Layer as _, ServiceExt as _};

use crate::init::CeComponents;
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

/// The UI prepared before the components start: its bundles and the
/// account client's key.
pub struct Prepared {
    account_dir: PathBuf,
    console_dir: PathBuf,
    account_url: String,
}

/// The UI `SID_UI_DIR` names, its account pages under the issuer's origin.
/// None when `SID_UI_DIR` is unset.
pub fn prepare(issuer: &str) -> anyhow::Result<Option<Prepared>> {
    let Some(dir) = crate::init::env_setting("SID_UI_DIR")? else {
        return Ok(None);
    };
    let dir = PathBuf::from(dir);
    let issuer = url::Url::parse(issuer).context("SID_ISSUER is not a URL")?;
    Ok(Some(Prepared {
        account_dir: dir.join("account"),
        console_dir: dir.join("admin"),
        account_url: format!("{}{ACCOUNT_MOUNT}", issuer.origin().ascii_serialization()),
    }))
}

impl Prepared {
    /// Where the account pages are served: their web client's URL.
    pub fn account_url(&self) -> &str {
        &self.account_url
    }
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

/// The installation's own gRPC services, as the account adapter calls them
/// in process: its web client's token calls and issuer lookups go to the
/// same services a caller on the gRPC port reaches, with no listener between
/// them. The adapter is one of those services, so it is built first and the
/// services are placed here once they all exist; a call before that is
/// answered UNAVAILABLE, as a server still starting answers.
#[derive(Clone, Default)]
pub struct OwnServices(Arc<std::sync::OnceLock<MountedService>>);

impl OwnServices {
    /// Place the installation's `services`, behind the operation context
    /// every call to them carries. The first placement stays.
    fn place(&self, services: tonic::service::Routes) {
        let services = tower::ServiceBuilder::new()
            .layer(sid_infra::authn::operation::OperationContextLayer)
            .service(services);
        // A second placement would be the same services of the same server.
        let _ = self.0.set(MountedService::new(services));
    }
}

impl tower::Service<http::Request<tonic::body::Body>> for OwnServices {
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // The placed services are cloned per call and polled there.
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        match self.0.get() {
            Some(services) => Box::pin(services.clone().oneshot(request)),
            None => Box::pin(async {
                Ok(
                    tonic::Status::unavailable("the installation's services are starting")
                        .into_http(),
                )
            }),
        }
    }
}

/// The account adapter's web client and issuer registry over
/// [`OwnServices`].
type OwnClient = RpClient<sid_infra::deadline::Deadline<OwnServices>>;

/// What the UI adds to the server.
pub struct Started {
    /// The HTTP port's routes: the bundles and the sign-in start.
    pub routes: Vec<ExtraRoute>,
    /// The account adapter's service, served among the server's own so its
    /// sign-in callback and back-channel logout at the origin's root reach
    /// it in process.
    pub adapter: Arc<ApplicationSessions<OwnClient>>,
    /// The account pages' calls (`/account/api/...`), served in process with
    /// the session's bearer.
    pub account_api: MountFactory,
}

/// Set up the account adapter and return what the server serves of the UI.
pub async fn start(c: &CeComponents, prepared: Prepared) -> anyhow::Result<Started> {
    // The installation provisioned the pages' web client with its own key.
    let key = c
        .account_client_key
        .clone()
        .context("the installation provisioned no account client key")?;
    // The client calls the installation's services in this process: no port
    // of its own carries them.
    let own = OwnServices::default();
    let channel = sid_infra::deadline::in_process(own.clone());
    let client = RpClient::new(key, c.issuer.clone(), channel.clone())?;
    // The account sessions live in the installation's own store, in its
    // schema: replicas sharing the store share them, and the installation's
    // maintenance removes the expired ones.
    let store: Arc<dyn sid_plugin::CeremonyStateStore> = c.storage.clone();
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
        own.place(routes.clone());
        let api = tower::ServiceBuilder::new()
            .layer(sid_infra::authn::operation::OperationContextLayer)
            .service(routes);
        MountedService::new(
            tonic_web::GrpcWebLayer::new().layer(HostUpstream::new(host_sessions, Some(api))),
        )
    });

    // The account pages follow the installation's public settings: served
    // with their configuration, in process, from the engine's projection.
    let (account, settings) = UiBundle::live(
        &prepared.account_dir,
        ACCOUNT_MOUNT,
        &bundle_config(serde_json::json!({})),
    )?;
    serve_settings(settings, c.public_settings.subscribe())?;
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

/// Serve `projections` through `sink`: the current one before this returns,
/// so the bundle's configuration is complete from its first request, and
/// each newer one as the engine commits it, until the bundle is gone or the
/// engine's settings are.
fn serve_settings(
    sink: sid_ui_host::SettingsSink,
    mut projections: tokio::sync::watch::Receiver<sid_proto::sid::v1::ui::PublicUiSettings>,
) -> anyhow::Result<()> {
    let current = projections.borrow_and_update().clone();
    sink.stream()
        .apply(&current)
        .map_err(|e| anyhow::anyhow!("the installation's public UI settings: {e}"))?;
    tokio::spawn(async move {
        // A new stream: the projection applied above is its starting point.
        let mut stream = sink.stream();
        let mut served = current.revision;
        while projections.changed().await.is_ok() {
            if sink.is_closed() {
                return;
            }
            let next = projections.borrow_and_update().clone();
            if next.revision <= served {
                continue;
            }
            match stream.apply(&next) {
                Ok(()) => served = next.revision,
                Err(e) => tracing::warn!("public UI settings not served to the pages: {e}"),
            }
        }
    });
    Ok(())
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
