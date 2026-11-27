// SPDX-License-Identifier: AGPL-3.0-only
//! Serves one compiled web UI bundle (a Vue/Quasar SPA build) and its public
//! configuration: the deployment's, and for a bundle that follows its
//! installation, that installation's public UI settings as well
//! ([`UiBundle::live`]).
//!
//! The same [`router`] runs standalone (`sid-ui-host` binary) or merged into
//! a host application's listener. It serves assets and configuration only:
//! authentication, sessions and authorization stay with their own services.
//!
//! Under the bundle's mount path, for example `/account/`:
//! - `config.json`: the public configuration from memory, revalidated by its
//!   `ETag` on every use;
//! - `assets/…`: content-addressed build output, cached for good;
//! - another path with a file extension: that file of the bundle, or 404;
//! - any other path: the application shell (`index.html`), never cached, so
//!   the SPA's router shows the page. The mount path without its trailing
//!   slash is such a page too.
//!
//! Paths outside the mount are not this router's, so protocol endpoints,
//! callbacks and APIs never turn into `200 text/html`.
//!
//! Every response carries the bundle's content security policy: code only
//! from the page's own origin, connections to it and to the installation the
//! configuration names (`installationUrl`), no framing.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes, HttpBody};
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use serde_json::{Map, Value};
use tower::ServiceExt;
use tower_http::services::ServeFile;

pub mod application_session;
pub mod client_key_files;
pub mod host;
mod settings;

pub use settings::{
    GrpcSettingsSource, Retry, SettingsRejected, SettingsSink, SettingsSource, SettingsStream,
    SettingsUpdates, follow,
};
use settings::{Served, ServedConfig};

/// Why a bundle cannot be served.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("mount path {0:?} must start and end with '/'")]
    Mount(String),
    #[error("bundle directory {0:?} has no index.html")]
    NoShell(PathBuf),
    #[error("public configuration is not usable: {0}")]
    Config(String),
    #[error("the bundle's index.html cannot be served: {0}")]
    Shell(String),
}

/// A compiled UI bundle and where it is served.
#[derive(Debug, Clone)]
pub struct UiBundle {
    /// The bundle directory, canonical: every served file resolves inside it.
    dir: PathBuf,
    mount: String,
    /// The application shell as served: the bundle's `index.html` naming the
    /// mount as its `<base href>`, so one build, whose asset URLs are
    /// relative, works under whatever mount the installation configures.
    shell: Bytes,
    /// The configuration served now; `None` before a live bundle's first
    /// settings projection.
    config: ServedConfig,
    /// The content security policy of every response ([`policy`]).
    policy: HeaderValue,
}

impl UiBundle {
    /// The bundle in `dir`, served under `mount` (`/account/`), with the
    /// deployment's public configuration `config` (a JSON object).
    ///
    /// The mount is a literal path of unreserved characters (RFC 3986
    /// §2.3) and `/`, so it never reads as route syntax. The configuration
    /// must name its `environment` and `release`; it is served as given, so
    /// it must hold only public values.
    pub fn new(dir: &Path, mount: &str, config: &[u8]) -> Result<Self, BundleError> {
        let (dir, base) = Self::checked(dir, mount, config)?;
        let shell = shell(&dir, mount)?;
        let policy = policy(&base)?;
        // The sender goes: the configuration never changes, and a receiver
        // keeps the last value.
        let (_, served) = tokio::sync::watch::channel(Some(Served::of(config.to_vec())));
        Ok(Self {
            dir,
            mount: mount.to_owned(),
            shell,
            config: served,
            policy,
        })
    }

    /// As [`UiBundle::new`], for a bundle that follows its installation's
    /// public UI settings: the served configuration is `config` with those
    /// settings under `settings`, from the first projection the returned sink
    /// receives. Until then `config.json` answers 503. `config` must not hold
    /// `settings` itself.
    pub fn live(
        dir: &Path,
        mount: &str,
        config: &[u8],
    ) -> Result<(Self, SettingsSink), BundleError> {
        let (dir, base) = Self::checked(dir, mount, config)?;
        if base.contains_key(settings::SETTINGS_KEY) {
            return Err(BundleError::Config(format!(
                "`{}` is the installation's, not the deployment's",
                settings::SETTINGS_KEY
            )));
        }
        let shell = shell(&dir, mount)?;
        let policy = policy(&base)?;
        let (sink, served) = SettingsSink::new(base);
        Ok((
            Self {
                dir,
                mount: mount.to_owned(),
                shell,
                config: served,
                policy,
            },
            sink,
        ))
    }

    /// The canonical bundle directory and the configuration object, once
    /// both can be served.
    fn checked(
        dir: &Path,
        mount: &str,
        config: &[u8],
    ) -> Result<(PathBuf, Map<String, Value>), BundleError> {
        if !sid_core::models::is_ui_mount(mount) {
            return Err(BundleError::Mount(mount.to_owned()));
        }
        let dir = dir
            .canonicalize()
            .map_err(|_| BundleError::NoShell(dir.to_path_buf()))?;
        // The shell must be servable under the same rule as every request.
        match dir.join("index.html").canonicalize() {
            Ok(shell) if shell.starts_with(&dir) && shell.is_file() => {}
            _ => return Err(BundleError::NoShell(dir)),
        }
        let value: Value = serde_json::from_slice(config)
            .map_err(|e| BundleError::Config(format!("not JSON: {e}")))?;
        let Value::Object(object) = value else {
            return Err(BundleError::Config("not a JSON object".into()));
        };
        for key in ["environment", "release"] {
            match object.get(key).and_then(|v| v.as_str()) {
                Some(v) if !v.is_empty() => {}
                _ => return Err(BundleError::Config(format!("{key} is missing"))),
            }
        }
        Ok((dir, object))
    }
}

/// The key of the deployment's configuration naming the installation the
/// page calls when that is not the page's own origin (a console on a sibling
/// host).
const INSTALLATION_KEY: &str = "installationUrl";

/// The content security policy of a bundle with the deployment's
/// configuration `config`, enforced on every response.
///
/// Code, styles, fonts and workers come from the page's own origin; nothing
/// inline and no string evaluation, so markup that reaches the page cannot
/// run. `'wasm-unsafe-eval'` lets the password client compile its
/// WebAssembly and allows no JavaScript evaluation. The page connects to its
/// own origin and to the origin of the installation its configuration names,
/// posts forms nowhere else and is framed by no one.
fn policy(config: &Map<String, Value>) -> Result<HeaderValue, BundleError> {
    let mut connect = String::from("'self'");
    if let Some(named) = config.get(INSTALLATION_KEY) {
        let unusable = || BundleError::Config(format!("{INSTALLATION_KEY} is not an http(s) URL"));
        let url = named
            .as_str()
            .and_then(|named| url::Url::parse(named).ok())
            .filter(|url| matches!(url.scheme(), "http" | "https"))
            .ok_or_else(unusable)?;
        // The serialized origin of an http(s) URL is scheme, host and port
        // in ASCII: nothing in it ends the directive or starts another.
        connect.push(' ');
        connect.push_str(&url.origin().ascii_serialization());
    }
    HeaderValue::try_from(format!(
        "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
         img-src 'self' data: blob:; font-src 'self'; connect-src {connect}; \
         worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'self'; \
         form-action 'self'; frame-ancestors 'none'"
    ))
    .map_err(|_| BundleError::Config(format!("{INSTALLATION_KEY} cannot be named in a header")))
}

/// The bundle's `index.html` in `dir` with `<base href="{mount}">` as the
/// first element of its head, read once: a shell that names its own
/// `<base>` is refused, since it would contradict the mount. The mount is
/// a literal path of unreserved characters (checked before), so it needs no
/// escaping in the attribute.
fn shell(dir: &Path, mount: &str) -> Result<Bytes, BundleError> {
    let path = dir.join("index.html");
    let html =
        std::fs::read_to_string(&path).map_err(|_| BundleError::NoShell(dir.to_path_buf()))?;
    let lower = html.to_ascii_lowercase();
    if lower.contains("<base") {
        return Err(BundleError::Shell("the shell names its own <base>".into()));
    }
    // Right after the first of `<head>`, `<html>` or the doctype the shell
    // has (HTML lets both tags be omitted); before everything else
    // otherwise. Ahead of the doctype it would switch to quirks mode.
    let after = |tag: &str| -> Option<usize> {
        let start = lower.find(tag)?;
        lower[start..].find('>').map(|end| start + end + 1)
    };
    let at = after("<head")
        .or_else(|| after("<html"))
        .or_else(|| after("<!doctype"))
        .unwrap_or(0);
    Ok(Bytes::from(format!(
        "{}<base href=\"{mount}\">{}",
        &html[..at],
        &html[at..]
    )))
}

/// The routes serving `bundle`, to run alone or merge into a host router.
pub fn router(bundle: UiBundle) -> Router {
    let bare = bundle.mount.trim_end_matches('/').to_owned();
    let all = format!("{}{{*path}}", bundle.mount);
    let mut router = Router::new().route(&all, any(serve));
    // `/account` itself is a page of an app mounted at `/account/`; a bundle
    // mounted at `/` has no such second form.
    if !bare.is_empty() {
        router = router.route(&bare, any(serve));
    }
    router
        .route(&bundle.mount, any(serve))
        .with_state(Arc::new(bundle))
}

/// The standalone service's routes: `bundle` beside `GET /health`, which
/// answers 503 while the bundle has no configuration to serve. A bundle
/// mounted at `/health/` would take that route, so it is refused.
pub fn standalone(bundle: UiBundle) -> Result<Router, BundleError> {
    if bundle.mount == "/health/" {
        return Err(BundleError::Mount(bundle.mount));
    }
    let config = bundle.config.clone();
    let health = move || {
        let ready = config.borrow().is_some();
        async move {
            if ready {
                (StatusCode::OK, "ok")
            } else {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "waiting for the public UI settings",
                )
            }
        }
    };
    Ok(Router::new()
        .route("/health", axum::routing::get(health))
        .merge(router(bundle)))
}

/// A content-addressed asset never changes under its name.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// The shell and every error must follow each release at once.
const NO_STORE: &str = "no-store";
/// Stored, but asked again before every use (RFC 9111 §5.2.2.4).
const REVALIDATE: &str = "no-cache";

/// Routed with `any` so other methods get a 405 with `Allow`. A HEAD answer
/// still has no body: axum's method router drops it for every route, `any`
/// included (`test_head_has_no_body`).
async fn serve(State(bundle): State<Arc<UiBundle>>, request: Request) -> Response {
    let mut response = respond(&bundle, request).await;
    if response.status() == StatusCode::NOT_MODIFIED {
        without_length(&mut response);
    }
    protect(&bundle, &mut response);
    response
}

/// A 304 names no length. Sent, the field must be the selected
/// representation's length (RFC 9110 §8.6), which a proxy compressing the 200
/// changes; an empty body of known size would be declared as 0 by the router.
fn without_length(response: &mut Response) {
    response.headers_mut().remove(header::CONTENT_LENGTH);
    *response.body_mut() = Body::new(Unsized);
}

/// A finished body that states no size, so nothing derives a length from it.
struct Unsized;

impl HttpBody for Unsized {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        std::task::Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        true
    }
}

async fn respond(bundle: &UiBundle, request: Request) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        // RFC 9110 §15.5.6: a 405 names the methods the resource answers.
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return response;
    }
    // The body is never read; the parts are what a file response needs.
    let (request, _) = request.into_parts();
    let raw = request.uri.path().strip_prefix(&bundle.mount).unwrap_or("");
    // Classified as the browser means it: `robots%2Etxt` is `robots.txt`.
    let Ok(rest) = percent_encoding::percent_decode_str(raw).decode_utf8() else {
        return not_found();
    };
    // No dot segment (an alias of another file under another cache policy,
    // even behind an encoded `/`) and no hidden file (`.env`) is served.
    if rest.split('/').any(|segment| segment.starts_with('.')) {
        return not_found();
    }
    if rest == "config.json" {
        return config(bundle, &request);
    }
    if rest.starts_with("assets/") || has_extension(&rest) {
        // Everything under assets/ is build output, extension or not.
        let cache = if rest.starts_with("assets/") {
            IMMUTABLE
        } else {
            NO_STORE
        };
        return match file(bundle, &request, &rest).await {
            // A missing file stays a 404, never the shell.
            Some(response) if response.status() == StatusCode::NOT_FOUND => not_found(),
            // The file or a revalidation of it carries the file's policy.
            Some(response)
                if response.status().is_success()
                    || response.status() == StatusCode::NOT_MODIFIED =>
            {
                with_cache(response, cache)
            }
            // A request-specific error (412, 416) is never stored.
            Some(response) => no_store(response),
            None => not_found(),
        };
    }
    // The shell naming the mount as its base, never stored: it follows each
    // release at once.
    let mut response = Response::new(Body::from(bundle.shell.clone()));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    no_store(response)
}

/// The configuration from memory, kept by the browser and revalidated on
/// every use: a matching `If-None-Match` gets 304 with no body (RFC 9110
/// §13.1.2, §15.4.5). Before a live bundle's first settings projection it is
/// a 503: the deployment's configuration alone would be served as complete.
fn config(bundle: &UiBundle, request: &Parts) -> Response {
    // Cloned out of the channel so the lock is not held while responding.
    let Some(served) = bundle.config.borrow().clone() else {
        return no_store(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "the public UI settings have not arrived yet",
            )
                .into_response(),
        );
    };
    let unchanged = request
        .headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|list| list.split(','))
        .any(|tag| tag_matches(tag.trim(), &served.tag));
    let mut response = if unchanged {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let mut response = Response::new(Body::from(Bytes::from_owner(Arc::clone(&served.bytes))));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        response
    };
    response
        .headers_mut()
        .insert(header::ETAG, served.tag.clone());
    with_cache(response, REVALIDATE)
}

/// `If-None-Match` uses the weak comparison (RFC 9110 §13.1.2): `*` or the
/// same opaque tag, with or without `W/` on either side.
fn tag_matches(tag: &str, ours: &HeaderValue) -> bool {
    tag == "*" || opaque(tag.as_bytes()) == opaque(ours.as_bytes())
}

/// The opaque part of an entity tag: without the weakness indicator.
fn opaque(tag: &[u8]) -> &[u8] {
    tag.strip_prefix(b"W/").unwrap_or(tag)
}

/// A 404 nothing keeps: a later release may add the file.
fn not_found() -> Response {
    no_store(StatusCode::NOT_FOUND.into_response())
}

/// The bundle's file `rest` (decoded) answered for `request`, or `None` when
/// it does not resolve to a regular file inside the bundle: a symlink is
/// followed only while its target stays inside, and a directory is never
/// listed or redirected.
///
/// The resolved path is checked, then that path is opened. Swapping a file
/// in between would take write access to the bundle directory, which
/// already decides everything this host serves; no boundary is crossed.
async fn file(bundle: &UiBundle, request: &Parts, rest: &str) -> Option<Response> {
    let resolved = tokio::fs::canonicalize(bundle.dir.join(rest)).await.ok()?;
    if !resolved.starts_with(&bundle.dir) {
        return None;
    }
    if !tokio::fs::metadata(&resolved).await.ok()?.is_file() {
        return None;
    }
    let mut builder = Request::builder().method(request.method.clone()).uri("/");
    for (name, value) in &request.headers {
        builder = builder.header(name, value);
    }
    let file_request = builder
        .body(Body::empty())
        .expect("a request rebuilt from a valid one is valid");
    match ServeFile::new(resolved).oneshot(file_request).await {
        Ok(response) => Some(response.map(Body::new)),
        Err(never) => match never {},
    }
}

/// Whether the last path segment names a file (`app.js`), not a page.
fn has_extension(rest: &str) -> bool {
    rest.rsplit('/')
        .next()
        .is_some_and(|last| last.contains('.'))
}

fn no_store(response: Response) -> Response {
    with_cache(response, NO_STORE)
}

fn with_cache(mut response: Response, value: &'static str) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(value));
    response
}

/// What every response of `bundle` states to the browser: its content
/// security policy (a worker script takes the policy of its own response),
/// cross-origin isolation, which the password client's threaded WebAssembly
/// (shared memory) needs, no content sniffing, and a referrer that leaves
/// the origin as the origin alone, so a sign-in link or a flow's address is
/// never sent to another site.
fn protect(bundle: &UiBundle, response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, bundle.policy.clone());
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-embedder-policy",
        HeaderValue::from_static("credentialless"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}

#[cfg(test)]
mod tests;
