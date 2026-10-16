// SPDX-License-Identifier: AGPL-3.0-only
//! Serves one compiled web UI bundle (a Vue/Quasar SPA build) and the public
//! configuration the deployment generated for it.
//!
//! The same [`router`] runs standalone (`sid-ui-host` binary) or merged into
//! a host application's listener. It serves assets and configuration only:
//! authentication, sessions and authorization stay with their own services.
//!
//! Under the bundle's mount path, for example `/account/`:
//! - `config.json`: the public configuration, never cached;
//! - `assets/…`: content-addressed build output, cached for good;
//! - another path with a file extension: that file of the bundle, or 404;
//! - any other path: the application shell (`index.html`), never cached, so
//!   the SPA's router shows the page. The mount path without its trailing
//!   slash is such a page too.
//!
//! Paths outside the mount are not this router's, so protocol endpoints,
//! callbacks and APIs never turn into `200 text/html`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use tower::ServiceExt;
use tower_http::services::ServeFile;

/// Why a bundle cannot be served.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("mount path {0:?} must start and end with '/'")]
    Mount(String),
    #[error("bundle directory {0:?} has no index.html")]
    NoShell(PathBuf),
    #[error("public configuration is not usable: {0}")]
    Config(String),
}

/// A compiled UI bundle and where it is served.
#[derive(Debug, Clone)]
pub struct UiBundle {
    /// The bundle directory, canonical: every served file resolves inside it.
    dir: PathBuf,
    mount: String,
    config: Arc<[u8]>,
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
        let literal = mount
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~/".contains(&b));
        if !mount.starts_with('/') || !mount.ends_with('/') || !literal || mount.contains("//") {
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
        let value: serde_json::Value = serde_json::from_slice(config)
            .map_err(|e| BundleError::Config(format!("not JSON: {e}")))?;
        let object = value
            .as_object()
            .ok_or_else(|| BundleError::Config("not a JSON object".into()))?;
        for key in ["environment", "release"] {
            match object.get(key).and_then(|v| v.as_str()) {
                Some(v) if !v.is_empty() => {}
                _ => return Err(BundleError::Config(format!("{key} is missing"))),
            }
        }
        Ok(Self {
            dir,
            mount: mount.to_owned(),
            config: config.into(),
        })
    }
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

/// The standalone service's routes: `bundle` beside `GET /health`. A bundle
/// mounted at `/health/` would take that route, so it is refused.
pub fn standalone(bundle: UiBundle) -> Result<Router, BundleError> {
    if bundle.mount == "/health/" {
        return Err(BundleError::Mount(bundle.mount));
    }
    Ok(Router::new()
        .route("/health", axum::routing::get(|| async { "ok" }))
        .merge(router(bundle)))
}

/// A content-addressed asset never changes under its name.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// The shell, the configuration and every error must follow each release at
/// once.
const NO_STORE: &str = "no-store";

async fn serve(State(bundle): State<Arc<UiBundle>>, request: Request) -> Response {
    let mut response = respond(&bundle, request).await;
    isolate(&mut response);
    response
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
    if rest == "config.json" {
        let mut response = Response::new(Body::from(bundle.config.to_vec()));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return no_store(response);
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
    match file(bundle, &request, "index.html").await {
        Some(response) => no_store(response),
        None => not_found(),
    }
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

/// Cross-origin isolation, which the password client's threaded WebAssembly
/// (shared memory) needs, and no content sniffing.
fn isolate(response: &mut Response) {
    let headers = response.headers_mut();
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
