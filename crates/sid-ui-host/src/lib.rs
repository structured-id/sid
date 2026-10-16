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
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use tower::ServiceExt;
use tower_http::services::ServeDir;

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
    dir: PathBuf,
    mount: String,
    config: Arc<[u8]>,
}

impl UiBundle {
    /// The bundle in `dir`, served under `mount` (`/account/`), with the
    /// deployment's public configuration `config` (a JSON object).
    ///
    /// The configuration must name its `environment` and `release`; it is
    /// served as given, so it must hold only public values.
    pub fn new(dir: &Path, mount: &str, config: &[u8]) -> Result<Self, BundleError> {
        if !mount.starts_with('/') || !mount.ends_with('/') {
            return Err(BundleError::Mount(mount.to_owned()));
        }
        if !dir.join("index.html").is_file() {
            return Err(BundleError::NoShell(dir.to_path_buf()));
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
            dir: dir.to_path_buf(),
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

/// A content-addressed asset never changes under its name.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// The shell and the configuration must follow each release at once.
const NO_STORE: &str = "no-store";

async fn serve(State(bundle): State<Arc<UiBundle>>, request: Request) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = request.uri().path().to_owned();
    let rest = path.strip_prefix(&bundle.mount).unwrap_or("");
    let mut response = if rest == "config.json" {
        let mut response = Response::new(Body::from(bundle.config.to_vec()));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        no_store(response)
    } else if has_extension(rest) {
        let cache = if rest.starts_with("assets/") {
            IMMUTABLE
        } else {
            NO_STORE
        };
        let file = file_request(&request, rest);
        let response = match ServeDir::new(&bundle.dir).oneshot(file).await {
            Ok(response) => response.map(Body::new),
            Err(never) => match never {},
        };
        if response.status().is_success() {
            with_cache(response, cache)
        } else {
            // A missing file stays a 404, never the shell.
            StatusCode::NOT_FOUND.into_response()
        }
    } else {
        let shell = file_request(&request, "index.html");
        match ServeDir::new(&bundle.dir).oneshot(shell).await {
            Ok(response) => no_store(response.map(Body::new)),
            Err(never) => match never {},
        }
    };
    isolate(&mut response);
    response
}

/// Whether the last path segment names a file (`app.js`), not a page.
fn has_extension(rest: &str) -> bool {
    rest.rsplit('/')
        .next()
        .is_some_and(|last| last.contains('.'))
}

/// `request` for `file`, relative to the bundle directory.
fn file_request(request: &Request, file: &str) -> Request {
    let mut builder = Request::builder()
        .method(request.method().clone())
        .uri(format!("/{file}"));
    for (name, value) in request.headers() {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::empty())
        .expect("a request rebuilt from a valid one is valid")
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
