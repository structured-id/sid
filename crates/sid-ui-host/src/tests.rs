// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::http::Request;
use http_body_util::BodyExt;

const CONFIG: &[u8] =
    br#"{"sidUrl":"https://sid.example.com","environment":"dev","release":"1.2.3"}"#;

/// A bundle laid out as a Quasar SPA build: shell, hashed assets, a root file.
fn bundle_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sid-ui-host-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>shell</title>",
    )
    .unwrap();
    std::fs::write(dir.join("assets/app-abc123.js"), "console.log(1)").unwrap();
    std::fs::write(dir.join("favicon.ico"), "ico").unwrap();
    dir
}

async fn get_path(app: &Router, method: Method, path: &str) -> (StatusCode, Response) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    (response.status(), response)
}

async fn body(response: Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn header_of(response: &Response, name: header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .map(|v| v.to_str().unwrap().to_owned())
}

fn app(name: &str) -> Router {
    router(UiBundle::new(&bundle_dir(name), "/account/", CONFIG).unwrap())
}

/// The configuration is what start-up reads before anything else: served
/// exactly as the deployment generated it, never from a cache.
#[tokio::test]
async fn test_config_is_served_uncached() {
    let (status, response) = get_path(&app("config"), Method::GET, "/account/config.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header_of(&response, header::CACHE_CONTROL).as_deref(),
        Some("no-store")
    );
    assert_eq!(
        header_of(&response, header::CONTENT_TYPE).as_deref(),
        Some("application/json")
    );
    assert_eq!(body(response).await.as_bytes(), CONFIG);
}

/// Pages of the SPA, the mount path with and without its slash included,
/// get the shell, uncached so a new release is picked up at once.
#[tokio::test]
async fn test_pages_get_the_uncached_shell() {
    let app = app("pages");
    for path in [
        "/account",
        "/account/",
        "/account/login",
        "/account/login/mfa/totp",
    ] {
        let (status, response) = get_path(&app, Method::GET, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(
            header_of(&response, header::CACHE_CONTROL).as_deref(),
            Some("no-store")
        );
        assert!(body(response).await.contains("shell"), "{path}");
    }
}

/// Hashed assets are cached for good; the same path never changes content.
#[tokio::test]
async fn test_assets_are_immutable() {
    let (status, response) =
        get_path(&app("assets"), Method::GET, "/account/assets/app-abc123.js").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header_of(&response, header::CACHE_CONTROL).as_deref(),
        Some(IMMUTABLE)
    );
    assert_eq!(body(response).await, "console.log(1)");
}

/// A missing file is a 404, never the shell: a failed script load must not
/// become `200 text/html`.
#[tokio::test]
async fn test_missing_files_are_not_found() {
    let app = app("missing");
    for path in ["/account/assets/gone-123.js", "/account/robots.txt"] {
        let (status, response) = get_path(&app, Method::GET, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(!body(response).await.contains("shell"), "{path}");
    }
}

/// Everything under `assets/` is build output, extension or not: served
/// when it exists, 404 when it does not, never the shell.
#[tokio::test]
async fn test_extensionless_assets_are_files() {
    let dir = bundle_dir("extensionless");
    std::fs::write(dir.join("assets/runtime-config"), "data").unwrap();
    let app = router(UiBundle::new(&dir, "/account/", CONFIG).unwrap());
    let (status, response) = get_path(&app, Method::GET, "/account/assets/runtime-config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body(response).await, "data");
    let (status, response) = get_path(&app, Method::GET, "/account/assets/missing").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body(response).await.contains("shell"));
}

/// A revalidation the file still satisfies stays a 304, not a 404.
#[tokio::test]
async fn test_conditional_requests_keep_their_status() {
    let app = app("conditional");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/account/assets/app-abc123.js")
                .header(header::IF_MODIFIED_SINCE, "Fri, 31 Dec 2100 23:59:59 GMT")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
}

/// A symlink in the bundle never leads outside it.
#[cfg(unix)]
#[tokio::test]
async fn test_symlinks_out_of_the_bundle_are_refused() {
    let dir = bundle_dir("symlink");
    let outside = std::env::temp_dir().join(format!("sid-ui-host-secret-{}", std::process::id()));
    std::fs::write(&outside, "secret").unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("assets/leak.txt")).unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("leak.txt")).unwrap();
    let app = router(UiBundle::new(&dir, "/account/", CONFIG).unwrap());
    for path in ["/account/assets/leak.txt", "/account/leak.txt"] {
        let (status, response) = get_path(&app, Method::GET, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(!body(response).await.contains("secret"), "{path}");
    }
}

/// A mount path is a literal path, never route syntax that would capture
/// other paths of the host.
#[test]
fn test_route_syntax_in_mounts_is_refused() {
    let dir = bundle_dir("mountsyntax");
    for mount in ["/{tenant}/", "/*all/", "/a//b/", "/a b/", "/:id/"] {
        assert!(
            matches!(
                UiBundle::new(&dir, mount, CONFIG),
                Err(BundleError::Mount(_))
            ),
            "{mount}"
        );
    }
    assert!(UiBundle::new(&dir, "/account/v-2_x.y~/", CONFIG).is_ok());
}

/// A file at the bundle root is served, uncached.
#[tokio::test]
async fn test_root_files_are_served() {
    let (status, response) = get_path(&app("root"), Method::GET, "/account/favicon.ico").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header_of(&response, header::CACHE_CONTROL).as_deref(),
        Some("no-store")
    );
}

/// Nothing outside the bundle directory is reachable through the mount.
#[tokio::test]
async fn test_traversal_is_refused() {
    let app = app("traversal");
    for path in [
        "/account/../Cargo.toml",
        "/account/assets/../../etc/passwd.txt",
        "/account/%2e%2e/secret.txt",
    ] {
        let (status, _) = get_path(&app, Method::GET, path).await;
        assert_ne!(status, StatusCode::OK, "{path}");
    }
}

/// Paths outside the mount are not the UI's: protocol endpoints, callbacks
/// and APIs on the same origin are left to their owners.
#[tokio::test]
async fn test_other_paths_are_not_served() {
    let app = app("outside");
    for path in [
        "/",
        "/auth/callback",
        "/api/v1/x",
        "/i/abc/oauth2/authorize",
        "/accounts",
    ] {
        let (status, _) = get_path(&app, Method::GET, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

/// The UI is read-only.
#[tokio::test]
async fn test_only_reads_are_allowed() {
    let (status, _) = get_path(&app("methods"), Method::POST, "/account/login").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, _) = get_path(&app("head"), Method::HEAD, "/account/login").await;
    assert_eq!(status, StatusCode::OK);
}

/// Every response isolates the page, as the threaded password client needs.
#[tokio::test]
async fn test_responses_are_cross_origin_isolated() {
    let (_, response) = get_path(&app("isolation"), Method::GET, "/account/login").await;
    assert_eq!(
        header_of(&response, "cross-origin-opener-policy".parse().unwrap()).as_deref(),
        Some("same-origin")
    );
    assert_eq!(
        header_of(&response, "cross-origin-embedder-policy".parse().unwrap()).as_deref(),
        Some("credentialless")
    );
}

/// A bundle or configuration that cannot be served is refused at start.
#[test]
fn test_unusable_bundles_are_refused() {
    let dir = bundle_dir("refused");
    assert!(matches!(
        UiBundle::new(&dir, "account/", CONFIG),
        Err(BundleError::Mount(_))
    ));
    assert!(matches!(
        UiBundle::new(&dir, "/account", CONFIG),
        Err(BundleError::Mount(_))
    ));
    let empty = std::env::temp_dir().join(format!("sid-ui-host-empty-{}", std::process::id()));
    std::fs::create_dir_all(&empty).unwrap();
    assert!(matches!(
        UiBundle::new(&empty, "/account/", CONFIG),
        Err(BundleError::NoShell(_))
    ));
    for config in [
        &b"[]"[..],
        b"{",
        br#"{"release":"1"}"#,
        br#"{"environment":"","release":"1"}"#,
    ] {
        assert!(
            matches!(
                UiBundle::new(&dir, "/account/", config),
                Err(BundleError::Config(_))
            ),
            "{}",
            String::from_utf8_lossy(config)
        );
    }
}

/// Embedded in a host application's router, the UI serves its mount and the
/// host keeps every other route, on the one listener.
#[tokio::test]
async fn test_embedded_beside_host_routes() {
    let host = Router::new()
        .route("/api/v1/ping", axum::routing::get(|| async { "pong" }))
        .merge(app("embedded"));
    let (status, response) = get_path(&host, Method::GET, "/api/v1/ping").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body(response).await, "pong");
    let (status, response) = get_path(&host, Method::GET, "/account/login").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body(response).await.contains("shell"));
}

/// A bundle mounted at the root serves its pages at `/`.
#[tokio::test]
async fn test_root_mount() {
    let app = router(UiBundle::new(&bundle_dir("rootmount"), "/", CONFIG).unwrap());
    let (status, _) = get_path(&app, Method::GET, "/").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get_path(&app, Method::GET, "/config.json").await;
    assert_eq!(status, StatusCode::OK);
}
