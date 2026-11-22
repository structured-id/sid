// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::{AuditEntry, WebSettings};
use sid_plugin::StorageBackend;

/// A host name without its port, an IPv6 literal with its brackets.
#[test]
fn host_name_drops_the_port() {
    assert_eq!(host_name("sid.example.com"), "sid.example.com");
    assert_eq!(host_name("sid.example.com:8080"), "sid.example.com");
    assert_eq!(host_name("[::1]:8080"), "[::1]");
    assert_eq!(host_name("[::1]"), "[::1]");
}

// The account adapter reaches the gRPC listener where it actually listens:
// a wildcard bind on the loopback of its own family, a specific address as
// it is. Bug prevented: an adapter dialing 127.0.0.1 while the server
// listens only on [::1] or on one interface, so sign-in fails at run time.
#[test]
fn the_adapter_reaches_the_bound_grpc_address() {
    for (bound, reached) in [
        ("0.0.0.0:50051", "http://127.0.0.1:50051"),
        ("[::]:50051", "http://[::1]:50051"),
        ("127.0.0.1:50051", "http://127.0.0.1:50051"),
        ("[::1]:50051", "http://[::1]:50051"),
        ("10.0.0.5:50051", "http://10.0.0.5:50051"),
    ] {
        assert_eq!(reachable(bound.parse().unwrap()), reached, "{bound}");
    }
}

/// A console over a store whose settings are `stored`, with a bundle in a
/// temporary directory.
async fn console(stored: Option<WebSettings>) -> (Console, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("index.html"),
        "<!doctype html><html><head><title>console</title></head></html>",
    )
    .unwrap();
    let storage: Arc<dyn StorageBackend> = Arc::new(
        sid_storage::sqlite::SqliteBackend::new(dir.path().join("sid.db").to_str().unwrap())
            .await
            .unwrap(),
    );
    if let Some(stored) = stored {
        storage
            .set_web_settings(
                &stored,
                None,
                None,
                AuditEntry::system("test", "web_settings").into(),
            )
            .await
            .unwrap();
    }
    let web = Arc::new(sid::web_settings::WebSettingsAdmin::new(
        storage,
        &url::Url::parse("https://sid.example.com").unwrap(),
    ));
    (
        Console {
            dir: dir.path().to_owned(),
            web,
            served: Mutex::new(None),
        },
        dir,
    )
}

/// A GET of `path` on `host`.
fn get(host: &str, path: &str) -> RouteRequest {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, host.parse().unwrap());
    RouteRequest::new(
        http::Method::GET,
        path.parse().unwrap(),
        headers,
        axum::body::Bytes::new(),
        structured_proxy::ClientAddress::from_peer(None),
    )
}

/// The shell served under `mount` names it as its base.
fn shell_of(response: &RouteResponse, mount: &str) {
    assert_eq!(response.status, http::StatusCode::OK);
    let body = std::str::from_utf8(&response.body).unwrap();
    assert!(body.contains(&format!("<base href=\"{mount}\">")), "{body}");
}

/// A fresh installation serves the console at /admin/ on its own host, deep
/// links included; nothing else of the origin is the console's.
#[tokio::test]
async fn console_defaults_to_admin_on_the_installation_host() {
    let (console, _dir) = console(None).await;
    for path in ["/admin/", "/admin", "/admin/users/42"] {
        shell_of(
            &console.handle(get("sid.example.com", path)).await,
            "/admin/",
        );
    }
    for (host, path) in [
        ("sid.example.com", "/"),
        ("sid.example.com", "/administrator/"),
        ("other.example.com", "/admin/"),
    ] {
        assert_eq!(
            console.handle(get(host, path)).await.status,
            http::StatusCode::NOT_FOUND,
            "{host}{path}"
        );
    }
}

/// Moved to another prefix, the console is served there and no longer at
/// /admin/; moved to the root of a sibling host, only that host serves it.
#[tokio::test]
async fn console_follows_its_placement() {
    let (moved, _a) = console(Some(WebSettings {
        console_url: Some("https://sid.example.com/console/".into()),
        revision: 1,
        ..WebSettings::default()
    }))
    .await;
    shell_of(
        &moved.handle(get("sid.example.com", "/console/roles")).await,
        "/console/",
    );
    assert_eq!(
        moved.handle(get("sid.example.com", "/admin/")).await.status,
        http::StatusCode::NOT_FOUND
    );

    let (sibling, _b) = console(Some(WebSettings {
        console_url: Some("https://admin.example.com/".into()),
        revision: 1,
        ..WebSettings::default()
    }))
    .await;
    shell_of(
        &sibling.handle(get("admin.example.com:443", "/users")).await,
        "/",
    );
    assert_eq!(
        sibling.handle(get("sid.example.com", "/")).await.status,
        http::StatusCode::NOT_FOUND
    );
}
