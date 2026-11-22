// SPDX-License-Identifier: AGPL-3.0-only
//! The installation session established on a selected subdomain: three
//! navigations move a live session from the base host to a host the
//! selected scope admits, as a host-only cookie there, and nothing else
//! establishes it.

mod common;

use std::sync::Arc;

use axum::body::Body;
use common::mock_storage::MockStorage;
use sid_authn::browser_session::{BrowserCookie, BrowserSecret};
use sid_core::models::{AuditEntry, CookieScope, ProfileId, Session, WebSettings};
use sid_plugin::StorageBackend;
use tonic::codegen::http::{self, StatusCode, header};
use tower::ServiceExt;

const APP: &str = "app.sid.example.com";
const BASE: &str = "sid.example.com";

async fn with_scope(storage: &MockStorage, scope: CookieScope) {
    let stored = storage.web_settings().await.unwrap();
    let held = stored.clone().unwrap_or_default();
    assert!(
        storage
            .set_web_settings(
                &WebSettings {
                    cookie_scope: scope,
                    revision: held.revision + 1,
                    ..held
                },
                stored.as_ref(),
                None,
                AuditEntry::system("test", "web_settings").into()
            )
            .await
            .unwrap()
    );
}

fn selected() -> CookieScope {
    CookieScope::SelectedSubdomains {
        hosts: vec![APP.into()],
        pattern: None,
    }
}

/// A signed-in browser: its stored session and the cookie secret.
async fn signed_in(storage: &MockStorage) -> BrowserSecret {
    let secret = BrowserSecret::generate();
    let mut session = Session::new(
        ProfileId::generate(),
        None,
        jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1),
    );
    session.browser_secret_hash = Some(secret.hash());
    storage
        .create_session(&session, AuditEntry::system("test", "session").into())
        .await
        .unwrap();
    secret
}

fn router(storage: Arc<MockStorage>) -> axum::Router {
    let routes = sid_server::session_establish::routes(
        common::test_web_settings(storage.clone()),
        storage,
        common::test_key_manager(),
        BrowserCookie::default(),
    );
    structured_proxy::ProxyServer::new()
        .with_upstream_address("http://127.0.0.1:1")
        .with_extra_routes(routes)
        .router()
        .unwrap()
}

/// A GET of `path_and_query` on `host` carrying `cookie`.
async fn get(
    app: &axum::Router,
    host: &str,
    path_and_query: &str,
    cookie: Option<&str>,
) -> http::Response<Body> {
    let mut request = http::Request::get(path_and_query).header(header::HOST, host);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn location(response: &http::Response<Body>) -> url::Url {
    let value = response.headers()[header::LOCATION].to_str().unwrap();
    url::Url::parse(value)
        .or_else(|_| url::Url::parse(&format!("https://{APP}{value}")))
        .unwrap()
}

/// The `name=value` pair of the `Set-Cookie` header naming `name`.
fn set_pair(response: &http::Response<Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .find(|v| v.starts_with(&format!("{name}=")))
        .map(|v| v.split(';').next().unwrap().to_owned())
}

/// Steps 1 and 2 for a browser signed in with `secret`: the correlation
/// cookie step 1 set on the app host and the completion URL step 2 named.
async fn started(app: &axum::Router, secret: &BrowserSecret) -> (String, url::Url) {
    let first = get(app, APP, "/session/establish?return=/home", None).await;
    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    let grant = location(&first);
    assert_eq!(grant.host_str(), Some(BASE));
    assert_eq!(grant.path(), "/session/grant");
    let correlation = set_pair(&first, "__Host-sid_establish").unwrap();

    let session = format!("__Host-sid_session={}", secret.encode().as_str());
    let path = format!("{}?{}", grant.path(), grant.query().unwrap());
    let second = get(app, BASE, &path, Some(&session)).await;
    assert_eq!(second.status(), StatusCode::SEE_OTHER);
    let complete = location(&second);
    assert_eq!(complete.host_str(), Some(APP));
    assert_eq!(complete.path(), "/session/complete");
    (correlation, complete)
}

// The three navigations put the browser's live session on the selected
// host as its own host-only cookie and continue at the page's path. Bug
// prevented: a selected scope that leaves every listed host signed out.
#[tokio::test]
async fn a_selected_host_establishes_its_own_cookie() {
    let storage = Arc::new(MockStorage::new());
    with_scope(&storage, selected()).await;
    let secret = signed_in(&storage).await;
    let app = router(storage);
    let (correlation, complete) = started(&app, &secret).await;

    let path = format!("{}?{}", complete.path(), complete.query().unwrap());
    let third = get(&app, APP, &path, Some(&correlation)).await;
    assert_eq!(third.status(), StatusCode::SEE_OTHER);
    assert_eq!(third.headers()[header::LOCATION], "/home");
    let set = third
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .find(|v| v.starts_with("__Host-sid_session="))
        .unwrap();
    assert!(!set.contains("Domain"), "{set}");
    let read = BrowserCookie::default()
        .secret([set.split(';').next().unwrap()])
        .unwrap();
    assert_eq!(read.hash(), secret.hash());
    assert_eq!(
        set_pair(&third, "__Host-sid_establish").as_deref(),
        Some("__Host-sid_establish=")
    );
}

// A grant completed without the correlation cookie of the browser that
// started it establishes nothing, and is spent: a second try, even with
// the right cookie, fails too. Bug prevented: login CSRF, where another
// browser's grant key signs the victim in as someone else.
#[tokio::test]
async fn a_grant_needs_the_browser_that_started_it() {
    let storage = Arc::new(MockStorage::new());
    with_scope(&storage, selected()).await;
    let secret = signed_in(&storage).await;
    let app = router(storage);
    let (correlation, complete) = started(&app, &secret).await;
    let path = format!("{}?{}", complete.path(), complete.query().unwrap());

    let foreign = get(&app, APP, &path, Some("__Host-sid_establish=other")).await;
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
    assert!(set_pair(&foreign, "__Host-sid_session").is_none());
    let late = get(&app, APP, &path, Some(&correlation)).await;
    assert_eq!(late.status(), StatusCode::FORBIDDEN);
}

// A host the scope does not select, the base host itself and another scope
// serve none of the steps; a grant is never made for an unselected host,
// and a browser without a session is sent to sign in.
#[tokio::test]
async fn only_selected_hosts_of_a_selected_scope_are_served() {
    let storage = Arc::new(MockStorage::new());
    with_scope(&storage, selected()).await;
    let app = router(storage.clone());
    let other = get(&app, "other.sid.example.com", "/session/establish", None).await;
    assert_eq!(other.status(), StatusCode::NOT_FOUND);
    let base = get(&app, BASE, "/session/establish", None).await;
    assert_eq!(base.status(), StatusCode::NOT_FOUND);
    let unselected = get(
        &app,
        BASE,
        "/session/grant?host=other.sid.example.com&correlation=x&return=/",
        None,
    )
    .await;
    assert_eq!(unselected.status(), StatusCode::FORBIDDEN);
    let signed_out = get(
        &app,
        BASE,
        &format!("/session/grant?host={APP}&correlation=x&return=/"),
        None,
    )
    .await;
    assert_eq!(signed_out.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&signed_out).as_str(),
        "https://sid.example.com/account/"
    );

    let storage = Arc::new(MockStorage::new());
    with_scope(&storage, CookieScope::AllSubdomains).await;
    let app = router(storage);
    let wide = get(&app, APP, "/session/establish", None).await;
    assert_eq!(wide.status(), StatusCode::NOT_FOUND);
}
