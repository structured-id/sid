// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::account::AccountLink;
use crate::session::BffSessionStore;
use axum::body::Body;
use axum::http::{HeaderValue, Request};
use std::sync::Arc;
use tower::ServiceExt;

/// A state whose session store cannot reach its backend, to check what
/// the endpoints answer during an outage.
fn broken_store_state() -> ProxyState {
    let mut state = bff_test_state();
    state.bff_sessions = Arc::new(BffSessionStore::new(
        Arc::new(UnreachableCache),
        std::time::Duration::from_secs(86400),
        std::time::Duration::from_secs(3600),
        std::time::Duration::from_secs(300),
    ));
    state
}

struct UnreachableCache;

#[async_trait::async_trait]
impl sid_plugin::cache::CacheBackend for UnreachableCache {
    async fn get(&self, _k: &str) -> sid_plugin::cache::CacheResult<Option<Vec<u8>>> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn set(
        &self,
        _k: &str,
        _v: &[u8],
        _t: std::time::Duration,
    ) -> sid_plugin::cache::CacheResult<()> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn delete(&self, _k: &str) -> sid_plugin::cache::CacheResult<()> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn take(&self, _k: &str) -> sid_plugin::cache::CacheResult<Option<Vec<u8>>> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn set_nx(
        &self,
        _k: &str,
        _v: &[u8],
        _t: std::time::Duration,
    ) -> sid_plugin::cache::CacheResult<bool> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn publish(&self, _c: &str, _m: &[u8]) -> sid_plugin::cache::CacheResult<()> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn subscribe(
        &self,
        _c: &str,
    ) -> sid_plugin::cache::CacheResult<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
    async fn health_check(&self) -> sid_plugin::cache::CacheResult<()> {
        Err(sid_plugin::cache::CacheError::Connection("down".into()))
    }
}

/// A valid-looking id, so the request reaches the store instead of being
/// turned away by the shape check.
fn plausible_session_id() -> String {
    "a".repeat(64)
}

/// The configured switch is the answer, not a key it was inferred from.
#[tokio::test]
async fn test_disabled_bff_serves_nothing_even_with_a_key() {
    let mut state = bff_test_state();
    state.bff_enabled = false;
    assert!(
        state.account.is_some(),
        "the key is set, so only the switch can turn this off"
    );

    for path in ["/auth/userinfo", "/auth/login", "/api/x"] {
        let response = routes()
            .layer(axum::extract::connect_info::MockConnectInfo(
                std::net::SocketAddr::from(([192, 0, 2, 1], 1)),
            ))
            .with_state(state.clone())
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

/// And enabling it without a client key is not enabled: the BFF could not
/// prove itself to SID or authenticate at its token endpoint.
#[tokio::test]
async fn test_enabled_bff_without_a_key_serves_nothing() {
    let mut state = bff_test_state();
    state.account = None;

    let app = routes().with_state(state);
    let response = app
        .oneshot(Request::get("/auth/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Before SID has provisioned the integration there is no sign-in to start:
/// 503, and the next request asks SID again.
#[tokio::test]
async fn test_login_without_a_connection_is_unavailable() {
    let mut state = bff_test_state();
    let (key, _) = crate::client_key::ClientKey::generate().unwrap();
    state.account = Some(Arc::new(AccountLink::new(
        key,
        "https://sid.example.com".into(),
        crate::test_channel(),
    )));
    let response = routes()
        .with_state(state)
        .oneshot(Request::get("/auth/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_login_reports_unavailable_when_the_store_is_down() {
    let app = routes().with_state(broken_store_state());
    let response = app
        .oneshot(Request::get("/auth/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// Not 400: "unknown state" would tell the caller its authorization was
/// rejected when in truth nobody could check it.
#[tokio::test]
async fn test_callback_reports_unavailable_when_the_store_is_down() {
    let app = routes().with_state(broken_store_state());
    let response = app
        .oneshot(
            Request::get(format!(
                "/auth/callback?state={}&code=abc",
                plausible_session_id()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// Not 401: an outage must not look like a signed-out user, or every
/// client logs itself out at once.
#[tokio::test]
async fn test_userinfo_reports_unavailable_when_the_store_is_down() {
    let app = routes().with_state(broken_store_state());
    let response = app
        .oneshot(
            Request::get("/auth/userinfo")
                .header(
                    "cookie",
                    format!("__Host-sid-bff={}", plausible_session_id()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// Clearing the cookies while the session stayed usable would be worse
/// than refusing: the caller would believe it had logged out.
#[tokio::test]
async fn test_logout_reports_unavailable_when_the_store_is_down() {
    let app = routes().with_state(broken_store_state());
    let response = app
        .oneshot(
            Request::post("/auth/logout")
                .header(
                    "cookie",
                    format!("__Host-sid-bff={}", plausible_session_id()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// The issuer the test BFF's client belongs to.
const BFF_ISSUER: &str = "https://sid.example.com/i/0123456789abcdef0123456789abcdef";
/// The account client's registered callback.
const CALLBACK: &str = "https://account.sid.example.com/auth/callback";

/// The connection SID would give the test BFF.
pub(crate) fn test_connection() -> Connection {
    Connection::from_answer(
        sid_proto::sid::v1::AccountConnection {
            issuer: BFF_ISSUER.into(),
            client_id: "account-web".into(),
            resource: "https://sid.example.com/account".into(),
            scopes: vec![
                "openid".into(),
                "profile".into(),
                "email".into(),
                "account".into(),
            ],
            redirect_uri: CALLBACK.into(),
            token_endpoint_auth_method: "private_key_jwt".into(),
        },
        "https://sid.example.com",
    )
    .unwrap()
}

pub(crate) fn bff_test_state() -> ProxyState {
    let (key, _) = crate::client_key::ClientKey::generate().unwrap();
    let mut state = crate::test_state();
    state.account = Some(Arc::new(AccountLink::connected(key, test_connection())));
    state
}

/// Login goes to the authorization endpoint of the BFF client's issuer.
#[tokio::test]
async fn test_login_goes_to_the_bff_issuer() {
    let response = routes()
        .with_state(bff_test_state())
        .oneshot(Request::get("/auth/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let location = response.headers()["location"].to_str().unwrap();
    assert!(
        location.starts_with(&format!("{BFF_ISSUER}/oauth2/authorize?")),
        "{location}"
    );
}

/// An authorization response that does not name the BFF's issuer, or names
/// another one, is refused before its code is used (RFC 9207 §2.4).
#[tokio::test]
async fn test_callback_from_another_issuer_is_refused() {
    for iss in [
        None,
        Some("https://sid.example.com/i/fedcba9876543210fedcba9876543210"),
    ] {
        let state = bff_test_state();
        let state_param = state
            .bff_sessions
            .store_pending("verifier".into(), "nonce".into(), "/".into())
            .await
            .unwrap();
        let mut uri = format!("/auth/callback?state={state_param}&code=abc");
        if let Some(iss) = iss {
            uri.push_str(&format!("&iss={}", urlencode(iss)));
        }
        let response = routes()
            .with_state(state)
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{iss:?}");
    }
}

fn urlencode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[test]
fn test_pkce_verifier_length() {
    let verifier = generate_pkce_verifier();
    assert!(verifier.len() >= 43);
}

#[test]
fn test_pkce_challenge_deterministic() {
    let verifier = "test_verifier_string";
    let c1 = generate_pkce_challenge(verifier);
    let c2 = generate_pkce_challenge(verifier);
    assert_eq!(c1, c2);
}

#[test]
fn test_pkce_challenge_different_for_different_verifiers() {
    let c1 = generate_pkce_challenge("verifier_a");
    let c2 = generate_pkce_challenge("verifier_b");
    assert_ne!(c1, c2);
}

#[tokio::test]
async fn test_bff_disabled_returns_404() {
    let state = crate::test_state(); // no client key = BFF disabled
    let app = routes().with_state(state);

    let req = Request::builder()
        .uri("/auth/login")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_login_redirect_includes_state_and_pkce() {
    let state = bff_test_state();
    let app = routes().with_state(state);

    let req = Request::builder()
        .uri("/auth/login?rd=/dashboard")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], "account-web");
    assert_eq!(query["redirect_uri"], CALLBACK);
    assert_eq!(query["resource"], "https://sid.example.com/account");
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(!query["code_challenge"].is_empty());
    assert!(!query["state"].is_empty());
}

/// The return path is kept only when it stays on this origin: an absolute
/// URL, a scheme-relative `//host` or `/\host` would make the BFF an open
/// redirector.
#[test]
fn test_only_local_return_paths_are_kept() {
    assert_eq!(local_path(Some("/settings?tab=keys")), "/settings?tab=keys");
    for foreign in [
        None,
        Some("https://evil.example/"),
        Some("//evil.example/"),
        Some("/\\evil.example/"),
        Some("settings"),
        Some("/a\r\nSet-Cookie: x=y"),
    ] {
        assert_eq!(local_path(foreign), "/", "{foreign:?}");
    }
}

/// A foreign return path is not stored for the callback to redirect to.
#[tokio::test]
async fn test_login_with_a_foreign_return_path_returns_to_the_root() {
    let state = bff_test_state();
    let sessions = state.bff_sessions.clone();
    let response = routes()
        .with_state(state)
        .oneshot(
            Request::get("/auth/login?rd=https://evil.example/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let location = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    let state_param = location
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let pending = sessions.take_pending(&state_param).await.unwrap().unwrap();
    assert_eq!(pending.redirect_url, "/");
}

#[tokio::test]
async fn test_callback_unknown_state_returns_400() {
    let state = bff_test_state();
    let app = routes().with_state(state);

    let req = Request::builder()
        .uri("/auth/callback?state=unknown&code=test_code")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_callback_auth_error_returns_403() {
    let state = bff_test_state();
    // Store a pending auth first
    let state_param = state
        .bff_sessions
        .store_pending("verifier".into(), "nonce".into(), "/".into())
        .await
        .unwrap();
    let app = routes().with_state(state);

    let req = Request::builder()
        .uri(format!(
            "/auth/callback?state={}&error=access_denied&iss={}",
            state_param,
            urlencode(BFF_ISSUER)
        ))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_logout_clears_cookie() {
    let state = bff_test_state();
    let claims = sid_auth::auth::jwt::ForwardAuthClaims {
        sub: "user1".into(),
        iss: "test".into(),
        exp: 0,
        iat: 0,
        auth_time: 0,
        acr: "basic".into(),
        scope: "".into(),
        roles: "".into(),
        sid: "s1".into(),
        jti: "j1".into(),
        email: None,
        name: None,
        preferred_username: None,
        groups: None,
        cnf: None,
    };
    let (session_id, csrf_token) = state
        .bff_sessions
        .create_session("token".into(), None, claims)
        .await
        .unwrap();
    assert!(
        state
            .bff_sessions
            .get_session(&session_id)
            .await
            .unwrap()
            .is_some()
    );

    let app = routes().with_state(state);

    let req = Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .header("cookie", format!("__Host-sid-bff={}", session_id))
        .header("x-csrf-token", &csrf_token)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(set_cookie.contains("Max-Age=0"));
    assert!(set_cookie.contains("__Host-sid-bff="));
}

#[tokio::test]
async fn test_userinfo_no_cookie_returns_401() {
    let state = bff_test_state();
    let app = routes().with_state(state);

    let req = Request::builder()
        .uri("/auth/userinfo")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_userinfo_invalid_session_returns_401() {
    let state = bff_test_state();
    let app = routes().with_state(state);

    let req = Request::builder()
        .uri("/auth/userinfo")
        .header("cookie", "__Host-sid-bff=nonexistent_session")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

fn session_claims() -> sid_auth::auth::jwt::ForwardAuthClaims {
    sid_auth::auth::jwt::ForwardAuthClaims {
        sub: "up_01HY000000000000000000".into(),
        iss: "https://sid.example.com".into(),
        exp: 9999999999,
        iat: 1000000000,
        auth_time: 1000000000,
        acr: "standard".into(),
        scope: "openid".into(),
        roles: "admin".into(),
        sid: "sess_01".into(),
        jti: "tok_01".into(),
        email: Some("user@sid.example.com".into()),
        name: Some("Test User".into()),
        preferred_username: Some("testuser".into()),
        groups: None,
        cnf: None,
    }
}

#[tokio::test]
async fn test_userinfo_valid_session_returns_claims() {
    let state = bff_test_state();
    let (session_id, _csrf) = state
        .bff_sessions
        .create_session("access_token".into(), None, session_claims())
        .await
        .unwrap();
    let app = routes().with_state(state);

    let req = Request::builder()
        .uri("/auth/userinfo")
        .header("cookie", format!("__Host-sid-bff={}", session_id))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["sub"], "up_01HY000000000000000000");
    assert_eq!(json["email"], "user@sid.example.com");
    assert_eq!(json["name"], "Test User");
    assert_eq!(json["preferred_username"], "testuser");
    assert_eq!(json["acr"], "standard");
    assert_eq!(json["roles"], "admin");
}

/// The session's CSRF token reaches the page with the session check, which
/// the page makes on every boot: no readable cookie whose name the page
/// would have to know. A state-changing call echoes it in `X-CSRF-Token`.
#[tokio::test]
async fn test_userinfo_carries_the_sessions_csrf_token() {
    let state = bff_test_state();
    let (session_id, csrf) = state
        .bff_sessions
        .create_session("access_token".into(), None, session_claims())
        .await
        .unwrap();
    let app = routes().with_state(state);

    let req = Request::builder()
        .uri("/auth/userinfo")
        .header("cookie", format!("__Host-sid-bff={}", session_id))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["csrf_token"], csrf);
}

/// A BFF session whose SID session was revoked (sign-out elsewhere, admin
/// kill) signs the browser out: 401, and the stored session is destroyed.
#[tokio::test]
async fn test_userinfo_revoked_session_signs_out() {
    let state = bff_test_state();
    let (session_id, _csrf) = state
        .bff_sessions
        .create_session("access_token".into(), None, session_claims())
        .await
        .unwrap();
    state
        .revocation
        .revoke_session("sess_01".into())
        .await
        .unwrap();
    let sessions = state.bff_sessions.clone();
    let app = routes().with_state(state);

    let req = Request::builder()
        .uri("/auth/userinfo")
        .header("cookie", format!("__Host-sid-bff={}", session_id))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(sessions.get_session(&session_id).await.unwrap().is_none());
}

#[test]
fn test_extract_bff_cookie() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_static("other=val; __Host-sid-bff=sess123; foo=bar"),
    );
    assert_eq!(
        extract_bff_cookie(&headers, "__Host-sid-bff"),
        Some("sess123".to_string())
    );
}

#[test]
fn test_extract_bff_cookie_missing() {
    let headers = axum::http::HeaderMap::new();
    assert_eq!(extract_bff_cookie(&headers, "__Host-sid-bff"), None);
}

#[tokio::test]
async fn test_pending_store_and_take() {
    let store = BffSessionStore::new(
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        std::time::Duration::from_secs(86400),
        std::time::Duration::from_secs(3600),
        std::time::Duration::from_secs(300),
    );
    let state = store
        .store_pending("verifier123".into(), "nonce123".into(), "/dashboard".into())
        .await
        .unwrap();
    assert!(!state.is_empty());

    let pending = store.take_pending(&state).await.unwrap().unwrap();
    assert_eq!(pending.code_verifier, "verifier123");
    assert_eq!(pending.nonce, "nonce123");
    assert_eq!(pending.redirect_url, "/dashboard");

    // Second take returns None (consumed)
    assert!(store.take_pending(&state).await.unwrap().is_none());
}
