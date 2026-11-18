// SPDX-License-Identifier: AGPL-3.0-only
//! The BFF's HTTP surface: what each route answers for each outcome of the
//! shared browser sessions, and the cookies it sets. The sessions' own
//! decisions are tested with them.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use sid_authn::bff_session::{BffSessionStore, SessionClaims};
use sid_authn::relying_party::Connection;
use sid_authn::revocation_cache::RevocationCache;
use sid_plugin::CeremonyStateStore;
use tower::ServiceExt;

use super::*;

/// The issuer the test BFF's client belongs to.
const BFF_ISSUER: &str = "https://sid.example.com/i/0123456789abcdef0123456789abcdef";
/// The account application's origin: its registered callback's.
pub(crate) const ORIGIN: &str = "https://account.sid.example.com";
/// The account client's registered callback.
const CALLBACK: &str = "https://account.sid.example.com/auth/callback";
pub(crate) const COOKIE: &str = "__Host-sid-bff";
const LONG: std::time::Duration = std::time::Duration::from_secs(3600);

/// The connection SID would give the test BFF.
pub(crate) fn test_connection() -> Connection {
    Connection::accept(
        sid_authn::client_connection::ClientConnection {
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
            key_ids: vec!["bff-key".into()],
        },
        "https://sid.example.com",
    )
    .unwrap()
}

/// A proxy whose BFF is on, and the stores behind its sessions.
pub(crate) struct Bff {
    pub(crate) state: ProxyState,
    pub(crate) sessions: Arc<BffSessionStore>,
    revocation: Arc<RevocationCache>,
}

/// A BFF over `store`, with its connection delivered or, when `delivered`
/// is false, to be asked of a SID that never answers.
pub(crate) fn bff_with(store: Arc<dyn CeremonyStateStore>, delivered: bool) -> Bff {
    let (key, _) = sid_authn::client_key::ClientKey::generate_ed25519().unwrap();
    let channel = sid_infra::deadline::issuer(crate::test_channel());
    let client = if delivered {
        RpClient::delivered(
            key,
            "https://sid.example.com".into(),
            channel,
            test_connection(),
        )
    } else {
        RpClient::new(key, "https://sid.example.com".into(), channel)
    }
    .unwrap();
    let sessions = Arc::new(BffSessionStore::new(store, LONG, LONG, LONG));
    let revocation =
        RevocationCache::receiver_view(Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()));
    let mut state = crate::test_state();
    state.bff = Some(Arc::new(BrowserSessions::new(
        Arc::new(client),
        crate::test_issuers(),
        sessions.clone(),
        revocation.clone(),
        COOKIE.into(),
    )));
    Bff {
        state,
        sessions,
        revocation,
    }
}

/// A BFF over an in-process store, its connection delivered.
pub(crate) fn bff() -> Bff {
    bff_with(Arc::new(sid_plugin::InProcessCeremonyState::new()), true)
}

pub(crate) fn session_claims() -> SessionClaims {
    SessionClaims {
        sub: "up_01HY000000000000000000".into(),
        iss: BFF_ISSUER.into(),
        exp: chrono::Utc::now().timestamp() + 3600,
        iat: 1_000_000_000,
        auth_time: 1_000_000_000,
        acr: "standard".into(),
        scope: "openid".into(),
        roles: "admin".into(),
        sid: "sess_01".into(),
        jti: "tok_01".into(),
        email: Some("user@sid.example.com".into()),
        name: Some("Test User".into()),
        preferred_username: Some("testuser".into()),
        groups: Some(vec!["staff".into()]),
    }
}

/// A live session of the BFF's connection: its id and CSRF token.
pub(crate) async fn signed_in(bff: &Bff, refresh: Option<&str>) -> (String, String) {
    bff.sessions
        .create_session(
            "access-1".into(),
            refresh.map(secrecy::SecretString::from),
            session_claims(),
            &test_connection().binding(),
        )
        .await
        .unwrap()
}

async fn send(state: ProxyState, request: Request<Body>) -> Response {
    routes()
        .layer(axum::extract::connect_info::MockConnectInfo(
            std::net::SocketAddr::from(([192, 0, 2, 7], 40000)),
        ))
        .with_state(state)
        .oneshot(request)
        .await
        .unwrap()
}

/// A logout from the application's page.
fn logout(cookie: Option<&str>, csrf: Option<&str>) -> Request<Body> {
    let mut request = Request::post("/auth/logout").header("origin", ORIGIN);
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    if let Some(csrf) = csrf {
        request = request.header("x-csrf-token", csrf);
    }
    request.body(Body::empty()).unwrap()
}

/// What a logout answered about the grant behind the session.
async fn logout_grant(response: Response) -> String {
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    json["grant"].as_str().unwrap().to_owned()
}

/// A session store whose every call fails, as an unreachable database does.
struct UnreachableStore;

fn down() -> sid_core::Error {
    sid_core::Error::Storage("down".into())
}

#[async_trait::async_trait]
impl sid_plugin::SingleUseAdmissions for UnreachableStore {
    async fn admit_once(&self, _: &str, _: &str, _: std::time::Duration) -> sid_core::Result<bool> {
        Err(down())
    }
    async fn admit_for(
        &self,
        _: &str,
        _: &str,
        _: &[u8],
        _: std::time::Duration,
    ) -> sid_core::Result<bool> {
        Err(down())
    }
}

#[async_trait::async_trait]
impl CeremonyStateStore for UnreachableStore {
    async fn put_ceremony_state(
        &self,
        _: &str,
        _: &str,
        _: &[u8],
        _: std::time::Duration,
    ) -> sid_core::Result<()> {
        Err(down())
    }
    async fn take_ceremony_state(&self, _: &str, _: &str) -> sid_core::Result<Option<Vec<u8>>> {
        Err(down())
    }
    async fn read_ceremony_state(&self, _: &str, _: &str) -> sid_core::Result<Option<Vec<u8>>> {
        Err(down())
    }
    async fn replace_ceremony_state(
        &self,
        _: &str,
        _: &str,
        _: &[u8],
        _: &[u8],
        _: std::time::Duration,
    ) -> sid_core::Result<bool> {
        Err(down())
    }
    async fn count_in_window(
        &self,
        _: &str,
        _: &str,
        _: std::time::Duration,
    ) -> sid_core::Result<u64> {
        Err(down())
    }
    async fn read_count(&self, _: &str, _: &str) -> sid_core::Result<u64> {
        Err(down())
    }
    async fn clear_count(&self, _: &str, _: &str) -> sid_core::Result<()> {
        Err(down())
    }
    async fn purge_expired_ceremony_state(&self) -> sid_core::Result<u64> {
        Err(down())
    }
}

/// A valid-looking id, so the request reaches the store instead of being
/// turned away by the shape check.
fn plausible_session_id() -> String {
    "a".repeat(64)
}

fn urlencode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// The `name=value` of the first cookie `response` sets.
fn set_cookie(response: &Response) -> String {
    response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .to_owned()
}

// ── Off ──

/// A proxy without BFF sessions (switched off, or without a client key)
/// serves none of its routes.
#[tokio::test]
async fn an_absent_bff_serves_nothing() {
    for path in [
        "/auth/login",
        "/auth/userinfo",
        "/auth/callback?state=x",
        "/api/x",
    ] {
        let response = send(
            crate::test_state(),
            Request::get(path).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

// ── Sign-in ──

/// Login goes to the authorization endpoint of the BFF client's issuer with
/// the code flow, S256 PKCE and the resource, and gives the browser the
/// sign-in's correlation cookie: HttpOnly, Secure, SameSite=Lax, lasting as
/// long as the sign-in waits.
#[tokio::test]
async fn login_redirects_to_the_issuer_with_its_correlation_cookie() {
    let bff = bff();
    let response = send(
        bff.state,
        Request::get("/auth/login?rd=/dashboard")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    assert!(
        location
            .as_str()
            .starts_with(&format!("{BFF_ISSUER}/oauth2/authorize?")),
        "{location}"
    );
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], "account-web");
    assert_eq!(query["redirect_uri"], CALLBACK);
    assert_eq!(query["resource"], "https://sid.example.com/account");
    assert_eq!(query["code_challenge_method"], "S256");
    let cookie = set_cookie(&response);
    let correlation = sid_authn::relying_party::sign_in_cookie(COOKIE, &query["state"]);
    assert!(cookie.starts_with(&format!("{correlation}=")), "{cookie}");
    for attribute in ["HttpOnly", "Secure", "SameSite=Lax", "Max-Age=3600"] {
        assert!(cookie.contains(attribute), "{attribute}: {cookie}");
    }
}

/// In development over plain HTTP the cookies drop only `Secure`.
#[tokio::test]
async fn dev_mode_cookies_are_not_secure() {
    let mut bff = bff();
    bff.state.bff_dev_mode = true;
    let response = send(
        bff.state,
        Request::get("/auth/login").body(Body::empty()).unwrap(),
    )
    .await;
    let cookie = set_cookie(&response);
    assert!(!cookie.contains("Secure"), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
}

/// Before SID has provisioned the integration, or with the store down, there
/// is no sign-in to start: 503.
#[tokio::test]
async fn login_is_unavailable_without_a_connection_or_a_store() {
    for bff in [
        bff_with(Arc::new(sid_plugin::InProcessCeremonyState::new()), false),
        bff_with(Arc::new(UnreachableStore), true),
    ] {
        let response = send(
            bff.state,
            Request::get("/auth/login").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

/// A callback without the sign-in's correlation cookie, or with another
/// browser's secret in it, is 400 and leaves the sign-in for its own
/// browser, which completes it: here the issuer refused, so 403. Only the
/// taken sign-in's correlation cookie is cleared.
#[tokio::test]
async fn a_callback_completes_only_in_its_own_browser() {
    let bff = bff();
    let login = send(
        bff.state.clone(),
        Request::get("/auth/login").body(Body::empty()).unwrap(),
    )
    .await;
    let location = url::Url::parse(login.headers()["location"].to_str().unwrap()).unwrap();
    let state = location
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let correlation = sid_authn::relying_party::sign_in_cookie(COOKIE, &state);
    let own = set_cookie(&login).split(';').next().unwrap().to_owned();
    let callback = format!(
        "/auth/callback?state={state}&error=access_denied&iss={}",
        urlencode(BFF_ISSUER)
    );
    for foreign in [None, Some(format!("{correlation}=another-browsers-secret"))] {
        let mut request = Request::get(&callback);
        if let Some(cookie) = &foreign {
            request = request.header("cookie", cookie);
        }
        let response = send(bff.state.clone(), request.body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{foreign:?}");
        assert!(response.headers().get("set-cookie").is_none());
    }
    let response = send(
        bff.state,
        Request::get(&callback)
            .header("cookie", own)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let cleared = set_cookie(&response);
    assert!(
        cleared.starts_with(&format!("{correlation}=;")) && cleared.contains("Max-Age=0"),
        "{cleared}"
    );
}

/// An authorization response that names another issuer, or none, is 400.
#[tokio::test]
async fn a_callback_from_another_issuer_is_refused() {
    for iss in [
        None,
        Some("https://sid.example.com/i/fedcba9876543210fedcba9876543210"),
    ] {
        let bff = bff();
        let state = bff
            .sessions
            .store_pending(
                "verifier".into(),
                "nonce".into(),
                "/".into(),
                &test_connection().browser_sign_in_binding("browser"),
            )
            .await
            .unwrap();
        let mut uri = format!("/auth/callback?state={state}&code=abc");
        if let Some(iss) = iss {
            uri.push_str(&format!("&iss={}", urlencode(iss)));
        }
        let cookie = sid_authn::relying_party::sign_in_cookie(COOKIE, &state);
        let response = send(
            bff.state,
            Request::get(uri)
                .header("cookie", format!("{cookie}=browser"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{iss:?}");
    }
}

/// A sign-in started under another connection is not completed under this
/// one, and is not consumed: during a rollout a replica of that connection
/// may still complete it.
#[tokio::test]
async fn a_sign_in_of_another_connection_is_refused_and_kept() {
    let bff = bff();
    let other = "https://sid.example.com/i/0123456789abcdef0123456789abcdef\nother-web\nhttps://sid.example.com/account\nbrowser";
    let state = bff
        .sessions
        .store_pending("verifier".into(), "nonce".into(), "/".into(), other)
        .await
        .unwrap();
    let cookie = sid_authn::relying_party::sign_in_cookie(COOKIE, &state);
    let response = send(
        bff.state,
        Request::get(format!(
            "/auth/callback?state={state}&code=abc&iss={}",
            urlencode(BFF_ISSUER)
        ))
        .header("cookie", format!("{cookie}=browser"))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        bff.sessions
            .take_pending(&state, other)
            .await
            .unwrap()
            .is_some()
    );
}

/// Not 400: with the store down nobody could check the state, so the answer
/// is that the sign-in is unavailable.
#[tokio::test]
async fn a_callback_with_the_store_down_is_unavailable() {
    let bff = bff_with(Arc::new(UnreachableStore), true);
    let state = plausible_session_id();
    let cookie = sid_authn::relying_party::sign_in_cookie(COOKIE, &state);
    let response = send(
        bff.state,
        Request::get(format!("/auth/callback?state={state}&code=abc"))
            .header("cookie", format!("{cookie}=browser"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ── Session check ──

/// The signed-in user with the session's CSRF token, which every
/// state-changing call echoes: the page reads it on boot.
#[tokio::test]
async fn userinfo_answers_the_session_and_its_csrf_token() {
    let bff = bff();
    let (id, csrf) = signed_in(&bff, None).await;
    let response = send(
        bff.state,
        Request::get("/auth/userinfo")
            .header("cookie", format!("{COOKIE}={id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["sub"], "up_01HY000000000000000000");
    assert_eq!(json["email"], "user@sid.example.com");
    assert_eq!(json["name"], "Test User");
    assert_eq!(json["preferred_username"], "testuser");
    assert_eq!(json["groups"], serde_json::json!(["staff"]));
    assert_eq!(json["acr"], "standard");
    assert_eq!(json["roles"], "admin");
    assert_eq!(json["csrf_token"], csrf);
}

/// No cookie, a cookie naming no session, a session of another connection
/// and a revoked SID session are all a signed-out user: 401. The revoked one
/// is removed; the other connection's is kept for its own replicas.
#[tokio::test]
async fn userinfo_without_a_live_session_is_unauthenticated() {
    let bff = bff();
    let (other, _) = bff
        .sessions
        .create_session("token".into(), None, session_claims(), "another connection")
        .await
        .unwrap();
    let (revoked, _) = signed_in(&bff, None).await;
    bff.revocation
        .revoke_session("sess_01".into())
        .await
        .unwrap();
    for cookie in [
        None,
        Some(format!("{COOKIE}={}", plausible_session_id())),
        Some(format!("{COOKIE}={other}")),
        Some(format!("{COOKIE}={revoked}")),
    ] {
        let mut request = Request::get("/auth/userinfo");
        if let Some(cookie) = &cookie {
            request = request.header("cookie", cookie);
        }
        let response = send(bff.state.clone(), request.body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{cookie:?}");
    }
    assert!(bff.sessions.get_session(&other).await.unwrap().is_some());
    assert!(bff.sessions.get_session(&revoked).await.unwrap().is_none());
}

/// Not 401: an outage must not look like a signed-out user, or every client
/// signs itself out at once.
#[tokio::test]
async fn userinfo_with_the_store_down_is_unavailable() {
    let bff = bff_with(Arc::new(UnreachableStore), true);
    let response = send(
        bff.state,
        Request::get("/auth/userinfo")
            .header("cookie", format!("{COOKIE}={}", plausible_session_id()))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ── Sign-out ──

/// Logout ends the session and clears its cookie; a session without a
/// refresh token held no grant.
#[tokio::test]
async fn logout_ends_the_session_and_clears_its_cookie() {
    let bff = bff();
    let (id, csrf) = signed_in(&bff, None).await;
    let response = send(
        bff.state,
        logout(Some(&format!("{COOKIE}={id}")), Some(&csrf)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cleared = set_cookie(&response);
    assert!(
        cleared.starts_with(&format!("{COOKIE}=;")) && cleared.contains("Max-Age=0"),
        "{cleared}"
    );
    assert_eq!(logout_grant(response).await, "none");
    assert!(bff.sessions.get_session(&id).await.unwrap().is_none());
}

/// Logout needs no answer from SID: with the connection unknown the session
/// still ends, and the answer says the grant was not revoked.
#[tokio::test]
async fn logout_without_a_connection_reports_the_grant_not_revoked() {
    let bff = bff_with(Arc::new(sid_plugin::InProcessCeremonyState::new()), false);
    let (id, csrf) = bff
        .sessions
        .create_session(
            "token".into(),
            Some("refresh".into()),
            session_claims(),
            &test_connection().binding(),
        )
        .await
        .unwrap();
    // Without the connection the page's origin cannot be known: the request
    // is refused before anything is ended.
    let refused = send(
        bff.state.clone(),
        logout(Some(&format!("{COOKIE}={id}")), Some(&csrf)),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(bff.sessions.get_session(&id).await.unwrap().is_some());
}

/// With the delivered connection and SID unreachable, the grant's fate after
/// a revocation that got no answer is unknown; the session is ended anyway.
#[tokio::test]
async fn logout_with_sid_unreachable_reports_the_grant_unknown() {
    let bff = bff();
    let (id, csrf) = signed_in(&bff, Some("refresh")).await;
    let response = send(
        bff.state,
        logout(Some(&format!("{COOKIE}={id}")), Some(&csrf)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(logout_grant(response).await, "unknown");
    assert!(bff.sessions.get_session(&id).await.unwrap().is_none());
}

/// Logout needs the page's origin and the session's CSRF token; without a
/// cookie there is nobody to sign out; a cookie naming no session clears it
/// and knows nothing of the grant.
#[tokio::test]
async fn logout_refusals() {
    let bff = bff();
    let (id, csrf) = signed_in(&bff, None).await;
    let cookie = format!("{COOKIE}={id}");
    let foreign = Request::post("/auth/logout")
        .header("origin", "https://evil.example.com")
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        send(bff.state.clone(), foreign).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(bff.state.clone(), logout(Some(&cookie), Some("guess")))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(bff.state.clone(), logout(None, Some(&csrf)))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(bff.sessions.get_session(&id).await.unwrap().is_some());

    let gone = send(
        bff.state,
        logout(
            Some(&format!("{COOKIE}={}", plausible_session_id())),
            Some("x"),
        ),
    )
    .await;
    assert_eq!(gone.status(), StatusCode::OK);
    assert_eq!(logout_grant(gone).await, "unknown");
}

/// Clearing the cookie while the session stayed usable would be worse than
/// refusing: the caller would believe it had signed out.
#[tokio::test]
async fn logout_with_the_store_down_is_unavailable() {
    let bff = bff_with(Arc::new(UnreachableStore), true);
    let response = send(
        bff.state,
        logout(
            Some(&format!("{COOKIE}={}", plausible_session_id())),
            Some("x"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get("set-cookie").is_none());
}
