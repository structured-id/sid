// SPDX-License-Identifier: AGPL-3.0-only
//! The proxy's configured BFF integration against a real issuer served over
//! gRPC and the BFF's shared PostgreSQL store, as two replicas of the proxy
//! run it: sign-in through the issuer's authorization endpoint, code
//! redemption with the client's `private_key_jwt`, the session it makes and
//! the revocation of its grant at sign-out. Requests go through the proxy's
//! own routes.
//!
//! Run with: cargo nextest run -p sid-auth-proxy --test real_issuer

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use secrecy::SecretString;
use sid_auth_proxy::ProxyState;
use sid_authn::application_session::BrowserSessions;
use sid_authn::bff_session::BffSessionStore;
use sid_authn::client_connection::ClientConnection;
use sid_authn::client_key::ClientKey;
use sid_authn::issuer_directory::IssuerDirectory;
use sid_authn::relying_party::Connection;
use sid_authn::revocation_cache::RevocationCache;
use sid_infra::issuer_client::RpClient;
use sid_infra::issuer_registry::GrpcIssuerSource;
use sid_plugin::cache::{CacheBackend, InMemoryCacheBackend};
use sid_proto::sid::v1::OAuth2AuthorizeRequest;
use sid_test_issuer::{INSTALLATION, Setup, TestIssuer};
use tower::ServiceExt;

#[path = "../../../tests/support/crypto.rs"]
mod test_crypto;

/// The account application's API and the callback the proxy serves.
const API: &str = "https://account.sid.example.com/api/";
const CALLBACK: &str = "https://account.sid.example.com/auth/callback";
const CLIENT: &str = "account-bff";
const COOKIE: &str = "__Host-sid-bff";
const LONG: Duration = Duration::from_secs(3600);

/// The BFF's shared PostgreSQL: the test database unless
/// `SID_TEST_DATABASE_URL` names another.
fn database() -> String {
    std::env::var("SID_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".into())
}

/// The issuer, the proxy's two replicas over one session store, and a user
/// signed in at the issuer in the browser: the bearer its pages present.
struct World {
    issuer: TestIssuer,
    replicas: [Router; 2],
    bearer: String,
}

async fn world() -> World {
    let issuer = TestIssuer::start(Setup {
        resources: vec![API.into()],
        ..Default::default()
    })
    .await;
    let (key, pem) = ClientKey::generate_ed25519().unwrap();
    issuer
        .web_client(CLIENT, API, CALLBACK, key.public_jwks().unwrap())
        .await;
    let kid = key.kid().unwrap().to_owned();
    drop(key);
    let store = sid_storage::application_store::ceremony_store(&database())
        .await
        .expect("the test database (docker compose -f docker-compose.test.yml up -d)");
    let sessions = Arc::new(BffSessionStore::new(store, LONG, LONG, LONG));
    // Revocations recorded anywhere reach both replicas.
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let replica = |pem: &SecretString| {
        let channel =
            sid_infra::deadline::bounded_channel(&issuer.upstream(), Duration::from_secs(5))
                .unwrap();
        let account = RpClient::delivered(
            ClientKey::ed25519_from_pem(pem).unwrap(),
            INSTALLATION.into(),
            channel.clone(),
            connection(&issuer, &kid),
        )
        .unwrap();
        let bff = BrowserSessions::new(
            Arc::new(account),
            Arc::new(IssuerDirectory::new(Arc::new(GrpcIssuerSource::new(
                channel.clone(),
            )))),
            sessions.clone(),
            RevocationCache::receiver_view(cache.clone()),
            COOKIE.into(),
        );
        let state = ProxyState {
            // Health only, which these tests do not ask.
            grpc_channel: tonic::transport::Channel::from_shared(issuer.upstream())
                .unwrap()
                .connect_lazy(),
            bff: Some(Arc::new(bff)),
            api_upstream: None,
            http: test_crypto::with_tls(sid_auth_proxy::api_client),
            bff_dev_mode: false,
        };
        sid_auth_proxy::bff::routes().with_state(state)
    };
    let replicas = [replica(&pem), replica(&pem)];
    let profile = issuer.profile().await;
    let (_, bearer) = issuer.sign_in(&profile).await;
    World {
        issuer,
        replicas,
        bearer,
    }
}

/// The connection the installation delivers to the BFF.
fn connection(issuer: &TestIssuer, kid: &str) -> Connection {
    Connection::accept(ClientConnection {
        issuer: issuer.issuer.canonical_url.clone(),
        client_id: CLIENT.into(),
        resource: API.into(),
        scopes: vec!["openid".into()],
        redirect_uri: CALLBACK.into(),
        token_endpoint_auth_method: "private_key_jwt".into(),
        key_ids: vec![kid.to_owned()],
    })
    .unwrap()
}

/// `request` through `replica`'s routes.
async fn call(replica: &Router, request: Request<Body>) -> Response<Body> {
    replica.clone().oneshot(request).await.unwrap()
}

fn header(response: &Response<Body>, name: &str) -> String {
    response
        .headers()
        .get(name)
        .unwrap_or_else(|| panic!("no {name}"))
        .to_str()
        .unwrap()
        .to_owned()
}

/// The `name=value` pairs of the cookies `response` sets with a value.
fn set_cookies(response: &Response<Body>) -> Vec<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|set| set.to_str().unwrap().split(';').next().unwrap().to_owned())
        .filter(|pair| !pair.ends_with('='))
        .collect()
}

/// The `name=value` of the session cookie `response` sets, if any.
fn session_cookie(response: &Response<Body>) -> Option<String> {
    set_cookies(response)
        .into_iter()
        .find(|pair| pair.starts_with(&format!("{COOKIE}=")))
}

/// A sign-in the browser starts at `replica`: the authorization request it
/// is sent to and the `name=value` of the correlation cookie it keeps.
async fn start(replica: &Router) -> (HashMap<String, String>, String) {
    let response = call(
        replica,
        Request::get("/auth/login?rd=/settings")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location: url::Url = header(&response, "location").parse().unwrap();
    let query = location.query_pairs().into_owned().collect();
    let pair = set_cookies(&response).pop().expect("a correlation cookie");
    (query, pair)
}

/// The code the issuer's authorization endpoint answers `query` with for
/// the signed-in browser.
async fn authorize(w: &World, query: &HashMap<String, String>) -> String {
    w.issuer
        .authorize(
            &w.bearer,
            OAuth2AuthorizeRequest {
                client_id: query["client_id"].clone(),
                redirect_uri: query["redirect_uri"].clone(),
                response_type: query["response_type"].clone(),
                scope: Some(query["scope"].clone()),
                state: Some(query["state"].clone()),
                code_challenge: Some(query["code_challenge"].clone()),
                code_challenge_method: Some(query["code_challenge_method"].clone()),
                nonce: Some(query["nonce"].clone()),
                resource: vec![query["resource"].clone()],
                ..Default::default()
            },
        )
        .await
}

/// The issuer's redirect back with `code` for `query`, arriving at `replica`
/// with the browser's `cookies`.
async fn callback(
    w: &World,
    replica: &Router,
    query: &HashMap<String, String>,
    code: &str,
    cookies: &str,
) -> Response<Body> {
    let mut uri = url::Url::parse("https://account.sid.example.com/auth/callback").unwrap();
    uri.query_pairs_mut()
        .append_pair("state", &query["state"])
        .append_pair("code", code)
        .append_pair("iss", &w.issuer.issuer.canonical_url);
    let path = format!("{}?{}", uri.path(), uri.query().unwrap());
    call(
        replica,
        Request::get(path)
            .header("cookie", cookies)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

/// The signed-in user and the session's CSRF token, read at `replica`.
async fn userinfo(replica: &Router, session: &str) -> Result<serde_json::Value, StatusCode> {
    let response = call(
        replica,
        Request::get("/auth/userinfo")
            .header("cookie", session)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    if response.status() != StatusCode::OK {
        return Err(response.status());
    }
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Ok(serde_json::from_slice(&body).unwrap())
}

/// A complete sign-in started at one replica and finished at the other.
async fn signed_in(w: &World) -> (String, serde_json::Value) {
    let (query, pair) = start(&w.replicas[0]).await;
    let code = authorize(w, &query).await;
    let done = callback(w, &w.replicas[1], &query, &code, &pair).await;
    assert_eq!(done.status(), StatusCode::FOUND);
    let session = session_cookie(&done).expect("a session cookie");
    let user = userinfo(&w.replicas[0], &session).await.unwrap();
    (session, user)
}

/// A sign-in started at one replica completes at the other against the
/// issuer: the code is redeemed with the client's key, the tokens are
/// verified against the issuer's published keys, and the session it makes
/// is read on both replicas. The browser returns to the page it asked for,
/// and the callback is used once.
#[tokio::test]
async fn a_sign_in_completes_at_the_issuer() {
    let w = world().await;
    let (query, pair) = start(&w.replicas[0]).await;
    assert_eq!(query["client_id"], CLIENT);
    assert_eq!(query["redirect_uri"], CALLBACK);
    let code = authorize(&w, &query).await;
    let done = callback(&w, &w.replicas[1], &query, &code, &pair).await;
    assert_eq!(done.status(), StatusCode::FOUND);
    assert_eq!(header(&done, "location"), "/settings");
    let session = session_cookie(&done).expect("a session cookie");
    for replica in &w.replicas {
        let user = userinfo(replica, &session).await.unwrap();
        assert!(!user["sub"].as_str().unwrap().is_empty());
        assert!(!user["csrf_token"].as_str().unwrap().is_empty());
    }

    let replay = callback(&w, &w.replicas[0], &query, &code, &pair).await;
    assert_eq!(
        replay.status(),
        StatusCode::BAD_REQUEST,
        "the sign-in is taken once"
    );
    assert!(session_cookie(&replay).is_none());
}

/// Two tabs start their first sign-ins before either has a cookie and the
/// issuer answers both; in either order of the callbacks, each completes
/// into a session of its own, and the later one leaves the earlier session
/// standing.
#[tokio::test]
async fn concurrent_first_sign_ins_both_become_sessions() {
    for a_first in [true, false] {
        let w = world().await;
        let ((a, cookie_a), (b, cookie_b)) =
            tokio::join!(start(&w.replicas[0]), start(&w.replicas[1]));
        let (code_a, code_b) = (authorize(&w, &a).await, authorize(&w, &b).await);
        let jar = format!("{cookie_a}; {cookie_b}");
        let order = if a_first {
            [(&a, &code_a), (&b, &code_b)]
        } else {
            [(&b, &code_b), (&a, &code_a)]
        };
        let mut sessions = Vec::new();
        for (i, (query, code)) in order.into_iter().enumerate() {
            let done = callback(&w, &w.replicas[i], query, code, &jar).await;
            assert_eq!(done.status(), StatusCode::FOUND, "a_first={a_first}");
            sessions.push(session_cookie(&done).expect("a session cookie"));
        }
        assert_ne!(sessions[0], sessions[1]);
        for session in &sessions {
            userinfo(&w.replicas[0], session)
                .await
                .expect("each sign-in's session stands");
        }
    }
}

/// A callback carrying another browser's correlation cookie redeems
/// nothing; the code stays usable by the browser that started the sign-in.
#[tokio::test]
async fn another_browser_cannot_complete_a_sign_in() {
    let w = world().await;
    let (query, own) = start(&w.replicas[0]).await;
    let (_, other) = start(&w.replicas[0]).await;
    let code = authorize(&w, &query).await;
    // The other browser's cookie under this sign-in's name.
    let (name, _) = own.split_once('=').unwrap();
    let (_, value) = other.split_once('=').unwrap();
    let refused = callback(
        &w,
        &w.replicas[1],
        &query,
        &code,
        &format!("{name}={value}"),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(session_cookie(&refused).is_none());

    let done = callback(&w, &w.replicas[1], &query, &code, &own).await;
    assert_eq!(done.status(), StatusCode::FOUND);
    assert!(session_cookie(&done).is_some());
}

/// A code issued to another client of the issuer is refused at redemption:
/// no session.
#[tokio::test]
async fn a_code_of_another_client_makes_no_session() {
    let w = world().await;
    let (other_key, _) = ClientKey::generate_ed25519().unwrap();
    w.issuer
        .web_client(
            "other-web",
            API,
            "https://other.sid.example.com/auth/callback",
            other_key.public_jwks().unwrap(),
        )
        .await;
    let (query, pair) = start(&w.replicas[0]).await;
    let mut foreign = query.clone();
    foreign.insert("client_id".into(), "other-web".into());
    foreign.insert(
        "redirect_uri".into(),
        "https://other.sid.example.com/auth/callback".into(),
    );
    let code = authorize(&w, &foreign).await;
    let done = callback(&w, &w.replicas[0], &query, &code, &pair).await;
    assert_eq!(done.status(), StatusCode::BAD_GATEWAY);
    assert!(session_cookie(&done).is_none());
}

/// A sign-in whose token endpoint cannot be reached is not completed: no
/// session, and the browser is told the issuer did not finish it.
#[tokio::test]
async fn an_unreachable_token_endpoint_completes_nothing() {
    let mut w = world().await;
    let (query, pair) = start(&w.replicas[0]).await;
    let code = authorize(&w, &query).await;
    w.issuer.stop().await;
    let done = callback(&w, &w.replicas[0], &query, &code, &pair).await;
    assert_eq!(done.status(), StatusCode::BAD_GATEWAY);
    assert!(session_cookie(&done).is_none());
}

/// Sign-out at one replica ends the session on both and revokes its grant
/// at the issuer; a sign-out without the session's CSRF token ends nothing.
#[tokio::test]
async fn sign_out_revokes_the_grant_at_the_issuer() {
    let w = world().await;
    let (session, user) = signed_in(&w).await;
    let csrf = user["csrf_token"].as_str().unwrap().to_owned();
    let logout = |csrf: &str| {
        // The browser sends the page's origin with every POST.
        Request::post("/auth/logout")
            .header("cookie", &session)
            .header("origin", "https://account.sid.example.com")
            .header("x-csrf-token", csrf)
            .body(Body::empty())
            .unwrap()
    };

    let forged = call(&w.replicas[1], logout("forged")).await;
    assert_eq!(forged.status(), StatusCode::FORBIDDEN);
    userinfo(&w.replicas[0], &session)
        .await
        .expect("a forged sign-out ends nothing");

    let done = call(&w.replicas[1], logout(&csrf)).await;
    assert_eq!(done.status(), StatusCode::OK);
    let body = done.into_body().collect().await.unwrap().to_bytes();
    let answer: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(answer["grant"], "revoked");
    for replica in &w.replicas {
        assert_eq!(
            userinfo(replica, &session).await.unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
    }
}
