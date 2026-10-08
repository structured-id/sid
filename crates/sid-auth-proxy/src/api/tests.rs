// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::bff::routes;
use crate::bff::tests::bff_test_state;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::Request;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// What the fake account API saw of one request.
#[derive(Debug, Clone)]
struct Seen {
    path_and_query: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// A fake account API on a local port: records each request and answers
/// with a body, a header of its own and a cookie the BFF must not pass on.
async fn fake_api() -> (url::Url, Arc<Mutex<Vec<Seen>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    let app = axum::Router::new().fallback(move |request: Request<Body>| {
        let record = record.clone();
        async move {
            let (parts, body) = request.into_parts();
            let body = axum::body::to_bytes(body, 1 << 20).await.unwrap().to_vec();
            record.lock().unwrap().push(Seen {
                path_and_query: parts.uri.path_and_query().unwrap().to_string(),
                headers: parts.headers,
                body,
            });
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/grpc-web+proto")
                .header("grpc-status", "0")
                .header("set-cookie", "sid_session=idp; Path=/")
                .body(Body::from("answer"))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url::Url::parse(&format!("http://{addr}")).unwrap(), seen)
}

fn claims(exp: i64) -> sid_auth::auth::jwt::ForwardAuthClaims {
    sid_auth::auth::jwt::ForwardAuthClaims {
        sub: "0190f000-0000-7000-8000-000000000001".into(),
        iss: "https://sid.example.com/i/0123456789abcdef0123456789abcdef".into(),
        exp,
        iat: 1_000_000_000,
        auth_time: 1_000_000_000,
        acr: "urn:sid:acr:standard".into(),
        scope: "account".into(),
        roles: String::new(),
        sid: "sess-1".into(),
        jti: "jti-1".into(),
        email: None,
        name: None,
        preferred_username: None,
        groups: None,
        cnf: None,
    }
}

fn in_an_hour() -> i64 {
    chrono::Utc::now().timestamp() + 3600
}

/// A signed-in state with the fake API behind `/api`, and the session's id
/// and CSRF token.
async fn signed_in_state(
    upstream: Option<url::Url>,
    exp: i64,
    refresh_token: Option<&str>,
) -> (ProxyState, String, String) {
    let mut state = bff_test_state();
    state.api_upstream = upstream;
    let (id, csrf) = state
        .bff_sessions
        .create_session(
            "access-1".into(),
            refresh_token.map(str::to_owned),
            claims(exp),
        )
        .await
        .unwrap();
    (state, id, csrf)
}

async fn call(state: ProxyState, request: Request<Body>) -> Response {
    routes()
        .layer(MockConnectInfo(SocketAddr::from(([192, 0, 2, 7], 40000))))
        .with_state(state)
        .oneshot(request)
        .await
        .unwrap()
}

fn api_post(id: &str, csrf: Option<&str>) -> Request<Body> {
    let mut request = Request::post("/api/sid.v1.IdentityService/GetCurrentProfile?x=1")
        .header("cookie", format!("__Host-sid-bff={id}; other=1"))
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1");
    if let Some(csrf) = csrf {
        request = request.header("x-csrf-token", csrf);
    }
    request.body(Body::from("request-body")).unwrap()
}

/// The API gets the call as the signed-in user: the session's token as
/// Bearer, the path without `/api`, the query and body as sent. The browser's
/// cookies and CSRF token stay at the BFF; the API's cookie does not reach
/// the browser, its own headers and body do.
#[tokio::test]
async fn a_call_reaches_the_api_with_the_sessions_token_only() {
    let (upstream, seen) = fake_api().await;
    let (state, id, csrf) = signed_in_state(Some(upstream), in_an_hour(), None).await;
    let response = call(state, api_post(&id, Some(&csrf))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["grpc-status"], "0");
    assert!(response.headers().get("set-cookie").is_none());
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"answer");

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let call = &seen[0];
    assert_eq!(
        call.path_and_query,
        "/sid.v1.IdentityService/GetCurrentProfile?x=1"
    );
    assert_eq!(call.headers["authorization"], "Bearer access-1");
    assert_eq!(call.headers["x-grpc-web"], "1");
    assert_eq!(call.headers["x-forwarded-for"], "192.0.2.7");
    assert!(call.headers.get("cookie").is_none());
    assert!(call.headers.get("x-csrf-token").is_none());
    assert_eq!(call.body, b"request-body");
}

/// A call without the session's CSRF token, or with another one, is what a
/// foreign page can make the browser send: refused before the API sees it.
#[tokio::test]
async fn a_call_without_the_csrf_token_never_reaches_the_api() {
    let (upstream, seen) = fake_api().await;
    let (state, id, _) = signed_in_state(Some(upstream), in_an_hour(), None).await;
    for csrf in [None, Some("forged")] {
        let response = call(state.clone(), api_post(&id, csrf)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{csrf:?}");
    }
    assert!(seen.lock().unwrap().is_empty());
}

/// Without a session there is nobody to call the API as.
#[tokio::test]
async fn a_call_without_a_session_is_unauthenticated() {
    let (upstream, seen) = fake_api().await;
    let (state, _, _) = signed_in_state(Some(upstream), in_an_hour(), None).await;
    let unknown = "b".repeat(64);
    for request in [
        Request::post("/api/x").body(Body::empty()).unwrap(),
        api_post(&unknown, Some("x")),
    ] {
        let response = call(state.clone(), request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    assert!(seen.lock().unwrap().is_empty());
}

/// A BFF with no API configured serves no API.
#[tokio::test]
async fn no_upstream_no_api() {
    let (state, id, csrf) = signed_in_state(None, in_an_hour(), None).await;
    let response = call(state, api_post(&id, Some(&csrf))).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// A path leaving the API's base is not forwarded.
#[test]
fn a_path_leaving_the_api_is_refused() {
    let upstream = url::Url::parse("http://sid:8080/grpc").unwrap();
    assert_eq!(
        api_target(&upstream, "sid.v1.X/Y", Some("a=1"))
            .unwrap()
            .as_str(),
        "http://sid:8080/grpc/sid.v1.X/Y?a=1"
    );
    for escaping in ["../admin", "a/../../b", "..", "a/.."] {
        assert!(
            api_target(&upstream, escaping, None).is_none(),
            "{escaping}"
        );
    }
}

/// An expired token without a refresh token ends the session: 401, and the
/// stored session is gone.
#[tokio::test]
async fn an_expired_session_without_refresh_signs_out() {
    let (upstream, seen) = fake_api().await;
    let (state, id, csrf) = signed_in_state(Some(upstream), 0, None).await;
    let sessions = state.bff_sessions.clone();
    let response = call(state, api_post(&id, Some(&csrf))).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(sessions.get_session(&id).await.unwrap().is_none());
    assert!(seen.lock().unwrap().is_empty());
}

/// When SID cannot be reached to refresh, the call is unavailable and the
/// session stays: an outage is not a sign-out.
#[tokio::test]
async fn a_refresh_sid_cannot_answer_keeps_the_session() {
    let (upstream, seen) = fake_api().await;
    let (state, id, csrf) = signed_in_state(Some(upstream), 0, Some("refresh-1")).await;
    let sessions = state.bff_sessions.clone();
    let response = call(state, api_post(&id, Some(&csrf))).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(sessions.get_session(&id).await.unwrap().is_some());
    assert!(seen.lock().unwrap().is_empty());
}

/// When another replica holds the refresh, this one waits for its result
/// and calls the API with the new token instead of refreshing again, which
/// would replay the rotated refresh token and end the grant.
#[tokio::test]
async fn a_refresh_held_elsewhere_is_awaited() {
    let (upstream, seen) = fake_api().await;
    let (state, id, csrf) = signed_in_state(Some(upstream), 0, Some("refresh-1")).await;
    let sessions = state.bff_sessions.clone();
    assert!(
        sessions
            .claim_refresh(&id, Duration::from_secs(15))
            .await
            .unwrap()
    );
    let other_replica = {
        let sessions = sessions.clone();
        let id = id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            sessions
                .replace_tokens(
                    &id,
                    "access-2".into(),
                    Some("refresh-2".into()),
                    claims(in_an_hour()),
                )
                .await
                .unwrap()
        })
    };
    let response = call(state, api_post(&id, Some(&csrf))).await;
    assert!(other_replica.await.unwrap());
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        seen.lock().unwrap()[0].headers["authorization"],
        "Bearer access-2"
    );
}

/// The refresh claim goes to exactly one of many concurrent claimants.
#[tokio::test]
async fn one_claimant_refreshes() {
    let state = bff_test_state();
    let claims: Vec<_> = futures_claims(&state, 8).await;
    assert_eq!(claims.iter().filter(|won| **won).count(), 1);
}

async fn futures_claims(state: &ProxyState, n: usize) -> Vec<bool> {
    let mut tasks = Vec::new();
    for _ in 0..n {
        let sessions = state.bff_sessions.clone();
        tasks.push(tokio::spawn(async move {
            sessions
                .claim_refresh(&"c".repeat(64), Duration::from_secs(15))
                .await
                .unwrap()
        }));
    }
    let mut won = Vec::new();
    for task in tasks {
        won.push(task.await.unwrap());
    }
    won
}
