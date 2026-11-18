// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::connect_info::MockConnectInfo;
use axum::http::Request;
use sid_authn::bff_session::{RefreshClaim, TokenReplacement};
use tower::ServiceExt;

use super::*;
use crate::bff::routes;
use crate::bff::tests::{Bff, COOKIE, ORIGIN, bff, session_claims, signed_in, test_connection};

/// What the fake account API saw of one request.
#[derive(Debug, Clone)]
struct Seen {
    path_and_query: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// A fake account API on a local port: records each request and answers
/// with `grpc_status`, a body, a header of its own and a cookie the BFF must
/// not pass on.
async fn fake_api(grpc_status: &'static str) -> (url::Url, Arc<Mutex<Vec<Seen>>>) {
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
                .header("grpc-status", grpc_status)
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

/// A BFF with the fake API behind `/api`.
fn with_api(upstream: Option<url::Url>) -> Bff {
    let mut bff = bff();
    bff.state.api_upstream = upstream;
    bff
}

async fn call(state: ProxyState, request: Request<Body>) -> Response {
    routes()
        .layer(MockConnectInfo(SocketAddr::from(([192, 0, 2, 7], 40000))))
        .with_state(state)
        .oneshot(request)
        .await
        .unwrap()
}

/// A gRPC-Web call of the account page with session `id`.
fn api_post(id: &str, csrf: Option<&str>) -> Request<Body> {
    let mut request = Request::post("/api/sid.v1.IdentityService/GetCurrentProfile?x=1")
        .header("origin", ORIGIN)
        .header("cookie", format!("{COOKIE}={id}; other=1"))
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1");
    if let Some(csrf) = csrf {
        request = request.header("x-csrf-token", csrf);
    }
    request.body(Body::from("request-body")).unwrap()
}

/// Make session `id`'s access token due for a refresh.
async fn expire(bff: &Bff, id: &str) {
    let session = bff.sessions.get_session(id).await.unwrap().unwrap();
    let mut claims = session.claims.clone();
    claims.exp = 0;
    let refresh = session.refresh_token.clone().unwrap();
    bff.sessions
        .replace_tokens(
            id,
            &refresh,
            session.access_token,
            Some(refresh.clone()),
            claims,
        )
        .await
        .unwrap();
}

/// The API gets the call as the signed-in user: the session's token as
/// Bearer, the path without `/api`, the query and body as sent. The browser's
/// cookies and CSRF token stay at the BFF; the API's cookie does not reach
/// the browser, its own headers and body do.
#[tokio::test]
async fn a_call_reaches_the_api_with_the_sessions_token_only() {
    let (upstream, seen) = fake_api("0").await;
    let bff = with_api(Some(upstream));
    let (id, csrf) = signed_in(&bff, None).await;
    let response = call(bff.state, api_post(&id, Some(&csrf))).await;
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

/// A call without the session's CSRF token, with another one, or from
/// another origin is what a foreign page can make the browser send: refused
/// before the API sees it.
#[tokio::test]
async fn a_call_not_from_the_page_never_reaches_the_api() {
    let (upstream, seen) = fake_api("0").await;
    let bff = with_api(Some(upstream));
    let (id, csrf) = signed_in(&bff, None).await;
    for csrf in [None, Some("forged")] {
        let response = call(bff.state.clone(), api_post(&id, csrf)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{csrf:?}");
    }
    let mut foreign = api_post(&id, Some(&csrf));
    foreign
        .headers_mut()
        .insert("origin", "https://evil.example.com".parse().unwrap());
    assert_eq!(
        call(bff.state, foreign).await.status(),
        StatusCode::FORBIDDEN
    );
    assert!(seen.lock().unwrap().is_empty());
}

/// Without a session there is nobody to call the API as.
#[tokio::test]
async fn a_call_without_a_session_is_unauthenticated() {
    let (upstream, seen) = fake_api("0").await;
    let bff = with_api(Some(upstream));
    let response = call(bff.state, api_post(&"b".repeat(64), Some("x"))).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(seen.lock().unwrap().is_empty());
}

/// A BFF with no API configured serves no API.
#[tokio::test]
async fn no_upstream_no_api() {
    let bff = with_api(None);
    let (id, csrf) = signed_in(&bff, None).await;
    let response = call(bff.state, api_post(&id, Some(&csrf))).await;
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

/// An API answer `UNAUTHENTICATED` marks the token the call carried as
/// refused: the session refreshes before its next use.
#[tokio::test]
async fn an_unauthenticated_answer_marks_the_token_refused() {
    let (upstream, _) = fake_api("16").await;
    let bff = with_api(Some(upstream));
    let (id, csrf) = signed_in(&bff, Some("refresh-1")).await;
    let response = call(bff.state, api_post(&id, Some(&csrf))).await;
    assert_eq!(response.headers()["grpc-status"], "16");
    assert!(
        bff.sessions
            .get_session(&id)
            .await
            .unwrap()
            .unwrap()
            .token_refused
    );
}

/// An expired token without a refresh token ends the session: 401, and the
/// stored session is gone.
#[tokio::test]
async fn an_expired_session_without_refresh_signs_out() {
    let (upstream, seen) = fake_api("0").await;
    let bff = with_api(Some(upstream));
    let mut claims = session_claims();
    claims.exp = 0;
    let (id, csrf) = bff
        .sessions
        .create_session(
            "access-1".into(),
            None,
            claims,
            &test_connection().binding(),
        )
        .await
        .unwrap();
    let response = call(bff.state, api_post(&id, Some(&csrf))).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(bff.sessions.get_session(&id).await.unwrap().is_none());
    assert!(seen.lock().unwrap().is_empty());
}

/// When SID cannot be reached to refresh, the call is unavailable and the
/// session stays: an outage is not a sign-out.
#[tokio::test]
async fn a_refresh_sid_cannot_answer_keeps_the_session() {
    let (upstream, seen) = fake_api("0").await;
    let bff = with_api(Some(upstream));
    let (id, csrf) = signed_in(&bff, Some("refresh-1")).await;
    expire(&bff, &id).await;
    let response = call(bff.state, api_post(&id, Some(&csrf))).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(bff.sessions.get_session(&id).await.unwrap().is_some());
    assert!(seen.lock().unwrap().is_empty());
}

/// When another replica holds the refresh, this one waits for its result and
/// calls the API with the new token instead of refreshing again, which would
/// replay the rotated refresh token and end the grant.
#[tokio::test]
async fn a_refresh_held_elsewhere_is_awaited() {
    let (upstream, seen) = fake_api("0").await;
    let bff = with_api(Some(upstream));
    let (id, csrf) = signed_in(&bff, Some("refresh-1")).await;
    expire(&bff, &id).await;
    assert!(matches!(
        bff.sessions
            .claim_refresh(&id, &"refresh-1".into(), Duration::from_secs(15), |_| true)
            .await
            .unwrap(),
        RefreshClaim::Claimed(_)
    ));
    let other_replica = {
        let sessions = bff.sessions.clone();
        let id = id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            sessions
                .replace_tokens(
                    &id,
                    &"refresh-1".into(),
                    "access-2".into(),
                    Some("refresh-2".into()),
                    session_claims(),
                )
                .await
                .unwrap()
        })
    };
    let response = call(bff.state, api_post(&id, Some(&csrf))).await;
    assert!(matches!(
        other_replica.await.unwrap(),
        TokenReplacement::Replaced
    ));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        seen.lock().unwrap()[0].headers["authorization"],
        "Bearer access-2"
    );
}
