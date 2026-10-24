// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Mutex;

use crate::application_session::tests::{COOKIE, ORIGIN, fixture, memory, signed_in};

use super::*;

/// What a fake API saw of each call.
type Seen = Arc<Mutex<Vec<http::HeaderMap>>>;

/// An API that records the headers of every call and answers OK.
fn recording_api() -> (
    impl tower::Service<
        http::Request<tonic::body::Body>,
        Response = Answer,
        Error = Infallible,
        Future = impl Send,
    > + Clone
    + Send
    + Sync
    + 'static,
    Seen,
) {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    let api = tower::service_fn(move |request: http::Request<tonic::body::Body>| {
        record.lock().unwrap().push(request.headers().clone());
        async move {
            let mut answer = http::Response::new(tonic::body::Body::empty());
            answer
                .headers_mut()
                .insert("grpc-status", http::HeaderValue::from_static("0"));
            Ok::<_, Infallible>(answer)
        }
    });
    (api, seen)
}

/// A call of the application's page to `path` with `cookie` and `csrf`.
fn call(path: &str, cookie: Option<&str>, csrf: Option<&str>) -> http::Request<tonic::body::Body> {
    let mut request = http::Request::post(path)
        .header("content-type", "application/grpc")
        .header("origin", ORIGIN)
        .header("authorization", "Bearer forged-by-the-page")
        // One empty message: uncompressed flag and a zero length (gRPC
        // PROTOCOL-HTTP2, "Length-Prefixed-Message").
        .body(tonic::body::Body::new(http_body_util::Full::new(
            bytes::Bytes::from_static(&[0, 0, 0, 0, 0]),
        )))
        .unwrap();
    if let Some(cookie) = cookie {
        request
            .headers_mut()
            .insert("cookie", cookie.parse().unwrap());
    }
    if let Some(csrf) = csrf {
        request
            .headers_mut()
            .insert("x-csrf-token", csrf.parse().unwrap());
    }
    request
}

fn grpc_status(answer: &Answer) -> String {
    answer
        .headers()
        .get("grpc-status")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

/// A method of the hosted application's API; any path that is not the
/// adapter's goes there.
const API_METHOD: &str = "/example.v1.OrderService/ListOrders";

/// A call of the signed-in page reaches the API as the user: with the
/// session's access token and neither the session cookie, the CSRF token nor
/// an `authorization` the page sent.
#[tokio::test]
async fn a_signed_in_call_reaches_the_api_with_the_session_token() {
    let f = fixture(memory(), true);
    let (id, csrf) = signed_in(&f, false).await;
    let (api, seen) = recording_api();
    let host = HostUpstream::new(Arc::new(f.adapter), Some(api));
    let answer = host
        .oneshot(call(
            API_METHOD,
            Some(&format!("{COOKIE}={id}")),
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(grpc_status(&answer), "0");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["authorization"], "Bearer access");
    assert!(seen[0].get("cookie").is_none());
    assert!(seen[0].get(CSRF_HEADER).is_none());
}

/// Without a session, or without its CSRF token, nothing reaches the API.
#[tokio::test]
async fn a_call_without_a_session_or_its_csrf_token_stays_here() {
    let f = fixture(memory(), true);
    let (id, csrf) = signed_in(&f, false).await;
    let (api, seen) = recording_api();
    let host = HostUpstream::new(Arc::new(f.adapter), Some(api));
    let cookie = format!("{COOKIE}={id}");
    let mut foreign = call(API_METHOD, Some(&cookie), Some(&csrf));
    foreign.headers_mut().insert(
        "origin",
        http::HeaderValue::from_static("https://evil.example.com"),
    );
    for (request, code) in [
        (call(API_METHOD, None, None), "16"),
        (call(API_METHOD, Some(&cookie), None), "7"),
        (call(API_METHOD, Some(&cookie), Some("not-the-token")), "7"),
        (foreign, "7"),
    ] {
        let answer = host.clone().oneshot(request).await.unwrap();
        assert_eq!(grpc_status(&answer), code);
    }
    assert!(seen.lock().unwrap().is_empty());
}

/// The adapter's own service is answered here, never forwarded.
#[tokio::test]
async fn the_adapter_service_is_answered_in_process() {
    let f = fixture(memory(), true);
    let (api, seen) = recording_api();
    let host = HostUpstream::new(Arc::new(f.adapter), Some(api));
    let answer = host
        .oneshot(call(
            "/sid.v1.authn.ApplicationSessionService/GetApplicationSession",
            None,
            None,
        ))
        .await
        .unwrap();
    // No session: the adapter's own refusal, UNAUTHENTICATED.
    assert_eq!(grpc_status(&answer), "16");
    assert!(seen.lock().unwrap().is_empty());
}

/// A host with a browser adapter does not start without the shared cache:
/// a store of its own would break every sign-in another replica completes.
#[test]
fn the_adapter_requires_the_shared_cache() {
    assert!(required_shared_cache(None).is_err());
    assert_eq!(
        required_shared_cache(Some("redis://cache:6379".into())).unwrap(),
        "redis://cache:6379"
    );
}

/// A call to the issuer is bounded below the refresh claim's hold, so a
/// refresh never outlives its claim.
#[test]
fn an_issuer_call_ends_before_its_refresh_claim() {
    assert!(ISSUER_CALL_TIMEOUT < crate::application_session::REFRESH_HOLD);
}

/// An issuer that accepts the connection and never answers fails the call at
/// the bound instead of holding it.
#[tokio::test]
async fn a_silent_issuer_fails_at_the_bound() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    // Accepts, reads nothing, answers nothing.
    let held = tokio::spawn(async move {
        let mut open = Vec::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            open.push(socket);
        }
    });
    let channel = bounded_channel(&address, Duration::from_millis(300)).unwrap();
    let started = std::time::Instant::now();
    let answer =
        sid_proto::sid::v1::oidc_issuer_service_client::OidcIssuerServiceClient::new(channel)
            .get_oidc_issuer(sid_proto::sid::v1::GetOidcIssuerRequest {
                handle: "0123456789abcdef0123456789abcdef".into(),
            })
            .await;
    assert!(answer.is_err());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    held.abort();
}

/// The `ErrorInfo.reason` the answer's `grpc-status-details-bin` carries.
fn reason(answer: &Answer) -> String {
    let status = tonic::Status::from_header_map(answer.headers()).expect("a gRPC status");
    sid_core::grpc_error::extract_error_info(&status)
        .expect("a google.rpc.ErrorInfo")
        .0
}

/// An API that cannot be reached is an outage of a dependency, with its
/// reason and without the transport's own words.
#[tokio::test]
async fn an_unreachable_api_is_a_typed_outage() {
    let f = fixture(memory(), true);
    let (id, csrf) = signed_in(&f, false).await;
    let api = tower::service_fn(|_: http::Request<tonic::body::Body>| async {
        Err::<Answer, _>("connection refused by 10.0.0.7:50061")
    });
    let host = HostUpstream::new(Arc::new(f.adapter), Some(api));
    let answer = host
        .oneshot(call(
            API_METHOD,
            Some(&format!("{COOKIE}={id}")),
            Some(&csrf),
        ))
        .await
        .unwrap();
    assert_eq!(grpc_status(&answer), "14");
    assert_eq!(reason(&answer), "DEPENDENCY_UNAVAILABLE");
    let message = answer.headers()["grpc-message"].to_str().unwrap();
    assert!(!message.contains("10.0.0.7"), "{message}");
}

/// Without a hosted API, a call that is not the adapter's is unimplemented.
#[tokio::test]
async fn without_an_api_other_calls_are_unimplemented() {
    let f = fixture(memory(), true);
    let host: HostUpstream = HostUpstream::new(Arc::new(f.adapter), None);
    let answer = host.oneshot(call(API_METHOD, None, None)).await.unwrap();
    assert_eq!(grpc_status(&answer), "12");
    assert_eq!(reason(&answer), "FEATURE_NOT_AVAILABLE");
}

/// A unary call's bound covers the whole answer, its message and final
/// status included, also after the peer sent successful response headers:
/// an issuer that stops mid-answer fails the call at the bound.
async fn assert_unary_response_is_bounded(frame: bytes::Bytes) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(tokio::sync::Notify::new());
    let called = seen.clone();
    let router = axum::Router::new().fallback(axum::routing::post(move || {
        let frame = frame.clone();
        let called = called.clone();
        async move {
            called.notify_one();
            let body = http_body_util::Full::new(frame).with_trailers(std::future::pending::<
                Option<Result<http::HeaderMap, Infallible>>,
            >());
            http::Response::builder()
                .header("content-type", "application/grpc")
                .body(axum::body::Body::new(body))
                .unwrap()
        }
    }));
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let channel = bounded_channel(&address, Duration::from_millis(300)).unwrap();
    let mut client =
        sid_proto::sid::v1::oidc_issuer_service_client::OidcIssuerServiceClient::new(channel);
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        client.get_oidc_issuer(sid_proto::sid::v1::GetOidcIssuerRequest {
            handle: "0123456789abcdef0123456789abcdef".into(),
        }),
    )
    .await;
    // This outer limit bounds the test itself; reaching it is a failure,
    // never evidence that the call's bound worked.
    let reached = tokio::time::timeout(Duration::from_millis(100), seen.notified()).await;
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    assert!(reached.is_ok(), "the request reached the issuer");
    let refused = outcome.expect("the call's bound covers the body and the trailers");
    assert_eq!(refused.unwrap_err().code(), tonic::Code::DeadlineExceeded);
}

/// Headers followed by an unfinished message.
#[tokio::test]
async fn the_bound_covers_an_unfinished_message() {
    assert_unary_response_is_bounded(bytes::Bytes::from_static(&[0, 0, 0, 0, 1])).await;
}

/// A whole message and no final status.
#[tokio::test]
async fn the_bound_covers_missing_trailers() {
    assert_unary_response_is_bounded(bytes::Bytes::from_static(&[0, 0, 0, 0, 0])).await;
}
