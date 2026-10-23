// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Mutex;

use crate::application_session::tests::{COOKIE, fixture, memory, signed_in};

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

/// A gRPC call to `path` with `cookie` and `csrf`.
fn call(path: &str, cookie: Option<&str>, csrf: Option<&str>) -> http::Request<tonic::body::Body> {
    let mut request = http::Request::post(path)
        .header("content-type", "application/grpc")
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

const API_METHOD: &str = "/sid.ops.v1.OrganizationService/ListOrganizations";

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
    let (id, _) = signed_in(&f, false).await;
    let (api, seen) = recording_api();
    let host = HostUpstream::new(Arc::new(f.adapter), Some(api));
    let cookie = format!("{COOKIE}={id}");
    for (request, code) in [
        (call(API_METHOD, None, None), "16"),
        (call(API_METHOD, Some(&cookie), None), "7"),
        (call(API_METHOD, Some(&cookie), Some("not-the-token")), "7"),
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

/// Without a hosted API, a call that is not the adapter's is unimplemented.
#[tokio::test]
async fn without_an_api_other_calls_are_unimplemented() {
    let f = fixture(memory(), true);
    let host: HostUpstream = HostUpstream::new(Arc::new(f.adapter), None);
    let answer = host.oneshot(call(API_METHOD, None, None)).await.unwrap();
    assert_eq!(grpc_status(&answer), "12");
}
