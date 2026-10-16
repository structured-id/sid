// SPDX-License-Identifier: AGPL-3.0-only
//! Browser sign-in calls addressed to an issuer on a shared origin
//! (`/i/{handle}/grpc/{package.Service}/{Method}`): a stored handle and a
//! sign-in method reach the same service as the root path, with the issuer
//! and the received path attached; anything else under the prefix is
//! refused there, and nothing falls back to another issuer.

mod common;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::TestServices;
use common::mock_storage::MockStorage;
use sid_authn::issuer::AddressedIssuer;
use sid_authn::resource::TranscodedRequest;
use sid_proto::sid::v1::auth_service_server::AuthServiceServer;
use sid_server::serve::browser_route::{BROWSER_METHODS, IssuerRoute};
use tonic::body::Body;
use tonic::codegen::{Service, http};

const LOGIN_START: &str = "/sid.v1.authn.AuthService/OpaqueLoginStart";

/// What the service behind the route received: its path, the addressed
/// issuer's handle and the received request.
type Seen = Arc<Mutex<Vec<(String, Option<String>, Option<TranscodedRequest>)>>>;

/// A service recording what reaches it and answering OK.
#[derive(Clone)]
struct Recording(Seen);

impl Service<http::Request<Body>> for Recording {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Infallible>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Infallible>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        self.0.lock().unwrap().push((
            request.uri().path().to_owned(),
            request
                .extensions()
                .get::<AddressedIssuer>()
                .map(|issuer| issuer.0.handle.to_string()),
            request.extensions().get::<TranscodedRequest>().cloned(),
        ));
        std::future::ready(Ok(http::Response::new(Body::empty())))
    }
}

/// `path` POSTed through the route over `seen`; the answer's gRPC status
/// when the route refused it.
async fn through_route(svc: &TestServices, seen: &Seen, path: &str) -> Option<String> {
    let mut route = IssuerRoute::new(Recording(seen.clone()), svc.issuers.clone());
    std::future::poll_fn(|cx| route.poll_ready(cx))
        .await
        .unwrap();
    let request = http::Request::post(path).body(Body::empty()).unwrap();
    let answer = route.call(request).await.unwrap();
    answer
        .headers()
        .get("grpc-status")
        .map(|status| status.to_str().unwrap().to_owned())
}

/// A sign-in method under a stored handle reaches the service at its gRPC
/// path, carrying that issuer and the path and method it was received with.
#[tokio::test]
async fn sign_in_call_reaches_its_service_with_the_issuer() {
    let svc = TestServices::new(MockStorage::new());
    let seen = Seen::default();
    let handle = svc.issuer.handle.to_string();
    let received = format!("/i/{handle}/grpc{LOGIN_START}");

    assert_eq!(through_route(&svc, &seen, &received).await, None);

    let seen = seen.lock().unwrap();
    assert_eq!(
        *seen,
        [(
            LOGIN_START.to_owned(),
            Some(handle),
            Some(TranscodedRequest::new("POST", received)),
        )]
    );
}

/// A handle of no issuer here, well-formed or not, is NOT_FOUND and reaches
/// no service: no other issuer stands in.
#[tokio::test]
async fn unknown_handle_is_not_found() {
    let svc = TestServices::new(MockStorage::new());
    let seen = Seen::default();
    for handle in [
        sid_core::models::IssuerHandle::generate().to_string(),
        "not-a-handle".to_owned(),
    ] {
        let path = format!("/i/{handle}/grpc{LOGIN_START}");
        assert_eq!(
            through_route(&svc, &seen, &path).await.as_deref(),
            Some("5"),
            "{handle}"
        );
    }
    assert!(seen.lock().unwrap().is_empty());
}

/// Under the prefix only the sign-in surface exists: another method of the
/// same service, a management service and a path that is no addressed call
/// are UNIMPLEMENTED there, even under a stored handle, and reach nothing.
#[tokio::test]
async fn only_the_sign_in_surface_is_published() {
    let svc = TestServices::new(MockStorage::new());
    let seen = Seen::default();
    let handle = svc.issuer.handle.to_string();
    for path in [
        format!("/i/{handle}/grpc/sid.v1.authn.AuthService/OAuth2Token"),
        format!("/i/{handle}/grpc/sid.v1.admin.AdminService/ListProfiles"),
        format!("/i/{handle}/grpcx{LOGIN_START}"),
        format!("/i/{handle}{LOGIN_START}"),
        format!("/i/{handle}"),
    ] {
        assert_eq!(
            through_route(&svc, &seen, &path).await.as_deref(),
            Some("12"),
            "{path}"
        );
    }
    assert!(seen.lock().unwrap().is_empty());
}

/// A call outside `/i/` reaches the service as it came, with no issuer
/// attached.
#[tokio::test]
async fn root_calls_pass_unchanged() {
    let svc = TestServices::new(MockStorage::new());
    let seen = Seen::default();

    assert_eq!(through_route(&svc, &seen, LOGIN_START).await, None);

    assert_eq!(
        *seen.lock().unwrap(),
        [(LOGIN_START.to_owned(), None, None)]
    );
}

/// Every published path names a method of the served protocol, so the
/// sign-in surface has no entry that could never be answered.
#[test]
fn browser_methods_exist_in_the_protocol() {
    let pool = prost_reflect::DescriptorPool::decode(sid_proto::FILE_DESCRIPTOR_SET).unwrap();
    for method in BROWSER_METHODS {
        let (service, name) = method[1..].split_once('/').unwrap();
        let service = pool
            .get_service_by_name(service)
            .unwrap_or_else(|| panic!("{method}: no such service"));
        assert!(
            service.methods().any(|m| m.name() == name),
            "{method}: no such method"
        );
    }
}

/// The gRPC status of a gRPC-Web answer: in its headers when it has no
/// body, else in its trailer frame (gRPC-Web protocol: a frame is a flag
/// byte, a 4-byte length and the payload; trailers carry flag 0x80).
async fn grpc_web_status(response: reqwest::Response) -> String {
    if let Some(status) = response.headers().get("grpc-status") {
        return status.to_str().unwrap().to_owned();
    }
    let body = response.bytes().await.unwrap();
    let mut rest = &body[..];
    while rest.len() >= 5 {
        let len = u32::from_be_bytes(rest[1..5].try_into().unwrap()) as usize;
        let (frame, next) = rest[5..].split_at(len);
        if rest[0] & 0x80 != 0 {
            for line in std::str::from_utf8(frame).unwrap().split("\r\n") {
                if let Some(status) = line.strip_prefix("grpc-status:") {
                    return status.trim().to_owned();
                }
            }
        }
        rest = next;
    }
    panic!("no grpc-status in {body:?}");
}

/// Over the transcoder, as a browser calls it with gRPC-Web: the sign-in
/// call under the issuer path gets the answer the same call gets at the
/// root path, while an unknown handle and a management method are refused.
#[tokio::test]
async fn grpc_web_through_the_transcoder() {
    let svc = TestServices::new(MockStorage::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let proxy = sid_server::serve::http_transcoder(Some("127.0.0.1:0"), None, None)
        .unwrap()
        .expect("a bind address gives a transcoder");
    let upstream = sid_server::serve::transcoder_upstream(
        tonic::service::Routes::new(AuthServiceServer::from_arc(svc.auth.clone())),
        svc.issuers.clone(),
    );
    tokio::spawn(async move {
        sid_infra::http::serve_on(
            &proxy,
            upstream,
            listener,
            std::future::pending(),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
    });
    let client = sid_plugin::client_builder().build().unwrap();
    // An empty request message, framed.
    let call = |path: String| {
        client
            .post(format!("http://{addr}{path}"))
            .header("content-type", "application/grpc-web+proto")
            .header("x-grpc-web", "1")
            .body(vec![0u8, 0, 0, 0, 0])
            .send()
    };
    let handle = svc.issuer.handle.to_string();

    let at_root = grpc_web_status(call(LOGIN_START.to_owned()).await.unwrap()).await;
    let addressed = grpc_web_status(
        call(format!("/i/{handle}/grpc{LOGIN_START}"))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(addressed, at_root);
    assert!(!["5", "12"].contains(&at_root.as_str()), "{at_root}");

    let unknown = sid_core::models::IssuerHandle::generate();
    let refused = grpc_web_status(
        call(format!("/i/{unknown}/grpc{LOGIN_START}"))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(refused, "5");
    let management = grpc_web_status(
        call(format!(
            "/i/{handle}/grpc/sid.v1.authn.AuthService/OAuth2Token"
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(management, "12");
}
