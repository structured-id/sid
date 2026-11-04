// SPDX-License-Identifier: AGPL-3.0-only
//! The operation context at the transport boundary, for every method the
//! proto declares keyed: a call without a valid context is refused before
//! any method runs, a call with one goes on, and over HTTP both headers
//! reach the boundary through the transcoder.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::mock_storage::MockStorage;
use sid_authn::operation::grpc::OperationPeriods;
use sid_proto::sid::v1::operation_service_server::OperationServiceServer;
use tonic::codegen::{Bytes, http};
use tower::ServiceExt;

/// What the server routes to: the operation service alone, so every other
/// method answers UNIMPLEMENTED once it passes the boundary.
fn upstream() -> impl tower::Service<
    http::Request<tonic::body::Body>,
    Response = http::Response<tonic::body::Body>,
    Error = std::convert::Infallible,
> + Clone {
    let routes = tonic::service::Routes::new(OperationServiceServer::new(OperationPeriods::new(
        Arc::new(MockStorage::new()),
    )));
    tower::ServiceBuilder::new()
        .layer(sid_authn::operation::grpc::OperationContextLayer)
        .service(routes)
}

fn grpc_call(method: &str, context: bool) -> http::Request<tonic::body::Body> {
    let mut request = http::Request::builder()
        .method("POST")
        .uri(format!("http://sid.example.com/{method}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    if context {
        request = request
            .header("idempotency-key", r#""k-1""#)
            .header("sid-operation-period", "1");
    }
    request
        // One empty message: the frame's flag byte and zero length.
        .body(tonic::body::Body::new(http_body_util::Full::new(
            Bytes::from_static(&[0, 0, 0, 0, 0]),
        )))
        .unwrap()
}

/// Every keyed method, from the list the build generates from the proto:
/// without a context it is refused at the boundary with the field named;
/// with one the call goes on to routing.
#[tokio::test]
async fn every_keyed_method_requires_its_context() {
    assert!(!sid_proto::keyed::METHODS.is_empty());
    for method in sid_proto::keyed::METHODS {
        let refused = upstream().oneshot(grpc_call(method, false)).await.unwrap();
        let status = tonic::Status::from_header_map(refused.headers())
            .unwrap_or_else(|| panic!("{method}: refused at the boundary"));
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "{method}");
        assert_eq!(
            sid_core::grpc_error::extract_error_info(&status).unwrap().0,
            "REQUIRED_FIELD_MISSING",
            "{method}"
        );

        let passed = upstream().oneshot(grpc_call(method, true)).await.unwrap();
        let status = tonic::Status::from_header_map(passed.headers());
        assert!(
            status
                .as_ref()
                .is_none_or(|s| s.code() == tonic::Code::Unimplemented),
            "{method}: a call with its context reaches routing, got {status:?}"
        );
    }
}

/// A method the proto does not declare keyed is not asked for a context.
#[tokio::test]
async fn an_unkeyed_method_needs_no_context() {
    let method = "sid.v1.common.OperationService/GetOperationPeriod";
    assert!(!sid_proto::keyed::is_keyed_path(&format!("/{method}")));
    let response = upstream().oneshot(grpc_call(method, false)).await.unwrap();
    assert!(
        tonic::Status::from_header_map(response.headers())
            .is_none_or(|s| s.code() == tonic::Code::Ok),
        "the period is answered"
    );
}

/// The server's own HTTP form over the transcoder: the HTTP base URL.
async fn over_http() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let proxy = sid_server::serve::http_transcoder(Some("127.0.0.1:0"), None, None)
        .unwrap()
        .expect("a bind address gives a transcoder");
    let routes = sid_server::serve::transcoder_upstream(
        tonic::service::Routes::new(OperationServiceServer::new(OperationPeriods::new(
            Arc::new(MockStorage::new()),
        ))),
        Arc::new(sid_authn::issuer::IssuerRegistry::new(
            Arc::new(MockStorage::new()),
            common::test_key_manager(),
        )),
    );
    tokio::spawn(async move {
        sid_infra::http::serve_on(
            &proxy,
            routes,
            listener,
            std::future::pending(),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
    });
    format!("http://{addr}")
}

fn client() -> reqwest::Client {
    common::crypto::with_tls(sid_plugin::client_builder)
        .build()
        .unwrap()
}

/// Over HTTP the period is answered at its annotated route, and a keyed
/// method's call carries `Idempotency-Key` and `SID-Operation-Period` to the
/// boundary: without them it is refused there, with them it goes on.
#[tokio::test]
async fn the_http_form_carries_the_context() {
    let base = over_http().await;
    let period: serde_json::Value = client()
        .get(format!("{base}/v1/operations/period"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(period["period"], serde_json::json!("1"), "{period}");

    let create = format!("{base}/v1/projects");
    let refused = client()
        .post(&create)
        .json(&serde_json::json!({ "name": "p" }))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = refused.text().await.unwrap();
    assert!(body.contains("REQUIRED_FIELD_MISSING"), "{body}");

    let passed = client()
        .post(&create)
        .header("Idempotency-Key", r#""k-1""#)
        .header("SID-Operation-Period", "1")
        .json(&serde_json::json!({ "name": "p" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        passed.status(),
        reqwest::StatusCode::NOT_IMPLEMENTED,
        "past the boundary to routing"
    );
}
