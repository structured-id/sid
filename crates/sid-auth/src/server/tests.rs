// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn config(extra: &str) -> AuthConfig {
    serde_yaml::from_str(&format!(
        "upstream: http://127.0.0.1:1\nissuer_url: https://sid.example.com\n{extra}"
    ))
    .unwrap()
}

fn cache() -> Arc<dyn sid_plugin::cache::CacheBackend> {
    Arc::new(sid_plugin::cache::InMemoryCacheBackend::new())
}

/// A route file that does not load stops start-up instead of leaving every
/// application refused.
#[tokio::test]
async fn broken_route_file_stops_startup() {
    let result = AuthServer::new(
        config("route_policy_path: /nonexistent/route-policies.yaml\n"),
        cache(),
    );
    assert!(result.is_err());
}

/// Without a route file the service starts and refuses every application.
#[tokio::test]
async fn no_route_file_refuses_everything() {
    let server = AuthServer::new(config(""), cache()).unwrap();
    assert!(server.pdp().applications.application("orders").is_none());
}

/// Every refusal of the SID services served here, without a token, with a
/// malformed one and with an unknown issuer's, carries ErrorInfo in the
/// structured.id domain. Envoy ext_authz answers denials in its response, by
/// its own protocol, and is not described by SID's descriptors.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_refusal_carries_error_info() {
    use sid_serve::error_contract::{Caller, probe};
    let server = AuthServer::new(config(""), cache()).unwrap();
    let (routes, health) = server.services().await.into_parts();
    let report = probe(
        routes,
        health.names(),
        &[sid_proto::FILE_DESCRIPTOR_SET],
        &[sid_core::grpc_error::DOMAIN_SID],
        &[
            Caller {
                name: "anonymous",
                token: None,
            },
            Caller {
                name: "malformed",
                token: Some("not-a-jwt"),
            },
            Caller {
                name: "unknown issuer",
                token: Some(
                    "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL290aGVyLmV4YW1wbGUuY29tIn0.c2ln",
                ),
            },
        ],
    )
    .await;
    assert!(report.methods >= 1, "{report:?}");
    assert!(report.refusals >= report.methods, "{report:?}");
    assert!(
        report.violations.is_empty(),
        "{}",
        report.violations.join("\n")
    );
}

/// Without an `http` section there is no HTTP form.
#[cfg(feature = "http")]
#[tokio::test]
async fn no_http_section_no_transcoder() {
    let server = AuthServer::new(config(""), cache()).unwrap();
    assert!(server.http_proxy().unwrap().is_none());
}

/// The transcoder forwards the original request's headers whatever the
/// operator listed.
#[cfg(feature = "http")]
#[tokio::test]
async fn transcoder_forwards_the_original_request() {
    let server = AuthServer::new(
        config(
            "http:\n  listen: { http: \"127.0.0.1:8080\" }\n  forwarded_headers: [x-request-id]\n",
        ),
        cache(),
    )
    .unwrap();
    let proxy = server
        .http_proxy()
        .unwrap()
        .expect("an http section gives a transcoder");
    let forwarded = &proxy.config().forwarded_headers;
    assert!(forwarded.iter().any(|h| h == "x-request-id"));
    for name in FORWARDED_HEADERS {
        assert!(forwarded.iter().any(|h| h == name), "{name}");
    }
}

/// The HTTP form is answered by this process's own decision, not through a
/// network hop to its gRPC listener: with nothing listening on the gRPC
/// address, an unknown application still gets the decision's 404, never 503.
#[cfg(feature = "http")]
#[tokio::test]
async fn http_form_answers_without_a_grpc_listener() {
    use tower::ServiceExt;
    let server = AuthServer::new(
        config("http:\n  listen: { http: \"127.0.0.1:0\" }\n"),
        cache(),
    )
    .unwrap();
    // No gRPC listener is started: the transcoder has only this process.
    let service = server
        .http_proxy()
        .unwrap()
        .expect("an http section gives a transcoder")
        .service(server.routes().await)
        .unwrap();
    let response = service
        .oneshot(
            http::Request::get("/auth/verify/orders")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
}
