// SPDX-License-Identifier: AGPL-3.0-only
//! An installation served by a host with a listener of its own: the host
//! calls the installation's HTTP surface in process, and the installation
//! binds nothing.
#![cfg(all(feature = "ui", feature = "storage-pg"))]

use http_body_util::BodyExt as _;
use tonic::codegen::http;
use tower::ServiceExt as _;

const ISSUER: &str = "https://sid.example.com";

/// The body of the answer to `GET path`, which must be 200.
async fn get<S>(surface: &S, path: &str) -> serde_json::Value
where
    S: tower::Service<
            http::Request<tonic::body::Body>,
            Response = http::Response<axum::body::Body>,
            Error = std::convert::Infallible,
        > + Clone,
{
    let request = http::Request::get(path)
        .header("host", "sid.example.com")
        .body(tonic::body::Body::empty())
        .unwrap();
    let Ok(answer) = surface.clone().oneshot(request).await;
    assert_eq!(answer.status(), http::StatusCode::OK, "GET {path}");
    let body = answer.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

/// An address nothing listens on: bound once, then released.
fn free_address() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// A host assembles the installation from its settings and gets its HTTP
/// surface as one service: discovery and the issuer's keys answer through it
/// in process, nothing listens on the addresses the server would have bound,
/// and the background work drains when the host stops.
/// Bug prevented: an installation whose HTTP surface exists only behind the
/// server's own gRPC and HTTP ports, so a host with one listener cannot
/// serve it.
#[test]
fn a_host_serves_the_installation_on_no_listener_of_the_installations() {
    let data = tempfile::tempdir().unwrap();
    let (grpc, http_port) = (free_address(), free_address());
    let settings = [
        (
            "SID_DATABASE_URL",
            std::env::var("SID_TEST_DATABASE_URL")
                .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".into()),
        ),
        // A schema of this run's own: the installation is opened from empty.
        (
            "SID_STORAGE_POSTGRESQL_SCHEMA",
            format!("hosted_{}", uuid::Uuid::new_v4().simple()),
        ),
        ("SID_DATA_DIR", data.path().to_str().unwrap().to_owned()),
        ("SID_ISSUER", ISSUER.to_owned()),
        ("SID_GRPC_BIND", grpc.to_string()),
    ];
    for (name, value) in settings {
        // SAFETY: the test's only thread so far; the runtime starts below.
        unsafe { std::env::set_var(name, value) };
    }
    // Ignored when another test of this process installed them already.
    let _ = sid_crypto::tls::aws_lc::provider().install_default();
    sid_crypto::jwt::install_jwt_provider().unwrap();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let c = sid_server::init::init_ce_with(Default::default())
            .await
            .unwrap();
        let services = sid_server::serve::CeServices::new(&c, Default::default())
            .await
            .unwrap();
        let hosted = sid_server::serve::hosted(c, services, serde_json::json!({})).unwrap();

        let discovery = get(&hosted.http, "/.well-known/openid-configuration").await;
        assert_eq!(discovery["issuer"], ISSUER);
        let keys = get(&hosted.http, "/jwks").await;
        assert!(!keys["keys"].as_array().unwrap().is_empty());

        for address in [grpc, http_port] {
            assert!(
                tokio::net::TcpStream::connect(address).await.is_err(),
                "the installation listens on {address}"
            );
        }
        hosted.background.drain().await.unwrap();
    });
    runtime.shutdown_background();
}
