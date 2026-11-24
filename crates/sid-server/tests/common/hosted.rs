// SPDX-License-Identifier: AGPL-3.0-only
//! What the tests of an installation hosted in another process's listener
//! share. Each of them sets process settings, so each is the only test of
//! its binary.

use http_body_util::BodyExt as _;
use tonic::codegen::http;
use tower::ServiceExt as _;

pub const ISSUER: &str = "https://sid.example.com";

/// The body of the answer to `GET path`, which must be 200.
pub async fn get<S>(surface: &S, path: &str) -> serde_json::Value
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
pub fn free_address() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// The test PostgreSQL (docker-compose.test.yml).
pub fn database_url() -> String {
    std::env::var("SID_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".into())
}

/// The process settings `settings` name and the crypto providers, once for
/// the binary. Called first in its test, on its only thread: the runtime
/// starts afterwards.
pub fn configure(settings: &[(&str, String)]) {
    for (name, value) in settings {
        // SAFETY: no other thread exists yet.
        unsafe { std::env::set_var(name, value) };
    }
    sid_crypto::tls::aws_lc::provider()
        .install_default()
        .expect("no TLS provider is installed yet");
    sid_crypto::jwt::install_jwt_provider().unwrap();
}
