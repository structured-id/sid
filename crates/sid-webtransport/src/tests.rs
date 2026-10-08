// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::config::{Config, TlsMode};

fn dev_config() -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        tls: TlsMode::Dev,
    }
}

#[tokio::test]
async fn test_resolve_cert_hash_makes_hash_available() {
    let dispatcher = Dispatcher::new();
    let mut server = WebTransportServer::new(dev_config(), dispatcher);

    assert!(server.cert_hash().is_none());

    let hash = server.resolve_cert_hash().await.unwrap();
    assert!(!hash.is_empty());
    assert!(hash.contains(':'));
    assert_eq!(server.cert_hash(), Some(hash.as_str()));
}

#[tokio::test]
async fn test_resolve_cert_hash_stores_identity() {
    let dispatcher = Dispatcher::new();
    let mut server = WebTransportServer::new(dev_config(), dispatcher);

    assert!(server.resolved_identity.is_none());

    server.resolve_cert_hash().await.unwrap();

    assert!(server.resolved_identity.is_some());
}

/// The server ends when its shutdown future resolves instead of accepting
/// forever, so the process that owns it can stop.
#[tokio::test]
async fn test_serve_returns_after_shutdown() {
    let server = WebTransportServer::new(dev_config(), Dispatcher::new());
    let served = tokio::time::timeout(
        Duration::from_secs(10),
        server.serve(
            tokio::time::sleep(Duration::from_millis(100)),
            Duration::from_secs(1),
        ),
    )
    .await
    .expect("the server did not stop after shutdown");
    assert!(served.is_ok(), "{served:?}");
}

/// A certificate that cannot be loaded makes `serve` fail instead of
/// panicking in its task.
#[tokio::test]
async fn test_serve_fails_without_its_certificate() {
    let missing = std::env::temp_dir().join(format!("sid-wt-serve-{}", std::process::id()));
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        tls: TlsMode::Pem {
            cert: missing.join("cert.pem"),
            key: missing.join("key.pem"),
        },
    };
    let served = WebTransportServer::new(config, Dispatcher::new())
        .serve(std::future::pending(), Duration::from_secs(1))
        .await;
    assert!(matches!(served, Err(ServeError::Tls(TlsError::Pem { .. }))));
}

#[test]
fn test_status_to_code_mapping() {
    assert_eq!(status_to_code(&Status::ok("")), 0);
    assert_eq!(status_to_code(&Status::not_found("")), 5);
    assert_eq!(status_to_code(&Status::permission_denied("")), 7);
    assert_eq!(status_to_code(&Status::unimplemented("")), 12);
    assert_eq!(status_to_code(&Status::internal("")), 13);
    assert_eq!(status_to_code(&Status::unavailable("")), 14);
    assert_eq!(status_to_code(&Status::unauthenticated("")), 16);
}
