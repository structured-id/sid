// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

/// Constructing an outbound client must leave backend selection to its host.
#[test]
fn client_construction_does_not_install_a_provider() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    assert!(matches!(
        client_builder(),
        Err(HttpClientError::ProviderNotSelected)
    ));
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_none(),
        "the HTTP library selected a TLS backend for its embedding host"
    );
}

/// Missing host configuration is a typed refusal, with no implicit installation.
#[test]
fn test_client_builds_without_a_preinstalled_provider() {
    assert!(matches!(
        client_builder(),
        Err(HttpClientError::ProviderNotSelected)
    ));
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
}

/// Callers construct clients independently and in any order, so the second
/// call must behave exactly like the first.
#[test]
fn test_repeated_calls_keep_working() {
    sid_crypto::tls::aws_lc::provider()
        .install_default()
        .unwrap();
    assert!(client_builder().unwrap().build().is_ok());
    assert!(client_builder().unwrap().build().is_ok());
}

/// A caller's explicit selection retains its identity across client creation.
#[test]
fn test_preserves_the_host_provider() {
    sid_crypto::tls::aws_lc::provider()
        .install_default()
        .unwrap();
    let selected = rustls::crypto::CryptoProvider::get_default().unwrap();
    assert!(client_builder().unwrap().build().is_ok());
    assert!(std::sync::Arc::ptr_eq(
        selected,
        rustls::crypto::CryptoProvider::get_default().unwrap()
    ));
}

/// Exercise an actual HTTPS request, preserving verification and host selection.
async fn https_with(provider: rustls::crypto::CryptoProvider) {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    provider.install_default().unwrap();
    let selected = rustls::crypto::CryptoProvider::get_default().unwrap();
    let identity = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let client = client_builder()
        .unwrap()
        .add_root_certificate(reqwest::Certificate::from_der(identity.cert.der()).unwrap())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    assert!(Arc::ptr_eq(
        selected,
        rustls::crypto::CryptoProvider::get_default().unwrap()
    ));
    let config =
        rustls::ServerConfig::builder_with_provider(Arc::new(sid_crypto::tls::aws_lc::provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(tokio::time::timeout(Duration::from_secs(20), async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(stream)
            .await
            .unwrap();
        let mut request = [0; 1024];
        let mut used = 0;
        loop {
            assert!(used < request.len(), "bounded test request headers");
            let read = stream.read(&mut request[used..]).await.unwrap();
            assert_ne!(read, 0, "complete HTTP request headers");
            used += read;
            if request[..used].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                break;
            }
        }
        assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    }));
    let response = client.get(format!("https://{address}/")).send().await;
    peer.await
        .unwrap()
        .expect("local TLS peer completed before its timeout");
    let response = response.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "ok");
}

/// The stock SID backend carries a real verified HTTPS request.
#[tokio::test]
async fn https_uses_the_host_aws_lc_provider() {
    https_with(sid_crypto::tls::aws_lc::provider()).await;
}

/// An embedding host can explicitly select RustCrypto for the same HTTP path.
#[tokio::test]
async fn https_uses_the_host_rustcrypto_provider() {
    https_with(sid_crypto::tls::rustcrypto::provider()).await;
}
