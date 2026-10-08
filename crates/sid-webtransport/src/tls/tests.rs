// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[test]
fn test_dev_cert_generates_non_empty_hash() {
    let identity =
        Identity::self_signed(["localhost"]).expect("failed to create self-signed identity");
    let hash = compute_cert_hash(&identity).unwrap();
    // wtransport formats hash as XX:XX:XX:... (32 bytes = 95 chars with colons)
    assert!(!hash.is_empty(), "cert hash should not be empty");
    assert!(
        hash.contains(':'),
        "cert hash should be colon-separated hex"
    );
}

#[test]
fn test_dev_cert_has_certificate_chain() {
    let identity = Identity::self_signed(["localhost", "127.0.0.1"])
        .expect("failed to create self-signed identity");
    let chain = identity.certificate_chain();
    assert!(!chain.as_slice().is_empty(), "chain should not be empty");
}

#[test]
fn test_different_certs_produce_different_hashes() {
    let id1 = Identity::self_signed(["localhost"]).unwrap();
    let id2 = Identity::self_signed(["localhost"]).unwrap();
    let hash1 = compute_cert_hash(&id1).unwrap();
    let hash2 = compute_cert_hash(&id2).unwrap();
    // Each call generates a new key pair, so hashes should differ
    assert_ne!(hash1, hash2);
}

#[tokio::test]
async fn test_resolve_identity_dev_mode() {
    let config = Config {
        bind: "127.0.0.1:4433".parse().unwrap(),
        tls: TlsMode::Dev,
    };
    let resolved = resolve_identity(&config).await.unwrap();
    assert!(!resolved.cert_hash.is_empty());
    assert!(resolved.cert_hash.contains(':'));
}

/// A configured certificate that cannot be loaded is an error naming the
/// files, which stops startup, not a panic in the serving task.
#[tokio::test]
async fn test_missing_pem_files_are_an_error() {
    let dir = std::env::temp_dir().join(format!("sid-wt-missing-{}", std::process::id()));
    let config = Config {
        bind: "127.0.0.1:4433".parse().unwrap(),
        tls: TlsMode::Pem {
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
        },
    };
    match resolve_identity(&config).await {
        Err(TlsError::Pem { cert, key, .. }) => {
            assert_eq!(cert, dir.join("cert.pem"));
            assert_eq!(key, dir.join("key.pem"));
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("missing PEM files were accepted"),
    }
}
