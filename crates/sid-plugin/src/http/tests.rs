// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

/// The panic this helper exists to prevent: building a client with no process
/// provider set. A plain `reqwest::Client::builder().build()` aborts here.
#[test]
fn test_client_builds_without_a_preinstalled_provider() {
    let client = client_builder().build();
    assert!(client.is_ok(), "{:?}", client.err());
}

/// Callers construct clients independently and in any order, so the second
/// call must behave exactly like the first.
#[test]
fn test_repeated_calls_keep_working() {
    assert!(client_builder().build().is_ok());
    assert!(client_builder().build().is_ok());
}

/// The installed provider is the one CE links. A build that silently fell back
/// to another provider would still pass the tests above.
#[test]
fn test_installed_provider_is_ring() {
    let _ = client_builder();
    let installed = rustls::crypto::CryptoProvider::get_default().expect("provider installed");
    let ring = rustls::crypto::ring::default_provider();
    assert_eq!(
        installed.cipher_suites.len(),
        ring.cipher_suites.len(),
        "a different provider is installed"
    );
    assert!(
        installed
            .cipher_suites
            .iter()
            .all(|s| ring.cipher_suites.contains(s))
    );
}
