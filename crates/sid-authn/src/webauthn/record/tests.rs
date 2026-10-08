use super::*;
use crate::test_support::key_manager;
use crate::webauthn::soft_authenticator::SoftAuthenticator;
use crate::webauthn::{RegistrationResponse, WebAuthnServer};
use sid_core::models::WebAuthnUserHandle;
use sid_plugin::cache::InMemoryCacheBackend;
use std::sync::Arc;

/// The record of a passkey registered through a real ceremony.
async fn record_bytes() -> Vec<u8> {
    let server = WebAuthnServer::new(
        "sid.example.com",
        &url::Url::parse("https://sid.example.com").unwrap(),
        Arc::new(InMemoryCacheBackend::new()),
        key_manager(),
    )
    .unwrap();
    let start = server
        .registration_start(WebAuthnUserHandle([3; 16]), "alice", &[])
        .await
        .unwrap();
    let mut key = SoftAuthenticator::new("https://sid.example.com", "sid.example.com");
    let response = RegistrationResponse::parse(&key.register(&start.options)).unwrap();
    server.registration_finish(&response).await.unwrap().data
}

/// Every field round-trips, and every truncation of a valid record is
/// refused, never read short.
#[tokio::test]
async fn test_record_round_trips_and_truncations_are_refused() {
    let bytes = record_bytes().await;
    let record = decode(&bytes).unwrap();
    assert_eq!(record.user_handle, [3; 16]);
    assert_eq!(record.id.as_ref().len(), 16);
    for len in 0..bytes.len() {
        assert!(decode(&bytes[..len]).is_err(), "decoded {len} bytes");
    }
}

/// Trailing bytes and an unknown version are refused.
#[tokio::test]
async fn test_trailing_data_and_unknown_version_are_refused() {
    let mut bytes = record_bytes().await;
    bytes.push(0);
    assert!(decode(&bytes).is_err());
    let mut bytes = record_bytes().await;
    bytes[0] = 2;
    assert!(decode(&bytes).is_err());
}

/// Rewriting the dynamic state changes those 7 bytes and nothing else.
#[tokio::test]
async fn test_dynamic_state_is_rewritten_in_place() {
    let bytes = record_bytes().await;
    let record = decode(&bytes).unwrap();
    let mut dynamic = record.dynamic_state;
    dynamic.sign_count = 0xdead_beef;
    let out = with_dynamic_state(&bytes, record.dynamic_at, dynamic);
    assert_eq!(out.len(), bytes.len());
    assert_eq!(decode(&out).unwrap().dynamic_state, dynamic);
    assert_eq!(out[..record.dynamic_at], bytes[..record.dynamic_at]);
    assert_eq!(
        out[record.dynamic_at + DYNAMIC_LEN..],
        bytes[record.dynamic_at + DYNAMIC_LEN..]
    );
}
