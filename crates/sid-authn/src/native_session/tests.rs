// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use secrecy::SecretBox;
use sid_core::models::security_policy::SecurityPolicy;
use sid_keys::{KeyVersionParams, SoftwareKeyManager};
use sid_plugin::StorageBackend;
use sid_storage::sqlite::SqliteBackend;
use std::sync::Arc;

const URL: &str = "https://sid.example.com/sid.v1.authn.AuthService/RefreshNativeSession";
const JWK_X: &str = "b0K7RgRe5HiYfkZuCqJFDTDaIAkBIkVOP3xIggAghyc";
const JWK_Y: &str = "01y9J7CAYH9p1uB6va3wvUKXiyIlFK_fm2NJckH7xcQ";

struct Harness {
    store: SqliteBackend,
    keys: SoftwareKeyManager,
    proofs: DPopValidator,
    policy: NativePolicy,
}

fn keys() -> SoftwareKeyManager {
    SoftwareKeyManager::new(
        SecretBox::new(Box::new([9u8; 32])),
        vec![KeyVersionParams::new(1, vec![1u8; 16], "key-v1")],
        Arc::new(sid_crypto::RustCryptoPrimitives::new()),
    )
    .unwrap()
}

async fn harness() -> Harness {
    Harness {
        store: SqliteBackend::new_in_memory().await.unwrap(),
        keys: keys(),
        proofs: DPopValidator::new(Arc::new(sid_plugin::InProcessCeremonyState::new())),
        policy: NativePolicy::from_session_policy(&SecurityPolicy::ce_default().session).unwrap(),
    }
}

/// The thumbprint of the fixture key every proof below is signed with.
fn fixture_jkt() -> String {
    use sha2::Digest;
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{JWK_X}","y":"{JWK_Y}"}}"#);
    URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(canonical.as_bytes()))
}

/// A stored session of a new Profile bound to `jkt`, with its first generation.
async fn session(h: &Harness, jkt: &str) -> (Session, NativeCredentialSet) {
    let profile = sid_core::models::Profile::new(Some("native"));
    h.store
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    let session = Session::new(
        profile.id,
        None,
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    h.store
        .create_session_atomic(
            &session,
            0,
            None,
            AuditEntry::system("test", "session").into(),
        )
        .await
        .unwrap();
    let set = issue(&h.store, &session, jkt, h.policy).await.unwrap();
    (session, set)
}

fn exchange(byte: u8) -> NativeExchange {
    NativeExchange::from_bytes(&[byte; 16]).unwrap()
}

/// A fresh proof by the fixture key for presenting `credential` in `exchange`.
fn proof(credential: &str, exchange: &NativeExchange) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": JWK_X, "y": JWK_Y,
    }))
    .unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some(crate::dpop::NATIVE_PROOF_TYPE.into());
    header.jwk = Some(jwk);
    let payload = serde_json::json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": "POST",
        "htu": URL,
        "iat": chrono::Utc::now().timestamp(),
        "sid_rt": crate::dpop::native_digest(credential.as_bytes()),
        "sid_ex": URL_SAFE_NO_PAD.encode(exchange.as_bytes()),
    });
    let key = EncodingKey::from_ec_pem(include_bytes!(
        "../../tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    encode(&header, &payload, &key).unwrap()
}

async fn present(
    h: &Harness,
    credential: &str,
    exchange: NativeExchange,
) -> Result<Refreshed, NativeError> {
    let proof = proof(credential, &exchange);
    refresh(
        &h.store,
        &h.keys,
        &h.proofs,
        RefreshRequest {
            proof: &proof,
            method: "POST",
            url: URL,
            credential,
            exchange,
        },
        h.policy,
    )
    .await
}

/// The first generation holds the policy's number of credentials; a refresh
/// with one of them and a fresh proof by the session's key gets the next
/// generation for the same session.
#[tokio::test]
async fn a_refresh_rotates_into_the_next_generation() {
    let h = harness().await;
    let (s, first) = session(&h, &fixture_jkt()).await;
    assert_eq!(first.refresh_credentials.len(), 2);
    assert_eq!(first.redelivery_window, 30);
    let next = present(&h, &first.refresh_credentials[0], exchange(1))
        .await
        .unwrap();
    assert_eq!(next.session_id, s.id);
    assert_eq!(next.set.refresh_credentials.len(), 2);
    assert!(
        next.set
            .refresh_credentials
            .iter()
            .all(|c| !first.refresh_credentials.contains(c))
    );
}

/// A lost response: the retry of the same exchange, with the spare
/// credential and a new proof, gets the very generation the first attempt
/// committed; no second successor exists.
#[tokio::test]
async fn a_retry_after_a_lost_response_gets_the_committed_generation() {
    let h = harness().await;
    let (_, first) = session(&h, &fixture_jkt()).await;
    let lost = present(&h, &first.refresh_credentials[0], exchange(1))
        .await
        .unwrap();
    let retried = present(&h, &first.refresh_credentials[1], exchange(1))
        .await
        .unwrap();
    assert_eq!(retried.set, lost.set);
    // And the delivered generation works.
    present(&h, &lost.set.refresh_credentials[0], exchange(2))
        .await
        .unwrap();
}

/// Token-only theft: a copied credential with a proof by another key is
/// refused before any effect, and the client keeps its session.
#[tokio::test]
async fn a_credential_without_its_key_rotates_and_ends_nothing() {
    let h = harness().await;
    let (s, first) = session(&h, "the-device-key-thumbprint").await;
    let err = present(&h, &first.refresh_credentials[0], exchange(1))
        .await
        .err()
        .unwrap();
    assert!(matches!(err, NativeError::KeyMismatch), "{err:?}");
    assert!(h.store.get_session(s.id).await.unwrap().is_some());
    let still = h
        .store
        .native_generation_by_credential(&OAuth2Server::hash_token(&first.refresh_credentials[0]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        still.state,
        sid_core::models::NativeGenerationState::Current
    );
}

/// A retired credential presented with the session's key in another
/// exchange ends the session: whoever holds it is not the client alone.
#[tokio::test]
async fn a_retired_credential_with_its_key_ends_the_session() {
    let h = harness().await;
    let (s, first) = session(&h, &fixture_jkt()).await;
    present(&h, &first.refresh_credentials[0], exchange(1))
        .await
        .unwrap();
    let err = present(&h, &first.refresh_credentials[1], exchange(2))
        .await
        .err()
        .unwrap();
    assert!(matches!(err, NativeError::Reused), "{err:?}");
    assert!(h.store.get_session(s.id).await.unwrap().is_none());
}

/// A credential no generation holds is refused and ends nothing.
#[tokio::test]
async fn an_unknown_credential_is_refused() {
    let h = harness().await;
    let err = present(&h, "never-issued", exchange(1))
        .await
        .err()
        .unwrap();
    assert!(matches!(err, NativeError::UnknownCredential), "{err:?}");
}

/// A generation size outside the bounds is a policy error, not a silent
/// default.
#[test]
fn the_generation_size_is_bounded() {
    let mut policy = SecurityPolicy::ce_default().session;
    for size in [0, NATIVE_GENERATION_SIZE_MAX + 1] {
        policy.native_refresh_generation_size = size;
        assert!(
            NativePolicy::from_session_policy(&policy).is_err(),
            "{size}"
        );
    }
}
