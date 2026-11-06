// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::sync::Arc;

const URI: &str = "https://app.sid.example.com/api/items";
const TOKEN: &str = "eyJ.bound.token";
/// RFC 7638 thumbprint of the fixture key.
const FIXTURE_JKT: &str = "IzldvVrK202QRbmgX2y6_CaeNdfk9cCd6-2B-mLPdBA";

fn validator() -> DPopValidator {
    DPopValidator::new(Arc::new(sid_plugin::InProcessCeremonyState::new()))
}

/// A proof by the fixture key for `GET htu`, naming `token`.
fn proof(jti: &str, htu: &str, token: &str) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC", "crv": "P-256",
        "x": "b0K7RgRe5HiYfkZuCqJFDTDaIAkBIkVOP3xIggAghyc",
        "y": "01y9J7CAYH9p1uB6va3wvUKXiyIlFK_fm2NJckH7xcQ",
    }))
    .unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".into());
    header.jwk = Some(jwk);
    let payload = serde_json::json!({
        "jti": jti, "htm": "GET", "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
        "ath": crate::dpop::access_token_hash(token),
    });
    let key = EncodingKey::from_ec_pem(include_bytes!(
        "../../tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    encode(&header, &payload, &key).unwrap()
}

async fn check(scheme: Scheme, bound: Option<&str>, proofs: &[&str]) -> Result<(), SenderError> {
    check_sender(&validator(), scheme, TOKEN, bound, proofs, "GET", Some(URI)).await
}

/// An unbound token keeps working as a bearer token.
#[tokio::test]
async fn unbound_bearer_is_accepted() {
    check(Scheme::Bearer, None, &[]).await.unwrap();
}

/// A bound token presented as a bearer token is refused, proof or not: that
/// is how a stolen bound token would be replayed without the key.
#[tokio::test]
async fn bound_token_as_bearer_is_refused() {
    let p = proof("s-1", URI, TOKEN);
    let err = check(Scheme::Bearer, Some(FIXTURE_JKT), &[&p])
        .await
        .unwrap_err();
    assert!(matches!(err, SenderError::ProofRequired), "{err:?}");
    assert_eq!(err.challenge(), r#"DPoP error="invalid_token""#);
}

/// The DPoP scheme with a proof by the bound key for this request passes.
#[tokio::test]
async fn bound_token_with_its_proof_is_accepted() {
    let p = proof("s-2", URI, TOKEN);
    check(Scheme::DPoP, Some(FIXTURE_JKT), &[&p]).await.unwrap();
}

/// The DPoP scheme without a proof, or with two, is refused.
#[tokio::test]
async fn bound_token_needs_exactly_one_proof() {
    let err = check(Scheme::DPoP, Some(FIXTURE_JKT), &[])
        .await
        .unwrap_err();
    assert!(matches!(err, SenderError::ProofRequired));

    let (a, b) = (proof("s-3", URI, TOKEN), proof("s-4", URI, TOKEN));
    let err = check(Scheme::DPoP, Some(FIXTURE_JKT), &[&a, &b])
        .await
        .unwrap_err();
    assert!(matches!(err, SenderError::ProofRequired));
}

/// A proof made for another resource does not open this one.
#[tokio::test]
async fn proof_for_another_uri_is_refused() {
    let p = proof("s-5", "https://app.sid.example.com/other", TOKEN);
    let err = check(Scheme::DPoP, Some(FIXTURE_JKT), &[&p])
        .await
        .unwrap_err();
    assert!(matches!(err, SenderError::Proof(DPopError::UriMismatch)));
    assert_eq!(err.challenge(), r#"DPoP error="invalid_dpop_proof""#);
}

/// A proof by a key the token is not bound to is refused.
#[tokio::test]
async fn proof_by_another_key_is_refused() {
    let p = proof("s-6", URI, TOKEN);
    let err = check(Scheme::DPoP, Some("other-jkt"), &[&p])
        .await
        .unwrap_err();
    assert!(matches!(err, SenderError::Proof(DPopError::KeyMismatch)));
}

/// The DPoP scheme with an unbound token is refused (RFC 9449 §7.1).
#[tokio::test]
async fn dpop_scheme_with_unbound_token_is_refused() {
    let p = proof("s-7", URI, TOKEN);
    let err = check(Scheme::DPoP, None, &[&p]).await.unwrap_err();
    assert!(matches!(err, SenderError::NotBound));
}

/// Without the request URI the proof cannot be checked: refused.
#[tokio::test]
async fn unknown_uri_is_refused() {
    let p = proof("s-8", URI, TOKEN);
    let err = check_sender(
        &validator(),
        Scheme::DPoP,
        TOKEN,
        Some(FIXTURE_JKT),
        &[&p],
        "GET",
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, SenderError::UriUnknown));
}
