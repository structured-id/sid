// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::auth::jwt::Confirmation;
use axum::http::HeaderValue;
use sid_plugin::cache::InMemoryCacheBackend;
use std::sync::Arc;

const URI: &str = "https://app.sid.example.com/api/items";
const TOKEN: &str = "eyJ.bound.token";
/// RFC 7638 thumbprint of the fixture key.
const FIXTURE_JKT: &str = "IzldvVrK202QRbmgX2y6_CaeNdfk9cCd6-2B-mLPdBA";

fn validator() -> DPopValidator {
    DPopValidator::new(Arc::new(InMemoryCacheBackend::new()))
}

fn claims(jkt: Option<&str>) -> ForwardAuthClaims {
    ForwardAuthClaims {
        sub: "sub".into(),
        iss: "https://sid.example.com".into(),
        exp: 0,
        iat: 0,
        auth_time: 0,
        acr: "standard".into(),
        scope: String::new(),
        roles: String::new(),
        sid: "sid".into(),
        jti: "jti".into(),
        email: None,
        name: None,
        preferred_username: None,
        groups: None,
        cnf: jkt.map(|jkt| Confirmation { jkt: jkt.into() }),
    }
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
        "ath": sid_authn::dpop::access_token_hash(token),
    });
    let key = EncodingKey::from_ec_pem(include_bytes!(
        "../../../../sid-authn/tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    encode(&header, &payload, &key).unwrap()
}

fn with_proof(proof: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("dpop", HeaderValue::from_str(proof).unwrap());
    headers
}

async fn check(
    presented: Presented<'_>,
    claims: &ForwardAuthClaims,
    headers: &HeaderMap,
) -> Result<(), SenderError> {
    check_sender(&validator(), presented, claims, headers, "GET", Some(URI)).await
}

/// An unbound token keeps working as a bearer token.
#[tokio::test]
async fn unbound_bearer_is_accepted() {
    let none = HeaderMap::new();
    check(Presented::Bearer(TOKEN), &claims(None), &none)
        .await
        .unwrap();
}

/// A bound token presented as a bearer token is refused, even beside a
/// valid proof: that is how a stolen bound token would be replayed.
#[tokio::test]
async fn bound_token_as_bearer_is_refused() {
    let bound = claims(Some(FIXTURE_JKT));
    let headers = with_proof(&proof("s-1", URI, TOKEN));
    let err = check(Presented::Bearer(TOKEN), &bound, &headers)
        .await
        .unwrap_err();
    assert!(matches!(err, SenderError::ProofRequired), "{err:?}");
}

/// The DPoP scheme with a proof by the bound key for this request passes.
#[tokio::test]
async fn bound_token_with_its_proof_is_accepted() {
    let headers = with_proof(&proof("s-2", URI, TOKEN));
    check(Presented::DPoP(TOKEN), &claims(Some(FIXTURE_JKT)), &headers)
        .await
        .unwrap();
}

/// The DPoP scheme without a proof, or with two, is refused.
#[tokio::test]
async fn bound_token_needs_exactly_one_proof() {
    let bound = claims(Some(FIXTURE_JKT));
    let err = check(Presented::DPoP(TOKEN), &bound, &HeaderMap::new())
        .await
        .unwrap_err();
    assert!(matches!(err, SenderError::ProofRequired));

    let mut two = with_proof(&proof("s-3", URI, TOKEN));
    two.append(
        "dpop",
        HeaderValue::from_str(&proof("s-4", URI, TOKEN)).unwrap(),
    );
    let err = check(Presented::DPoP(TOKEN), &bound, &two)
        .await
        .unwrap_err();
    assert!(matches!(err, SenderError::ProofRequired));
}
