// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

/// ES256 test key JWK coordinates (from test_es256_public.pem fixture).
const TEST_JWK_X: &str = "b0K7RgRe5HiYfkZuCqJFDTDaIAkBIkVOP3xIggAghyc";
const TEST_JWK_Y: &str = "01y9J7CAYH9p1uB6va3wvUKXiyIlFK_fm2NJckH7xcQ";

fn test_admissions() -> Arc<dyn SingleUseAdmissions> {
    Arc::new(sid_plugin::InProcessCeremonyState::new())
}

/// Build a DPoP proof JWT signed with ES256 for testing.
///
/// Uses `jsonwebtoken::encode` with `Header.jwk` (supported in v9.3+).
fn build_dpop_proof(method: &str, url: &str, iat_offset_secs: i64, jti: &str) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    let ec_private_key = include_bytes!("../../tests/fixtures/test_es256_private.pem");

    // Build JWK for header
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": TEST_JWK_X,
        "y": TEST_JWK_Y,
    }))
    .unwrap();

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(jwk);

    let now = chrono::Utc::now().timestamp() + iat_offset_secs;
    let payload = serde_json::json!({
        "jti": jti,
        "htm": method,
        "htu": url,
        "iat": now,
    });

    let encoding_key = EncodingKey::from_ec_pem(ec_private_key).unwrap();
    encode(&header, &payload, &encoding_key).unwrap()
}

#[tokio::test]
async fn test_valid_dpop_proof() {
    let validator = DPopValidator::new(test_admissions());
    let proof = build_dpop_proof(
        "POST",
        "https://sid.example.com/v1/oauth2/token",
        0,
        "unique-jti-1",
    );

    let result = validator
        .validate(&proof, "POST", "https://sid.example.com/v1/oauth2/token")
        .await;
    assert!(result.is_ok(), "expected Ok, got: {:?}", result);

    let binding = result.unwrap();
    assert!(!binding.jkt.is_empty());
}

#[tokio::test]
async fn test_dpop_thumbprint_matches_known_value() {
    let validator = DPopValidator::new(test_admissions());
    let proof = build_dpop_proof(
        "POST",
        "https://sid.example.com/v1/oauth2/token",
        0,
        "thumbprint-jti",
    );

    let binding = validator
        .validate(&proof, "POST", "https://sid.example.com/v1/oauth2/token")
        .await
        .unwrap();

    // Verify the thumbprint matches what we computed offline.
    assert_eq!(binding.jkt, "IzldvVrK202QRbmgX2y6_CaeNdfk9cCd6-2B-mLPdBA");
}

#[tokio::test]
async fn test_dpop_replay_detected() {
    let validator = DPopValidator::new(test_admissions());
    let proof = build_dpop_proof(
        "POST",
        "https://sid.example.com/v1/oauth2/token",
        0,
        "replay-jti",
    );

    // First use — OK
    let r1 = validator
        .validate(&proof, "POST", "https://sid.example.com/v1/oauth2/token")
        .await;
    assert!(r1.is_ok());

    // Second use with same jti — replay
    let proof2 = build_dpop_proof(
        "POST",
        "https://sid.example.com/v1/oauth2/token",
        0,
        "replay-jti",
    );
    let r2 = validator
        .validate(&proof2, "POST", "https://sid.example.com/v1/oauth2/token")
        .await;
    assert!(matches!(r2, Err(DPopError::ReplayDetected)));
}

#[tokio::test]
async fn test_dpop_expired_proof() {
    let validator = DPopValidator::new(test_admissions());
    let proof = build_dpop_proof(
        "POST",
        "https://sid.example.com/v1/oauth2/token",
        -120, // 2 minutes ago
        "expired-jti",
    );

    let result = validator
        .validate(&proof, "POST", "https://sid.example.com/v1/oauth2/token")
        .await;
    assert!(matches!(result, Err(DPopError::Expired { .. })));
}

#[tokio::test]
async fn test_dpop_future_proof_rejected() {
    let validator = DPopValidator::new(test_admissions());
    let proof = build_dpop_proof(
        "POST",
        "https://sid.example.com/v1/oauth2/token",
        60, // 60 seconds in the future (beyond 5s tolerance)
        "future-jti",
    );

    let result = validator
        .validate(&proof, "POST", "https://sid.example.com/v1/oauth2/token")
        .await;
    assert!(matches!(result, Err(DPopError::Expired { .. })));
}

#[tokio::test]
async fn test_dpop_wrong_method() {
    let validator = DPopValidator::new(test_admissions());
    let proof = build_dpop_proof(
        "GET",
        "https://sid.example.com/v1/oauth2/token",
        0,
        "method-jti",
    );

    let result = validator
        .validate(&proof, "POST", "https://sid.example.com/v1/oauth2/token")
        .await;
    assert!(matches!(result, Err(DPopError::MethodMismatch { .. })));
}

#[tokio::test]
async fn test_dpop_wrong_url() {
    let validator = DPopValidator::new(test_admissions());
    let proof = build_dpop_proof("POST", "https://evil.example.com/token", 0, "url-jti");

    let result = validator
        .validate(&proof, "POST", "https://sid.example.com/v1/oauth2/token")
        .await;
    assert!(matches!(result, Err(DPopError::UriMismatch)));
}

#[tokio::test]
async fn test_dpop_url_ignores_query_fragment() {
    let validator = DPopValidator::new(test_admissions());
    let proof = build_dpop_proof(
        "POST",
        "https://sid.example.com/v1/oauth2/token",
        0,
        "query-jti",
    );

    // URL with query and fragment should still match
    let result = validator
        .validate(
            &proof,
            "POST",
            "https://sid.example.com/v1/oauth2/token?foo=bar#baz",
        )
        .await;
    assert!(result.is_ok());
}

/// `htu` is compared after URI normalization (RFC 9449 §4.3, RFC 3986
/// §6.2.2/§6.2.3): host case and the scheme's default port do not matter.
#[tokio::test]
async fn test_dpop_url_normalized() {
    let validator = DPopValidator::new(test_admissions());
    let proof = build_dpop_proof(
        "POST",
        "https://SID.Example.com:443/v1/oauth2/token",
        0,
        "normalized-jti",
    );

    let result = validator
        .validate(&proof, "POST", "https://sid.example.com/v1/oauth2/token")
        .await;
    assert!(result.is_ok(), "{result:?}");
}

/// A different port or path is a different resource.
#[tokio::test]
async fn test_dpop_url_other_port_rejected() {
    let validator = DPopValidator::new(test_admissions());
    let proof = build_dpop_proof(
        "POST",
        "https://sid.example.com:8443/v1/oauth2/token",
        0,
        "port-jti",
    );

    let result = validator
        .validate(&proof, "POST", "https://sid.example.com/v1/oauth2/token")
        .await;
    assert!(matches!(result, Err(DPopError::UriMismatch)));
}

/// The `jwk` header must hold a public key only (RFC 9449 §4.3): a proof
/// carrying private key material is refused, even with a valid signature.
#[tokio::test]
async fn test_dpop_private_key_in_jwk_rejected() {
    use jsonwebtoken::{Algorithm, EncodingKey};

    // Built by hand: a typed JWK would drop the private member.
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": TEST_JWK_X,
            "y": TEST_JWK_Y,
            "d": "c2VjcmV0LXByaXZhdGUtc2NhbGFyLXZhbHVlLTMyYg",
        },
    });
    let payload = serde_json::json!({
        "jti": "private-jwk-jti",
        "htm": "POST",
        "htu": "https://sid.example.com/token",
        "iat": chrono::Utc::now().timestamp(),
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    let key = EncodingKey::from_ec_pem(include_bytes!(
        "../../tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    let signature =
        jsonwebtoken::crypto::sign(signing_input.as_bytes(), &key, Algorithm::ES256).unwrap();
    let proof = format!("{signing_input}.{signature}");

    let result = DPopValidator::new(test_admissions())
        .validate(&proof, "POST", "https://sid.example.com/token")
        .await;

    let err = result.unwrap_err().to_string();
    assert!(err.contains("private"), "{err}");
}

#[tokio::test]
async fn test_dpop_malformed_jwt() {
    let validator = DPopValidator::new(test_admissions());
    let result = validator
        .validate("not-a-jwt", "POST", "https://sid.example.com")
        .await;
    assert!(matches!(result, Err(DPopError::InvalidProof(_))));
}

#[tokio::test]
async fn test_dpop_symmetric_algorithm_rejected() {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "HS256",
        "jwk": {"kty": "oct", "k": "dGVzdA"}
    });
    let payload = serde_json::json!({
        "jti": "sym-jti",
        "htm": "POST",
        "htu": "https://sid.example.com/token",
        "iat": chrono::Utc::now().timestamp(),
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let fake_jwt = format!("{header_b64}.{payload_b64}.fakesig");

    let validator = DPopValidator::new(test_admissions());
    let result = validator
        .validate(&fake_jwt, "POST", "https://sid.example.com/token")
        .await;
    assert!(matches!(result, Err(DPopError::InvalidProof(_))));
}

/// A proof carries the key that is supposed to have signed it, so the one
/// thing that must never pass is a proof whose embedded key is somebody
/// else's: that is the whole binding. The key below is well-formed and on
/// the curve, so only the signature check can reject it.
#[tokio::test]
async fn test_dpop_proof_signed_by_another_key_rejected() {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use p256::elliptic_curve::Generate;
    use p256::elliptic_curve::sec1::ToSec1Point;

    let other = p256::SecretKey::generate_from_rng(&mut rand::rng());
    let point = other.public_key().to_sec1_point(false);
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    }))
    .unwrap();

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(jwk);

    let payload = serde_json::json!({
        "jti": "other-key-jti",
        "htm": "POST",
        "htu": "https://sid.example.com/token",
        "iat": chrono::Utc::now().timestamp(),
    });
    let signing_key = EncodingKey::from_ec_pem(include_bytes!(
        "../../tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    let proof = encode(&header, &payload, &signing_key).unwrap();

    let validator = DPopValidator::new(test_admissions());
    let result = validator
        .validate(&proof, "POST", "https://sid.example.com/token")
        .await;
    // The layer matters here: the key parses and is on the curve, so a
    // rejection anywhere earlier would mean the signature went unchecked.
    let err = result.unwrap_err().to_string();
    assert!(err.contains("signature verification failed"), "{err}");
}

/// A JWK whose key type is not one we can build a key from is refused.
/// Which layer refuses it has moved between jsonwebtoken releases — such a
/// JWK used to fail to deserialize and now parses — so the test asserts the
/// outcome rather than the layer.
#[tokio::test]
async fn test_dpop_unknown_key_type_rejected() {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {"kty": "Unsupported", "x": TEST_JWK_X, "y": TEST_JWK_Y},
    });
    let payload = serde_json::json!({
        "jti": "unknown-kty-jti",
        "htm": "POST",
        "htu": "https://sid.example.com/token",
        "iat": chrono::Utc::now().timestamp(),
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let fake_jwt = format!("{header_b64}.{payload_b64}.fakesig");

    let validator = DPopValidator::new(test_admissions());
    let result = validator
        .validate(&fake_jwt, "POST", "https://sid.example.com/token")
        .await;
    assert!(matches!(result, Err(DPopError::InvalidProof(_))));
}

/// The header names EdDSA while the embedded key is EC. Accepting this
/// would mean the algorithm is taken from one place and the key from
/// another, which is how signature verification gets bypassed.
#[tokio::test]
async fn test_dpop_algorithm_not_matching_key_type_rejected() {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": TEST_JWK_X,
            "y": TEST_JWK_Y,
        },
    });
    let payload = serde_json::json!({
        "jti": "alg-mismatch-jti",
        "htm": "POST",
        "htu": "https://sid.example.com/token",
        "iat": chrono::Utc::now().timestamp(),
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let fake_jwt = format!("{header_b64}.{payload_b64}.fakesig");

    let validator = DPopValidator::new(test_admissions());
    let result = validator
        .validate(&fake_jwt, "POST", "https://sid.example.com/token")
        .await;
    assert!(matches!(result, Err(DPopError::InvalidProof(_))));
}

#[tokio::test]
async fn test_dpop_wrong_typ_rejected() {
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": TEST_JWK_X,
            "y": TEST_JWK_Y,
        },
    });
    let payload = serde_json::json!({
        "jti": "typ-jti",
        "htm": "POST",
        "htu": "https://sid.example.com/token",
        "iat": chrono::Utc::now().timestamp(),
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let fake_jwt = format!("{header_b64}.{payload_b64}.fakesig");

    let validator = DPopValidator::new(test_admissions());
    let result = validator
        .validate(&fake_jwt, "POST", "https://sid.example.com/token")
        .await;
    assert!(matches!(result, Err(DPopError::InvalidProof(_))));
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("dpop+jwt"));
}

#[test]
fn test_jwk_thumbprint_ec() {
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": TEST_JWK_X,
        "y": TEST_JWK_Y,
    });
    let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();
    // base64url-encoded SHA-256 = 43 chars
    assert_eq!(thumbprint.len(), 43);
    assert_eq!(thumbprint, "IzldvVrK202QRbmgX2y6_CaeNdfk9cCd6-2B-mLPdBA");
}

#[test]
fn test_jwk_thumbprint_rsa() {
    let jwk = serde_json::json!({
        "kty": "RSA",
        "n": "test_modulus",
        "e": "AQAB",
    });
    let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();
    assert_eq!(thumbprint.len(), 43);
}

#[test]
fn test_jwk_thumbprint_deterministic() {
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "abc",
        "y": "def",
    });
    let t1 = compute_jwk_thumbprint(&jwk).unwrap();
    let t2 = compute_jwk_thumbprint(&jwk).unwrap();
    assert_eq!(t1, t2);
}

/// A proof is rejected when its replay cannot be checked: accepting it
/// would accept a replay the store would have caught.
#[tokio::test]
async fn test_unreachable_replay_store_rejects_the_proof() {
    let validator = DPopValidator::new(Arc::new(crate::test_support::DownCeremonies));
    let proof = build_dpop_proof("POST", "https://sid.example.com/token", 0, "jti-down");

    let result = validator
        .validate(&proof, "POST", "https://sid.example.com/token")
        .await;

    assert!(matches!(result, Err(DPopError::ReplayStoreUnavailable)));
}

/// A `jti` is recorded for the key and target that proved it: another key
/// using the same `jti`, or the same key at another target, is no replay,
/// while the same key at the same target is.
#[tokio::test]
async fn test_replay_record_is_scoped_to_key_and_target() {
    let validator = DPopValidator::new(test_admissions());
    let token = "https://sid.example.com/token";
    validator.first_use("key-a", token, "j").await.unwrap();
    validator.first_use("key-b", token, "j").await.unwrap();
    validator
        .first_use("key-a", "https://sid.example.com/userinfo", "j")
        .await
        .unwrap();
    assert!(matches!(
        validator.first_use("key-a", token, "j").await,
        Err(DPopError::ReplayDetected)
    ));
}

/// A proof admitted for one request is confirmed to that request and refused
/// to any other; a proof the issuer no longer accepts is not admitted.
#[tokio::test]
async fn test_a_request_holds_its_proof_admission() {
    let validator = DPopValidator::new(test_admissions());
    let scope = "https://sid.example.com/i/a resource-1";
    let proof = VerifiedProof {
        jti: "j".into(),
        iat: chrono::Utc::now().timestamp(),
    };
    let first = request_holder(&[1; 16], "token", "POST", "https://app/x", "verifier");
    let retried = request_holder(&[1; 16], "token", "POST", "https://app/x", "verifier");
    let changed = request_holder(&[1; 16], "token", "POST", "https://app/y", "verifier");
    validator
        .admit_for_request(scope, "key", &proof, &first)
        .await
        .unwrap();
    validator
        .admit_for_request(scope, "key", &proof, &retried)
        .await
        .unwrap();
    assert!(matches!(
        validator
            .admit_for_request(scope, "key", &proof, &changed)
            .await,
        Err(DPopError::ReplayDetected)
    ));
    // Another resource's scope is another admission.
    validator
        .admit_for_request(
            "https://sid.example.com/i/a resource-2",
            "key",
            &proof,
            &changed,
        )
        .await
        .unwrap();

    let stale = VerifiedProof {
        jti: "old".into(),
        iat: chrono::Utc::now().timestamp() - 120,
    };
    assert!(matches!(
        validator
            .admit_for_request(scope, "key", &stale, &first)
            .await,
        Err(DPopError::Expired { .. })
    ));
}

/// Admission that cannot be decided is no admission.
#[tokio::test]
async fn test_undecided_admission_is_unavailable() {
    let validator = DPopValidator::new(Arc::new(crate::test_support::DownCeremonies));
    let proof = VerifiedProof {
        jti: "j".into(),
        iat: chrono::Utc::now().timestamp(),
    };
    assert!(matches!(
        validator
            .admit_for_request("scope", "key", &proof, &[0; 32])
            .await,
        Err(DPopError::ReplayStoreUnavailable)
    ));
}

/// A replay record outlives the last moment its proof is still accepted: a
/// proof issued at the furthest accepted future `iat` stays fresh for the
/// whole proof age after it.
#[test]
fn test_replay_record_outlives_the_acceptance_window() {
    let validator = DPopValidator::new(test_admissions());
    let latest_acceptance = DPopProof::MAX_AGE_SECONDS as i64 + FUTURE_IAT_ALLOWANCE_SECS;
    assert!(validator.retention.as_secs() as i64 >= latest_acceptance);
}

/// Two replicas sharing the store: a proof used on one is a replay on the
/// other.
#[tokio::test]
async fn test_replay_is_caught_across_replicas() {
    let admissions = test_admissions();
    let a = DPopValidator::new(admissions.clone());
    let b = DPopValidator::new(admissions);
    let proof = build_dpop_proof("POST", "https://sid.example.com/token", 0, "jti-shared");

    a.validate(&proof, "POST", "https://sid.example.com/token")
        .await
        .unwrap();
    let replay = b
        .validate(&proof, "POST", "https://sid.example.com/token")
        .await;

    assert!(matches!(replay, Err(DPopError::ReplayDetected)));
}

/// Every advertised algorithm is one the validator accepts.
#[test]
fn test_advertised_algorithms_are_accepted() {
    for alg in DPopProof::SIGNING_ALGORITHMS {
        assert!(parse_algorithm(alg).is_ok(), "{alg}");
    }
}

#[test]
fn test_same_htu() {
    assert!(same_htu(
        "https://example.com/path?q=1#frag",
        "https://example.com/path"
    ));
    assert!(same_htu(
        "https://EXAMPLE.com:443/path",
        "https://example.com/path"
    ));
    assert!(!same_htu(
        "https://example.com/path",
        "http://example.com/path"
    ));
    assert!(!same_htu("https://example.com/a", "https://example.com/b"));
    assert!(!same_htu("not a url", "not a url"));
}

const RESOURCE: &str = "https://app.sid.example.com/api/items";

/// A proof for a resource request, carrying `ath` when given.
fn build_resource_proof(jti: &str, ath: Option<&str>) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": TEST_JWK_X, "y": TEST_JWK_Y,
    }))
    .unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(jwk);
    let mut payload = serde_json::json!({
        "jti": jti, "htm": "GET", "htu": RESOURCE, "iat": chrono::Utc::now().timestamp(),
    });
    if let Some(ath) = ath {
        payload["ath"] = serde_json::Value::String(ath.to_string());
    }
    let key = EncodingKey::from_ec_pem(include_bytes!(
        "../../tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    encode(&header, &payload, &key).unwrap()
}

fn test_key_jkt() -> String {
    compute_jwk_thumbprint(&serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": TEST_JWK_X, "y": TEST_JWK_Y,
    }))
    .unwrap()
}

/// RFC 9449 §4.3 step 12 / §7.1: at a resource the proof carries the hash of
/// the presented token and is signed by the key the token is bound to.
#[tokio::test]
async fn test_resource_proof_accepted() {
    let validator = DPopValidator::new(test_admissions());
    let token = "eyJ.access.token";
    let proof = build_resource_proof("res-1", Some(&access_token_hash(token)));
    validator
        .validate_for_resource(&proof, "GET", RESOURCE, token, &test_key_jkt())
        .await
        .unwrap();
}

/// A proof without `ath` cannot accompany an access token.
#[tokio::test]
async fn test_resource_proof_without_ath_rejected() {
    let validator = DPopValidator::new(test_admissions());
    let proof = build_resource_proof("res-2", None);
    let err = validator
        .validate_for_resource(&proof, "GET", RESOURCE, "eyJ.access.token", &test_key_jkt())
        .await
        .unwrap_err();
    assert!(matches!(err, DPopError::AccessTokenHashMismatch));
}

/// A proof made for another token does not cover this one.
#[tokio::test]
async fn test_resource_proof_for_another_token_rejected() {
    let validator = DPopValidator::new(test_admissions());
    let proof = build_resource_proof("res-3", Some(&access_token_hash("eyJ.other.token")));
    let err = validator
        .validate_for_resource(&proof, "GET", RESOURCE, "eyJ.access.token", &test_key_jkt())
        .await
        .unwrap_err();
    assert!(matches!(err, DPopError::AccessTokenHashMismatch));
}

// ── SID native proofs ──

const NATIVE_REFRESH: &str =
    "https://sid.example.com/sid.v1.authn.AuthService/RefreshNativeSession";

/// A SID native proof of `typ` for a POST to `htu` with `claims` added.
fn build_native_proof(typ: &str, htu: &str, jti: &str, claims: serde_json::Value) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": TEST_JWK_X, "y": TEST_JWK_Y,
    }))
    .unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some(typ.to_string());
    header.jwk = Some(jwk);
    let mut payload = serde_json::json!({
        "jti": jti, "htm": "POST", "htu": htu, "iat": chrono::Utc::now().timestamp(),
    });
    for (name, value) in claims.as_object().unwrap() {
        payload[name] = value.clone();
    }
    let key = EncodingKey::from_ec_pem(include_bytes!(
        "../../tests/fixtures/test_es256_private.pem"
    ))
    .unwrap();
    encode(&header, &payload, &key).unwrap()
}

fn exchange(byte: u8) -> sid_core::models::NativeExchange {
    sid_core::models::NativeExchange::from_bytes(&[byte; 16]).unwrap()
}

/// The claims a refresh proof binds: the presented credential's digest and
/// the exchange.
fn refresh_claims(
    credential: &str,
    exchange: &sid_core::models::NativeExchange,
) -> serde_json::Value {
    serde_json::json!({
        "sid_rt": native_digest(credential.as_bytes()),
        "sid_ex": URL_SAFE_NO_PAD.encode(exchange.as_bytes()),
    })
}

/// A refresh proof for the presented credential and exchange, by the key,
/// at the endpoint actually called, is accepted and names that key.
#[tokio::test]
async fn native_refresh_proof_accepted() {
    let validator = DPopValidator::new(test_admissions());
    let x = exchange(1);
    let proof = build_native_proof(
        NATIVE_PROOF_TYPE,
        NATIVE_REFRESH,
        "n-1",
        refresh_claims("rt-1", &x),
    );
    let binding = validator
        .validate_native(
            &proof,
            "POST",
            NATIVE_REFRESH,
            NativeProofBinding::Refresh {
                credential: "rt-1",
                exchange: &x,
            },
        )
        .await
        .unwrap();
    assert_eq!(binding.jkt, test_key_jkt());
}

/// The proof binds what it presents: another credential (a stolen one under
/// the victim's proof), another exchange, or a ceremony proof offered for a
/// refresh is refused.
#[tokio::test]
async fn native_refresh_proof_binds_credential_and_exchange() {
    let validator = DPopValidator::new(test_admissions());
    let x = exchange(1);
    let cases = [
        (
            NativeProofBinding::Refresh {
                credential: "rt-other",
                exchange: &x,
            },
            refresh_claims("rt-1", &x),
        ),
        (
            NativeProofBinding::Refresh {
                credential: "rt-1",
                exchange: &exchange(2),
            },
            refresh_claims("rt-1", &x),
        ),
        (
            NativeProofBinding::Refresh {
                credential: "rt-1",
                exchange: &x,
            },
            serde_json::json!({
                "sid_cer": native_digest(b"ceremony"),
            }),
        ),
    ];
    for (i, (binding, claims)) in cases.into_iter().enumerate() {
        let proof = build_native_proof(
            NATIVE_PROOF_TYPE,
            NATIVE_REFRESH,
            &format!("nb-{i}"),
            claims,
        );
        let err = validator
            .validate_native(&proof, "POST", NATIVE_REFRESH, binding)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DPopError::NativeBindingMismatch),
            "case {i}: {err:?}"
        );
    }
}

/// A ceremony proof binds the ceremony it completes and no other.
#[tokio::test]
async fn native_ceremony_proof_binds_its_ceremony() {
    let validator = DPopValidator::new(test_admissions());
    let url = "https://sid.example.com/sid.v1.authn.AuthService/OpaqueLoginFinish";
    let claims = serde_json::json!({ "sid_cer": native_digest(b"login-state-1") });
    let proof = build_native_proof(NATIVE_PROOF_TYPE, url, "nc-1", claims.clone());
    validator
        .validate_native(
            &proof,
            "POST",
            url,
            NativeProofBinding::Ceremony {
                reference: b"login-state-1",
            },
        )
        .await
        .unwrap();
    let proof = build_native_proof(NATIVE_PROOF_TYPE, url, "nc-2", claims);
    let err = validator
        .validate_native(
            &proof,
            "POST",
            url,
            NativeProofBinding::Ceremony {
                reference: b"login-state-2",
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DPopError::NativeBindingMismatch), "{err:?}");
}

/// An ordinary OAuth DPoP proof is not a SID native proof, even with the SID
/// claims, and a native proof is not an OAuth one: the type keeps them apart.
#[tokio::test]
async fn native_and_oauth_proofs_do_not_substitute() {
    let validator = DPopValidator::new(test_admissions());
    let x = exchange(1);
    let oauth = build_native_proof(
        "dpop+jwt",
        NATIVE_REFRESH,
        "s-1",
        refresh_claims("rt-1", &x),
    );
    let err = validator
        .validate_native(
            &oauth,
            "POST",
            NATIVE_REFRESH,
            NativeProofBinding::Refresh {
                credential: "rt-1",
                exchange: &x,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DPopError::InvalidProof(_)), "{err:?}");
    let native = build_native_proof(
        NATIVE_PROOF_TYPE,
        NATIVE_REFRESH,
        "s-2",
        refresh_claims("rt-1", &x),
    );
    let err = validator
        .validate(&native, "POST", NATIVE_REFRESH)
        .await
        .unwrap_err();
    assert!(matches!(err, DPopError::InvalidProof(_)), "{err:?}");
}

/// The proof names the endpoint the client called: a direct gRPC call is not
/// checked against the HTTP alias it did not call, nor the reverse.
#[tokio::test]
async fn native_proof_names_the_called_endpoint() {
    let validator = DPopValidator::new(test_admissions());
    let x = exchange(1);
    let http = "https://sid.example.com/v1/auth/native-session/refresh";
    let proof = build_native_proof(NATIVE_PROOF_TYPE, http, "e-1", refresh_claims("rt-1", &x));
    let err = validator
        .validate_native(
            &proof,
            "POST",
            NATIVE_REFRESH,
            NativeProofBinding::Refresh {
                credential: "rt-1",
                exchange: &x,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DPopError::UriMismatch), "{err:?}");
}

/// A native proof is used once: the same proof again is a replay.
#[tokio::test]
async fn native_proof_used_once() {
    let validator = DPopValidator::new(test_admissions());
    let x = exchange(1);
    let proof = build_native_proof(
        NATIVE_PROOF_TYPE,
        NATIVE_REFRESH,
        "once",
        refresh_claims("rt-1", &x),
    );
    let binding = || NativeProofBinding::Refresh {
        credential: "rt-1",
        exchange: &x,
    };
    validator
        .validate_native(&proof, "POST", NATIVE_REFRESH, binding())
        .await
        .unwrap();
    let err = validator
        .validate_native(&proof, "POST", NATIVE_REFRESH, binding())
        .await
        .unwrap_err();
    assert!(matches!(err, DPopError::ReplayDetected), "{err:?}");
}

/// A valid proof by a key other than the token's bound key is refused: a
/// stolen bound token cannot be used with the thief's own key.
#[tokio::test]
async fn test_resource_proof_by_another_key_rejected() {
    let validator = DPopValidator::new(test_admissions());
    let token = "eyJ.access.token";
    let proof = build_resource_proof("res-4", Some(&access_token_hash(token)));
    let err = validator
        .validate_for_resource(&proof, "GET", RESOURCE, token, "another-thumbprint")
        .await
        .unwrap_err();
    assert!(matches!(err, DPopError::KeyMismatch));
}
