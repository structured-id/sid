use super::*;
use sid_plugin::cache::InMemoryCacheBackend;

fn test_cache() -> Arc<dyn CacheBackend> {
    Arc::new(InMemoryCacheBackend::new())
}

#[test]
fn test_parse_algorithm_valid() {
    assert_eq!(parse_algorithm("RS256").unwrap(), Algorithm::RS256);
    assert_eq!(parse_algorithm("ES256").unwrap(), Algorithm::ES256);
    assert_eq!(parse_algorithm("EdDSA").unwrap(), Algorithm::EdDSA);
}

#[test]
fn test_parse_algorithm_invalid() {
    assert!(parse_algorithm("HS256").is_err());
    assert!(parse_algorithm("none").is_err());
}

#[tokio::test]
async fn test_jti_cache_first_use_succeeds() {
    let cache = AssertionJtiCache::new(test_cache());
    assert!(cache.check_and_record("jti-001").await.unwrap());
}

#[tokio::test]
async fn test_jti_cache_replay_detected() {
    let cache = AssertionJtiCache::new(test_cache());
    assert!(cache.check_and_record("jti-002").await.unwrap());
    assert!(!cache.check_and_record("jti-002").await.unwrap());
}

/// Two replicas sharing the cache: an assertion used on one is a replay on the other.
#[tokio::test]
async fn test_jti_replay_caught_across_replicas() {
    let shared = test_cache();
    let a = AssertionJtiCache::new(shared.clone());
    let b = AssertionJtiCache::new(shared);
    assert!(a.check_and_record("jti-shared").await.unwrap());
    assert!(!b.check_and_record("jti-shared").await.unwrap());
}

#[tokio::test]
async fn test_jti_cache_different_jtis_both_succeed() {
    let cache = AssertionJtiCache::new(test_cache());
    assert!(cache.check_and_record("jti-a").await.unwrap());
    assert!(cache.check_and_record("jti-b").await.unwrap());
}

#[test]
fn test_assertion_aud_single() {
    let aud = AssertionAud::Single("https://sid.example.com/oauth2/token".into());
    assert!(aud.contains("https://sid.example.com/oauth2/token"));
    assert!(!aud.contains("https://other.example.com"));
}

#[test]
fn test_assertion_aud_multiple() {
    let aud = AssertionAud::Multiple(vec![
        "https://sid.example.com/oauth2/token".into(),
        "https://sid.example.com".into(),
    ]);
    assert!(aud.contains("https://sid.example.com/oauth2/token"));
    assert!(aud.contains("https://sid.example.com"));
    assert!(!aud.contains("https://evil.com"));
}

#[tokio::test]
async fn test_validate_missing_assertion_jwt() {
    let cache = AssertionJtiCache::new(test_cache());
    let result = validate_client_assertion(
        "not-a-jwt",
        "client_id",
        "https://sid.example.com/oauth2/token",
        "not-a-key",
        "RS256",
        &cache,
    )
    .await;
    assert!(result.is_err());
}

// ── End-to-end tests with real crypto key pairs ──

use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;

#[derive(Serialize)]
struct TestClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    jti: String,
    iat: u64,
}

const TEST_CLIENT_ID: &str = "test-service-account";
const TEST_TOKEN_ENDPOINT: &str = "https://sid.example.com/oauth2/token";

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn valid_claims(jti: &str) -> TestClaims {
    let now = now_secs();
    TestClaims {
        iss: TEST_CLIENT_ID.into(),
        sub: TEST_CLIENT_ID.into(),
        aud: TEST_TOKEN_ENDPOINT.into(),
        exp: now + 120,
        jti: jti.into(),
        iat: now,
    }
}

// -- Test key pairs (generated with openssl, deterministic for tests) --

const RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDaJT4DGqR0ka3D\nY2I/epgzrantVqUN3BMVxe3/S3+/XpPzn0wWgo8gcuCWm/a8lgGqdZZdk94L+1/W\nwHNSt2Wz9jEzvXQ0iNG5SsShXLxMHj2LbsB+riZPH9oulhPYdd+aF3gYUeWwEAP0\nf7jbJurDSPfl57geBkf78fP4k2KmJTuEPTECJLJonvcLBmlBqBcbJuXG71qbssjT\nLxN1MxEDgY1sDwtJZleb+mEmKSDD0UQm4FAwqkeYmLPJgb/cAz1TsCmcrOloLro0\nPWAP5nKJkgk6ocvt03/h0p0gVieXJrpS/r5ivjLzJCUt74a6sTJwS1wtDVBOZngj\neodI1dDJAgMBAAECggEAGqW8PaGUZ4NwphqmsqGphD2RcYM5KhhhMfKR1DLfLeuy\nF8tUnnbQIEr8JZWzdh2+YhnXVoLEt/K65jcv1zG9QBahs8PvtSel89Qe8SWsgEFc\n7AKJS+g+2IFH9BMj5Tgf6nk1s8XUUJWiQAyWkpm+SYDpPFm6F1vV0QBhOLMbVLdj\neazcqU8VcqHcLAE8y+anqpXZNocrtf0gpnf6hbf1CPD0E17AN4xutPCgL1AvFrzN\nji8Ukc8Y5hGqMXau8P2ihAHvaF6rDHWPG/gcQIwOS/2WOsADD/hV2EAmWNEN6yRs\nvxakqvROVbSNtHytVmiHK9N3dWj2Z0ZftVI5SBUDIQKBgQD+YhGFPF3aDEFhCoYv\nIeevkn50Erzb78T/0knM2ZqV6/1M2bFC13KGn8YsdvJkixFgEoSfgtFyoHl3h3AR\nzCZwex65QFQZL8m6S9Fz2LG0L+SvqP9+Daa+EDCvwKb8Uag1LedbFV/7j8QgYrbq\nYXabBlyrRCRlkthmDcPQ/2fFIQKBgQDbiDVC79LFxmOgwjtIKWcASmzeVeEYrZ7u\noktDrvyVE6vzp80CjwXveMkjGEGTIxeesFDwBq3gHryg2esR8z187PSSaTkzwyEp\nQQEXO3wzyk06/NOv/sngZgxglPMwjrUvaq+ay8vFI+EZTVdnF10NfMlmcS432c8O\nt4nBohDuqQKBgGUq+2zRpUGivh2p4dO82DerOz9OdG3D3cUgDNm7cQ9O215E9Ypv\nxMxlnprwc1YpOK/MrZICpOnBiI1Q//EUD/WMAZwLSWb66m9818AK3iGbKofx3ipz\no2zTY4mCROb0UsFTkD9ZMOMLOiTnHXf5awIcdZ5na1I6JHXx436rFMoBAoGAIVVS\nOQKvL0aLVBqJ49AdiqbCVxQVJKkgK73KzdEhGwWso0eEUnIjBZSCfeit9EhsyrSc\n5YUuG4yvOYE9NzGG0ZQtIpoFjH2BaIEtSDjJCBgcl+tRvTRjtMXp9TRIpMPWcQey\n+D8fhqSHBk9/CPE8ONMMxZhD20kgLmzh5tvT1FkCgYAilY/8UMJEEFrPHFSSl4o+\nqvwJFz6K257Pyx0hKS+hXq1WNdgx9tXLm40u53tlvRW1rLKXUv8Fxt0AA/iatZwB\nXsowtKPYS4gXlBrazjwIinjF+Rpj5mpQjhd8Ta3wWZcsW7UkaMuHb5pbk4Y9WrGx\n32y+KDbk0EXdAqJn2zUwBw==\n-----END PRIVATE KEY-----";

const RSA_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2iU+AxqkdJGtw2NiP3qY\nM62p7ValDdwTFcXt/0t/v16T859MFoKPIHLglpv2vJYBqnWWXZPeC/tf1sBzUrdl\ns/YxM710NIjRuUrEoVy8TB49i27Afq4mTx/aLpYT2HXfmhd4GFHlsBAD9H+42ybq\nw0j35ee4HgZH+/Hz+JNipiU7hD0xAiSyaJ73CwZpQagXGyblxu9am7LI0y8TdTMR\nA4GNbA8LSWZXm/phJikgw9FEJuBQMKpHmJizyYG/3AM9U7ApnKzpaC66ND1gD+Zy\niZIJOqHL7dN/4dKdIFYnlya6Uv6+Yr4y8yQlLe+GurEycEtcLQ1QTmZ4I3qHSNXQ\nyQIDAQAB\n-----END PUBLIC KEY-----";

const EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5N2eJG8rPodJbdAX\nfChoMXCZkpJqlz0PNNWZoxQNRzOhRANCAARa90QK2ST6bdJvXRUvsVGsnoqX4AxY\nsblCcfcVl0daQBhY/6Hn4Hgk55T1rYmyPz38tvEadpq9KRpkKzsszUl9\n-----END PRIVATE KEY-----";

const EC_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWvdECtkk+m3Sb10VL7FRrJ6Kl+AM\nWLG5QnH3FZdHWkAYWP+h5+B4JOeU9a2Jsj89/LbxGnaavSkaZCs7LM1JfQ==\n-----END PUBLIC KEY-----";

const ED_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGnMIVUgwI0tTO1AANoNzICml1zLy8M4WqrJlomrTGlU\n-----END PRIVATE KEY-----";

const ED_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAqK9dvWXRiLy73AXFvVRAMzmlQwKF6q/R/UJmjngfLLs=\n-----END PUBLIC KEY-----";

fn sign_jwt(claims: &TestClaims, alg: Algorithm, private_pem: &str) -> String {
    let key = match alg {
        Algorithm::RS256 => EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap(),
        Algorithm::ES256 => EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap(),
        Algorithm::EdDSA => EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap(),
        _ => panic!("unsupported algorithm in test"),
    };
    encode(&Header::new(alg), claims, &key).unwrap()
}

// ── RS256 end-to-end ──

#[tokio::test]
async fn test_rs256_valid_assertion() {
    let cache = AssertionJtiCache::new(test_cache());
    let claims = valid_claims("rs256-jti-001");
    let jwt = sign_jwt(&claims, Algorithm::RS256, RSA_PRIVATE_PEM);

    let result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        RSA_PUBLIC_PEM,
        "RS256",
        &cache,
    )
    .await;
    let c = result.unwrap();
    assert_eq!(c.iss, TEST_CLIENT_ID);
    assert_eq!(c.sub, TEST_CLIENT_ID);
    assert_eq!(c.jti, "rs256-jti-001");
}

// ── ES256 end-to-end ──

#[tokio::test]
async fn test_es256_valid_assertion() {
    let cache = AssertionJtiCache::new(test_cache());
    let claims = valid_claims("es256-jti-001");
    let jwt = sign_jwt(&claims, Algorithm::ES256, EC_PRIVATE_PEM);

    let result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        EC_PUBLIC_PEM,
        "ES256",
        &cache,
    )
    .await;
    assert!(
        result.is_ok(),
        "ES256 validation failed: {:?}",
        result.err()
    );
}

// ── EdDSA end-to-end ──

#[tokio::test]
async fn test_eddsa_valid_assertion() {
    let cache = AssertionJtiCache::new(test_cache());
    let claims = valid_claims("eddsa-jti-001");
    let jwt = sign_jwt(&claims, Algorithm::EdDSA, ED_PRIVATE_PEM);

    let result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        ED_PUBLIC_PEM,
        "EdDSA",
        &cache,
    )
    .await;
    assert!(
        result.is_ok(),
        "EdDSA validation failed: {:?}",
        result.err()
    );
}

// ── Expired assertion ──

#[tokio::test]
async fn test_expired_assertion_rejected() {
    let cache = AssertionJtiCache::new(test_cache());
    let mut claims = valid_claims("expired-jti");
    claims.exp = now_secs() - 120; // Expired 2 minutes ago (beyond 60s leeway).
    let jwt = sign_jwt(&claims, Algorithm::RS256, RSA_PRIVATE_PEM);

    let result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        RSA_PUBLIC_PEM,
        "RS256",
        &cache,
    )
    .await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("assertion verification failed"),
        "should fail on expired JWT"
    );
}

// ── Wrong issuer ──

#[tokio::test]
async fn test_wrong_issuer_rejected() {
    let cache = AssertionJtiCache::new(test_cache());
    let mut claims = valid_claims("wrong-iss-jti");
    claims.iss = "wrong-client-id".into();
    let jwt = sign_jwt(&claims, Algorithm::RS256, RSA_PRIVATE_PEM);

    let result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        RSA_PUBLIC_PEM,
        "RS256",
        &cache,
    )
    .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("iss"));
}

// ── Wrong subject ──

#[tokio::test]
async fn test_wrong_subject_rejected() {
    let cache = AssertionJtiCache::new(test_cache());
    let mut claims = valid_claims("wrong-sub-jti");
    claims.sub = "wrong-subject".into();
    let jwt = sign_jwt(&claims, Algorithm::RS256, RSA_PRIVATE_PEM);

    let result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        RSA_PUBLIC_PEM,
        "RS256",
        &cache,
    )
    .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("sub"));
}

// ── Wrong audience ──

#[tokio::test]
async fn test_wrong_audience_rejected() {
    let cache = AssertionJtiCache::new(test_cache());
    let mut claims = valid_claims("wrong-aud-jti");
    claims.aud = "https://wrong.example.com/token".into();
    let jwt = sign_jwt(&claims, Algorithm::RS256, RSA_PRIVATE_PEM);

    let result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        RSA_PUBLIC_PEM,
        "RS256",
        &cache,
    )
    .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("aud"));
}

// ── Algorithm mismatch ──

#[tokio::test]
async fn test_algorithm_mismatch_rejected() {
    let cache = AssertionJtiCache::new(test_cache());
    let claims = valid_claims("alg-mismatch-jti");
    // Sign with ES256 but present RS256 public key.
    let jwt = sign_jwt(&claims, Algorithm::ES256, EC_PRIVATE_PEM);

    let result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        RSA_PUBLIC_PEM,
        "RS256",
        &cache,
    )
    .await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("algorithm mismatch")
    );
}

// ── JTI replay with real signed JWT ──

#[tokio::test]
async fn test_jti_replay_with_signed_jwt() {
    let cache = AssertionJtiCache::new(test_cache());
    let claims = valid_claims("replay-jti-001");
    let jwt = sign_jwt(&claims, Algorithm::RS256, RSA_PRIVATE_PEM);

    // First use succeeds.
    let result1 = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        RSA_PUBLIC_PEM,
        "RS256",
        &cache,
    )
    .await;
    assert!(result1.is_ok());

    // Replay fails.
    let result2 = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        RSA_PUBLIC_PEM,
        "RS256",
        &cache,
    )
    .await;
    assert!(result2.is_err());
    assert!(result2.unwrap_err().to_string().contains("replay"));
}

// ── Empty JTI rejected ──

#[tokio::test]
async fn test_empty_jti_rejected() {
    let cache = AssertionJtiCache::new(test_cache());
    let claims = valid_claims(""); // Empty JTI.
    let jwt = sign_jwt(&claims, Algorithm::RS256, RSA_PRIVATE_PEM);

    let result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        RSA_PUBLIC_PEM,
        "RS256",
        &cache,
    )
    .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("jti"));
}

// ── Invalid key format ──

#[tokio::test]
async fn test_invalid_rsa_key_rejected() {
    let cache = AssertionJtiCache::new(test_cache());
    let claims = valid_claims("bad-key-jti");
    let jwt = sign_jwt(&claims, Algorithm::RS256, RSA_PRIVATE_PEM);

    let result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        "not-a-valid-pem",
        "RS256",
        &cache,
    )
    .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid RSA"));
}

// ── Wrong key (valid PEM but different key) ──

#[tokio::test]
async fn test_wrong_key_signature_fails() {
    let cache = AssertionJtiCache::new(test_cache());
    // Sign with RSA, verify with EC public key (type mismatch → key parsing error).
    let claims = valid_claims("wrong-key-jti");
    let jwt = sign_jwt(&claims, Algorithm::RS256, RSA_PRIVATE_PEM);

    let result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        EC_PUBLIC_PEM, // EC key, not RSA
        "RS256",
        &cache,
    )
    .await;
    assert!(result.is_err());
}

// ── Key rotation: old key fails, new key succeeds ──

#[tokio::test]
async fn test_key_rotation_old_key_fails_new_key_succeeds() {
    let cache = AssertionJtiCache::new(test_cache());

    // Sign assertion with EC private key.
    let claims = valid_claims("rotation-jti-001");
    let jwt = sign_jwt(&claims, Algorithm::ES256, EC_PRIVATE_PEM);

    // Old credential (RSA) cannot validate this assertion.
    let old_result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        RSA_PUBLIC_PEM,
        "RS256", // Old credential algorithm.
        &cache,
    )
    .await;
    assert!(
        old_result.is_err(),
        "old RSA key should reject ES256 assertion"
    );

    // New credential (EC) validates successfully.
    let new_result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        EC_PUBLIC_PEM,
        "ES256", // New credential algorithm.
        &cache,
    )
    .await;
    assert!(
        new_result.is_ok(),
        "new EC key should accept ES256 assertion: {:?}",
        new_result.err()
    );
}

// ── Tampered JWT (modified payload) ──

#[tokio::test]
async fn test_tampered_jwt_rejected() {
    let cache = AssertionJtiCache::new(test_cache());
    let claims = valid_claims("tampered-jti");
    let jwt = sign_jwt(&claims, Algorithm::RS256, RSA_PRIVATE_PEM);

    // Tamper with the payload (change a character in the middle part).
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let mut payload_bytes = parts[1].as_bytes().to_vec();
    if !payload_bytes.is_empty() {
        payload_bytes[0] ^= 0xFF; // Flip bits.
    }
    let tampered_payload = String::from_utf8_lossy(&payload_bytes);
    let tampered_jwt = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

    let result = validate_client_assertion(
        &tampered_jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        RSA_PUBLIC_PEM,
        "RS256",
        &cache,
    )
    .await;
    assert!(result.is_err(), "tampered JWT should be rejected");
}

// ── Assertions verified with a client's registered keys (RFC 7591 `jwks`) ──

/// The DER bytes of a PEM public key.
fn der(pem: &str) -> Vec<u8> {
    use base64::Engine;
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The test Ed25519 key as a JWK named `kid`: the key follows a 12-byte
/// SubjectPublicKeyInfo prefix.
fn ed_jwk(kid: &str) -> serde_json::Value {
    serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": b64url(&der(ED_PUBLIC_PEM)[12..]), "kid": kid})
}

/// The test P-256 key as a JWK named `kid`: the uncompressed point follows a
/// 26-byte prefix and its 0x04 tag.
fn ec_jwk(kid: &str) -> serde_json::Value {
    let der = der(EC_PUBLIC_PEM);
    serde_json::json!({"kty": "EC", "crv": "P-256", "x": b64url(&der[27..59]), "y": b64url(&der[59..91]), "kid": kid})
}

fn key_set(keys: &[serde_json::Value]) -> ClientKeySet {
    ClientKeySet::try_from(serde_json::json!({ "keys": keys })).unwrap()
}

fn sign_with_kid(claims: &TestClaims, alg: Algorithm, private_pem: &str, kid: &str) -> String {
    let key = match alg {
        Algorithm::ES256 => EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap(),
        Algorithm::EdDSA => EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap(),
        _ => panic!("unsupported algorithm in test"),
    };
    let header = Header {
        kid: Some(kid.to_owned()),
        ..Header::new(alg)
    };
    encode(&header, claims, &key).unwrap()
}

/// The key the header's kid names verifies the assertion, whatever else the
/// client registered: rotation keeps the old and the next key side by side.
#[tokio::test]
async fn a_registered_key_named_by_kid_verifies() {
    let cache = AssertionJtiCache::new(test_cache());
    let keys = key_set(&[ed_jwk("old"), ec_jwk("next")]);
    for (alg, pem, kid) in [
        (Algorithm::EdDSA, ED_PRIVATE_PEM, "old"),
        (Algorithm::ES256, EC_PRIVATE_PEM, "next"),
    ] {
        let jwt = sign_with_kid(&valid_claims(&format!("kid-{kid}")), alg, pem, kid);
        validate_client_assertion_with_keys(
            &jwt,
            TEST_CLIENT_ID,
            TEST_TOKEN_ENDPOINT,
            &keys,
            &cache,
        )
        .await
        .unwrap();
    }
}

/// A kid the client never registered, or a signature by another key under a
/// registered kid, authenticates nobody.
#[tokio::test]
async fn an_unregistered_key_is_refused() {
    let cache = AssertionJtiCache::new(test_cache());
    let keys = key_set(&[ed_jwk("mine")]);
    let unknown = sign_with_kid(
        &valid_claims("unknown"),
        Algorithm::EdDSA,
        ED_PRIVATE_PEM,
        "other",
    );
    assert!(
        validate_client_assertion_with_keys(
            &unknown,
            TEST_CLIENT_ID,
            TEST_TOKEN_ENDPOINT,
            &keys,
            &cache
        )
        .await
        .is_err()
    );
    let forged = sign_with_kid(
        &valid_claims("forged"),
        Algorithm::ES256,
        EC_PRIVATE_PEM,
        "mine",
    );
    assert!(
        validate_client_assertion_with_keys(
            &forged,
            TEST_CLIENT_ID,
            TEST_TOKEN_ENDPOINT,
            &keys,
            &cache
        )
        .await
        .is_err()
    );
}

/// Without a kid the key is known only when the client registered one.
#[tokio::test]
async fn a_missing_kid_is_accepted_only_for_a_single_key() {
    let cache = AssertionJtiCache::new(test_cache());
    let jwt = sign_jwt(&valid_claims("single"), Algorithm::EdDSA, ED_PRIVATE_PEM);
    let single = key_set(&[ed_jwk("only")]);
    validate_client_assertion_with_keys(&jwt, TEST_CLIENT_ID, TEST_TOKEN_ENDPOINT, &single, &cache)
        .await
        .unwrap();
    let jwt = sign_jwt(&valid_claims("several"), Algorithm::EdDSA, ED_PRIVATE_PEM);
    let several = key_set(&[ed_jwk("a"), ec_jwk("b")]);
    assert!(
        validate_client_assertion_with_keys(
            &jwt,
            TEST_CLIENT_ID,
            TEST_TOKEN_ENDPOINT,
            &several,
            &cache
        )
        .await
        .is_err()
    );
}

/// The claims checks apply to key-set assertions too: a replay is refused.
#[tokio::test]
async fn a_key_set_assertion_is_used_once() {
    let cache = AssertionJtiCache::new(test_cache());
    let keys = key_set(&[ed_jwk("k")]);
    let jwt = sign_with_kid(&valid_claims("once"), Algorithm::EdDSA, ED_PRIVATE_PEM, "k");
    validate_client_assertion_with_keys(&jwt, TEST_CLIENT_ID, TEST_TOKEN_ENDPOINT, &keys, &cache)
        .await
        .unwrap();
    assert!(
        validate_client_assertion_with_keys(
            &jwt,
            TEST_CLIENT_ID,
            TEST_TOKEN_ENDPOINT,
            &keys,
            &cache
        )
        .await
        .is_err()
    );
}

/// An assertion valid longer than the replay record would be replayable once
/// its jti is forgotten, so an `exp` beyond the accepted lifetime is refused.
#[tokio::test]
async fn an_assertion_expiring_too_late_is_refused() {
    let cache = AssertionJtiCache::new(test_cache());
    let mut claims = valid_claims("far-future");
    claims.exp = now_secs() + 3600;
    let jwt = sign_jwt(&claims, Algorithm::EdDSA, ED_PRIVATE_PEM);
    let result = validate_client_assertion(
        &jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        ED_PUBLIC_PEM,
        "EdDSA",
        &cache,
    )
    .await;
    assert!(result.is_err(), "an hour-long assertion was accepted");
}

/// A P-384 key for ES384 assertions (generated with openssl for the tests).
const EC384_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCym7ZpgUjvm+xBQiL4\n+7f7Ud0+YGIscEyhn3UL8DOrL6skd25Qq4LzTddvdHtTjHOhZANiAARskXigzHoo\nRfXNsrVbRIbVXHg9pYeElj53o7W47Uc7RvCXqGFSbmFEaD8BtYGGBc6KgcbDi/8z\nBp5LTe3CXxPaucQJtoUK8NCXAh6V+4p8Iq8SU0bOXhwa1rf4CazMdEQ=\n-----END PRIVATE KEY-----";

/// Every algorithm discovery offers for client assertions verifies with a
/// registered JWK of its key type: RSA (PKCS#1 v1.5 and PSS), P-256, P-384
/// and Ed25519. A key registered for one algorithm refuses another.
#[tokio::test]
async fn every_offered_algorithm_verifies_with_its_registered_key() {
    let cache = AssertionJtiCache::new(test_cache());
    let cases = [
        (
            Algorithm::RS256,
            EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM.as_bytes()).unwrap(),
        ),
        (
            Algorithm::RS512,
            EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM.as_bytes()).unwrap(),
        ),
        (
            Algorithm::PS256,
            EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM.as_bytes()).unwrap(),
        ),
        (
            Algorithm::ES256,
            EncodingKey::from_ec_pem(EC_PRIVATE_PEM.as_bytes()).unwrap(),
        ),
        (
            Algorithm::ES384,
            EncodingKey::from_ec_pem(EC384_PRIVATE_PEM.as_bytes()).unwrap(),
        ),
        (
            Algorithm::EdDSA,
            EncodingKey::from_ed_pem(ED_PRIVATE_PEM.as_bytes()).unwrap(),
        ),
    ];
    for (i, (alg, key)) in cases.iter().enumerate() {
        let jwk = jsonwebtoken::jwk::Jwk::from_encoding_key(key, *alg).unwrap();
        let mut value = serde_json::to_value(&jwk).unwrap();
        value["kid"] = serde_json::json!("k");
        let keys = key_set(&[value]);
        let header = Header {
            kid: Some("k".into()),
            ..Header::new(*alg)
        };
        let jwt = encode(&header, &valid_claims(&format!("alg-{i}")), key).unwrap();
        validate_client_assertion_with_keys(
            &jwt,
            TEST_CLIENT_ID,
            TEST_TOKEN_ENDPOINT,
            &keys,
            &cache,
        )
        .await
        .unwrap_or_else(|e| panic!("{alg:?}: {e}"));
    }

    // The RSA key registered for RS256 does not verify a PS256 assertion.
    let rsa = EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM.as_bytes()).unwrap();
    let mut value = serde_json::to_value(
        jsonwebtoken::jwk::Jwk::from_encoding_key(&rsa, Algorithm::RS256).unwrap(),
    )
    .unwrap();
    value["kid"] = serde_json::json!("k");
    let keys = key_set(&[value]);
    let header = Header {
        kid: Some("k".into()),
        ..Header::new(Algorithm::PS256)
    };
    let jwt = encode(&header, &valid_claims("pinned"), &rsa).unwrap();
    assert!(
        validate_client_assertion_with_keys(
            &jwt,
            TEST_CLIENT_ID,
            TEST_TOKEN_ENDPOINT,
            &keys,
            &cache
        )
        .await
        .is_err()
    );
}

/// A key proof names its key and is issued by it: `iss` and `sub` are the
/// `kid`, the audience is the one asked for, and it is used once.
#[tokio::test]
async fn a_key_proof_proves_the_named_key() {
    let cache = AssertionJtiCache::new(test_cache());
    let keys = key_set(&[ed_jwk("bff")]);
    let claims = |jti: &str, iss: &str| TestClaims {
        iss: iss.into(),
        sub: iss.into(),
        aud: TEST_TOKEN_ENDPOINT.into(),
        exp: now_secs() + 60,
        jti: jti.into(),
        iat: now_secs(),
    };
    let proof = sign_with_kid(
        &claims("p1", "bff"),
        Algorithm::EdDSA,
        ED_PRIVATE_PEM,
        "bff",
    );
    validate_key_proof(&proof, TEST_TOKEN_ENDPOINT, &keys, &cache)
        .await
        .unwrap();
    assert!(
        validate_key_proof(&proof, TEST_TOKEN_ENDPOINT, &keys, &cache)
            .await
            .is_err(),
        "a proof is used once"
    );
    let other_issuer = sign_with_kid(
        &claims("p2", "someone"),
        Algorithm::EdDSA,
        ED_PRIVATE_PEM,
        "bff",
    );
    assert!(
        validate_key_proof(&other_issuer, TEST_TOKEN_ENDPOINT, &keys, &cache)
            .await
            .is_err()
    );
    let elsewhere = sign_with_kid(
        &claims("p3", "bff"),
        Algorithm::EdDSA,
        ED_PRIVATE_PEM,
        "bff",
    );
    assert!(
        validate_key_proof(&elsewhere, "https://other.example/x", &keys, &cache)
            .await
            .is_err()
    );
    let unnamed = sign_jwt(&claims("p4", "bff"), Algorithm::EdDSA, ED_PRIVATE_PEM);
    assert!(
        validate_key_proof(&unnamed, TEST_TOKEN_ENDPOINT, &keys, &cache)
            .await
            .is_err(),
        "a proof must name its key"
    );
}

// ── Not-before (RFC 7523 §3 items 5 and 10, RFC 7519 §4.1.5) ──

/// The claims of a valid assertion issued at `now`, with `nbf` set to
/// `nbf` when given (any JSON value, so malformed ones can be sent too).
fn claims_with_nbf(jti: &str, now: u64, nbf: Option<serde_json::Value>) -> serde_json::Value {
    let mut claims = serde_json::json!({
        "iss": TEST_CLIENT_ID,
        "sub": TEST_CLIENT_ID,
        "aud": TEST_TOKEN_ENDPOINT,
        "exp": now + 240,
        "jti": jti,
        "iat": now,
    });
    if let Some(nbf) = nbf {
        claims["nbf"] = nbf;
    }
    claims
}

/// `claims` signed with the test EdDSA key, its header naming `kid`.
fn sign_value(claims: &serde_json::Value, kid: Option<&str>) -> String {
    let header = Header {
        kid: kid.map(str::to_owned),
        ..Header::new(Algorithm::EdDSA)
    };
    let key = EncodingKey::from_ed_pem(ED_PRIVATE_PEM.as_bytes()).unwrap();
    encode(&header, claims, &key).unwrap()
}

/// Verify an assertion through the PEM entry point.
async fn verify_pem(jwt: &str, cache: &AssertionJtiCache) -> SidResult<AssertionClaims> {
    validate_client_assertion(
        jwt,
        TEST_CLIENT_ID,
        TEST_TOKEN_ENDPOINT,
        ED_PUBLIC_PEM,
        "EdDSA",
        cache,
    )
    .await
}

/// An assertion that is not yet valid by far is refused: the regression a
/// verifier with `nbf` checking off lets through.
#[tokio::test]
async fn an_assertion_not_yet_valid_is_refused() {
    let cache = AssertionJtiCache::new(test_cache());
    let now = now_secs();
    let jwt = sign_value(
        &claims_with_nbf("nbf-future", now, Some((now + 180).into())),
        None,
    );
    assert!(verify_pem(&jwt, &cache).await.is_err());
}

/// The outcome for `nbf = now + offset`, checked within the second the
/// assertion was made in: the library reads the clock itself, so a run that
/// crosses a second boundary is repeated rather than judged. Crossing it
/// changes the expected answer (the same `nbf` is one second nearer), which
/// is why the check is not simply retried until it passes.
async fn pinned_outcome(offset: u64) -> bool {
    for attempt in 0..3 {
        let cache = AssertionJtiCache::new(test_cache());
        let before = now_secs();
        let jwt = sign_value(
            &claims_with_nbf(
                &format!("nbf-{offset}-{attempt}"),
                before,
                Some((before + offset).into()),
            ),
            None,
        );
        let accepted = verify_pem(&jwt, &cache).await.is_ok();
        if now_secs() == before {
            return accepted;
        }
    }
    panic!("the check could not be kept within one second");
}

/// The clock allowance is exactly 60 seconds: up to it an early `nbf` is
/// accepted, one second beyond it is not.
#[tokio::test]
async fn the_not_before_allowance_is_sixty_seconds() {
    assert!(pinned_outcome(30).await, "+30 is within the allowance");
    assert!(pinned_outcome(60).await, "+60 is the allowance itself");
    assert!(!pinned_outcome(61).await, "+61 is beyond it");
    assert!(!pinned_outcome(180).await, "+180 is far beyond it");
}

/// `nbf` is optional: absent or already passed, the assertion is valid.
#[tokio::test]
async fn an_absent_or_past_not_before_is_accepted() {
    let cache = AssertionJtiCache::new(test_cache());
    let now = now_secs();
    let absent = sign_value(&claims_with_nbf("nbf-absent", now, None), None);
    verify_pem(&absent, &cache).await.unwrap();
    let past = sign_value(
        &claims_with_nbf("nbf-past", now, Some((now - 120).into())),
        None,
    );
    verify_pem(&past, &cache).await.unwrap();
    // A NumericDate may be non-integer (RFC 7519 §2).
    let fractional = sign_value(
        &claims_with_nbf(
            "nbf-fractional",
            now,
            Some(serde_json::json!(now as f64 - 120.5)),
        ),
        None,
    );
    verify_pem(&fractional, &cache).await.unwrap();
}

/// A present `nbf` that is not a NumericDate is refused, `null` included: it
/// is a malformed claim, not an absent one.
#[tokio::test]
async fn a_malformed_not_before_is_refused() {
    let cache = AssertionJtiCache::new(test_cache());
    let now = now_secs();
    for (name, nbf) in [
        ("null", serde_json::Value::Null),
        ("string", serde_json::json!(now.to_string())),
        ("object", serde_json::json!({ "at": now })),
    ] {
        let jwt = sign_value(
            &claims_with_nbf(&format!("nbf-{name}"), now, Some(nbf)),
            None,
        );
        assert!(verify_pem(&jwt, &cache).await.is_err(), "nbf {name}");
    }
}

/// A premature assertion is refused before its `jti` is recorded: the same
/// `jti` in a time-valid assertion is then admitted, on any replica sharing
/// the cache, exactly once.
#[tokio::test]
async fn a_premature_assertion_leaves_its_jti_unused() {
    let shared = test_cache();
    let a = AssertionJtiCache::new(shared.clone());
    let b = AssertionJtiCache::new(shared);
    let now = now_secs();
    let early = sign_value(
        &claims_with_nbf("nbf-shared", now, Some((now + 180).into())),
        None,
    );
    assert!(verify_pem(&early, &a).await.is_err());

    let valid = sign_value(&claims_with_nbf("nbf-shared", now, None), None);
    verify_pem(&valid, &b).await.unwrap();
    assert!(verify_pem(&valid, &a).await.is_err(), "used once");
}

/// The registered-key and key-proof entry points run the same check.
#[tokio::test]
async fn every_entry_point_refuses_a_premature_assertion() {
    let cache = AssertionJtiCache::new(test_cache());
    let keys = key_set(&[ed_jwk("k1")]);
    let now = now_secs();
    let early = sign_value(
        &claims_with_nbf("nbf-jwk", now, Some((now + 180).into())),
        Some("k1"),
    );
    assert!(
        validate_client_assertion_with_keys(
            &early,
            TEST_CLIENT_ID,
            TEST_TOKEN_ENDPOINT,
            &keys,
            &cache
        )
        .await
        .is_err()
    );

    let mut proof = claims_with_nbf("nbf-proof", now, Some((now + 180).into()));
    proof["iss"] = "k1".into();
    proof["sub"] = "k1".into();
    let proof = sign_value(&proof, Some("k1"));
    assert!(
        validate_key_proof(&proof, TEST_TOKEN_ENDPOINT, &keys, &cache)
            .await
            .is_err()
    );
}
