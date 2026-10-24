// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use jsonwebtoken::jwk::{Jwk, ThumbprintHash};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};

fn generated() -> ClientKey {
    ClientKey::generate_ed25519().unwrap().0
}

fn public_jwk(key: &ClientKey) -> Jwk {
    serde_json::from_value(key.public_jwks().unwrap()["keys"][0].clone()).unwrap()
}

/// The key id is the RFC 7638 thumbprint, as jsonwebtoken computes it for
/// the published JWK: a verifier can recompute it from the public key.
#[test]
fn kid_is_the_rfc7638_thumbprint() {
    let key = generated();
    assert_eq!(
        public_jwk(&key).thumbprint(ThumbprintHash::SHA256).unwrap(),
        key.kid().unwrap()
    );
}

/// A generated key reloads from its own PEM with the same id: the id is the
/// public key's thumbprint, not something random per load.
#[test]
fn generated_key_reloads_with_the_same_kid() {
    let (key, pem) = ClientKey::generate_ed25519().unwrap();
    let again = ClientKey::ed25519_from_pem(&pem).unwrap();
    assert_eq!(key.kid(), again.kid());
}

/// Two generated keys differ.
#[test]
fn generated_keys_are_distinct() {
    assert_ne!(generated().kid(), generated().kid());
}

/// The published JWKS carries only the public half, marked for signatures,
/// and SID's key-set rules accept it.
#[test]
fn public_jwks_is_public_only_and_accepted_by_sid() {
    let key = generated();
    let jwks = key.public_jwks().unwrap();
    let jwk = &jwks["keys"][0];
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["kid"], key.kid().unwrap());
    assert_eq!(jwk["use"], "sig");
    assert!(
        jwk.get("d").is_none(),
        "private scalar must not be published"
    );
    let set = sid_core::models::ClientKeySet::from_json(&jwks.to_string()).unwrap();
    assert!(set.key(key.kid().unwrap()).is_some());
}

/// A signed JWT names the key, verifies with the public half and carries the
/// claims RFC 7523 §3 requires, expiring within a minute.
#[test]
fn signed_jwt_verifies_with_the_public_key() {
    let key = generated();
    let token = key
        .sign("client-1", "https://sid.example.com/token")
        .unwrap();
    let header = decode_header(&token).unwrap();
    assert_eq!(header.alg, Algorithm::EdDSA);
    assert_eq!(header.kid.as_deref(), key.kid());

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&["https://sid.example.com/token"]);
    validation.set_issuer(&["client-1"]);
    let claims = decode::<Value>(
        &token,
        &DecodingKey::from_jwk(&public_jwk(&key)).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    assert_eq!(claims["sub"], "client-1");
    let lifetime = claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap();
    assert_eq!(lifetime, ASSERTION_LIFETIME_SECS);
    assert!(!claims["jti"].as_str().unwrap().is_empty());
}

/// Every JWT names a fresh `jti`, so the issuer's replay check never refuses
/// the second of two assertions signed in the same second.
#[test]
fn every_jwt_names_a_fresh_jti() {
    let key = generated();
    let jti = |token: String| {
        let payload = token.split('.').nth(1).unwrap().to_owned();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        claims["jti"].as_str().unwrap().to_owned()
    };
    assert_ne!(
        jti(key.sign("c", "a").unwrap()),
        jti(key.sign("c", "a").unwrap())
    );
}

/// Anything but a private key of the named algorithm is refused at load,
/// and an algorithm outside the supported set is refused by name.
#[test]
fn a_non_key_is_refused() {
    let junk = SecretString::from("not a key");
    assert!(ClientKey::ed25519_from_pem(&junk).is_err());
    assert!(matches!(
        ClientKey::from_pem(&junk, "EdDSA", None),
        Err(ClientKeyError::NotAKey { .. })
    ));
    let (_, pem) = ClientKey::generate_ed25519().unwrap();
    assert!(matches!(
        ClientKey::from_pem(&pem, "HS256", None),
        Err(ClientKeyError::Unsupported(_))
    ));
}

/// A key loaded for a configured client sends the configured `kid`, or none
/// when the client registered a single key, and derives no public JWK.
#[test]
fn a_configured_key_sends_its_configured_kid() {
    let (_, pem) = ClientKey::generate_ed25519().unwrap();
    let named = ClientKey::from_pem(&pem, "EdDSA", Some("k-1".into())).unwrap();
    let header = decode_header(named.sign("c", "a").unwrap()).unwrap();
    assert_eq!(header.kid.as_deref(), Some("k-1"));
    assert!(named.public_jwks().is_none());

    let unnamed = ClientKey::from_pem(&pem, "EdDSA", None).unwrap();
    assert!(
        decode_header(unnamed.sign("c", "a").unwrap())
            .unwrap()
            .kid
            .is_none()
    );
}

/// The debug form never prints key material.
#[test]
fn debug_names_only_the_kid() {
    let key = generated();
    let shown = format!("{key:?}");
    assert!(shown.contains(key.kid().unwrap()));
    assert!(!shown.contains("encoding"));
}
