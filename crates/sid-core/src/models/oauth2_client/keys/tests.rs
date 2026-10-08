use super::*;
use serde_json::json;

fn ed25519(kid: &str) -> Value {
    json!({"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": kid})
}

/// A registered set keeps its keys and finds each by kid.
#[test]
fn a_public_key_set_is_registered() {
    let set = ClientKeySet::try_from(json!({"keys": [ed25519("a"), ed25519("b")]})).unwrap();
    assert_eq!(set.keys().len(), 2);
    assert!(set.key("b").is_some());
    assert!(set.key("c").is_none());
    assert_eq!(ClientKeySet::from_json(&set.to_json()).unwrap(), set);
}

/// A private member would put the client's secret into SID's database.
#[test]
fn a_private_key_is_refused() {
    let mut key = ed25519("a");
    key["d"] = json!("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    assert!(ClientKeySet::try_from(json!({"keys": [key]})).is_err());
    let secret = json!({"kty": "oct", "k": "c2VjcmV0", "kid": "s"});
    assert!(ClientKeySet::try_from(json!({"keys": [secret]})).is_err());
}

/// Without a kid, or with two keys under one, a signature's key is ambiguous.
#[test]
fn kids_are_required_and_distinct() {
    let mut nameless = ed25519("a");
    nameless.as_object_mut().unwrap().remove("kid");
    assert!(ClientKeySet::try_from(json!({"keys": [nameless]})).is_err());
    assert!(ClientKeySet::try_from(json!({"keys": [ed25519("a"), ed25519("a")]})).is_err());
}

/// A key is for verifying signatures, with an algorithm its type can verify.
#[test]
fn use_and_alg_must_fit_a_signing_key() {
    let mut encryption = ed25519("a");
    encryption["use"] = json!("enc");
    assert!(ClientKeySet::try_from(json!({"keys": [encryption]})).is_err());
    let mut wrong_alg = ed25519("a");
    wrong_alg["alg"] = json!("RS256");
    assert!(ClientKeySet::try_from(json!({"keys": [wrong_alg]})).is_err());
    let mut right_alg = ed25519("a");
    right_alg["alg"] = json!("EdDSA");
    assert!(ClientKeySet::try_from(json!({"keys": [right_alg]})).is_ok());
}

/// RFC 7518 §3.3: an RSA key shorter than 2048 bits is not accepted.
#[test]
fn a_short_rsa_key_is_refused() {
    let short = json!({"kty": "RSA", "n": "x".repeat(171), "e": "AQAB", "kid": "r"});
    assert!(ClientKeySet::try_from(json!({"keys": [short]})).is_err());
    let long = json!({"kty": "RSA", "n": "x".repeat(342), "e": "AQAB", "kid": "r"});
    assert!(ClientKeySet::try_from(json!({"keys": [long]})).is_ok());
}

/// An empty set authenticates nobody, and an unbounded one is refused.
#[test]
fn the_set_size_is_bounded() {
    assert!(ClientKeySet::try_from(json!({"keys": []})).is_err());
    let many: Vec<Value> = (0..=ClientKeySet::MAX_KEYS)
        .map(|i| ed25519(&i.to_string()))
        .collect();
    assert!(ClientKeySet::try_from(json!({ "keys": many })).is_err());
    assert!(ClientKeySet::try_from(json!([ed25519("a")])).is_err());
}
