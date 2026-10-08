use super::*;

const ORDERS: &str = "https://resources.example/orders";

fn verifiers() -> RequestVerifiers {
    RequestVerifiers::from_json(&format!(
        r#"{{"verifiers": [{{"subject": "oauth_client:sid-auth", "resources": ["{ORDERS}"], "profiles": ["dpop"]}}]}}"#
    ))
    .expect("valid configuration")
}

/// The configured service confirms proofs for the configured resource.
#[test]
fn a_configured_verifier_is_permitted_on_its_resource() {
    assert!(verifiers().permits("oauth_client:sid-auth", ORDERS, ProofProfile::Dpop));
}

/// Another service, or the same one on another resource, is not a verifier.
#[test]
fn others_are_not_permitted() {
    let v = verifiers();
    assert!(!v.permits("oauth_client:other", ORDERS, ProofProfile::Dpop));
    assert!(!v.permits("machine:sid-auth", ORDERS, ProofProfile::Dpop));
    assert!(!v.permits(
        "oauth_client:sid-auth",
        "https://resources.example/wiki",
        ProofProfile::Dpop
    ));
}

/// No configuration trusts nobody.
#[test]
fn an_empty_configuration_permits_nothing() {
    assert!(!RequestVerifiers::default().permits(
        "oauth_client:sid-auth",
        ORDERS,
        ProofProfile::Dpop
    ));
    let empty = RequestVerifiers::from_json("{}").expect("empty object");
    assert!(!empty.permits("oauth_client:sid-auth", ORDERS, ProofProfile::Dpop));
}

/// A malformed configuration is refused rather than read as trusting
/// nobody or everybody.
#[test]
fn a_malformed_configuration_is_refused() {
    for text in [
        "not json",
        r#"{"verifiers": [{"subject": "user:1", "resources": ["https://a.example"], "profiles": ["dpop"]}]}"#,
        r#"{"verifiers": [{"subject": "oauth_client:", "resources": ["https://a.example"], "profiles": ["dpop"]}]}"#,
        r#"{"verifiers": [{"subject": "oauth_client:x", "resources": [], "profiles": ["dpop"]}]}"#,
        r#"{"verifiers": [{"subject": "oauth_client:x", "resources": ["https://a.example"], "profiles": []}]}"#,
        r#"{"verifiers": [{"subject": "oauth_client:x", "resources": ["not a uri"], "profiles": ["dpop"]}]}"#,
        r#"{"verifiers": [{"subject": "oauth_client:x", "resources": ["https://a.example"], "profiles": ["mtls"]}]}"#,
        r#"{"verifiers": [{"subject": "oauth_client:x", "resources": ["https://a.example"], "profiles": ["dpop"], "all": true}]}"#,
    ] {
        assert!(RequestVerifiers::from_json(text).is_err(), "{text}");
    }
}
