use super::*;

/// Every endpoint this server serves is advertised, under the issuer URL
/// whatever its path depth, and the issuer is copied byte for byte (no
/// trailing slash added or removed).
#[test]
fn test_metadata_endpoints_are_under_the_issuer() {
    let issuer = "https://sid.example.com/auth/i/0123456789abcdef0123456789abcdef";
    let m = metadata(issuer);
    assert_eq!(m.issuer, issuer);
    let optional = [
        ("userinfo", &m.userinfo_endpoint),
        ("end_session", &m.end_session_endpoint),
        ("introspection", &m.introspection_endpoint),
        ("revocation", &m.revocation_endpoint),
        ("device_authorization", &m.device_authorization_endpoint),
        ("registration", &m.registration_endpoint),
    ]
    .map(|(name, endpoint)| {
        endpoint
            .as_ref()
            .unwrap_or_else(|| panic!("the served {name} endpoint is advertised"))
    });
    for endpoint in [&m.authorization_endpoint, &m.token_endpoint, &m.jwks_uri]
        .into_iter()
        .chain(optional)
    {
        assert!(
            endpoint.starts_with(&format!("{issuer}/")),
            "{endpoint} is not under {issuer}"
        );
    }
}

/// Only the code flow, S256 PKCE and public subjects are advertised, and the
/// DPoP algorithms are the ones proofs are verified with.
#[test]
fn test_metadata_advertises_what_is_served() {
    let m = metadata("https://sid.example.com/i/x");
    assert_eq!(m.response_types_supported, ["code"]);
    assert_eq!(m.code_challenge_methods_supported, ["S256"]);
    assert_eq!(m.subject_types_supported, ["public"]);
    assert_eq!(
        m.dpop_signing_alg_values_supported,
        strings(sid_core::models::dpop::DPopProof::SIGNING_ALGORITHMS)
    );
    assert!(m.backchannel_logout_supported);
    assert!(m.backchannel_logout_session_supported);
}

/// The holder's consent sharing `given_name` and `email` with their
/// reviewed values, `phone_number` not shared, and a `family_name` grant
/// recorded without a reviewed value.
fn consent() -> sid_core::models::ConsentRecord {
    use sid_core::models::{ClaimType, ConsentMode, DisclosedValue};
    let mut consent =
        sid_core::models::ConsentRecord::new(sid_core::models::ProfileId::generate(), "rp");
    consent.grant_claim("given_name", ClaimType::Data, ConsentMode::Static);
    consent.grant_claim("email", ClaimType::Data, ConsentMode::Static);
    consent.grant_claim("family_name", ClaimType::Data, ConsentMode::Static);
    consent.grants[0].disclosed = Some(DisclosedValue {
        value: "Alice".into(),
        verified: None,
    });
    consent.grants[1].disclosed = Some(DisclosedValue {
        value: "alice@sid.example.com".into(),
        verified: Some(false),
    });
    consent.as_requested().unwrap().grant();
    consent
}

/// UserInfo delivers only what the holder approved for this client, for the
/// claims the token's scopes ask for (OIDC Core 1.0 §5.4): `openid` alone
/// asks for none, a shared value comes as approved, a claim not shared or
/// granted without a reviewed value is left out, and without consent
/// nothing but `sub` (consent-flow.md, OIDC scope requests).
#[test]
fn test_userinfo_discloses_the_approved_values_only() {
    let held = consent();

    let none = disclosed_claims("s".into(), "openid", &[], Some(&held));
    assert_eq!(none.sub, "s");
    assert!(none.given_name.is_none() && none.email.is_none());

    let all = disclosed_claims("s".into(), "openid profile email phone", &[], Some(&held));
    assert_eq!(all.given_name.as_deref(), Some("Alice"));
    assert_eq!(all.email.as_deref(), Some("alice@sid.example.com"));
    assert_eq!(all.email_verified, Some(false));
    assert!(
        all.family_name.is_none(),
        "granted without a reviewed value"
    );
    assert!(all.preferred_username.is_none() && all.phone_number.is_none());
    assert!(all.updated_at.is_none());

    let without_consent = disclosed_claims("s".into(), "openid profile email", &[], None);
    assert!(without_consent.given_name.is_none() && without_consent.email.is_none());
}

#[test]
fn test_strings_keeps_order() {
    assert_eq!(strings(&["b", "a"]), ["b".to_string(), "a".to_string()]);
    assert!(strings(&[]).is_empty());
}
