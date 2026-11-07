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

fn profile() -> Profile {
    let mut profile = Profile::new(Some("alice"));
    profile.given_name = Some("Alice".into());
    profile
}

/// Each scope grants its own claims only; `sub` is always there
/// (OIDC Core 1.0 §5.4).
#[test]
fn test_granted_claims_follow_the_scopes() {
    let profile = profile();
    let now = chrono::Utc::now();
    let email = ProfileEmail {
        id: sid_core::models::ProfileEmailId::new(),
        profile_id: profile.id,
        email: "alice@sid.example.com".into(),
        label: sid_core::models::EmailLabel::Personal,
        custom_label: None,
        is_primary: true,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    };

    let none = granted_claims("s".into(), "openid", &profile, Some(&email), None);
    assert_eq!(none.sub, "s");
    assert!(none.given_name.is_none() && none.email.is_none() && none.updated_at.is_none());

    let all = granted_claims(
        "s".into(),
        "openid profile email phone",
        &profile,
        Some(&email),
        None,
    );
    assert_eq!(all.given_name.as_deref(), Some("Alice"));
    assert_eq!(all.preferred_username.as_deref(), Some("alice"));
    assert!(all.updated_at.is_some());
    assert_eq!(all.email.as_deref(), Some("alice@sid.example.com"));
    assert_eq!(all.email_verified, Some(false));
    // Granted but not set: absent, not empty.
    assert!(all.phone_number.is_none() && all.phone_number_verified.is_none());
}

#[test]
fn test_strings_keeps_order() {
    assert_eq!(strings(&["b", "a"]), ["b".to_string(), "a".to_string()]);
    assert!(strings(&[]).is_empty());
}
