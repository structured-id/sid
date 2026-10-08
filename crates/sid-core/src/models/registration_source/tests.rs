use super::*;

#[test]
fn test_source_type_default() {
    assert_eq!(
        RegistrationSourceType::default(),
        RegistrationSourceType::SelfSignup
    );
}

#[test]
fn test_source_type_serde() {
    let s = RegistrationSourceType::ScimProvisioned;
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"scim_provisioned\"");
    let parsed: RegistrationSourceType = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, RegistrationSourceType::ScimProvisioned);
}

#[test]
fn test_source_type_as_str() {
    assert_eq!(RegistrationSourceType::SelfSignup.as_str(), "self_signup");
    assert_eq!(RegistrationSourceType::Invite.as_str(), "invite");
    assert_eq!(
        RegistrationSourceType::AdminCreated.as_str(),
        "admin_created"
    );
    assert_eq!(
        RegistrationSourceType::ScimProvisioned.as_str(),
        "scim_provisioned"
    );
    assert_eq!(RegistrationSourceType::Federation.as_str(), "federation");
    assert_eq!(
        RegistrationSourceType::IdentityBrokered.as_str(),
        "identity_brokered"
    );
}

/// Every stored name reads back as its type; an unknown one is an error,
/// not a self-signup the row never recorded.
#[test]
fn test_source_type_parses_stored_names() {
    for t in [
        RegistrationSourceType::SelfSignup,
        RegistrationSourceType::Invite,
        RegistrationSourceType::AdminCreated,
        RegistrationSourceType::ScimProvisioned,
        RegistrationSourceType::Federation,
        RegistrationSourceType::IdentityBrokered,
    ] {
        assert_eq!(t.as_str().parse::<RegistrationSourceType>(), Ok(t));
    }
    assert!("organic".parse::<RegistrationSourceType>().is_err());
}

#[test]
fn test_utm_params_empty() {
    let utm = UtmParams::default();
    assert!(utm.is_empty());
}

#[test]
fn test_utm_params_not_empty() {
    let utm = UtmParams {
        source: "google".into(),
        ..Default::default()
    };
    assert!(!utm.is_empty());
}

#[test]
fn test_self_signup_source() {
    let src = RegistrationSource::self_signup(Some("app1".into()));
    assert_eq!(src.source_type, RegistrationSourceType::SelfSignup);
    assert_eq!(src.source_id, "self:app1");
    assert_eq!(src.client_id.as_deref(), Some("app1"));
}

#[test]
fn test_invite_source() {
    let src = RegistrationSource::from_invite("ABCD1234", None);
    assert_eq!(src.source_type, RegistrationSourceType::Invite);
    assert_eq!(src.source_id, "invite:ABCD1234");
}

#[test]
fn test_admin_created_source() {
    let admin = ProfileId::generate();
    let src = RegistrationSource::admin_created(admin);
    assert_eq!(src.source_type, RegistrationSourceType::AdminCreated);
    assert!(src.source_id.starts_with("admin:"));
}

#[test]
fn test_registration_source_serde_roundtrip() {
    let src = RegistrationSource {
        source_type: RegistrationSourceType::Federation,
        source_id: "federation:okta-123".into(),
        referrer_id: Some(ProfileId::generate()),
        utm: UtmParams {
            source: "newsletter".into(),
            medium: "email".into(),
            campaign: "q1-launch".into(),
            term: String::new(),
            content: String::new(),
        },
        client_id: Some("frontend".into()),
        created_at: Utc::now(),
    };
    let json = serde_json::to_string(&src).unwrap();
    let parsed: RegistrationSource = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.source_type, RegistrationSourceType::Federation);
    assert_eq!(parsed.source_id, "federation:okta-123");
    assert!(parsed.referrer_id.is_some());
    assert_eq!(parsed.utm.source, "newsletter");
}
