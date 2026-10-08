use super::*;

/// Create a consent in Requested state (default from new()).
fn make_consent_requested() -> ConsentRecord {
    ConsentRecord::new(ProfileId::generate(), "site_abc_client_id")
}

/// Create a consent already granted (Active).
fn make_consent() -> ConsentRecord {
    let mut c = ConsentRecord::new(ProfileId::generate(), "site_abc_client_id");
    c.as_requested().unwrap().grant();
    c
}

#[test]
fn test_consent_new_is_requested() {
    let c = make_consent_requested();
    assert_eq!(c.client_id, "site_abc_client_id");
    assert_eq!(c.status, ConsentStatus::Requested);
    assert!(c.grants.is_empty());
    assert!(c.revoked_at.is_none());
}

#[test]
fn test_consent_grant_transitions_to_active() {
    let mut c = make_consent_requested();
    assert!(c.as_requested().is_some());
    assert!(c.as_active().is_none());

    c.as_requested().unwrap().grant();
    assert_eq!(c.status, ConsentStatus::Active);
    assert!(c.as_active().is_some());
    assert!(c.as_requested().is_none());
}

#[test]
fn test_consent_deny_transitions_to_revoked() {
    let mut c = make_consent_requested();
    c.as_requested().unwrap().deny();
    assert_eq!(c.status, ConsentStatus::Revoked);
    assert!(c.revoked_at.is_some());
    assert!(c.as_requested().is_none());
    assert!(c.as_active().is_none());
}

#[test]
fn test_grant_claim() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data);
    c.grant_claim("passport_verified", ClaimType::Attestation);

    assert_eq!(c.grants.len(), 2);
    assert_eq!(c.grants[0].claim_name, "email");
    assert_eq!(c.grants[0].claim_type, ClaimType::Data);
    assert_eq!(c.grants[1].claim_name, "passport_verified");
    assert_eq!(c.grants[1].claim_type, ClaimType::Attestation);
}

#[test]
fn test_revoke_claim() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data);
    c.grant_claim("phone", ClaimType::Data);

    c.as_active().unwrap().revoke_claim("email");
    assert!(!c.grants[0].is_active());
    assert!(c.grants[1].is_active());
    assert_eq!(c.active_grants().len(), 1);
}

#[test]
fn test_revoke_all() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data);
    c.grant_claim("phone", ClaimType::Data);

    c.as_active().unwrap().revoke_all();
    assert_eq!(c.status(), ConsentStatus::Revoked);
    assert!(c.revoked_at.is_some());
    assert!(!c.has_active_grants());
}

#[test]
fn test_gateway_returns_none_after_revoke() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data);
    c.as_active().unwrap().revoke_all();
    assert!(c.as_active().is_none());
}

#[test]
fn test_active_grants() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data);
    c.grant_claim("phone", ClaimType::Data);
    c.grant_claim("name", ClaimType::Data);

    c.as_active().unwrap().revoke_claim("phone");
    let active = c.active_grants();
    assert_eq!(active.len(), 2);
    assert!(active.iter().all(|g| g.claim_name != "phone"));
}

#[test]
fn test_claim_request_mandatory() {
    let r = ClaimRequest::mandatory("email", ClaimType::Data);
    assert_eq!(r.level, ClaimLevel::Mandatory);
    assert!(r.justification.is_none());
}

#[test]
fn test_claim_request_highly_demanded() {
    let r = ClaimRequest::highly_demanded(
        "age_verified",
        ClaimType::Attestation,
        "Age-restricted content by law.",
    );
    assert_eq!(r.level, ClaimLevel::HighlyDemanded);
    assert_eq!(
        r.justification.as_deref(),
        Some("Age-restricted content by law.")
    );
}

#[test]
fn test_claim_request_optional() {
    let r = ClaimRequest::optional("phone", ClaimType::Data);
    assert_eq!(r.level, ClaimLevel::Optional);
}

#[test]
fn test_claim_level_serde() {
    let l = ClaimLevel::HighlyDemanded;
    let json = serde_json::to_string(&l).unwrap();
    assert_eq!(json, "\"highly_demanded\"");
    let parsed: ClaimLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ClaimLevel::HighlyDemanded);
}

#[test]
fn test_claim_type_serde() {
    let t = ClaimType::Attestation;
    let json = serde_json::to_string(&t).unwrap();
    assert_eq!(json, "\"attestation\"");
    let parsed: ClaimType = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ClaimType::Attestation);
}

#[test]
fn test_consent_status_serde() {
    let s = ConsentStatus::Revoked;
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"revoked\"");
    let parsed: ConsentStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ConsentStatus::Revoked);

    let s2 = ConsentStatus::Requested;
    let json2 = serde_json::to_string(&s2).unwrap();
    assert_eq!(json2, "\"requested\"");
    let parsed2: ConsentStatus = serde_json::from_str(&json2).unwrap();
    assert_eq!(parsed2, ConsentStatus::Requested);
}

/// The stored text of every status and claim type reads back as itself, and
/// an unknown value is an error rather than a default a stored row never had.
#[test]
fn test_stored_names_parse_back() {
    for s in [
        ConsentStatus::Requested,
        ConsentStatus::Active,
        ConsentStatus::Revoked,
        ConsentStatus::Expired,
    ] {
        assert_eq!(s.as_str().parse::<ConsentStatus>(), Ok(s));
    }
    for t in [ClaimType::Data, ClaimType::Attestation] {
        assert_eq!(t.as_str().parse::<ClaimType>(), Ok(t));
    }
    assert!("granted".parse::<ConsentStatus>().is_err());
    assert!("".parse::<ClaimType>().is_err());
}

#[test]
fn test_consent_serde_roundtrip() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data);

    let json = serde_json::to_string(&c).unwrap();
    let parsed: ConsentRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.client_id, "site_abc_client_id");
    assert_eq!(parsed.grants.len(), 1);
    assert_eq!(parsed.grants[0].claim_name, "email");
}

#[test]
fn test_consent_id_unique() {
    let id1 = ConsentId::new();
    let id2 = ConsentId::new();
    assert_ne!(id1, id2);
}

#[test]
fn test_double_claim_revoke_is_idempotent() {
    let mut c = make_consent();
    c.grant_claim("email", ClaimType::Data);

    c.as_active().unwrap().revoke_claim("email");
    let first_revoke = c.grants[0].revoked_at;
    // Second revoke_claim through gateway — claim already revoked, no change.
    c.as_active().unwrap().revoke_claim("email");
    assert_eq!(c.grants[0].revoked_at, first_revoke);
}
