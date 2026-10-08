use super::*;

#[test]
fn test_principal_new_defaults() {
    let profile_id = ProfileId::generate();
    let p = Principal::new(profile_id, PrincipalType::Email, "alice@sid.example.com");
    assert_eq!(p.profile_id, profile_id);
    assert_eq!(p.principal_type, PrincipalType::Email);
    assert_eq!(p.value, "alice@sid.example.com");
    assert!(!p.verified);
    assert!(!p.is_primary);
    assert!(p.source_field.is_none());
    assert!(p.assigned_profile_id.is_none());
    assert_eq!(p.assignment_revision, 0);
}

#[test]
fn test_principal_new_email() {
    let profile_id = ProfileId::generate();
    let p = Principal::new_email(profile_id, "bob@sid.example.com");
    assert_eq!(p.principal_type, PrincipalType::Email);
    assert!(p.is_primary);
    assert!(!p.verified);
    assert_eq!(p.source_field.as_deref(), Some("email"));
}

#[test]
fn test_principal_new_phone() {
    let profile_id = ProfileId::generate();
    let p = Principal::new_phone(profile_id, "+12125551234");
    assert_eq!(p.principal_type, PrincipalType::Phone);
    assert!(!p.is_primary);
    assert_eq!(p.source_field.as_deref(), Some("phone"));
}

#[test]
fn test_principal_new_username_global() {
    let p = Principal::new_username(ProfileId::generate(), "alice");
    assert_eq!(p.principal_type, PrincipalType::Username);
    assert!(p.is_global_username());
    assert!(!p.is_federated_username());
}

#[test]
fn test_principal_new_username_federated() {
    let p = Principal::new_username(ProfileId::generate(), "alice#acme.corp");
    assert_eq!(p.principal_type, PrincipalType::Username);
    assert!(p.is_federated_username());
    assert!(!p.is_global_username());
}

#[test]
fn test_principal_verify_with_ttl() {
    let mut p = Principal::new(ProfileId::generate(), PrincipalType::Phone, "+380501234567");
    assert!(!p.verified);
    assert!(p.verified_at.is_none());
    assert!(p.verification_expires.is_none());

    p.verify(180); // 180 days TTL
    assert!(p.verified);
    assert!(p.verified_at.is_some());
    assert!(p.verification_expires.is_some());
    assert!(!p.is_verification_expired());
}

#[test]
fn test_principal_verify_no_expiry() {
    let mut p = Principal::new(ProfileId::generate(), PrincipalType::Email, "a@b.com");
    p.verify(0); // 0 = never expires
    assert!(p.verified);
    assert!(p.verified_at.is_some());
    assert!(p.verification_expires.is_none()); // no expiry
    assert!(!p.is_verification_expired());
}

#[test]
fn test_principal_verification_expired() {
    let mut p = Principal::new(ProfileId::generate(), PrincipalType::Phone, "+1234");
    p.verified = true;
    p.verified_at = Some(Utc::now() - chrono::Duration::days(200));
    p.verification_expires = Some(Utc::now() - chrono::Duration::days(20)); // expired 20 days ago
    assert!(p.is_verification_expired());
}

#[test]
fn test_principal_type_as_str() {
    assert_eq!(PrincipalType::Email.as_str(), "email");
    assert_eq!(PrincipalType::Phone.as_str(), "phone");
    assert_eq!(PrincipalType::Username.as_str(), "username");
    assert_eq!(PrincipalType::FaceEmbedding.as_str(), "face_embedding");
    assert_eq!(PrincipalType::NfcTag.as_str(), "nfc_tag");
}

/// Only contact channels are shared; every other type is a login handle.
#[test]
fn test_principal_type_contestable() {
    assert!(PrincipalType::Email.is_contestable());
    assert!(PrincipalType::Phone.is_contestable());
    assert!(!PrincipalType::Username.is_contestable());
    assert!(!PrincipalType::FaceEmbedding.is_contestable());
    assert!(!PrincipalType::NfcTag.is_contestable());
}

/// Parsing inverts `as_str` and refuses anything else instead of guessing.
#[test]
fn test_principal_type_from_str() {
    for t in [
        PrincipalType::Email,
        PrincipalType::Phone,
        PrincipalType::Username,
        PrincipalType::FaceEmbedding,
        PrincipalType::NfcTag,
    ] {
        assert_eq!(t.as_str().parse::<PrincipalType>(), Ok(t));
    }
    assert_eq!(
        "messenger".parse::<PrincipalType>(),
        Err(UnknownPrincipalType("messenger".into()))
    );
}

#[test]
fn test_principal_type_serde_roundtrip() {
    let t = PrincipalType::Username;
    let json = serde_json::to_string(&t).unwrap();
    assert_eq!(json, "\"username\"");
    let parsed: PrincipalType = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, PrincipalType::Username);
}

#[test]
fn test_principal_id_unique() {
    let id1 = PrincipalId::new();
    let id2 = PrincipalId::new();
    assert_ne!(id1, id2);
}

// ── PrincipalBinding ──

#[test]
fn test_principal_binding_new() {
    let principal_id = PrincipalId::new();
    let profile_id = ProfileId::generate();
    let binding = PrincipalBinding::new(principal_id, profile_id);
    assert_eq!(binding.principal_id, principal_id);
    assert_eq!(binding.profile_id, profile_id);
    assert!(!binding.is_primary);
    assert!(binding.source_field.is_none());
}

#[test]
fn test_principal_binding_with_source_and_primary() {
    let binding = PrincipalBinding::new(PrincipalId::new(), ProfileId::generate())
        .with_source("email")
        .as_primary();

    assert!(binding.is_primary);
    assert_eq!(binding.source_field.as_deref(), Some("email"));
}

// ── Assignment ──

/// Proof recorded before the first bind assigns the verifying Profile.
#[test]
fn test_verify_assigns_the_profile() {
    let profile_id = ProfileId::generate();
    let mut p = Principal::new(profile_id, PrincipalType::Email, "alice@sid.example.com");
    assert!(p.assigned_profile_id.is_none());

    p.verify(0);
    assert_eq!(p.assigned_profile_id, Some(profile_id));
}

/// Proof expiry must not remove the login route: the holder keeps it.
#[test]
fn test_expire_verification_keeps_assignment() {
    let profile_id = ProfileId::generate();
    let mut p = Principal::new(profile_id, PrincipalType::Phone, "+1234");
    p.verify(180);

    p.expire_verification();
    assert!(!p.verified);
    assert_eq!(p.assigned_profile_id, Some(profile_id));
}

/// The holder keeps its proof in its own view; a claimant sees none.
#[test]
fn test_proof_is_seen_by_the_assigned_profile_only() {
    let holder = ProfileId::generate();
    let mut held = Principal::new(holder, PrincipalType::Email, "a@b.com");
    held.verify(0);
    assert!(held.clone().as_seen_by_subject().verified);

    let mut claimed = held.clone();
    claimed.profile_id = ProfileId::generate();
    let claimed = claimed.as_seen_by_subject();
    assert!(!claimed.verified);
    assert!(claimed.verified_at.is_none());
}

// ── PrincipalEligibility ──

fn assigned_to(profile_id: ProfileId) -> PrincipalEntity {
    let mut p = Principal::new(profile_id, PrincipalType::Email, "a@b.com");
    p.assigned_profile_id = Some(profile_id);
    p.assignment_revision = 1;
    p.entity()
}

/// A lookup key derived under the installation's current email policy.
const CURRENT: Option<i64> = Some(INSTALLATION_EMAIL_POLICY_REVISION);

/// The assigned holder routes whether or not its proof is current.
#[test]
fn test_eligibility_assigned_unverified() {
    let profile_id = ProfileId::generate();
    let result = check_principal_eligibility(&assigned_to(profile_id), profile_id, true, CURRENT);
    assert_eq!(result, PrincipalEligibility::Eligible);
    assert!(result.is_eligible());
}

/// An email key written before policy revisions (provenance unknown) is
/// reserved but routes nobody, its holder included; so is a key of a
/// revision other than the lookup's.
#[test]
fn test_eligibility_key_not_current() {
    let profile_id = ProfileId::generate();
    let mut entity = assigned_to(profile_id);
    entity.email_policy_revision = Some(0);
    let result = check_principal_eligibility(&entity, profile_id, true, CURRENT);
    assert_eq!(result, PrincipalEligibility::KeyNotCurrent);
    assert!(!result.is_eligible());

    let current = assigned_to(profile_id);
    let other = Some(INSTALLATION_EMAIL_POLICY_REVISION + 1);
    assert_eq!(
        check_principal_eligibility(&current, profile_id, true, other),
        PrincipalEligibility::KeyNotCurrent
    );
}

/// Other principal types carry no email policy revision and route as before.
#[test]
fn test_eligibility_non_email() {
    let profile_id = ProfileId::generate();
    let mut p = Principal::new(profile_id, PrincipalType::Phone, "+380501234567");
    p.assigned_profile_id = Some(profile_id);
    assert_eq!(p.email_policy_revision, None);
    let result = check_principal_eligibility(&p.entity(), profile_id, true, None);
    assert_eq!(result, PrincipalEligibility::Eligible);
}

/// An expired proof keeps the route; freshness is access policy's concern.
#[test]
fn test_eligibility_assigned_with_expired_proof() {
    let profile_id = ProfileId::generate();
    let mut entity = assigned_to(profile_id);
    entity.verified = false;
    entity.verified_at = Some(Utc::now() - chrono::Duration::days(200));
    entity.verification_expires = Some(Utc::now() - chrono::Duration::days(20));
    let result = check_principal_eligibility(&entity, profile_id, true, CURRENT);
    assert_eq!(result, PrincipalEligibility::Eligible);
}

/// A pending claim never routes, however many claims exist.
#[test]
fn test_eligibility_pending_claim() {
    let holder = ProfileId::generate();
    let claimant = ProfileId::generate();
    let result = check_principal_eligibility(&assigned_to(holder), claimant, true, CURRENT);
    assert_eq!(result, PrincipalEligibility::NotAssigned);
    assert!(!result.is_eligible());
}

/// A released principal routes nobody, even its remaining sole claimant.
#[test]
fn test_eligibility_released() {
    let claimant = ProfileId::generate();
    let mut entity = assigned_to(ProfileId::generate());
    entity.assigned_profile_id = None;
    entity.assignment_revision = 2;
    let result = check_principal_eligibility(&entity, claimant, true, CURRENT);
    assert_eq!(result, PrincipalEligibility::NotAssigned);
}

/// The assignment alone is not enough: the holder must still hold its claim.
#[test]
fn test_eligibility_not_bound() {
    let profile_id = ProfileId::generate();
    let result = check_principal_eligibility(&assigned_to(profile_id), profile_id, false, CURRENT);
    assert_eq!(result, PrincipalEligibility::NotBound);
}
