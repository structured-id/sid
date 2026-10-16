use super::*;

/// A username is verified and owned from the start, and has no contact row.
#[test]
fn username_signup_is_verified_by_construction() {
    let registration = NewRegistration::new(
        Profile::new(Some("alice")),
        SignupIdentifier::Username("alice"),
        None,
    )
    .unwrap();

    let principal = &registration.principal;
    assert!(principal.verified);
    assert_eq!(principal.assigned_profile_id, Some(registration.profile.id));
    assert_eq!(principal.source_field.as_deref(), Some("username"));
    assert!(registration.email.is_none() && registration.phone.is_none());
}

/// An email signup creates the contact row and links the principal to it;
/// both stay unverified until the address is proven. The principal holds the
/// resolution key, the contact the spelling mail goes to.
#[test]
fn email_signup_links_its_contact_row() {
    let registration = NewRegistration::new(
        Profile::new(None::<String>),
        SignupIdentifier::Email {
            key: "annsmith@sid.example.com",
            address: "Ann.Smith+work@sid.example.com",
            revision: 7,
        },
        None,
    )
    .unwrap();

    let email = registration.email.as_ref().expect("email row");
    assert_eq!(email.email, "Ann.Smith+work@sid.example.com");
    assert_eq!(registration.principal.value, "annsmith@sid.example.com");
    assert_eq!(registration.principal.email_policy_revision, Some(7));
    assert_eq!(email.profile_id, registration.profile.id);
    assert!(!email.verified);
    assert_eq!(registration.principal.source_email_id, Some(email.id));
    assert!(!registration.principal.verified);
    assert_eq!(registration.principal.assigned_profile_id, None);
}

/// A phone signup stores the E.164 digits and links the principal to them.
#[test]
fn phone_signup_links_its_contact_row() {
    let registration = NewRegistration::new(
        Profile::new(None::<String>),
        SignupIdentifier::Phone("+380501234567"),
        None,
    )
    .unwrap();

    let phone = registration.phone.as_ref().expect("phone row");
    assert_eq!(phone.e164, 380501234567);
    assert_eq!(registration.principal.source_phone_id, Some(phone.id));
    assert_eq!(registration.principal.email_policy_revision, None);
}

fn stored(mode: EnrollmentMode, domains: &[&str]) -> Option<EnrollmentPolicy> {
    let mut policy = SecurityPolicy::ce_default().enrollment;
    policy.mode = mode;
    policy.allowed_domains = domains.iter().map(|d| (*d).to_string()).collect();
    Some(policy)
}

fn gate(
    pinned: Option<EnrollmentMode>,
    email: Option<&str>,
    invite: Option<&str>,
) -> EnrollmentGate {
    EnrollmentGate {
        pinned,
        email: email.map(str::to_string),
        invite_code: invite.map(str::to_string),
    }
}

/// Nothing stored is the open default; a stored mode applies; a pinned mode
/// applies over whatever is stored.
#[test]
fn gate_applies_the_pinned_mode_over_the_stored() {
    assert_eq!(gate(None, None, None).admit(None), Ok(None));
    assert_eq!(
        gate(None, None, None).admit(stored(EnrollmentMode::AdminOnly, &[])),
        Err(EnrollmentDenialReason::AdminOnly)
    );
    assert_eq!(
        gate(Some(EnrollmentMode::AdminOnly), None, None).admit(stored(EnrollmentMode::Open, &[])),
        Err(EnrollmentDenialReason::AdminOnly)
    );
    assert_eq!(
        gate(Some(EnrollmentMode::Open), None, None).admit(stored(EnrollmentMode::AdminOnly, &[])),
        Ok(None)
    );
}

/// Invite-only admits a presented code and names it to spend; without one it
/// refuses. Other modes spend no invite even when a code is presented.
#[test]
fn gate_names_the_invite_to_spend_only_when_invite_only() {
    let invite_only = || stored(EnrollmentMode::InviteOnly, &[]);
    assert_eq!(
        gate(None, None, Some("ABCD1234")).admit(invite_only()),
        Ok(Some("ABCD1234"))
    );
    assert_eq!(
        gate(None, None, None).admit(invite_only()),
        Err(EnrollmentDenialReason::InviteRequired)
    );
    assert_eq!(
        gate(None, None, Some("ABCD1234")).admit(stored(EnrollmentMode::Open, &[])),
        Ok(None)
    );
}

/// Domain-restricted admits only an email in an allowed domain.
#[test]
fn gate_checks_the_email_domain() {
    let restricted = || stored(EnrollmentMode::DomainRestricted, &["acme.example"]);
    assert_eq!(
        gate(None, Some("a@acme.example"), None).admit(restricted()),
        Ok(None)
    );
    assert!(matches!(
        gate(None, Some("a@other.example"), None).admit(restricted()),
        Err(EnrollmentDenialReason::DomainNotAllowed { .. })
    ));
    assert_eq!(
        gate(None, None, None).admit(restricted()),
        Err(EnrollmentDenialReason::EmailRequired)
    );
}

/// A malformed phone number is refused instead of being stored as a zero.
#[test]
fn invalid_signup_identifier_is_refused() {
    for value in ["not-a-number", "+0"] {
        assert!(
            NewRegistration::new(
                Profile::new(None::<String>),
                SignupIdentifier::Phone(value),
                None
            )
            .is_err(),
            "{value}"
        );
    }
}
