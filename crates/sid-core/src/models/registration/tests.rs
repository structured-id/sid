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
