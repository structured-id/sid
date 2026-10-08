use super::*;
use sid_core::models::PrincipalType;

/// Text handles are stored in the form login normalizes input to; an email
/// keeps the address as given beside its key.
#[test]
fn stored_value_is_the_login_form() {
    let (key, email) = stored_principal_value(PrincipalType::Email, " Alice@Example.COM ").unwrap();
    assert_eq!(key, "alice@example.com");
    assert_eq!(email.unwrap().delivery, "Alice@example.com");
    assert_eq!(
        stored_principal_value(PrincipalType::Phone, "+380 50 123 4567").unwrap(),
        ("+380501234567".to_string(), None)
    );
    assert_eq!(
        stored_principal_value(PrincipalType::Username, "Alice_Smith").unwrap(),
        ("alice_smith".to_string(), None)
    );
}

/// A value of another type than requested is refused, not stored under a
/// type that login would never look it up by.
#[test]
fn stored_value_must_match_the_type() {
    for (principal_type, value) in [
        (PrincipalType::Email, "+380501234567"),
        (PrincipalType::Phone, "alice@example.com"),
        (PrincipalType::Username, "alice@example.com"),
    ] {
        let err = stored_principal_value(principal_type, value).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{principal_type}");
    }
}

/// Unreadable text and empty device identifiers are refused.
#[test]
fn stored_value_refuses_empty_and_invalid() {
    assert_eq!(
        stored_principal_value(PrincipalType::Email, "  ")
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        stored_principal_value(PrincipalType::NfcTag, "")
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        stored_principal_value(PrincipalType::NfcTag, "tag-01").unwrap(),
        ("tag-01".to_string(), None)
    );
}
