use super::*;

fn field_of(e: IdentityError) -> &'static str {
    match e {
        IdentityError::InvalidField { field, .. } | IdentityError::MissingField(field) => field,
        other => panic!("refused as {other:?}"),
    }
}

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
        assert_eq!(field_of(err), "value", "{principal_type}");
    }
}

/// Unreadable text and empty device identifiers are refused; a federated
/// subject is never added by a caller.
#[test]
fn stored_value_refuses_empty_and_invalid() {
    assert_eq!(
        field_of(stored_principal_value(PrincipalType::Email, "  ").unwrap_err()),
        "value"
    );
    assert_eq!(
        field_of(stored_principal_value(PrincipalType::NfcTag, "").unwrap_err()),
        "value"
    );
    assert_eq!(
        stored_principal_value(PrincipalType::NfcTag, "tag-01").unwrap(),
        ("tag-01".to_string(), None)
    );
    assert_eq!(
        field_of(stored_principal_value(PrincipalType::FederatedSubject, "x").unwrap_err()),
        "type"
    );
}

/// A new account starts from an email with its address, a phone or a
/// username; any other kind is refused, and an email without its address is
/// an internal failure.
#[test]
fn signup_identifier_of_each_kind() {
    assert!(matches!(
        signup_identifier(PrincipalType::Phone, "+380501234567", None),
        Ok(SignupIdentifier::Phone("+380501234567"))
    ));
    assert!(matches!(
        signup_identifier(PrincipalType::Username, "alice", None),
        Ok(SignupIdentifier::Username("alice"))
    ));
    let (key, email) = stored_principal_value(PrincipalType::Email, "Alice@Example.com").unwrap();
    assert!(matches!(
        signup_identifier(PrincipalType::Email, &key, email.as_ref()),
        Ok(SignupIdentifier::Email {
            address: "Alice@example.com",
            ..
        })
    ));
    assert!(matches!(
        signup_identifier(PrincipalType::Email, &key, None),
        Err(IdentityError::Internal)
    ));
    assert_eq!(
        field_of(signup_identifier(PrincipalType::NfcTag, "tag", None).unwrap_err()),
        "identifier"
    );
}

/// Bug prevented: revoking a profile's last way to sign in; a credential
/// already gone is revoked as asked.
#[test]
fn last_primary_is_refused() {
    use sid_core::models::CredentialRevocation;
    let id = CredentialId(uuid::Uuid::now_v7());
    assert!(matches!(
        last_primary(CredentialRevocation::LastPrimary, id),
        Err(IdentityError::LastPrimary(refused)) if refused == id
    ));
    assert!(last_primary(CredentialRevocation::Revoked, id).is_ok());
    assert!(last_primary(CredentialRevocation::AlreadyGone, id).is_ok());
}

/// The closure and export refusals keep their meaning: a missing record the
/// operation needs is not found, a missing one anywhere else internal; a
/// wrong state names its record; a rate limit is the cancellation limit.
#[test]
fn account_refusals_by_cause() {
    let owner = ProfileId::generate();
    assert!(matches!(
        account_refusal(
            "op",
            AccountRecord::Export,
            true,
            owner,
            SidError::NotFound("x".into())
        ),
        IdentityError::AccountRecordNotFound {
            record: AccountRecord::Export,
            ..
        }
    ));
    assert!(matches!(
        account_refusal(
            "op",
            AccountRecord::Closure,
            false,
            owner,
            SidError::NotFound("x".into())
        ),
        IdentityError::Internal
    ));
    assert!(matches!(
        account_refusal(
            "op",
            AccountRecord::Closure,
            false,
            owner,
            SidError::InvalidState("closing".into())
        ),
        IdentityError::AccountState { record: AccountRecord::Closure, why, .. } if why == "closing"
    ));
    assert!(matches!(
        account_refusal(
            "op",
            AccountRecord::Closure,
            true,
            owner,
            SidError::RateLimited("y".into())
        ),
        IdentityError::CancelLimit
    ));
    assert_eq!(AccountRecord::Closure.state(), "CLOSURE_STATE");
    assert_eq!(AccountRecord::Export.state(), "EXPORT_STATE");
}

/// A keyed account command's commit completed by another attempt, or
/// refused its period, is resolved by the command rather than refused.
#[test]
fn account_effects_leave_commit_outcomes_to_the_command() {
    let owner = ProfileId::generate();
    assert!(matches!(
        account_effect(
            "op",
            AccountRecord::Export,
            true,
            owner,
            SidError::OperationCompleted("k".into())
        ),
        Effect::Store(SidError::OperationCompleted(_))
    ));
    assert!(matches!(
        account_effect(
            "op",
            AccountRecord::Export,
            true,
            owner,
            SidError::InvalidState("s".into())
        ),
        Effect::Refused(IdentityError::AccountState { .. })
    ));
}

/// A deferring operation refuses a missing context only when it reaches it.
#[test]
fn a_missing_context_is_required_when_reached() {
    assert!(matches!(
        required(None),
        Err(IdentityError::ContextRequired)
    ));
}
