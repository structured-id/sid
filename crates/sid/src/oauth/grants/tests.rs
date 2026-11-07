use super::*;
use sid_core::models::{MachineOwner, ProjectId};

fn machine(scopes: &[&str]) -> MachineUser {
    let mut mu = MachineUser::new(ProjectId::SYSTEM, "mu_ci", "CI", MachineOwner::System);
    mu.scopes = scopes.iter().map(|s| (*s).to_string()).collect();
    mu
}

/// A machine user's token carries the requested scopes it may have, or all
/// of its own when none are requested; one with no scope list is
/// unrestricted.
#[test]
fn test_machine_scopes() {
    let restricted = machine(&["read", "write"]);
    assert_eq!(machine_scopes(&restricted, Some("read admin")), ["read"]);
    assert_eq!(machine_scopes(&restricted, None), ["read", "write"]);
    let open = machine(&[]);
    assert_eq!(machine_scopes(&open, Some("read admin")), ["read", "admin"]);
}

/// The client names itself once with one method; an ambiguous request is
/// `invalid_request`, a malformed credential `invalid_client`.
#[test]
fn test_client_authentication_refusals() {
    assert!(matches!(
        client_authentication(None, None, None, None, None),
        Err(OAuthError::Token {
            error: TokenError::InvalidRequest,
            ..
        }) | Err(OAuthError::ClientRefused)
    ));
    assert!(client_authentication(None, Some("client"), None, None, None).is_ok());
}

/// Every grant engine refusal keeps its RFC 6749 error and description; a
/// host refusal is returned as is.
#[test]
fn test_grant_refusal() {
    assert!(matches!(
        grant_refusal(GrantFailure::MissingParameter("code")),
        OAuthError::MissingParameter("code")
    ));
    assert!(matches!(
        grant_refusal(GrantFailure::Refused(
            TokenError::InvalidGrant,
            "used".into()
        )),
        OAuthError::Token {
            error: TokenError::InvalidGrant,
            ..
        }
    ));
    assert!(matches!(
        grant_refusal(GrantFailure::ProofMismatch),
        OAuthError::Dpop(_)
    ));
    assert!(matches!(
        grant_refusal(GrantFailure::Issuance(SidError::Storage("x".into()))),
        OAuthError::Internal
    ));
    assert!(matches!(
        grant_refusal(GrantFailure::Host(OAuthError::ClientRefused)),
        OAuthError::ClientRefused
    ));
}
