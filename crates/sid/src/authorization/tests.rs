use super::*;
use sid_core::models::{OperationPeriodRefusal, ProfileId, RoleId};

/// A service acting is named by its engine subject, recorded as a machine or
/// a service, and administers only as a holder of its own assignments.
#[test]
fn test_service_actor() {
    let machine = MachineUserId::generate();
    let actor = Actor::Service(format!("machine:{machine}"));
    assert_eq!(actor.subject(), format!("machine:{machine}"));
    assert_eq!(
        actor.audit_actor(),
        (machine.to_string(), ActorType::Machine)
    );
    assert!(matches!(
        actor.administrator(),
        Ok(Administrator::Holder(AuthzPrincipal::MachineUser(id))) if id == machine
    ));

    let client = Actor::Service("oauth_client:billing".into());
    assert_eq!(
        client.audit_actor(),
        ("billing".to_owned(), ActorType::Service)
    );
    assert!(matches!(
        client.administrator(),
        Ok(Administrator::Holder(AuthzPrincipal::OAuthClient(id))) if id == "billing"
    ));
}

/// Bug prevented: a service subject that names no administrator kind
/// administering as some default principal; it is an internal failure.
#[test]
fn test_unknown_service_subject_administers_nothing() {
    for subject in ["connector:x", "machine:not-a-uuid", "nonsense"] {
        assert!(matches!(
            Actor::Service(subject.into()).administrator(),
            Err(AuthorizationError::Internal)
        ));
    }
}

/// Each refusal of role administration keeps its meaning: missing
/// authority, an authority that moved, an invalid change, a ceiling, a
/// missing role; a store failure stays a store failure.
#[test]
fn test_administration_refusals() {
    assert!(matches!(
        administration(SidError::AuthorizationDenied(String::new())),
        AuthorizationError::Denied
    ));
    assert!(matches!(
        administration(SidError::Fenced("x".into())),
        AuthorizationError::AuthorityChanged
    ));
    assert!(matches!(
        administration(SidError::Validation("why".into())),
        AuthorizationError::InvalidAssignment(why) if why == "why"
    ));
    assert!(matches!(
        administration(SidError::InvalidState("why".into())),
        AuthorizationError::CeilingExceeded(why) if why == "why"
    ));
    assert!(matches!(
        administration(SidError::NotFound("r".into())),
        AuthorizationError::RoleNotFound(what) if what == "r"
    ));
    assert!(matches!(
        administration(SidError::Internal("down".into())),
        AuthorizationError::Store(_)
    ));
}

/// A revocation refused as an invalid state removes the last administrator,
/// not an approved ceiling.
#[test]
fn test_revocation_keeps_the_last_administrator() {
    assert!(matches!(
        revocation(SidError::InvalidState("last".into())),
        AuthorizationError::LastAdministrator(why) if why == "last"
    ));
    assert!(matches!(
        revocation(SidError::AuthorizationDenied(String::new())),
        AuthorizationError::Denied
    ));
}

/// A commit answers its response; a key another attempt completed is a
/// concurrent change, a refused period the command's own refusal, anything
/// else as the operation maps it.
#[test]
fn test_settled_outcomes() {
    assert_eq!(settled(Ok(()), 7, AuthorizationError::Store).unwrap(), 7);
    assert!(matches!(
        settled(
            Err(SidError::OperationCompleted("k".into())),
            7,
            AuthorizationError::Store
        ),
        Err(AuthorizationError::ChangedConcurrently)
    ));
    assert!(matches!(
        settled(
            Err(SidError::OperationPeriodRefused(
                OperationPeriodRefusal::Retired
            )),
            7,
            AuthorizationError::Store
        ),
        Err(AuthorizationError::Operation(
            OperationError::PeriodRefused(_)
        ))
    ));
    assert!(matches!(
        settled(Err(SidError::Conflict("name".into())), 7, |_| {
            AuthorizationError::RoleTaken("name".into())
        }),
        Err(AuthorizationError::RoleTaken(_))
    ));
}

/// Bug prevented: an installation administrator that the claim and the
/// last-administrator guard do not see, made by assigning the role to a
/// non-Profile or outside the installation scope, or the installation scope
/// to another role.
#[test]
fn test_installation_assignment_shapes() {
    let administrator = Role::installation_administrator();
    let profile = RoleAssignmentPrincipal::Profile(ProfileId::generate());

    let mut whole = RoleAssignment::new(profile.clone(), administrator.id);
    whole.scope = Some(sid_core::models::INSTALLATION_SCOPE.to_owned());
    assert!(check_installation_assignment(&administrator, &whole).is_ok());

    let mut to_machine = RoleAssignment::new(
        RoleAssignmentPrincipal::MachineUser(MachineUserId::generate()),
        administrator.id,
    );
    to_machine.scope = whole.scope.clone();
    assert!(matches!(
        check_installation_assignment(&administrator, &to_machine),
        Err(AuthorizationError::Assignment(
            AssignmentRule::AdministratorToProfile
        ))
    ));

    let narrow = RoleAssignment::new(profile.clone(), administrator.id);
    assert!(matches!(
        check_installation_assignment(&administrator, &narrow),
        Err(AuthorizationError::Assignment(
            AssignmentRule::InstallationScope
        ))
    ));

    let other = Role::new(sid_core::models::ProjectId::generate(), "reader", "Reader");
    let mut other_wide = RoleAssignment::new(profile, RoleId::generate());
    other_wide.scope = whole.scope.clone();
    assert!(matches!(
        check_installation_assignment(&other, &other_wide),
        Err(AuthorizationError::Assignment(
            AssignmentRule::InstallationScope
        ))
    ));
}

/// Every assignment rule names the request field it is about.
#[test]
fn test_assignment_rules_name_their_field() {
    use AssignmentRule::*;
    for (rule, field) in [
        (AdministratorToProfile, "principal"),
        (InstallationScope, "scope"),
        (ServicePrincipal, "principal"),
        (ServiceResource, "scope"),
        (InvitePrincipal, "principal"),
        (InviteResource, "scope"),
        (ConnectorResource, "scope"),
    ] {
        assert_eq!(rule.violation().0, field);
        assert!(!rule.message().is_empty());
    }
}

/// An absent principal is refused on its field; a malformed connector id on
/// the connector's.
#[test]
fn test_principal_of_refusals() {
    assert!(matches!(
        principal_of(None),
        Err(AuthorizationError::MissingField("principal"))
    ));
    let malformed = assign_role_request::Principal::ProvisioningConnectorId(
        sid_proto::sid::v1::ids::ProvisioningConnectorId { value: vec![1; 3] },
    );
    assert!(matches!(
        principal_of(Some(malformed)),
        Err(AuthorizationError::InvalidField {
            field: "provisioning_connector_id",
            ..
        })
    ));
}
