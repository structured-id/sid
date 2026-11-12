use super::*;
use crate::models::{ProfileId, ProjectId};

fn accountant() -> Role {
    let mut role = Role::new(ProjectId::SYSTEM, "accountant", "Accountant");
    role.permissions = vec!["ledger.read".into(), "ledger.post".into()];
    role
}

fn envelope(role: &Role) -> AdminEnvelope {
    AdminEnvelope {
        operations: [AdminOperation::Assign, AdminOperation::Revoke].into(),
        roles: [role.id].into(),
        permission_ceiling: ["ledger.read".to_string(), "ledger.post".to_string()].into(),
        recipient_kinds: [RecipientKind::Profile].into(),
        recipient_group: None,
        max_validity_secs: Some(90 * 86_400),
    }
}

fn worker() -> RoleAssignmentPrincipal {
    RoleAssignmentPrincipal::Profile(ProfileId::generate())
}

/// An access administrator's envelope covers assigning its role to an
/// eligible worker for a permitted time.
#[test]
fn an_envelope_covers_its_role_for_an_eligible_recipient() {
    let role = accountant();
    let e = envelope(&role);
    assert_eq!(e.validate(), Ok(()));
    assert_eq!(
        e.covers(
            AdminOperation::Assign,
            &role,
            &worker(),
            false,
            Some(86_400)
        ),
        Ok(())
    );
    assert_eq!(
        e.covers(AdminOperation::Revoke, &role, &worker(), false, None),
        Ok(())
    );
}

/// Every bound is checked on its own: another operation, another role, a
/// role whose content grew past the ceiling under the same id, another
/// recipient kind, a recipient outside the named group, and a grant without
/// or beyond the permitted validity.
#[test]
fn every_bound_refuses_on_its_own() {
    let role = accountant();
    let e = envelope(&role);
    assert_eq!(
        e.covers(AdminOperation::EditRole, &role, &worker(), false, Some(1)),
        Err(Uncovered::Operation)
    );
    let other = Role::new(ProjectId::SYSTEM, "auditor", "Auditor");
    assert_eq!(
        e.covers(AdminOperation::Assign, &other, &worker(), false, Some(1)),
        Err(Uncovered::Role)
    );
    let mut grown = role.clone();
    grown.permissions.push("payroll.read".into());
    assert_eq!(
        e.covers(AdminOperation::Assign, &grown, &worker(), false, Some(1)),
        Err(Uncovered::Ceiling)
    );
    let group = RoleAssignmentPrincipal::Group(GroupId::generate());
    assert_eq!(
        e.covers(AdminOperation::Assign, &role, &group, false, Some(1)),
        Err(Uncovered::Recipient)
    );
    let mut grouped = e.clone();
    grouped.recipient_group = Some(GroupId::generate());
    assert_eq!(
        grouped.covers(AdminOperation::Assign, &role, &worker(), false, Some(1)),
        Err(Uncovered::Recipient)
    );
    assert_eq!(
        grouped.covers(AdminOperation::Assign, &role, &worker(), true, Some(1)),
        Ok(())
    );
    for validity in [None, Some(0), Some(91 * 86_400)] {
        assert_eq!(
            e.covers(AdminOperation::Assign, &role, &worker(), false, validity),
            Err(Uncovered::Validity),
            "{validity:?}"
        );
    }
}

/// A connector's roles follow its own purpose limits: no envelope makes it
/// an administered recipient.
#[test]
fn a_connector_is_never_an_administered_recipient() {
    let role = accountant();
    let mut e = envelope(&role);
    e.recipient_kinds = [
        RecipientKind::Profile,
        RecipientKind::Group,
        RecipientKind::MachineUser,
        RecipientKind::OAuthClient,
    ]
    .into();
    let connector = RoleAssignmentPrincipal::ProvisioningConnector(
        crate::models::ProvisioningConnectorId::generate(),
    );
    assert_eq!(
        e.covers(AdminOperation::Assign, &role, &connector, false, Some(1)),
        Err(Uncovered::Recipient)
    );
}

/// An absent bound is refused, never read as a wildcard.
#[test]
fn an_incomplete_envelope_is_refused() {
    let role = accountant();
    let mut no_ops = envelope(&role);
    no_ops.operations.clear();
    assert_eq!(no_ops.validate(), Err(EnvelopeError::NoOperations));
    let mut no_roles = envelope(&role);
    no_roles.roles.clear();
    assert_eq!(no_roles.validate(), Err(EnvelopeError::NoRoles));
    let mut no_ceiling = envelope(&role);
    no_ceiling.permission_ceiling.clear();
    assert_eq!(
        no_ceiling.validate(),
        Err(EnvelopeError::NoPermissionCeiling)
    );
    let mut no_kinds = envelope(&role);
    no_kinds.recipient_kinds.clear();
    assert_eq!(no_kinds.validate(), Err(EnvelopeError::NoRecipientKinds));
    let mut no_time = envelope(&role);
    no_time.max_validity_secs = Some(0);
    assert_eq!(no_time.validate(), Err(EnvelopeError::Validity));
}

/// Bug prevented: every administered assignment was forced to expire, so an
/// authorized assignment without end could not be made at all. Without a
/// limit of its own an envelope admits an assignment without end or with any
/// end ahead; a limited one still refuses none and longer.
#[test]
fn an_unlimited_envelope_admits_an_assignment_without_end() {
    let role = accountant();
    let mut unlimited = envelope(&role);
    unlimited.max_validity_secs = None;
    assert_eq!(unlimited.validate(), Ok(()));
    for validity in [None, Some(1), Some(10 * 365 * 86_400)] {
        assert_eq!(
            unlimited.covers(AdminOperation::Assign, &role, &worker(), false, validity),
            Ok(()),
            "{validity:?}"
        );
    }
    for validity in [Some(0), Some(-1)] {
        assert_eq!(
            unlimited.covers(AdminOperation::Assign, &role, &worker(), false, validity),
            Err(Uncovered::Validity),
            "an end already past: {validity:?}"
        );
    }
}

/// A redelegated envelope may only narrow: it adds no operation, role,
/// permission, recipient kind or validity and keeps a recipient group.
#[test]
fn redelegation_only_narrows() {
    let role = accountant();
    let mut parent = envelope(&role);
    parent.operations.insert(AdminOperation::Redelegate);
    let mut child = envelope(&role);
    child.operations = [AdminOperation::Assign].into();
    child.max_validity_secs = Some(86_400);
    assert!(parent.is_narrowed_by(&child));
    assert!(parent.is_narrowed_by(&parent.clone()));
    let mut unlimited_child = child.clone();
    unlimited_child.max_validity_secs = None;
    assert!(
        !parent.is_narrowed_by(&unlimited_child),
        "a limited envelope passes on no unlimited one"
    );
    let mut unlimited_parent = parent.clone();
    unlimited_parent.max_validity_secs = None;
    assert!(unlimited_parent.is_narrowed_by(&unlimited_child));
    assert!(
        unlimited_parent.is_narrowed_by(&child),
        "a limit may be added"
    );

    let mut wider = child.clone();
    wider.operations.insert(AdminOperation::EditRole);
    assert!(!parent.is_narrowed_by(&wider));
    let mut longer = child.clone();
    longer.max_validity_secs = parent.max_validity_secs.map(|max| max + 1);
    assert!(!parent.is_narrowed_by(&longer));
    let mut more = child.clone();
    more.permission_ceiling.insert("payroll.read".into());
    assert!(!parent.is_narrowed_by(&more));
    let mut kinds = child.clone();
    kinds.recipient_kinds.insert(RecipientKind::Group);
    assert!(!parent.is_narrowed_by(&kinds));

    let group = GroupId::generate();
    parent.recipient_group = Some(group);
    assert!(
        !parent.is_narrowed_by(&child),
        "the group restriction is dropped"
    );
    child.recipient_group = Some(group);
    assert!(parent.is_narrowed_by(&child));
}

#[test]
fn spellings_round_trip() {
    for op in [
        AdminOperation::Assign,
        AdminOperation::Revoke,
        AdminOperation::EditRole,
        AdminOperation::Redelegate,
    ] {
        assert_eq!(AdminOperation::parse(op.as_str()), Some(op));
    }
    for kind in [
        RecipientKind::Profile,
        RecipientKind::Group,
        RecipientKind::MachineUser,
        RecipientKind::OAuthClient,
    ] {
        assert_eq!(RecipientKind::parse(kind.as_str()), Some(kind));
    }
    assert_eq!(AdminOperation::parse("all"), None);
    assert_eq!(RecipientKind::parse("connector"), None);
}
