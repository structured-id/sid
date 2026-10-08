use super::*;
use crate::models::{ProfileId, ProjectId};

fn accountant() -> Role {
    let mut role = Role::new(ProjectId::system(), "accountant", "Accountant");
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
        max_validity_secs: 90 * 86_400,
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
    let other = Role::new(ProjectId::system(), "auditor", "Auditor");
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
    let group = RoleAssignmentPrincipal::Group(GroupId(uuid::Uuid::now_v7()));
    assert_eq!(
        e.covers(AdminOperation::Assign, &role, &group, false, Some(1)),
        Err(Uncovered::Recipient)
    );
    let mut grouped = e.clone();
    grouped.recipient_group = Some(GroupId(uuid::Uuid::now_v7()));
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
    no_time.max_validity_secs = 0;
    assert_eq!(no_time.validate(), Err(EnvelopeError::Validity));
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
    child.max_validity_secs = 86_400;
    assert!(parent.is_narrowed_by(&child));
    assert!(parent.is_narrowed_by(&parent.clone()));

    let mut wider = child.clone();
    wider.operations.insert(AdminOperation::EditRole);
    assert!(!parent.is_narrowed_by(&wider));
    let mut longer = child.clone();
    longer.max_validity_secs = parent.max_validity_secs + 1;
    assert!(!parent.is_narrowed_by(&longer));
    let mut more = child.clone();
    more.permission_ceiling.insert("payroll.read".into());
    assert!(!parent.is_narrowed_by(&more));
    let mut kinds = child.clone();
    kinds.recipient_kinds.insert(RecipientKind::Group);
    assert!(!parent.is_narrowed_by(&kinds));

    let group = GroupId(uuid::Uuid::now_v7());
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
