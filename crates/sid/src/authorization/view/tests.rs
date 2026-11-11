use super::*;
use sid_core::models::{GroupId, ProfileId, ProjectId, RoleId};

fn field_of(e: AuthorizationError) -> &'static str {
    match e {
        AuthorizationError::InvalidField { field, .. }
        | AuthorizationError::MissingField(field) => field,
        other => panic!("refused as {other:?}"),
    }
}

#[test]
fn test_role_to_proto() {
    let project_id = ProjectId::generate();
    let mut role = Role::new(project_id, "admin", "Administrator");
    role.description = Some("Full access".to_string());
    role.permissions = vec!["profiles:read".into(), "profiles:write".into()];

    let proto = role_to_proto(&role);
    assert_eq!(proto.name, "admin");
    assert_eq!(proto.id, Some(role.id.into()));
    assert_eq!(proto.project_id, Some(project_id.into()));
    assert_eq!(proto.description, Some("Full access".to_string()));
    assert_eq!(proto.permissions, vec!["profiles:read", "profiles:write"]);
}

#[test]
fn test_group_to_proto() {
    let project_id = ProjectId::generate();
    let mut group = Group::new(project_id, "engineering");
    group.description = Some("Engineers".to_string());

    let proto = group_to_proto(&group);
    assert_eq!(proto.name, "engineering");
    assert_eq!(proto.description, Some("Engineers".to_string()));
    assert!(proto.created_at.is_some());
}

#[test]
fn test_assignment_to_proto_profile() {
    let profile_id = ProfileId::generate();
    let role_id = RoleId::generate();
    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role_id);

    let proto = assignment_to_proto(&assignment);
    assert_eq!(proto.role_id, Some(role_id.into()));
    match proto.principal {
        Some(role_assignment::Principal::ProfileId(pid)) => assert_eq!(pid, profile_id.into()),
        _ => panic!("expected ProfileId principal"),
    }
}

#[test]
fn test_assignment_to_proto_group() {
    let group_id = GroupId::generate();
    let assignment =
        RoleAssignment::new(RoleAssignmentPrincipal::Group(group_id), RoleId::generate());

    match assignment_to_proto(&assignment).principal {
        Some(role_assignment::Principal::GroupId(gid)) => assert_eq!(gid, group_id.into()),
        _ => panic!("expected GroupId principal"),
    }
}

#[test]
fn test_assignment_to_proto_with_scope_and_expiry() {
    let mut assignment = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(ProfileId::generate()),
        RoleId::generate(),
    );
    assignment.scope = Some("project:abc".to_string());
    assignment.expires_at = Some(chrono::Utc::now());

    let proto = assignment_to_proto(&assignment);
    assert_eq!(proto.scope, Some("project:abc".to_string()));
    assert!(proto.expires_at.is_some());
}

#[test]
fn test_policy_to_proto_permit_and_forbid() {
    let scope = PolicyScope::Project(ProjectId::generate());
    let permit = CedarPolicy::new(
        scope,
        "allow-read",
        "permit(principal, action, resource);",
        DomainPolicyEffect::Permit,
    );
    let proto = policy_to_proto(&permit);
    assert_eq!(proto.name, "allow-read");
    assert_eq!(
        proto.effect,
        i32::from(sid_proto::sid::v1::PolicyEffect::Permit)
    );
    assert!(proto.enabled);

    let forbid = CedarPolicy::new(
        scope,
        "deny-delete",
        "forbid(principal, action == Action::\"delete\", resource);",
        DomainPolicyEffect::Forbid,
    );
    assert_eq!(
        policy_to_proto(&forbid).effect,
        i32::from(sid_proto::sid::v1::PolicyEffect::Forbid)
    );
}

/// An unspecified effect permits, as the stored policy does; only an
/// explicit forbid forbids.
#[test]
fn test_policy_effect_of_each_value() {
    assert_eq!(
        policy_effect(sid_proto::sid::v1::PolicyEffect::Permit.into()),
        DomainPolicyEffect::Permit
    );
    assert_eq!(
        policy_effect(sid_proto::sid::v1::PolicyEffect::Forbid.into()),
        DomainPolicyEffect::Forbid
    );
    assert_eq!(policy_effect(0), DomainPolicyEffect::Permit);
}

/// Each policy scope survives the message and back; a missing scope or a
/// malformed project id is refused on the field the caller named.
#[test]
fn test_policy_scope_round_trip_and_refusals() {
    let project = ProjectId::generate();
    for scope in [PolicyScope::Installation, PolicyScope::Project(project)] {
        let wire = policy_scope_to_proto(scope);
        assert_eq!(
            policy_scope_from_proto(Some(&wire), "scope").unwrap(),
            scope
        );
    }
    assert_eq!(
        field_of(policy_scope_from_proto(None, "scope").unwrap_err()),
        "scope"
    );
    let malformed = sid_proto::sid::v1::PolicyScope {
        scope: Some(sid_proto::sid::v1::policy_scope::Scope::ProjectId(
            sid_proto::sid::v1::ids::ProjectId { value: vec![1; 3] },
        )),
    };
    assert_eq!(
        field_of(policy_scope_from_proto(Some(&malformed), "scope").unwrap_err()),
        "scope"
    );
}

fn envelope() -> AdminEnvelope {
    AdminEnvelope {
        operations: vec![AdminOperation::Assign as i32],
        role_ids: vec![RoleId::generate().into()],
        permission_ceiling: vec!["profiles:read".into()],
        recipient_kinds: vec![RecipientKind::Profile as i32],
        recipient_group_id: None,
        max_validity: Some(prost_types::Duration {
            seconds: 3600,
            nanos: 0,
        }),
    }
}

/// An administrative envelope a request asks for is the one stored and
/// answered.
#[test]
fn test_envelope_round_trip() {
    let wire = envelope();
    let domain = envelope_from_proto(wire.clone()).unwrap();
    assert_eq!(envelope_to_proto(&domain), wire);
}

/// An envelope without a maximum validity is one adding no limit of its
/// own: kept as absence on the way in and out, never a distant date.
#[test]
fn test_envelope_without_limit_round_trip() {
    let mut wire = envelope();
    wire.max_validity = None;
    let domain = envelope_from_proto(wire.clone()).unwrap();
    assert_eq!(domain.max_validity_secs, None);
    assert_eq!(envelope_to_proto(&domain), wire);
}

/// Bug prevented: a broken envelope stored as an authority nobody can use,
/// instead of refused on the field it breaks.
#[test]
fn test_envelope_refused_on_its_field() {
    let mut unknown_op = envelope();
    unknown_op.operations = vec![0];
    let mut fractional = envelope();
    fractional.max_validity = Some(prost_types::Duration {
        seconds: 1,
        nanos: 5,
    });
    let mut not_positive = envelope();
    not_positive.max_validity = Some(prost_types::Duration {
        seconds: 0,
        nanos: 0,
    });
    let mut no_roles = envelope();
    no_roles.role_ids.clear();
    for (refused, field) in [
        (unknown_op, "admin.operations"),
        (fractional, "admin.max_validity"),
        (not_positive, "admin.max_validity"),
        (no_roles, "admin.role_ids"),
    ] {
        assert_eq!(field_of(envelope_from_proto(refused).unwrap_err()), field);
    }
}

/// A policy authority survives the message and back; an unspecified
/// operation is refused on its field.
#[test]
fn test_policy_authority_round_trip_and_refusal() {
    let wire = PolicyAuthority {
        operations: vec![PolicyOperation::Read as i32, PolicyOperation::Edit as i32],
    };
    let domain = policy_authority_from_proto(wire.clone()).unwrap();
    assert_eq!(policy_authority_to_proto(&domain), wire);
    let refused = PolicyAuthority {
        operations: vec![PolicyOperation::Unspecified as i32],
    };
    assert_eq!(
        field_of(policy_authority_from_proto(refused).unwrap_err()),
        "policy_admin.operations"
    );
}
