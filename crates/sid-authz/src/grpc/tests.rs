use super::*;
use sid_core::models::RoleAssignmentId;

// ── Conversion tests ────────────────────────────────────────────

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
        Some(role_assignment::Principal::ProfileId(pid)) => {
            assert_eq!(pid, profile_id.into());
        }
        _ => panic!("expected ProfileId principal"),
    }
}

#[test]
fn test_assignment_to_proto_group() {
    let group_id = GroupId::generate();
    let role_id = RoleId::generate();
    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Group(group_id), role_id);

    let proto = assignment_to_proto(&assignment);
    match proto.principal {
        Some(role_assignment::Principal::GroupId(gid)) => {
            assert_eq!(gid, group_id.into());
        }
        _ => panic!("expected GroupId principal"),
    }
}

#[test]
fn test_assignment_to_proto_with_scope_and_expiry() {
    let profile_id = ProfileId::generate();
    let role_id = RoleId::generate();
    let mut assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role_id);
    assignment.scope = Some("project:abc".to_string());
    assignment.expires_at = Some(chrono::Utc::now());

    let proto = assignment_to_proto(&assignment);
    assert_eq!(proto.scope, Some("project:abc".to_string()));
    assert!(proto.expires_at.is_some());
}

#[test]
fn test_policy_to_proto_permit() {
    let project_id = ProjectId::generate();
    let policy = CedarPolicy::new(
        sid_core::models::PolicyScope::Project(project_id),
        "allow-read",
        "permit(principal, action, resource);",
        sid_core::models::PolicyEffect::Permit,
    );

    let proto = policy_to_proto(&policy);
    assert_eq!(proto.name, "allow-read");
    assert_eq!(
        proto.effect,
        i32::from(sid_proto::sid::v1::PolicyEffect::Permit)
    );
    assert!(proto.enabled);
}

#[test]
fn test_policy_to_proto_forbid() {
    let project_id = ProjectId::generate();
    let policy = CedarPolicy::new(
        sid_core::models::PolicyScope::Project(project_id),
        "deny-delete",
        "forbid(principal, action == Action::\"delete\", resource);",
        sid_core::models::PolicyEffect::Forbid,
    );

    let proto = policy_to_proto(&policy);
    assert_eq!(
        proto.effect,
        i32::from(sid_proto::sid::v1::PolicyEffect::Forbid)
    );
}

// ── Request identifiers ─────────────────────────────────────────

/// Each identifier a request names becomes its domain type, the system
/// project and built-in roles included.
#[test]
fn test_wire_id_accepts_each_kind() {
    use sid_proto::sid::v1::ids as wire;
    let project = ProjectId::generate();
    assert_eq!(
        wire_id(Some(&wire::ProjectId::from(project)), "project_id").unwrap(),
        project
    );
    assert_eq!(
        wire_id(
            Some(&wire::ProjectId::from(ProjectId::SYSTEM)),
            "project_id"
        )
        .unwrap(),
        ProjectId::SYSTEM
    );
    let role = Role::token_inspector().id;
    assert_eq!(
        wire_id(Some(&wire::RoleId::from(role)), "role_id").unwrap(),
        role
    );
    let assignment = RoleAssignmentId::generate();
    assert_eq!(
        wire_id(
            Some(&wire::RoleAssignmentId::from(assignment)),
            "assignment_id"
        )
        .unwrap(),
        assignment
    );
}

/// Bug prevented: an absent or malformed identifier reaching storage as a
/// lookup key instead of being refused on its field.
#[test]
fn test_wire_id_refuses_on_its_field() {
    use sid_proto::sid::v1::ids as wire;
    let missing = wire_id::<wire::GroupId>(None, "group_id").unwrap_err();
    let short = wire_id(Some(&wire::GroupId { value: vec![1; 15] }), "group_id").unwrap_err();
    let v4 = wire::CedarPolicyId {
        value: uuid::Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .unwrap()
            .as_bytes()
            .to_vec(),
    };
    let wrong_version = wire_id(Some(&v4), "id").unwrap_err();
    for (refused, field) in [
        (missing, "group_id"),
        (short, "group_id"),
        (wrong_version, "id"),
    ] {
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        let violations = tonic_types::StatusExt::get_details_bad_request(&refused)
            .expect("a BadRequest detail")
            .field_violations;
        assert_eq!(violations[0].field, field);
    }
}

// ── PolicyEffect conversion tests ───────────────────────────────

#[test]
fn test_proto_to_policy_effect_permit() {
    let result = proto_to_policy_effect(sid_proto::sid::v1::PolicyEffect::Permit.into());
    assert_eq!(result, sid_core::models::PolicyEffect::Permit);
}

#[test]
fn test_proto_to_policy_effect_forbid() {
    let result = proto_to_policy_effect(sid_proto::sid::v1::PolicyEffect::Forbid.into());
    assert_eq!(result, sid_core::models::PolicyEffect::Forbid);
}

#[test]
fn test_proto_to_policy_effect_default() {
    let result = proto_to_policy_effect(0); // Unspecified
    assert_eq!(result, sid_core::models::PolicyEffect::Permit);
}
