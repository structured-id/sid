use super::*;

// ── Conversion tests ────────────────────────────────────────────

#[test]
fn test_role_to_proto() {
    let project_id = ProjectId::new();
    let mut role = Role::new(project_id, "admin", "Administrator");
    role.description = Some("Full access".to_string());
    role.permissions = vec!["profiles:read".into(), "profiles:write".into()];

    let proto = role_to_proto(&role);
    assert_eq!(proto.name, "admin");
    assert_eq!(proto.project_id, project_id.0.to_string());
    assert_eq!(proto.description, Some("Full access".to_string()));
    assert_eq!(proto.permissions, vec!["profiles:read", "profiles:write"]);
}

#[test]
fn test_group_to_proto() {
    let project_id = ProjectId::new();
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
    let role_id = RoleId::new();
    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role_id);

    let proto = assignment_to_proto(&assignment);
    assert_eq!(proto.role_id, role_id.0.to_string());
    match proto.principal {
        Some(role_assignment::Principal::ProfileId(pid)) => {
            assert_eq!(pid, profile_id.to_string());
        }
        _ => panic!("expected ProfileId principal"),
    }
}

#[test]
fn test_assignment_to_proto_group() {
    let group_id = GroupId::new();
    let role_id = RoleId::new();
    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Group(group_id), role_id);

    let proto = assignment_to_proto(&assignment);
    match proto.principal {
        Some(role_assignment::Principal::GroupId(gid)) => {
            assert_eq!(gid, group_id.0.to_string());
        }
        _ => panic!("expected GroupId principal"),
    }
}

#[test]
fn test_assignment_to_proto_with_scope_and_expiry() {
    let profile_id = ProfileId::generate();
    let role_id = RoleId::new();
    let mut assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role_id);
    assignment.scope = Some("project:abc".to_string());
    assignment.expires_at = Some(chrono::Utc::now());

    let proto = assignment_to_proto(&assignment);
    assert_eq!(proto.scope, Some("project:abc".to_string()));
    assert!(proto.expires_at.is_some());
}

#[test]
fn test_policy_to_proto_permit() {
    let project_id = ProjectId::new();
    let policy = CedarPolicy::new(
        project_id,
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
    let project_id = ProjectId::new();
    let policy = CedarPolicy::new(
        project_id,
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

// ── Parse helper tests ──────────────────────────────────────────

#[test]
fn test_parse_project_id_valid() {
    let id = uuid::Uuid::now_v7();
    assert!(parse_project_id(&id.to_string()).is_ok());
}

#[test]
fn test_parse_project_id_invalid() {
    assert!(parse_project_id("not-a-uuid").is_err());
}

#[test]
fn test_parse_role_id_valid() {
    let id = uuid::Uuid::now_v7();
    assert!(parse_role_id(&id.to_string()).is_ok());
}

#[test]
fn test_parse_group_id_valid() {
    let id = uuid::Uuid::now_v7();
    assert!(parse_group_id(&id.to_string()).is_ok());
}

#[test]
fn test_parse_policy_id_valid() {
    let id = uuid::Uuid::now_v7();
    assert!(parse_policy_id(&id.to_string()).is_ok());
}

#[test]
fn test_parse_assignment_id_valid() {
    let id = uuid::Uuid::now_v7();
    assert!(parse_assignment_id(&id.to_string()).is_ok());
}

// ── Extract project from resource tests ─────────────────────────

#[test]
fn test_extract_project_prefix() {
    let id = uuid::Uuid::now_v7();
    let resource = format!("project:{}", id);
    let result = extract_project_from_resource(&resource).unwrap();
    assert_eq!(result.0, id);
}

#[test]
fn test_extract_project_bare_uuid() {
    let id = uuid::Uuid::now_v7();
    let result = extract_project_from_resource(&id.to_string()).unwrap();
    assert_eq!(result.0, id);
}

#[test]
fn test_extract_project_typed_resource() {
    let id = uuid::Uuid::now_v7();
    let resource = format!("document:{}", id);
    let result = extract_project_from_resource(&resource).unwrap();
    assert_eq!(result.0, id);
}

#[test]
fn test_extract_project_invalid() {
    assert!(extract_project_from_resource("invalid-resource").is_err());
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
