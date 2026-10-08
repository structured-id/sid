// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::test_mock::MockStorage;
use sid_core::models::*;

fn create_test_role(project_id: ProjectId, key: &str, permissions: &[&str]) -> Role {
    let mut role = Role::new(project_id, key, key);
    role.permissions = permissions.iter().map(|s| s.to_string()).collect();
    role
}

async fn setup() -> (RbacService<MockStorage>, Arc<MockStorage>, ProjectId) {
    let storage = Arc::new(MockStorage::new());
    let service = RbacService::new(storage.clone());
    let project_id = ProjectId::new();
    (service, storage, project_id)
}

#[tokio::test]
async fn test_check_permission_no_roles() {
    let (service, _, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let result = service
        .check_permission(profile_id, project_id, "profiles:read")
        .await
        .unwrap();
    assert!(!result);
}

#[tokio::test]
async fn test_check_permission_direct_role() {
    let (service, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "admin", &["profiles:read", "profiles:write"]);
    storage
        .create_role(&role, AuditEntry::system("role.ensure", &role.key).into())
        .await
        .unwrap();

    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
    storage
        .create_role_assignment(
            &assignment,
            AuditEntry::system("role_assignment.create", assignment.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    assert!(
        service
            .check_permission(profile_id, project_id, "profiles:read")
            .await
            .unwrap()
    );
    assert!(
        service
            .check_permission(profile_id, project_id, "profiles:write")
            .await
            .unwrap()
    );
    assert!(
        !service
            .check_permission(profile_id, project_id, "clients:delete")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_check_permission_via_group() {
    let (service, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "viewer", &["profiles:read"]);
    storage
        .create_role(&role, AuditEntry::system("role.ensure", &role.key).into())
        .await
        .unwrap();

    let group = Group::new(project_id, "engineering");
    storage
        .create_group(
            &group,
            AuditEntry::system("group.create", &group.name).into(),
        )
        .await
        .unwrap();
    storage
        .add_to_group(
            &GroupMember::new(group.id, profile_id),
            AuditEntry::system("group.add_member", group.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Group(group.id), role.id);
    storage
        .create_role_assignment(
            &assignment,
            AuditEntry::system("role_assignment.create", assignment.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    assert!(
        service
            .check_permission(profile_id, project_id, "profiles:read")
            .await
            .unwrap()
    );
    assert!(
        !service
            .check_permission(profile_id, project_id, "profiles:write")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_expired_assignment_filtered() {
    let (service, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "temp", &["profiles:read"]);
    storage
        .create_role(&role, AuditEntry::system("role.ensure", &role.key).into())
        .await
        .unwrap();

    let mut assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
    assignment.expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
    storage
        .create_role_assignment(
            &assignment,
            AuditEntry::system("role_assignment.create", assignment.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    assert!(
        !service
            .check_permission(profile_id, project_id, "profiles:read")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_non_expired_assignment_included() {
    let (service, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "temp", &["profiles:read"]);
    storage
        .create_role(&role, AuditEntry::system("role.ensure", &role.key).into())
        .await
        .unwrap();

    let mut assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
    assignment.expires_at = Some(chrono::Utc::now() + chrono::Duration::hours(1));
    storage
        .create_role_assignment(
            &assignment,
            AuditEntry::system("role_assignment.create", assignment.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    assert!(
        service
            .check_permission(profile_id, project_id, "profiles:read")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_resolve_effective_roles_deduplication() {
    let (service, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "admin", &["profiles:read"]);
    storage
        .create_role(&role, AuditEntry::system("role.ensure", &role.key).into())
        .await
        .unwrap();

    // Direct assignment.
    let a1 = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
    storage
        .create_role_assignment(
            &a1,
            AuditEntry::system("role_assignment.create", a1.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    // Also assign via group.
    let group = Group::new(project_id, "admins");
    storage
        .create_group(
            &group,
            AuditEntry::system("group.create", &group.name).into(),
        )
        .await
        .unwrap();
    storage
        .add_to_group(
            &GroupMember::new(group.id, profile_id),
            AuditEntry::system("group.add_member", group.id.0.to_string()).into(),
        )
        .await
        .unwrap();
    let a2 = RoleAssignment::new(RoleAssignmentPrincipal::Group(group.id), role.id);
    storage
        .create_role_assignment(
            &a2,
            AuditEntry::system("role_assignment.create", a2.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    let roles = service
        .resolve_effective_roles(profile_id, project_id)
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].key, "admin");
}

#[tokio::test]
async fn test_resolve_roles_project_scoped() {
    let (service, storage, _) = setup().await;
    let profile_id = ProfileId::generate();
    let project_a = ProjectId::new();
    let project_b = ProjectId::new();

    let role_a = create_test_role(project_a, "admin", &["all"]);
    let role_b = create_test_role(project_b, "viewer", &["read"]);
    storage
        .create_role(
            &role_a,
            AuditEntry::system("role.ensure", &role_a.key).into(),
        )
        .await
        .unwrap();
    storage
        .create_role(
            &role_b,
            AuditEntry::system("role.ensure", &role_b.key).into(),
        )
        .await
        .unwrap();

    let a1 = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role_a.id);
    let a2 = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role_b.id);
    storage
        .create_role_assignment(
            &a1,
            AuditEntry::system("role_assignment.create", a1.id.0.to_string()).into(),
        )
        .await
        .unwrap();
    storage
        .create_role_assignment(
            &a2,
            AuditEntry::system("role_assignment.create", a2.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    let roles_a = service
        .resolve_effective_roles(profile_id, project_a)
        .await
        .unwrap();
    assert_eq!(roles_a.len(), 1);
    assert_eq!(roles_a[0].key, "admin");

    let roles_b = service
        .resolve_effective_roles(profile_id, project_b)
        .await
        .unwrap();
    assert_eq!(roles_b.len(), 1);
    assert_eq!(roles_b[0].key, "viewer");
}

#[tokio::test]
async fn test_check_role() {
    let (service, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "editor", &[]);
    storage
        .create_role(&role, AuditEntry::system("role.ensure", &role.key).into())
        .await
        .unwrap();

    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
    storage
        .create_role_assignment(
            &assignment,
            AuditEntry::system("role_assignment.create", assignment.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    assert!(
        service
            .check_role(profile_id, project_id, "editor")
            .await
            .unwrap()
    );
    assert!(
        !service
            .check_role(profile_id, project_id, "admin")
            .await
            .unwrap()
    );
}

/// Store a role assignment directly; who may make it is the administration
/// core's concern, not the role checks under test here.
async fn assigned(
    storage: &Arc<MockStorage>,
    profile_id: ProfileId,
    role_id: RoleId,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> RoleAssignment {
    let mut assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role_id);
    assignment.expires_at = expires_at;
    storage
        .create_role_assignment(&assignment, AuditEntry::system("test", "assign").into())
        .await
        .unwrap();
    assignment
}

#[tokio::test]
async fn test_check_role_after_assignment() {
    let (service, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "operator", &["ops:restart"]);
    storage
        .create_role(&role, AuditEntry::system("role.ensure", &role.key).into())
        .await
        .unwrap();

    assigned(&storage, profile_id, role.id, None).await;
    assert!(
        service
            .check_role(profile_id, project_id, "operator")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_check_role_after_revocation() {
    let (service, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "admin", &["all"]);
    storage
        .create_role(&role, AuditEntry::system("role.ensure", &role.key).into())
        .await
        .unwrap();

    let assignment = assigned(&storage, profile_id, role.id, None).await;
    assert!(
        service
            .check_role(profile_id, project_id, "admin")
            .await
            .unwrap()
    );
    storage
        .delete_role_assignment(assignment.id, AuditEntry::system("test", "revoke").into())
        .await
        .unwrap();
    assert!(
        !service
            .check_role(profile_id, project_id, "admin")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_list_effective_permissions() {
    let (service, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role1 = create_test_role(project_id, "editor", &["profiles:read", "profiles:write"]);
    let role2 = create_test_role(project_id, "auditor", &["audit:read", "profiles:read"]);
    storage
        .create_role(&role1, AuditEntry::system("role.ensure", &role1.key).into())
        .await
        .unwrap();
    storage
        .create_role(&role2, AuditEntry::system("role.ensure", &role2.key).into())
        .await
        .unwrap();

    let a1 = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role1.id);
    let a2 = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role2.id);
    storage
        .create_role_assignment(
            &a1,
            AuditEntry::system("role_assignment.create", a1.id.0.to_string()).into(),
        )
        .await
        .unwrap();
    storage
        .create_role_assignment(
            &a2,
            AuditEntry::system("role_assignment.create", a2.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    let perms = service
        .list_effective_permissions(profile_id, project_id)
        .await
        .unwrap();

    assert_eq!(perms, vec!["audit:read", "profiles:read", "profiles:write"]);
}

#[tokio::test]
async fn test_check_permission_detailed_allow() {
    let (service, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "admin", &["profiles:delete"]);
    storage
        .create_role(&role, AuditEntry::system("role.ensure", &role.key).into())
        .await
        .unwrap();

    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
    storage
        .create_role_assignment(
            &assignment,
            AuditEntry::system("role_assignment.create", assignment.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    let decision = service
        .check_permission_detailed(profile_id, project_id, "profiles:delete")
        .await
        .unwrap();

    assert!(decision.is_allowed());
    match decision {
        AuthzDecision::Allow { granting_roles } => {
            assert_eq!(granting_roles, vec!["admin"]);
        }
        _ => panic!("expected Allow"),
    }
}

#[tokio::test]
async fn test_check_permission_detailed_deny() {
    let (service, _, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let decision = service
        .check_permission_detailed(profile_id, project_id, "profiles:delete")
        .await
        .unwrap();

    assert!(!decision.is_allowed());
    match decision {
        AuthzDecision::Deny { permission, .. } => {
            assert_eq!(permission, "profiles:delete");
        }
        _ => panic!("expected Deny"),
    }
}

#[tokio::test]
async fn test_multiple_groups_combine_roles() {
    let (service, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role1 = create_test_role(project_id, "reader", &["read"]);
    let role2 = create_test_role(project_id, "writer", &["write"]);
    storage
        .create_role(&role1, AuditEntry::system("role.ensure", &role1.key).into())
        .await
        .unwrap();
    storage
        .create_role(&role2, AuditEntry::system("role.ensure", &role2.key).into())
        .await
        .unwrap();

    let group1 = Group::new(project_id, "readers");
    let group2 = Group::new(project_id, "writers");
    storage
        .create_group(
            &group1,
            AuditEntry::system("group.create", &group1.name).into(),
        )
        .await
        .unwrap();
    storage
        .create_group(
            &group2,
            AuditEntry::system("group.create", &group2.name).into(),
        )
        .await
        .unwrap();

    storage
        .add_to_group(
            &GroupMember::new(group1.id, profile_id),
            AuditEntry::system("group.add_member", group1.id.0.to_string()).into(),
        )
        .await
        .unwrap();
    storage
        .add_to_group(
            &GroupMember::new(group2.id, profile_id),
            AuditEntry::system("group.add_member", group2.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    let a1 = RoleAssignment::new(RoleAssignmentPrincipal::Group(group1.id), role1.id);
    let a2 = RoleAssignment::new(RoleAssignmentPrincipal::Group(group2.id), role2.id);
    storage
        .create_role_assignment(
            &a1,
            AuditEntry::system("role_assignment.create", a1.id.0.to_string()).into(),
        )
        .await
        .unwrap();
    storage
        .create_role_assignment(
            &a2,
            AuditEntry::system("role_assignment.create", a2.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    assert!(
        service
            .check_permission(profile_id, project_id, "read")
            .await
            .unwrap()
    );
    assert!(
        service
            .check_permission(profile_id, project_id, "write")
            .await
            .unwrap()
    );
}

// ── Temporary role auto-revoke tests ─────────────────────────

#[tokio::test]
async fn test_list_expiring_role_assignments() {
    let (_, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "temp", &["read"]);
    storage
        .create_role(&role, AuditEntry::system("role.ensure", &role.key).into())
        .await
        .unwrap();

    // Assignment expiring in 12 hours
    let a1 = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id)
        .with_expiry(chrono::Utc::now() + chrono::Duration::hours(12));
    storage
        .create_role_assignment(
            &a1,
            AuditEntry::system("role_assignment.create", a1.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    // Assignment expiring in 96 hours (outside 72h window)
    let a2 = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id)
        .with_expiry(chrono::Utc::now() + chrono::Duration::hours(96));
    storage
        .create_role_assignment(
            &a2,
            AuditEntry::system("role_assignment.create", a2.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    // Permanent assignment (no expiry)
    let a3 = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
    storage
        .create_role_assignment(
            &a3,
            AuditEntry::system("role_assignment.create", a3.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    // Within 24h → only a1
    let expiring = storage.list_expiring_role_assignments(24).await.unwrap();
    assert_eq!(expiring.len(), 1);
    assert_eq!(expiring[0].id, a1.id);

    // Within 72h → a1
    let expiring = storage.list_expiring_role_assignments(72).await.unwrap();
    assert_eq!(expiring.len(), 1);
    assert_eq!(expiring[0].id, a1.id);

    // Within 100h → a1 + a2
    let expiring = storage.list_expiring_role_assignments(100).await.unwrap();
    assert_eq!(expiring.len(), 2);
}

#[tokio::test]
async fn test_cleanup_expired_role_assignments() {
    let (_, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "temp", &["read"]);
    storage
        .create_role(&role, AuditEntry::system("role.ensure", &role.key).into())
        .await
        .unwrap();

    // Expired assignment
    let a1 = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id)
        .with_expiry(chrono::Utc::now() - chrono::Duration::hours(1));
    storage
        .create_role_assignment(
            &a1,
            AuditEntry::system("role_assignment.create", a1.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    // Still active assignment
    let a2 = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id)
        .with_expiry(chrono::Utc::now() + chrono::Duration::hours(24));
    storage
        .create_role_assignment(
            &a2,
            AuditEntry::system("role_assignment.create", a2.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    // Permanent assignment
    let a3 = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile_id), role.id);
    storage
        .create_role_assignment(
            &a3,
            AuditEntry::system("role_assignment.create", a3.id.0.to_string()).into(),
        )
        .await
        .unwrap();

    let removed = storage
        .cleanup_expired_role_assignments(
            AuditEntry::system("role_assignment.auto_revoke", "test").into(),
        )
        .await
        .unwrap();
    let removed: Vec<_> = removed.iter().map(|a| a.id).collect();
    assert_eq!(removed, [a1.id]);

    // a2 and a3 should remain
    let remaining = storage
        .list_role_assignments_for_profile(profile_id)
        .await
        .unwrap();
    assert_eq!(remaining.len(), 2);
}

#[tokio::test]
async fn test_cleanup_no_expired_returns_zero() {
    let (_, storage, _) = setup().await;

    let removed = storage
        .cleanup_expired_role_assignments(
            AuditEntry::system("role_assignment.auto_revoke", "test").into(),
        )
        .await
        .unwrap();
    assert!(removed.is_empty());
}

#[tokio::test]
async fn test_assign_role_with_expiry() {
    let (service, storage, project_id) = setup().await;
    let profile_id = ProfileId::generate();

    let role = create_test_role(project_id, "temp_admin", &["admin:all"]);
    storage
        .create_role(&role, AuditEntry::system("role.ensure", &role.key).into())
        .await
        .unwrap();

    let expiry = chrono::Utc::now() + chrono::Duration::hours(4);
    let assignment = assigned(&storage, profile_id, role.id, Some(expiry)).await;

    assert_eq!(assignment.expires_at, Some(expiry));
    assert!(!assignment.is_expired());

    // Permission check should work while active
    assert!(
        service
            .check_role(profile_id, project_id, "temp_admin")
            .await
            .unwrap()
    );
}
