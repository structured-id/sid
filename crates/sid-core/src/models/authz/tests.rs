// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use chrono::Duration;

// ── Resource token inspection ─────────────────────────────────

/// The built-in inspector role of the system project holds exactly the
/// introspection action.
#[test]
fn test_token_inspector_role() {
    let role = Role::token_inspector();
    assert_eq!(role.project_id, ProjectId::system());
    assert_eq!(role.key, TOKEN_INSPECTOR_ROLE);
    assert_eq!(role.permissions, vec![TOKEN_INTROSPECT.to_string()]);
    // The same role in every installation, so restored assignments name it.
    assert_eq!(Role::token_inspector().id, role.id);
}

/// The built-in SCIM provisioner role of the system project holds every SCIM
/// directory action and nothing else, under one id in every installation,
/// distinct from the token inspector's.
#[test]
fn test_scim_provisioner_role() {
    let role = Role::scim_provisioner();
    assert_eq!(role.project_id, ProjectId::system());
    assert_eq!(role.key, SCIM_PROVISIONER_ROLE);
    assert_eq!(role.permissions.len(), SCIM_ACTIONS.len());
    for action in SCIM_ACTIONS {
        assert!(role.has_permission(action), "{action}");
        assert!(action.starts_with(SCIM_ACTION_PREFIX), "{action}");
    }
    assert!(!role.has_permission(TOKEN_INTROSPECT));
    assert_eq!(Role::scim_provisioner().id, role.id);
    assert_ne!(role.id, Role::token_inspector().id);
}

/// The built-in permission checker role of the system project holds exactly
/// the permission-query action, under one id in every installation, distinct
/// from the inspector's: asking about others and inspecting tokens are
/// separately assigned capabilities (D054).
#[test]
fn test_permission_checker_role() {
    let role = Role::permission_checker();
    assert_eq!(role.project_id, ProjectId::system());
    assert_eq!(role.key, PERMISSION_CHECKER_ROLE);
    assert_eq!(role.permissions, vec![AUTHZ_CHECK.to_string()]);
    assert!(!role.has_permission(TOKEN_INTROSPECT));
    assert!(!Role::token_inspector().has_permission(AUTHZ_CHECK));
    assert_eq!(Role::permission_checker().id, role.id);
    assert_ne!(role.id, Role::token_inspector().id);
    assert_ne!(role.id, Role::scim_provisioner().id);
}

/// An assignment on a protected resource names exactly that resource; any
/// other scope names none.
#[test]
fn test_resource_scope_round_trip() {
    let resource = crate::models::ResourceId::generate();
    let assignment = RoleAssignment::new(
        RoleAssignmentPrincipal::OAuthClient("orders-pdp".into()),
        RoleId::new(),
    )
    .on_resource(resource);
    assert_eq!(
        assignment.scope.as_deref(),
        Some(format!("oauth_resource:{resource}").as_str())
    );
    assert_eq!(assignment.resource_scope(), Some(resource));

    let mut other = assignment.clone();
    for scope in [
        None,
        Some("project:abc".to_string()),
        Some("oauth_resource:not-an-id".to_string()),
        Some(format!("oauth_resource:{resource}:x")),
    ] {
        other.scope = scope.clone();
        assert_eq!(other.resource_scope(), None, "{scope:?}");
    }
}

// ── Role tests ────────────────────────────────────────────────

#[test]
fn test_role_new_defaults() {
    let project_id = ProjectId::new();
    let role = Role::new(project_id, "admin", "Administrator");
    assert_eq!(role.key, "admin");
    assert_eq!(role.name, "Administrator");
    assert_eq!(role.project_id, project_id);
    assert!(role.description.is_none());
    assert!(role.group.is_none());
    assert!(role.permissions.is_empty());
}

#[test]
fn test_role_has_permission() {
    let mut role = Role::new(ProjectId::new(), "editor", "Editor");
    assert!(!role.has_permission("profiles:read"));

    role.permissions = vec!["profiles:read".into(), "profiles:write".into()];
    assert!(role.has_permission("profiles:read"));
    assert!(role.has_permission("profiles:write"));
    assert!(!role.has_permission("clients:write"));
}

#[test]
fn test_role_permissions_string() {
    let mut role = Role::new(ProjectId::new(), "admin", "Admin");
    role.permissions = vec!["profiles:read".into(), "clients:write".into()];
    assert_eq!(role.permissions_string(), "profiles:read clients:write");
}

#[test]
fn test_role_parse_permissions() {
    let perms = Role::parse_permissions("profiles:read clients:write");
    assert_eq!(perms, vec!["profiles:read", "clients:write"]);
}

#[test]
fn test_role_parse_permissions_empty() {
    let perms = Role::parse_permissions("");
    assert!(perms.is_empty());
}

#[test]
fn test_role_id_unique() {
    let id1 = RoleId::new();
    let id2 = RoleId::new();
    assert_ne!(id1, id2);
}

// ── Group tests ───────────────────────────────────────────────

#[test]
fn test_group_new_defaults() {
    let project_id = ProjectId::new();
    let group = Group::new(project_id, "engineering");
    assert_eq!(group.name, "engineering");
    assert_eq!(group.project_id, project_id);
    assert!(group.description.is_none());
}

#[test]
fn test_group_id_unique() {
    let id1 = GroupId::new();
    let id2 = GroupId::new();
    assert_ne!(id1, id2);
}

#[test]
fn test_group_member_new() {
    let group_id = GroupId::new();
    let profile_id = ProfileId::generate();
    let member = GroupMember::new(group_id, profile_id);
    assert_eq!(member.group_id, group_id);
    assert_eq!(member.profile_id, profile_id);
}

// ── Role Assignment tests ─────────────────────────────────────

#[test]
fn test_role_assignment_new() {
    let principal = RoleAssignmentPrincipal::Profile(ProfileId::generate());
    let role_id = RoleId::new();
    let assignment = RoleAssignment::new(principal.clone(), role_id);
    assert_eq!(assignment.principal, principal);
    assert_eq!(assignment.role_id, role_id);
    assert!(assignment.scope.is_none());
    assert!(assignment.expires_at.is_none());
    assert!(!assignment.is_expired());
}

#[test]
fn test_role_assignment_not_expired() {
    let mut assignment = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(ProfileId::generate()),
        RoleId::new(),
    );
    assignment.expires_at = Some(Utc::now() + Duration::hours(1));
    assert!(!assignment.is_expired());
}

#[test]
fn test_role_assignment_expired() {
    let mut assignment = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(ProfileId::generate()),
        RoleId::new(),
    );
    assignment.expires_at = Some(Utc::now() - Duration::seconds(1));
    assert!(assignment.is_expired());
}

#[test]
fn test_role_assignment_no_expiry_not_expired() {
    let assignment = RoleAssignment::new(
        RoleAssignmentPrincipal::Group(GroupId::new()),
        RoleId::new(),
    );
    assert!(!assignment.is_expired());
}

#[test]
fn test_role_assignment_id_unique() {
    let id1 = RoleAssignmentId::new();
    let id2 = RoleAssignmentId::new();
    assert_ne!(id1, id2);
}

// ── Scope Type tests ──────────────────────────────────────────

#[test]
fn test_scope_type_as_str() {
    assert_eq!(ScopeType::Global.as_str(), "global");
    assert_eq!(ScopeType::Project.as_str(), "project");
    assert_eq!(ScopeType::Site.as_str(), "site");
}

#[test]
fn test_scope_type_default() {
    assert_eq!(ScopeType::default(), ScopeType::Global);
}

#[test]
fn test_scope_type_serde_roundtrip() {
    let scope = ScopeType::Project;
    let json = serde_json::to_string(&scope).unwrap();
    assert_eq!(json, "\"project\"");
    let parsed: ScopeType = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ScopeType::Project);
}

// ── Cedar Policy tests ────────────────────────────────────────

#[test]
fn test_cedar_policy_new() {
    let project_id = ProjectId::new();
    let policy = CedarPolicy::new(
        project_id,
        "allow-read",
        "permit(principal, action == Action::\"read\", resource);",
        PolicyEffect::Permit,
    );
    assert_eq!(policy.name, "allow-read");
    assert_eq!(policy.project_id, project_id);
    assert_eq!(policy.effect, PolicyEffect::Permit);
    assert!(policy.enabled);
    assert!(policy.description.is_none());
}

#[test]
fn test_policy_effect_as_str() {
    assert_eq!(PolicyEffect::Permit.as_str(), "permit");
    assert_eq!(PolicyEffect::Forbid.as_str(), "forbid");
}

#[test]
fn test_policy_effect_default() {
    assert_eq!(PolicyEffect::default(), PolicyEffect::Permit);
}

#[test]
fn test_policy_effect_serde_roundtrip() {
    let effect = PolicyEffect::Forbid;
    let json = serde_json::to_string(&effect).unwrap();
    assert_eq!(json, "\"forbid\"");
    let parsed: PolicyEffect = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, PolicyEffect::Forbid);
}

#[test]
fn test_cedar_policy_id_unique() {
    let id1 = CedarPolicyId::new();
    let id2 = CedarPolicyId::new();
    assert_ne!(id1, id2);
}

// ── Internal Roles tests ──────────────────────────────────────

#[test]
fn test_internal_roles_constants() {
    assert_eq!(internal_roles::SUPERADMIN, "superadmin");
    assert_eq!(internal_roles::ORG_OWNER, "org:owner");
    assert_eq!(internal_roles::ORG_ADMIN, "org:admin");
    assert_eq!(internal_roles::ORG_MEMBER, "org:member");
    assert_eq!(internal_roles::SITE_OWNER, "site:owner");
    assert_eq!(internal_roles::SITE_ADMIN, "site:admin");
    assert_eq!(internal_roles::PROFILE_OWNER, "profile:owner");
}

// ── Profile Grant tests ────────────────────────────────────────

#[test]
fn test_profile_grant_new() {
    let project_id = ProjectId::new();
    let profile_id = ProfileId::generate();
    let grant = ProfileGrant::new(
        project_id,
        profile_id,
        vec!["admin".into(), "editor".into()],
    );
    assert_eq!(grant.project_id, project_id);
    assert_eq!(grant.profile_id, profile_id);
    assert_eq!(grant.role_keys, vec!["admin", "editor"]);
    assert!(grant.granted_by.is_none());
    assert!(grant.expires_at.is_none());
    assert!(!grant.is_expired());
}

#[test]
fn test_profile_grant_has_role() {
    let grant = ProfileGrant::new(
        ProjectId::new(),
        ProfileId::generate(),
        vec!["admin".into(), "viewer".into()],
    );
    assert!(grant.has_role("admin"));
    assert!(grant.has_role("viewer"));
    assert!(!grant.has_role("editor"));
}

#[test]
fn test_profile_grant_expired() {
    let mut grant = ProfileGrant::new(ProjectId::new(), ProfileId::generate(), vec!["temp".into()]);
    grant.expires_at = Some(Utc::now() - Duration::seconds(1));
    assert!(grant.is_expired());
}

#[test]
fn test_profile_grant_not_expired() {
    let mut grant = ProfileGrant::new(ProjectId::new(), ProfileId::generate(), vec!["temp".into()]);
    grant.expires_at = Some(Utc::now() + Duration::hours(1));
    assert!(!grant.is_expired());
}

#[test]
fn test_profile_grant_id_unique() {
    let id1 = ProfileGrantId::new();
    let id2 = ProfileGrantId::new();
    assert_ne!(id1, id2);
}

#[test]
fn test_profile_grant_serde_roundtrip() {
    let grant = ProfileGrant::new(
        ProjectId::new(),
        ProfileId::generate(),
        vec!["admin".into()],
    );
    let json = serde_json::to_string(&grant).unwrap();
    let parsed: ProfileGrant = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.role_keys, vec!["admin"]);
    assert_eq!(parsed.project_id, grant.project_id);
    assert_eq!(parsed.profile_id, grant.profile_id);
}

// ── Role key & group tests ────────────────────────────────────

#[test]
fn test_role_key_vs_name() {
    let role = Role::new(ProjectId::new(), "content_editor", "Content Editor");
    assert_eq!(role.key, "content_editor");
    assert_eq!(role.name, "Content Editor");
}

#[test]
fn test_role_group() {
    let mut role = Role::new(ProjectId::new(), "editor", "Editor");
    assert!(role.group.is_none());
    role.group = Some("Content".into());
    assert_eq!(role.group.as_deref(), Some("Content"));
}

// ── Temporary role assignment tests ──────────────────────────

#[test]
fn test_role_assignment_with_expiry() {
    let expiry = Utc::now() + Duration::hours(48);
    let assignment = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(ProfileId::generate()),
        RoleId::new(),
    )
    .with_expiry(expiry);

    assert_eq!(assignment.expires_at, Some(expiry));
    assert!(!assignment.is_expired());
}

#[test]
fn test_hours_until_expiry_future() {
    let assignment = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(ProfileId::generate()),
        RoleId::new(),
    )
    .with_expiry(Utc::now() + Duration::hours(48));

    let hours = assignment.hours_until_expiry().unwrap();
    assert!((47..=48).contains(&hours));
}

#[test]
fn test_hours_until_expiry_past() {
    let assignment = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(ProfileId::generate()),
        RoleId::new(),
    )
    .with_expiry(Utc::now() - Duration::hours(1));

    assert!(assignment.hours_until_expiry().is_none());
}

#[test]
fn test_hours_until_expiry_no_expiry() {
    let assignment = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(ProfileId::generate()),
        RoleId::new(),
    );

    assert!(assignment.hours_until_expiry().is_none());
}

#[test]
fn test_role_expiry_alert_hours_ordered() {
    // Alert thresholds must be in descending order (72, 24, 1)
    let thresholds = ROLE_EXPIRY_ALERT_HOURS;
    assert_eq!(thresholds.len(), 3);
    assert!(thresholds[0] > thresholds[1]);
    assert!(thresholds[1] > thresholds[2]);
}

// ── Governance events ──────────────────────────────────────────

fn temporary(principal: RoleAssignmentPrincipal) -> RoleAssignment {
    RoleAssignment::new(principal, RoleId::new()).with_expiry(Utc::now() - Duration::seconds(1))
}

/// The expired event names the assignment, its principal, role and expiry,
/// and is announced once: its id follows from the assignment.
#[test]
fn test_role_expired_event_once_per_assignment() {
    let pid = ProfileId::generate();
    let assignment = temporary(RoleAssignmentPrincipal::Profile(pid));

    let event = assignment.expired_event();
    assert_eq!(event.event_type, event_types::GOVERNANCE_ROLE_EXPIRED);
    assert_eq!(event.data["assignment_id"], assignment.id.0.to_string());
    assert_eq!(event.data["role_id"], assignment.role_id.0.to_string());
    assert_eq!(event.data["principal"]["Profile"], pid.to_string());
    assert!(event.data["expired_at"].is_string());
    assert_eq!(event.id, assignment.expired_event().id);
    let other = temporary(RoleAssignmentPrincipal::Profile(pid));
    assert_ne!(event.id, other.expired_event().id);
}

/// Each expiry warning threshold is announced once per assignment, however
/// often the scan sees it; a different threshold is a different warning.
#[test]
fn test_role_expiring_event_once_per_threshold() {
    let assignment = temporary(RoleAssignmentPrincipal::Group(GroupId::new()));

    let first = assignment.expiring_event(24, 20);
    assert_eq!(first.event_type, event_types::GOVERNANCE_ROLE_EXPIRING);
    assert_eq!(first.data["threshold"], 24);
    assert_eq!(first.data["hours_left"], 20);
    assert_eq!(first.id, assignment.expiring_event(24, 19).id);
    assert_ne!(first.id, assignment.expiring_event(1, 0).id);
    assert_ne!(first.id, assignment.expired_event().id);
}
