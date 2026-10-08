// SPDX-License-Identifier: AGPL-3.0-only
//! Roles: a create never replaces one and never duplicates a key or a name in
//! its project; an update applies only over the role it read and never
//! brings back a deleted role. A role assignment, once stored, is never
//! replaced.

use sid_core::Error;
use sid_core::models::{ProjectId, Role, RoleAssignment, RoleAssignmentPrincipal};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

/// A stored role of the system project, as read back from the store.
async fn stored_role(backend: &dyn StorageBackend) -> Role {
    backend.ensure_system_project(test_audit()).await.unwrap();
    let tag = Uuid::now_v7().simple().to_string();
    let mut role = Role::new(
        ProjectId::system(),
        format!("key-{tag}"),
        format!("name-{tag}"),
    );
    role.permissions = vec!["documents:read".into()];
    backend.create_role(&role, test_audit()).await.unwrap();
    backend.get_role(role.id).await.unwrap().unwrap()
}

/// `role` and its permissions, as a fence checks them.
fn content(role: &Role) -> (sid_core::models::RoleId, std::collections::BTreeSet<String>) {
    (role.id, role.permissions.iter().cloned().collect())
}

/// A create never replaces a role, and a project holds one role per key and
/// per name: roles are identified by their key in tokens and policies.
pub async fn test_create_role_never_replaces(backend: &dyn StorageBackend) {
    let role = stored_role(backend).await;

    let mut same_id = role.clone();
    same_id.permissions = vec!["*".into()];
    let err = backend
        .create_role(&same_id, test_audit())
        .await
        .expect_err("a create over an existing role");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let same_key = Role::new(role.project_id, role.key.clone(), "another display name");
    let err = backend
        .create_role(&same_key, test_audit())
        .await
        .expect_err("a second role with the same key");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let same_name = Role::new(
        role.project_id,
        format!("{}-other", role.key),
        role.name.clone(),
    );
    let err = backend
        .create_role(&same_name, test_audit())
        .await
        .expect_err("a second role with the same name");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let stored = backend.get_role(role.id).await.unwrap().unwrap();
    assert_eq!(stored.permissions, vec!["documents:read".to_string()]);
}

/// Of two updates from one read one applies, whether they race or follow each
/// other within the same instant; the key never changes; an update of a
/// deleted role applies nothing, and the deleted role stays deleted.
pub async fn test_update_role_is_compare_and_swap(backend: &dyn StorageBackend) {
    let role = stored_role(backend).await;
    let with = |from: &Role, perm: &str| {
        let mut r = from.clone();
        r.permissions = vec![perm.to_string()];
        r.key = format!("{}-renamed", from.key);
        r.updated_at = from.updated_at;
        r
    };

    let (a, b) = (with(&role, "a:write"), with(&role, "b:write"));
    let (ra, rb) = tokio::join!(
        backend.update_role(&a, test_audit()),
        backend.update_role(&b, test_audit()),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert!(ra ^ rb, "exactly one update must apply: {ra} {rb}");
    let stored = backend.get_role(role.id).await.unwrap().unwrap();
    let winner = if ra { &a } else { &b };
    assert_eq!(stored.permissions, winner.permissions);
    assert_eq!(stored.key, role.key, "an update changed the key");
    assert_eq!(stored.revision, role.revision + 1);

    // Same stored time, one after the other: the second read is stale.
    let first = with(&stored, "c:write");
    let second = with(&stored, "d:write");
    assert!(backend.update_role(&first, test_audit()).await.unwrap());
    assert!(!backend.update_role(&second, test_audit()).await.unwrap());
    let stored = backend.get_role(role.id).await.unwrap().unwrap();
    assert_eq!(stored.permissions, first.permissions);

    backend.delete_role(role.id, test_audit()).await.unwrap();
    assert!(
        !backend
            .update_role(&with(&stored, "e:write"), test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend.get_role(role.id).await.unwrap().is_none(),
        "a deleted role was recreated"
    );
}

/// An independent OAuth client holds a role on one protected resource: the
/// assignment is read back with its principal and scope, never under another
/// client, is refused for a client that does not exist, and goes with its
/// client.
pub async fn test_oauth_client_role_assignment(backend: &dyn StorageBackend) {
    let role = stored_role(backend).await;
    let client = super::create_test_oauth2_client(&format!("pdp-{}", Uuid::now_v7().simple()));
    super::application::store_client(backend, &client, test_audit())
        .await
        .unwrap();
    let resource = super::application::grant_resource(backend).await;
    let assignment = RoleAssignment::new(
        RoleAssignmentPrincipal::OAuthClient(client.client_id.clone()),
        role.id,
    )
    .on_resource(resource);
    backend
        .create_role_assignment(&assignment, test_audit())
        .await
        .unwrap();

    let stored = backend
        .list_role_assignments_for_oauth_client(&client.client_id)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, assignment.id);
    assert_eq!(stored[0].principal, assignment.principal);
    assert_eq!(stored[0].resource_scope(), Some(resource));
    assert!(
        backend
            .list_role_assignments_for_oauth_client("another-client")
            .await
            .unwrap()
            .is_empty()
    );

    let ghost = RoleAssignment::new(
        RoleAssignmentPrincipal::OAuthClient("no-such-client".into()),
        role.id,
    );
    assert!(
        backend
            .create_role_assignment(&ghost, test_audit())
            .await
            .is_err()
    );

    backend
        .delete_oauth2_client(&client.client_id, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .list_role_assignments_for_oauth_client(&client.client_id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A provisioning connector holds a role on one protected resource: the
/// assignment is read back with its principal and scope, never under another
/// connector, and is refused for a connector that does not exist.
pub async fn test_connector_role_assignment(backend: &dyn StorageBackend) {
    use sid_core::models::{OrgId, ProvisioningConnector, ProvisioningDirection};

    let role = stored_role(backend).await;
    let connector =
        ProvisioningConnector::new(OrgId::generate(), ProvisioningDirection::Inbound, "HR");
    backend
        .create_provisioning_connector(&connector, test_audit())
        .await
        .unwrap();
    let resource = super::application::grant_resource(backend).await;
    let assignment = RoleAssignment::new(
        RoleAssignmentPrincipal::ProvisioningConnector(connector.id),
        role.id,
    )
    .on_resource(resource);
    backend
        .create_role_assignment(&assignment, test_audit())
        .await
        .unwrap();

    let stored = backend
        .list_role_assignments_for_provisioning_connector(connector.id)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, assignment.id);
    assert_eq!(stored[0].principal, assignment.principal);
    assert_eq!(stored[0].resource_scope(), Some(resource));
    let other = sid_core::models::ProvisioningConnectorId::generate();
    assert!(
        backend
            .list_role_assignments_for_provisioning_connector(other)
            .await
            .unwrap()
            .is_empty()
    );

    let ghost = RoleAssignment::new(
        RoleAssignmentPrincipal::ProvisioningConnector(other),
        role.id,
    );
    assert!(
        backend
            .create_role_assignment(&ghost, test_audit())
            .await
            .is_err(),
        "an assignment to a connector that does not exist was stored"
    );
}

/// A project of its own, so its listings hold only this scenario's records.
async fn own_project(backend: &dyn StorageBackend) -> ProjectId {
    let project =
        sid_core::models::Project::new(format!("roles-{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&project, test_audit())
        .await
        .unwrap();
    project.id
}

/// Roles list per project and resolve by name within their project only.
pub async fn test_roles_by_project_and_name(backend: &dyn StorageBackend) {
    let project = own_project(backend).await;
    let other = own_project(backend).await;
    let viewer = Role::new(project, "viewer", "Viewer");
    let editor = Role::new(project, "editor", "Editor");
    let foreign = Role::new(other, "viewer", "Viewer");
    for role in [&viewer, &editor, &foreign] {
        backend.create_role(role, test_audit()).await.unwrap();
    }

    let mut listed: Vec<_> = backend
        .list_roles(project)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    listed.sort_by_key(|id| id.0);
    let mut expected = vec![viewer.id, editor.id];
    expected.sort_by_key(|id| id.0);
    assert_eq!(listed, expected);

    let found = backend
        .get_role_by_name(project, "Viewer")
        .await
        .unwrap()
        .expect("the role by its name");
    assert_eq!(found.id, viewer.id, "the name resolved in another project");
    assert!(
        backend
            .get_role_by_name(project, "Nobody")
            .await
            .unwrap()
            .is_none()
    );
}

/// Assignments list by their principal (group, machine user) and by their
/// role, and end one by one: deleting one leaves the others of the same role.
pub async fn test_role_assignments_by_principal(backend: &dyn StorageBackend) {
    use sid_core::models::Group;

    let role = stored_role(backend).await;
    let other_role = stored_role(backend).await;
    let group = Group::new(role.project_id, format!("team-{}", Uuid::now_v7().simple()));
    backend.create_group(&group, test_audit()).await.unwrap();
    let mu = super::machine::stored_machine_user(backend).await;

    let to_group = RoleAssignment::new(RoleAssignmentPrincipal::Group(group.id), role.id);
    let to_machine = RoleAssignment::new(RoleAssignmentPrincipal::MachineUser(mu.id), role.id);
    let other = RoleAssignment::new(RoleAssignmentPrincipal::Group(group.id), other_role.id);
    for a in [&to_group, &to_machine, &other] {
        backend
            .create_role_assignment(a, test_audit())
            .await
            .unwrap();
    }

    let assignments_of = |role_id| async move {
        let mut ids: Vec<_> = backend
            .list_role_assignments_for_role(role_id)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect();
        ids.sort_by_key(|id| id.0);
        ids
    };
    let mut of_role = vec![to_group.id, to_machine.id];
    of_role.sort_by_key(|id| id.0);
    assert_eq!(assignments_of(role.id).await, of_role);
    assert_eq!(assignments_of(other_role.id).await, vec![other.id]);

    let mut of_group: Vec<_> = backend
        .list_role_assignments_for_group(group.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.role_id == role.id)
        .collect();
    assert_eq!(of_group.len(), 1);
    let of_group = of_group.remove(0);
    assert_eq!(of_group.id, to_group.id);
    assert_eq!(of_group.principal, to_group.principal);
    let of_machine = backend
        .list_role_assignments_for_machine_user(mu.id)
        .await
        .unwrap();
    assert_eq!(of_machine.len(), 1);
    assert_eq!(of_machine[0].id, to_machine.id);

    backend
        .delete_role_assignment(to_group.id, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .list_role_assignments_for_group(group.id)
            .await
            .unwrap()
            .iter()
            .all(|a| a.id != to_group.id)
    );
    assert_eq!(assignments_of(role.id).await, vec![to_machine.id]);
    assert_eq!(
        backend
            .list_role_assignments_for_machine_user(mu.id)
            .await
            .unwrap()
            .len(),
        1,
        "deleting one assignment ended another"
    );
}

/// The expiry scan returns assignments already expired or expiring within
/// the window, never one expiring later or one without an expiry.
pub async fn test_expiring_role_assignments(backend: &dyn StorageBackend) {
    use chrono::{Duration, Utc};

    let role = stored_role(backend).await;
    let profile = super::create_test_profile("expiring");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let principal = RoleAssignmentPrincipal::Profile(profile.id);
    let expired = RoleAssignment::new(principal.clone(), role.id)
        .with_expiry(Utc::now() - Duration::hours(1));
    let soon = RoleAssignment::new(principal.clone(), role.id)
        .with_expiry(Utc::now() + Duration::hours(2));
    let later = RoleAssignment::new(principal.clone(), role.id)
        .with_expiry(Utc::now() + Duration::hours(48));
    let permanent = RoleAssignment::new(principal, role.id);
    for a in [&expired, &soon, &later, &permanent] {
        backend
            .create_role_assignment(a, test_audit())
            .await
            .unwrap();
    }

    let found: Vec<_> = backend
        .list_expiring_role_assignments(24)
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.id)
        .collect();
    // A concurrent expiry cleanup of another scenario may already have
    // removed the expired assignment; then it no longer exists at all.
    let still_stored = backend
        .list_role_assignments_for_profile(profile.id)
        .await
        .unwrap()
        .iter()
        .any(|a| a.id == expired.id);
    assert!(
        found.contains(&expired.id) || !still_stored,
        "an expired assignment is missing"
    );
    assert!(
        found.contains(&soon.id),
        "an assignment expiring in the window is missing"
    );
    assert!(
        !found.contains(&later.id),
        "an assignment expiring later was listed"
    );
    assert!(
        !found.contains(&permanent.id),
        "an assignment without expiry was listed"
    );
}

/// Cedar policies list per project only.
pub async fn test_cedar_policies_by_project(backend: &dyn StorageBackend) {
    use sid_core::models::{CedarPolicy, PolicyEffect};

    let project = own_project(backend).await;
    let other = own_project(backend).await;
    let text = "permit(principal, action, resource);";
    let a = CedarPolicy::new(project, "a", text, PolicyEffect::Permit);
    let b = CedarPolicy::new(project, "b", text, PolicyEffect::Forbid);
    let foreign = CedarPolicy::new(other, "a", text, PolicyEffect::Permit);
    for p in [&a, &b, &foreign] {
        backend.create_cedar_policy(p, test_audit()).await.unwrap();
    }

    let listed = backend.list_cedar_policies(project).await.unwrap();
    let mut ids: Vec<_> = listed.iter().map(|p| p.id).collect();
    ids.sort_by_key(|id| id.0);
    let mut expected = vec![a.id, b.id];
    expected.sort_by_key(|id| id.0);
    assert_eq!(ids, expected);
    let forbid = listed.iter().find(|p| p.id == b.id).unwrap();
    assert_eq!(forbid.effect, PolicyEffect::Forbid);
}

/// A stored profile, for assignments.
async fn assignee(backend: &dyn StorageBackend) -> sid_core::models::ProfileId {
    let profile = super::create_test_profile(&format!("admin_{}", Uuid::now_v7().simple()));
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    profile.id
}

/// An administrative assignment keeps its whole envelope and provenance
/// (D050 B); a redelegated one ends with the assignment it depends on,
/// while an assignment that only names its authorizing basis outlives it;
/// a group an envelope restricts recipients to cannot be deleted from under
/// it, which would silently widen the envelope.
pub async fn test_administrative_assignment(backend: &dyn StorageBackend) {
    use sid_core::models::{
        AdminEnvelope, AdminOperation, AssignmentProvenance, Group, RecipientKind,
    };
    let working = stored_role(backend).await;
    let administrator = stored_role(backend).await;
    let group = Group::new(
        ProjectId::system(),
        format!("g-{}", Uuid::now_v7().simple()),
    );
    backend.create_group(&group, test_audit()).await.unwrap();
    let envelope = AdminEnvelope {
        operations: [AdminOperation::Assign, AdminOperation::Redelegate].into(),
        roles: [working.id].into(),
        permission_ceiling: ["documents:read".to_string()].into(),
        recipient_kinds: [RecipientKind::Profile, RecipientKind::Group].into(),
        recipient_group: Some(group.id),
        max_validity_secs: 86_400,
    };
    let root_holder = assignee(backend).await;
    let root = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(root_holder),
        administrator.id,
    )
    .administering(envelope.clone())
    .granted(AssignmentProvenance {
        granted_by: format!("user:{}", Uuid::now_v7()),
        basis: None,
        depends_on: None,
        ceiling: None,
    })
    .with_expiry(chrono::Utc::now() + chrono::Duration::hours(1));
    backend
        .create_role_assignment(&root, test_audit())
        .await
        .unwrap();

    let stored = backend
        .list_role_assignments_for_profile(root_holder)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].admin.as_ref(), Some(&envelope));
    assert_eq!(stored[0].provenance, root.provenance);
    assert_eq!(stored[0].revision, 0);
    let by_id = backend.get_role_assignment(root.id).await.unwrap().unwrap();
    assert_eq!(by_id.admin.as_ref(), Some(&envelope));
    assert_eq!(by_id.provenance, root.provenance);
    assert!(
        backend
            .get_role_assignment(sid_core::models::RoleAssignmentId::new())
            .await
            .unwrap()
            .is_none()
    );

    // Redelegated: narrower, and dependent on the root.
    let mut narrower = envelope.clone();
    narrower.operations = [AdminOperation::Assign].into();
    let delegate_holder = assignee(backend).await;
    let delegated = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(delegate_holder),
        administrator.id,
    )
    .administering(narrower.clone())
    .granted(AssignmentProvenance {
        granted_by: format!("user:{root_holder}"),
        basis: Some(root.id),
        depends_on: Some(root.id),
        ceiling: None,
    });
    backend
        .create_role_assignment(&delegated, test_audit())
        .await
        .unwrap();
    // Ordinary: authorized by the root, but not dependent on it, keeping
    // the ceiling it was approved under.
    let worker = assignee(backend).await;
    let ordinary = RoleAssignment::new(RoleAssignmentPrincipal::Profile(worker), working.id)
        .granted(AssignmentProvenance {
            granted_by: format!("user:{root_holder}"),
            basis: Some(root.id),
            depends_on: None,
            ceiling: Some(envelope.permission_ceiling.clone()),
        });
    backend
        .create_role_assignment(&ordinary, test_audit())
        .await
        .unwrap();
    let read = backend
        .list_role_assignments_for_profile(delegate_holder)
        .await
        .unwrap();
    assert_eq!(read[0].admin.as_ref(), Some(&narrower));
    assert_eq!(read[0].provenance, delegated.provenance);

    let err = backend
        .delete_group(group.id, test_audit())
        .await
        .expect_err("a group an envelope restricts recipients to");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    backend
        .delete_role_assignment(root.id, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .list_role_assignments_for_profile(delegate_holder)
            .await
            .unwrap()
            .is_empty(),
        "a redelegated assignment ends with its source"
    );
    let kept = backend
        .list_role_assignments_for_profile(worker)
        .await
        .unwrap();
    assert_eq!(
        kept.len(),
        1,
        "an ordinary assignment outlives its grantor's basis"
    );
    assert_eq!(kept[0].provenance, ordinary.provenance);
    assert!(kept[0].admin.is_none());
}

/// An administered assignment commits only while what it was checked
/// against still holds: its basis unexpired at the checked revision, the
/// role's content at the checked revision and the recipient's group
/// membership. A broken fence writes nothing (`Fenced`); a fenced delete
/// behaves the same.
pub async fn test_fenced_assignment(backend: &dyn StorageBackend) {
    use sid_core::models::{
        AdminEnvelope, AdminOperation, AssignmentFence, AssignmentProvenance, Group, GroupMember,
        RecipientKind,
    };
    let working = stored_role(backend).await;
    let administrator = stored_role(backend).await;
    let holder = assignee(backend).await;
    let group = Group::new(
        ProjectId::system(),
        format!("g-{}", Uuid::now_v7().simple()),
    );
    backend.create_group(&group, test_audit()).await.unwrap();
    let worker = assignee(backend).await;
    backend
        .add_to_group(&GroupMember::new(group.id, worker), test_audit())
        .await
        .unwrap();
    let basis = RoleAssignment::new(RoleAssignmentPrincipal::Profile(holder), administrator.id)
        .administering(AdminEnvelope {
            operations: [AdminOperation::Assign, AdminOperation::Revoke].into(),
            roles: [working.id].into(),
            permission_ceiling: ["documents:read".to_string()].into(),
            recipient_kinds: [RecipientKind::Profile].into(),
            recipient_group: Some(group.id),
            max_validity_secs: 86_400,
        });
    backend
        .create_role_assignment(&basis, test_audit())
        .await
        .unwrap();
    let fence = AssignmentFence {
        basis: Some((basis.id, 0)),
        role: content(&working),
        recipient_membership: Some((group.id, worker)),
        grantor_outside: None,
    };
    let proposed = || {
        RoleAssignment::new(RoleAssignmentPrincipal::Profile(worker), working.id)
            .granted(AssignmentProvenance {
                granted_by: format!("user:{holder}"),
                basis: Some(basis.id),
                depends_on: None,
                ceiling: Some(["documents:read".to_string()].into()),
            })
            .with_expiry(chrono::Utc::now() + chrono::Duration::hours(1))
    };
    let fenced = |err: Error| assert!(matches!(err, Error::Fenced(_)), "{err:?}");
    async fn held(backend: &dyn StorageBackend, worker: sid_core::models::ProfileId) -> usize {
        backend
            .list_role_assignments_for_profile(worker)
            .await
            .unwrap()
            .len()
    }

    // A stale basis revision, other role permissions than stored.
    for stale in [
        AssignmentFence {
            basis: Some((basis.id, 1)),
            ..fence.clone()
        },
        AssignmentFence {
            role: (working.id, ["documents:write".to_string()].into()),
            ..fence.clone()
        },
    ] {
        fenced(
            backend
                .create_role_assignment_fenced(&proposed(), &stale, test_audit())
                .await
                .unwrap_err(),
        );
    }
    assert_eq!(held(backend, worker).await, 0, "nothing written");

    // Fresh: committed, and deletable under the same fence.
    let granted = proposed();
    backend
        .create_role_assignment_fenced(&granted, &fence, test_audit())
        .await
        .unwrap();
    assert_eq!(held(backend, worker).await, 1);
    assert!(
        backend
            .delete_role_assignment_fenced(granted.id, &fence, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .delete_role_assignment_fenced(granted.id, &fence, test_audit())
            .await
            .unwrap(),
        "already gone"
    );

    // The role's description changed after the check: its permissions did
    // not, so the check still holds.
    let mut described = working.clone();
    described.description = Some("documents".into());
    assert!(backend.update_role(&described, test_audit()).await.unwrap());
    let kept = proposed();
    backend
        .create_role_assignment_fenced(&kept, &fence, test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .delete_role_assignment_fenced(kept.id, &fence, test_audit())
            .await
            .unwrap()
    );

    // The role's permissions changed after the check.
    let mut edited = backend.get_role(working.id).await.unwrap().unwrap();
    edited.permissions.push("documents:write".into());
    assert!(backend.update_role(&edited, test_audit()).await.unwrap());
    fenced(
        backend
            .create_role_assignment_fenced(&proposed(), &fence, test_audit())
            .await
            .unwrap_err(),
    );
    let fresh_role = backend.get_role(working.id).await.unwrap().unwrap();
    let fence = AssignmentFence {
        role: content(&fresh_role),
        ..fence
    };

    // The recipient left the group after the check.
    backend
        .remove_from_group(group.id, worker, test_audit())
        .await
        .unwrap();
    fenced(
        backend
            .create_role_assignment_fenced(&proposed(), &fence, test_audit())
            .await
            .unwrap_err(),
    );

    // The basis was revoked after the check.
    backend
        .add_to_group(&GroupMember::new(group.id, worker), test_audit())
        .await
        .unwrap();
    backend
        .delete_role_assignment(basis.id, test_audit())
        .await
        .unwrap();
    fenced(
        backend
            .create_role_assignment_fenced(&proposed(), &fence, test_audit())
            .await
            .unwrap_err(),
    );
    assert_eq!(held(backend, worker).await, 0, "nothing written");
}

/// A Profile that granted a group a role under an administrative assignment
/// never joins that group, by any writer (`PolicyViolation`, nothing written);
/// and a grant to a group the grantor joined after the check is `Fenced`.
pub async fn test_grantor_never_joins_its_group(backend: &dyn StorageBackend) {
    use sid_core::models::{
        AdminEnvelope, AdminOperation, AssignmentFence, AssignmentProvenance, DirectoryGroupWrite,
        DirectoryWriteMode, Group, GroupMember, RecipientKind,
    };
    let working = stored_role(backend).await;
    let administrator = stored_role(backend).await;
    let grantor = assignee(backend).await;
    let basis = RoleAssignment::new(RoleAssignmentPrincipal::Profile(grantor), administrator.id)
        .administering(AdminEnvelope {
            operations: [AdminOperation::Assign].into(),
            roles: [working.id].into(),
            permission_ceiling: ["documents:read".to_string()].into(),
            recipient_kinds: [RecipientKind::Group].into(),
            recipient_group: None,
            max_validity_secs: 86_400,
        });
    backend
        .create_role_assignment(&basis, test_audit())
        .await
        .unwrap();
    let new_group = || {
        Group::new(
            ProjectId::system(),
            format!("g-{}", Uuid::now_v7().simple()),
        )
    };
    let to_group = |group: &Group| {
        RoleAssignment::new(RoleAssignmentPrincipal::Group(group.id), working.id)
            .granted(AssignmentProvenance {
                granted_by: format!("user:{grantor}"),
                basis: Some(basis.id),
                depends_on: None,
                ceiling: Some(["documents:read".to_string()].into()),
            })
            .with_expiry(chrono::Utc::now() + chrono::Duration::hours(1))
    };
    let fence = |group: &Group| AssignmentFence {
        basis: Some((basis.id, 0)),
        role: content(&working),
        recipient_membership: None,
        grantor_outside: Some((group.id, grantor)),
    };
    let refused = |err: Error| assert!(matches!(err, Error::PolicyViolation(_)), "{err:?}");

    let granted = new_group();
    backend.create_group(&granted, test_audit()).await.unwrap();
    backend
        .create_role_assignment_fenced(&to_group(&granted), &fence(&granted), test_audit())
        .await
        .unwrap();
    refused(
        backend
            .add_to_group(&GroupMember::new(granted.id, grantor), test_audit())
            .await
            .unwrap_err(),
    );
    let mut write = DirectoryGroupWrite::new(DirectoryWriteMode::Update, granted.clone());
    write
        .add_members
        .push(GroupMember::new(granted.id, grantor));
    refused(
        backend
            .write_directory_group(&write, test_audit())
            .await
            .unwrap_err(),
    );
    assert!(
        backend
            .list_group_members(granted.id)
            .await
            .unwrap()
            .is_empty(),
        "nothing written"
    );
    // Anyone else joins.
    let colleague = assignee(backend).await;
    backend
        .add_to_group(&GroupMember::new(granted.id, colleague), test_audit())
        .await
        .unwrap();

    // The grantor joined another group after the check: its grant is fenced.
    let joined = new_group();
    backend.create_group(&joined, test_audit()).await.unwrap();
    backend
        .add_to_group(&GroupMember::new(joined.id, grantor), test_audit())
        .await
        .unwrap();
    let err = backend
        .create_role_assignment_fenced(&to_group(&joined), &fence(&joined), test_audit())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Fenced(_)), "{err:?}");
    assert!(
        backend
            .list_role_assignments_for_group(joined.id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A fenced role edit commits only while what it was checked against still
/// holds: the editor's authority unexpired at its revision and, for an edit
/// adding permissions, no assignment under an approved ceiling beyond the
/// checked ones. A broken fence writes nothing; a stale role is `false`.
pub async fn test_fenced_role_edit(backend: &dyn StorageBackend) {
    use sid_core::models::{
        AdminEnvelope, AdminOperation, AssignmentProvenance, RecipientKind, RoleEditFence,
    };
    let working = stored_role(backend).await;
    let administrator = stored_role(backend).await;
    let editor = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(assignee(backend).await),
        administrator.id,
    )
    .administering(AdminEnvelope {
        operations: [AdminOperation::EditRole].into(),
        roles: [working.id].into(),
        permission_ceiling: ["documents:read".to_string()].into(),
        recipient_kinds: [RecipientKind::Profile].into(),
        recipient_group: None,
        max_validity_secs: 86_400,
    });
    backend
        .create_role_assignment(&editor, test_audit())
        .await
        .unwrap();
    let approved = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(assignee(backend).await),
        working.id,
    )
    .granted(AssignmentProvenance {
        granted_by: "user:holder".into(),
        basis: Some(editor.id),
        depends_on: None,
        ceiling: Some(["documents:read".to_string(), "documents:write".to_string()].into()),
    });
    backend
        .create_role_assignment(&approved, test_audit())
        .await
        .unwrap();
    let fenced = |err: Error| assert!(matches!(err, Error::Fenced(_)), "{err:?}");
    let mut widened = working.clone();
    widened.permissions.push("documents:write".into());
    async fn revision_of(backend: &dyn StorageBackend, role: sid_core::models::RoleId) -> u64 {
        backend.get_role(role).await.unwrap().unwrap().revision
    }

    // The approved assignment was not among the checked ones.
    fenced(
        backend
            .update_role_fenced(
                &widened,
                &RoleEditFence {
                    authority: None,
                    bounded: Some(Default::default()),
                },
                test_audit(),
            )
            .await
            .unwrap_err(),
    );
    assert_eq!(revision_of(backend, working.id).await, working.revision);
    // The editor's authority moved since the check.
    fenced(
        backend
            .update_role_fenced(
                &widened,
                &RoleEditFence {
                    authority: Some((editor.id, 1)),
                    bounded: None,
                },
                test_audit(),
            )
            .await
            .unwrap_err(),
    );
    assert_eq!(revision_of(backend, working.id).await, working.revision);

    let fence = RoleEditFence {
        authority: Some((editor.id, 0)),
        bounded: Some([approved.id].into()),
    };
    assert!(
        backend
            .update_role_fenced(&widened, &fence, test_audit())
            .await
            .unwrap()
    );
    let stored = backend.get_role(working.id).await.unwrap().unwrap();
    assert_eq!(stored.revision, working.revision + 1);
    assert!(stored.has_permission("documents:write"));
    assert!(
        !backend
            .update_role_fenced(&widened, &fence, test_audit())
            .await
            .unwrap(),
        "a role read before the edit is stale"
    );
}

/// A second write of an assignment id is refused and leaves the stored
/// assignment as it was: re-sending one cannot lift or move its expiry.
pub async fn test_create_role_assignment_never_replaces(backend: &dyn StorageBackend) {
    let role = stored_role(backend).await;
    let profile = super::create_test_profile(&format!("assignee_{}", Uuid::now_v7().simple()));
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
    let assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(profile.id), role.id)
        .with_expiry(expiry);
    backend
        .create_role_assignment(&assignment, test_audit())
        .await
        .unwrap();

    let mut replay = assignment.clone();
    replay.expires_at = None;
    replay.scope = Some("everything".into());
    let err = backend
        .create_role_assignment(&replay, test_audit())
        .await
        .expect_err("a create over an existing assignment");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let stored = backend
        .list_role_assignments_for_profile(profile.id)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].scope, None);
    assert_eq!(
        stored[0].expires_at.map(|t| t.timestamp_millis()),
        Some(expiry.timestamp_millis())
    );
}
