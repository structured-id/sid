// SPDX-License-Identifier: AGPL-3.0-only
//! Groups: a create never replaces a group or duplicates a name in its
//! project; a description change touches only the description and never
//! brings back a deleted group.

use sid_core::Error;
use sid_core::models::{Group, ProjectId};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

async fn stored_group(backend: &dyn StorageBackend) -> Group {
    backend.ensure_system_project(test_audit()).await.unwrap();
    let mut group = Group::new(
        ProjectId::system(),
        format!("group-{}", Uuid::now_v7().simple()),
    );
    group.description = Some("first".into());
    backend.create_group(&group, test_audit()).await.unwrap();
    group
}

/// A create over an existing id or a second group with the same name in the
/// project is refused and changes nothing.
pub async fn test_create_group_never_replaces(backend: &dyn StorageBackend) {
    let group = stored_group(backend).await;

    let mut same_id = group.clone();
    same_id.name = format!("{}-renamed", group.name);
    same_id.description = Some("replaced".into());
    let err = backend
        .create_group(&same_id, test_audit())
        .await
        .expect_err("a create over an existing group");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let same_name = Group::new(group.project_id, group.name.clone());
    let err = backend
        .create_group(&same_name, test_audit())
        .await
        .expect_err("a second group with the same name");
    assert!(matches!(err, Error::Conflict(_)), "{err:?}");

    let stored = backend.get_group(group.id).await.unwrap().unwrap();
    assert_eq!(stored.name, group.name);
    assert_eq!(stored.description.as_deref(), Some("first"));
}

/// A group of its own project, so the project's listings hold only this
/// scenario's groups.
async fn group_in_own_project(backend: &dyn StorageBackend, name: &str) -> Group {
    let project =
        sid_core::models::Project::new(format!("groups-{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&project, test_audit())
        .await
        .unwrap();
    let group = Group::new(project.id, name);
    backend.create_group(&group, test_audit()).await.unwrap();
    group
}

/// Groups list per project; membership is listed from both sides and ends
/// on removal, leaving the other memberships of the profile and the group.
pub async fn test_group_membership_roundtrip(backend: &dyn StorageBackend) {
    use sid_core::models::GroupMember;

    let admins = group_in_own_project(backend, "admins").await;
    let staff = Group::new(admins.project_id, "staff");
    backend.create_group(&staff, test_audit()).await.unwrap();
    let elsewhere = group_in_own_project(backend, "admins").await;

    let listed: Vec<_> = backend
        .list_groups(admins.project_id)
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    assert_eq!(listed.len(), 2, "{listed:?}");
    assert!(listed.contains(&admins.id) && listed.contains(&staff.id));

    let alice = super::create_test_profile("member_a");
    let bob = super::create_test_profile("member_b");
    for p in [&alice, &bob] {
        backend.create_profile(p, test_audit()).await.unwrap();
    }
    for (group, profile) in [
        (&admins, &alice),
        (&staff, &alice),
        (&admins, &bob),
        (&elsewhere, &bob),
    ] {
        backend
            .add_to_group(&GroupMember::new(group.id, profile.id), test_audit())
            .await
            .unwrap();
    }

    let mut members: Vec<_> = backend
        .list_group_members(admins.id)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.profile_id)
        .collect();
    members.sort_by_key(|p| p.to_string());
    let mut expected = vec![alice.id, bob.id];
    expected.sort_by_key(|p| p.to_string());
    assert_eq!(members, expected);

    let mut of_alice: Vec<_> = backend
        .list_groups_for_profile(alice.id)
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    of_alice.sort_by_key(|g| g.0);
    let mut expected = vec![admins.id, staff.id];
    expected.sort_by_key(|g| g.0);
    assert_eq!(of_alice, expected);

    backend
        .remove_from_group(admins.id, alice.id, test_audit())
        .await
        .unwrap();
    let members: Vec<_> = backend
        .list_group_members(admins.id)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.profile_id)
        .collect();
    assert_eq!(members, vec![bob.id]);
    let of_alice: Vec<_> = backend
        .list_groups_for_profile(alice.id)
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    assert_eq!(of_alice, vec![staff.id], "only the removed membership ends");
}

/// Adding a profile that is already a member, sequentially or by two
/// writers at once, leaves one membership: a repeated add is idempotent or
/// refused, never a duplicate.
pub async fn test_add_to_group_never_duplicates(backend: &dyn StorageBackend) {
    use sid_core::models::GroupMember;

    let group = group_in_own_project(backend, "dup").await;
    let profile = super::create_test_profile("dup_member");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let member = GroupMember::new(group.id, profile.id);

    backend.add_to_group(&member, test_audit()).await.unwrap();
    let again = backend.add_to_group(&member, test_audit()).await;
    assert!(
        matches!(again, Ok(()) | Err(Error::Conflict(_))),
        "{again:?}"
    );
    let (a, b) = tokio::join!(
        backend.add_to_group(&member, test_audit()),
        backend.add_to_group(&member, test_audit()),
    );
    for r in [a, b] {
        assert!(matches!(r, Ok(()) | Err(Error::Conflict(_))), "{r:?}");
    }
    assert_eq!(backend.list_group_members(group.id).await.unwrap().len(), 1);
    assert_eq!(
        backend
            .list_groups_for_profile(profile.id)
            .await
            .unwrap()
            .len(),
        1
    );
}

/// A description change keeps the name, and after a deletion it applies
/// nothing and the group stays deleted.
pub async fn test_set_group_description_keeps_deleted_deleted(backend: &dyn StorageBackend) {
    let group = stored_group(backend).await;

    assert!(
        backend
            .set_group_description(group.id, Some("second"), test_audit())
            .await
            .unwrap()
    );
    let stored = backend.get_group(group.id).await.unwrap().unwrap();
    assert_eq!(stored.description.as_deref(), Some("second"));
    assert_eq!(stored.name, group.name);

    backend.delete_group(group.id, test_audit()).await.unwrap();
    assert!(
        !backend
            .set_group_description(group.id, Some("third"), test_audit())
            .await
            .unwrap()
    );
    assert!(
        backend.get_group(group.id).await.unwrap().is_none(),
        "a deleted group was recreated"
    );
}
