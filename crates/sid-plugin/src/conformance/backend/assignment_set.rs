// SPDX-License-Identifier: AGPL-3.0-only
//! Assignment sets: every stored or removed assignment of one holder in one
//! exact scope moves that set's revision, cascades included, and a
//! replacement commits only at the revision it was decided on, moving it
//! whatever it changes. Nothing is written on any refusal.

use sid_core::Error;
use sid_core::models::{
    AdminEnvelope, AdminOperation, AssignmentFence, AssignmentProvenance, AssignmentSet,
    AssignmentSetChange, AuthorityBasis, ProfileId, ProjectId, RecipientKind, Role, RoleAssignment,
    RoleAssignmentPrincipal,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, test_audit};

/// A stored role of the system project.
async fn stored_role(backend: &dyn StorageBackend) -> Role {
    backend.ensure_system_project(test_audit()).await.unwrap();
    let tag = Uuid::now_v7().simple().to_string();
    let mut role = Role::new(
        ProjectId::SYSTEM,
        format!("key-{tag}"),
        format!("name-{tag}"),
    );
    role.permissions = vec!["documents:read".into()];
    backend.create_role(&role, test_audit()).await.unwrap();
    backend.get_role(role.id).await.unwrap().unwrap()
}

async fn stored_profile(backend: &dyn StorageBackend) -> ProfileId {
    let profile = create_test_profile(&format!("set_{}", Uuid::now_v7().simple()));
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    profile.id
}

/// An administrator of `role` and the fence an assignment of it is granted
/// and revoked under.
struct Grantor {
    id: ProfileId,
    basis: RoleAssignment,
    fence: AssignmentFence,
}

async fn grantor(backend: &dyn StorageBackend, role: &Role) -> Grantor {
    let administrator = stored_role(backend).await;
    let id = stored_profile(backend).await;
    let basis = RoleAssignment::new(RoleAssignmentPrincipal::Profile(id), administrator.id)
        .administering(AdminEnvelope {
            operations: [AdminOperation::Assign, AdminOperation::Revoke].into(),
            roles: [role.id].into(),
            permission_ceiling: ["documents:read".to_string()].into(),
            recipient_kinds: [RecipientKind::Profile].into(),
            recipient_group: None,
            max_validity_secs: None,
        });
    backend
        .create_role_assignment(&basis, test_audit())
        .await
        .unwrap();
    let fence = AssignmentFence {
        basis: AuthorityBasis {
            assignment: basis.id,
            revision: 0,
            member: None,
        },
        role: (role.id, role.permissions.iter().cloned().collect()),
        recipient_membership: None,
        grantor_outside: None,
    };
    Grantor { id, basis, fence }
}

/// An assignment of `role` to `holder` in `scope`, granted by `grantor`.
fn granted(
    grantor: &Grantor,
    holder: ProfileId,
    role: &Role,
    scope: Option<&str>,
) -> RoleAssignment {
    let mut assignment = RoleAssignment::new(RoleAssignmentPrincipal::Profile(holder), role.id)
        .granted(AssignmentProvenance {
            granted_by: format!("user:{}", grantor.id),
            basis: Some(grantor.basis.id),
            depends_on: None,
            ceiling: Some(["documents:read".to_string()].into()),
        });
    assignment.scope = scope.map(str::to_owned);
    assignment
}

fn set_of(holder: ProfileId, scope: Option<&str>) -> AssignmentSet {
    AssignmentSet {
        principal: RoleAssignmentPrincipal::Profile(holder),
        scope: scope.map(str::to_owned),
    }
}

async fn revision(backend: &dyn StorageBackend, set: &AssignmentSet) -> u64 {
    backend.role_assignment_set(set).await.unwrap().0
}

/// A set never changed is at revision 0; each stored or removed assignment
/// of it moves its revision, an emptied set keeps a moved one, and another
/// scope of the same holder is a set of its own. A removal by cascade (the
/// role deleted, the assignment it depends on removed) and by expiry
/// cleanup moves it too.
pub async fn test_every_change_moves_the_set(backend: &dyn StorageBackend) {
    let role = stored_role(backend).await;
    let holder = stored_profile(backend).await;
    let unscoped = set_of(holder, None);
    let scoped = set_of(holder, Some("tenant-a"));
    assert_eq!(
        backend.role_assignment_set(&unscoped).await.unwrap(),
        (0, vec![])
    );

    let first = RoleAssignment::new(RoleAssignmentPrincipal::Profile(holder), role.id);
    backend
        .create_role_assignment(&first, test_audit())
        .await
        .unwrap();
    let (stored, held) = backend.role_assignment_set(&unscoped).await.unwrap();
    assert!(stored > 0, "a stored assignment moves its set");
    assert_eq!(
        held.iter().map(|a| a.id).collect::<Vec<_>>(),
        vec![first.id]
    );
    assert_eq!(
        revision(backend, &scoped).await,
        0,
        "another scope is untouched"
    );

    backend
        .delete_role_assignment(first.id, test_audit())
        .await
        .unwrap();
    let (emptied, held) = backend.role_assignment_set(&unscoped).await.unwrap();
    assert!(held.is_empty());
    assert!(emptied > stored, "an emptied set keeps a moved revision");

    // The role deleted: its assignments go, and their sets move.
    let doomed = stored_role(backend).await;
    let mut cascaded = RoleAssignment::new(RoleAssignmentPrincipal::Profile(holder), doomed.id);
    cascaded.scope = Some("tenant-a".into());
    backend
        .create_role_assignment(&cascaded, test_audit())
        .await
        .unwrap();
    let before = revision(backend, &scoped).await;
    backend.delete_role(doomed.id, test_audit()).await.unwrap();
    assert!(
        revision(backend, &scoped).await > before,
        "a cascade moves the set"
    );

    // A redelegated administrative assignment ends with its source, in
    // another holder's set.
    let source_holder = stored_profile(backend).await;
    let delegate = stored_profile(backend).await;
    let envelope = AdminEnvelope {
        operations: [AdminOperation::Assign].into(),
        roles: [role.id].into(),
        permission_ceiling: ["documents:read".to_string()].into(),
        recipient_kinds: [RecipientKind::Profile].into(),
        recipient_group: None,
        max_validity_secs: None,
    };
    let source = RoleAssignment::new(RoleAssignmentPrincipal::Profile(source_holder), role.id)
        .administering(envelope.clone());
    backend
        .create_role_assignment(&source, test_audit())
        .await
        .unwrap();
    let redelegated = RoleAssignment::new(RoleAssignmentPrincipal::Profile(delegate), role.id)
        .administering(envelope)
        .granted(AssignmentProvenance {
            granted_by: format!("user:{source_holder}"),
            basis: Some(source.id),
            depends_on: Some(source.id),
            ceiling: None,
        });
    backend
        .create_role_assignment(&redelegated, test_audit())
        .await
        .unwrap();
    let delegated = set_of(delegate, None);
    let before = revision(backend, &delegated).await;
    backend
        .delete_role_assignment(source.id, test_audit())
        .await
        .unwrap();
    let (after, held) = backend.role_assignment_set(&delegated).await.unwrap();
    assert!(held.is_empty(), "the dependent ended with its source");
    assert!(after > before, "a dependent's removal moves its set");

    // Expiry cleanup.
    let expiring = RoleAssignment::new(RoleAssignmentPrincipal::Profile(holder), role.id)
        .with_expiry(chrono::Utc::now() - chrono::Duration::seconds(1));
    backend
        .create_role_assignment(&expiring, test_audit())
        .await
        .unwrap();
    let before = revision(backend, &unscoped).await;
    backend
        .cleanup_expired_role_assignments(test_audit())
        .await
        .unwrap();
    assert!(
        revision(backend, &unscoped).await > before,
        "cleanup moves the set"
    );
}

/// A replacement commits only at the expected revision and moves it, an
/// empty one included; a stale one is `AssignmentSetChanged` with the
/// current revision and writes nothing. An assignment outside the set, or a
/// deletion naming another set's assignment, writes nothing.
pub async fn test_replacement_is_conditional(backend: &dyn StorageBackend) {
    let role = stored_role(backend).await;
    let grantor = grantor(backend, &role).await;
    let holder = stored_profile(backend).await;
    let set = set_of(holder, Some("tenant-a"));
    let first = granted(&grantor, holder, &role, Some("tenant-a"));
    let change =
        |expected, create: Vec<RoleAssignment>, delete: Vec<RoleAssignment>| AssignmentSetChange {
            set: set.clone(),
            expected_revision: expected,
            create: create
                .into_iter()
                .map(|a| (a, grantor.fence.clone()))
                .collect(),
            delete: delete
                .into_iter()
                .map(|a| (a.id, grantor.fence.clone()))
                .collect(),
            hold: vec![grantor.fence.clone()],
        };

    let r1 = backend
        .replace_role_assignments(&change(0, vec![first.clone()], vec![]), test_audit())
        .await
        .unwrap();
    assert_eq!(r1, 1, "a replacement moves the set to the next revision");
    let (read, held) = backend.role_assignment_set(&set).await.unwrap();
    assert_eq!(read, r1, "the answered revision is the stored one");
    assert_eq!(
        held.iter().map(|a| a.id).collect::<Vec<_>>(),
        vec![first.id]
    );

    // Decided against revision 0: the set moved on since.
    let second = granted(&grantor, holder, &role, Some("tenant-a"));
    match backend
        .replace_role_assignments(
            &change(0, vec![second.clone()], vec![first.clone()]),
            test_audit(),
        )
        .await
    {
        Err(Error::AssignmentSetChanged { current }) => assert_eq!(current, r1),
        other => panic!("a stale replacement: {other:?}"),
    }
    assert_eq!(
        backend.role_assignment_set(&set).await.unwrap(),
        (r1, held.clone())
    );

    // An unchanged replacement still moves the revision.
    let r2 = backend
        .replace_role_assignments(&change(r1, vec![], vec![]), test_audit())
        .await
        .unwrap();
    assert_eq!(r2, r1 + 1);
    assert_eq!(backend.role_assignment_set(&set).await.unwrap().1, held);

    // An assignment of another scope, and a deletion of another set's.
    let elsewhere = granted(&grantor, holder, &role, None);
    assert!(matches!(
        backend
            .replace_role_assignments(&change(r2, vec![elsewhere], vec![]), test_audit())
            .await,
        Err(Error::Validation(_))
    ));
    let other_holder = stored_profile(backend).await;
    let foreign = granted(&grantor, other_holder, &role, Some("tenant-a"));
    backend
        .create_role_assignment(&foreign, test_audit())
        .await
        .unwrap();
    assert!(matches!(
        backend
            .replace_role_assignments(&change(r2, vec![], vec![foreign.clone()]), test_audit())
            .await,
        Err(Error::AssignmentSetChanged { .. })
    ));
    assert!(
        backend
            .get_role_assignment(foreign.id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(revision(backend, &set).await, r2, "nothing written");

    // Swapped in one commit.
    let r3 = backend
        .replace_role_assignments(
            &change(r2, vec![second.clone()], vec![first.clone()]),
            test_audit(),
        )
        .await
        .unwrap();
    assert_eq!(r3, r2 + 1, "one step whatever the change writes");
    let held = backend.role_assignment_set(&set).await.unwrap().1;
    assert_eq!(
        held.iter().map(|a| a.id).collect::<Vec<_>>(),
        vec![second.id]
    );
}

/// A replacement commits only while every fence holds, the fence of an
/// empty replacement included: a revoked basis is `Fenced`, nothing written.
pub async fn test_replacement_is_fenced(backend: &dyn StorageBackend) {
    let role = stored_role(backend).await;
    let grantor = grantor(backend, &role).await;
    let holder = stored_profile(backend).await;
    let set = set_of(holder, None);
    let stale = AssignmentFence {
        basis: AuthorityBasis {
            revision: 1,
            ..grantor.fence.basis
        },
        ..grantor.fence.clone()
    };
    for change in [
        AssignmentSetChange {
            set: set.clone(),
            expected_revision: 0,
            create: vec![(granted(&grantor, holder, &role, None), stale.clone())],
            delete: vec![],
            hold: vec![],
        },
        AssignmentSetChange {
            set: set.clone(),
            expected_revision: 0,
            create: vec![],
            delete: vec![],
            hold: vec![stale.clone()],
        },
    ] {
        let refused = backend
            .replace_role_assignments(&change, test_audit())
            .await
            .unwrap_err();
        assert!(matches!(refused, Error::Fenced(_)), "{refused:?}");
    }
    assert_eq!(
        backend.role_assignment_set(&set).await.unwrap(),
        (0, vec![])
    );
}

/// A replacement never leaves the installation without a usable
/// administrator: removing the last administrator assignment is
/// `InvalidState`, while replacing its term in the same commit is not.
pub async fn test_replacement_keeps_an_administrator(backend: &dyn StorageBackend) {
    let administrator = Role::installation_administrator();
    backend.ensure_system_project(test_audit()).await.unwrap();
    if backend.get_role(administrator.id).await.unwrap().is_none() {
        backend
            .create_role(&administrator, test_audit())
            .await
            .unwrap();
    }
    let holder = stored_profile(backend).await;
    let assignment = || {
        RoleAssignment::new(RoleAssignmentPrincipal::Profile(holder), administrator.id)
            .on_installation()
    };
    let held = assignment();
    backend
        .create_role_assignment(&held, test_audit())
        .await
        .unwrap();
    let set = AssignmentSet::of(&held);
    let at = revision(backend, &set).await;
    let fence = AssignmentFence {
        basis: AuthorityBasis {
            assignment: held.id,
            revision: 0,
            member: None,
        },
        role: (
            administrator.id,
            administrator.permissions.iter().cloned().collect(),
        ),
        recipient_membership: None,
        grantor_outside: None,
    };
    let removed = backend
        .replace_role_assignments(
            &AssignmentSetChange {
                set: set.clone(),
                expected_revision: at,
                create: vec![],
                delete: vec![(held.id, fence.clone())],
                hold: vec![],
            },
            test_audit(),
        )
        .await
        .unwrap_err();
    assert!(matches!(removed, Error::InvalidState(_)), "{removed:?}");
    assert_eq!(revision(backend, &set).await, at, "nothing written");

    let renewed = assignment().with_expiry(chrono::Utc::now() + chrono::Duration::days(1));
    backend
        .replace_role_assignments(
            &AssignmentSetChange {
                set: set.clone(),
                expected_revision: at,
                create: vec![(renewed.clone(), fence.clone())],
                delete: vec![(held.id, fence)],
                hold: vec![],
            },
            test_audit(),
        )
        .await
        .unwrap();
    let kept = backend.role_assignment_set(&set).await.unwrap().1;
    assert_eq!(
        kept.iter().map(|a| a.id).collect::<Vec<_>>(),
        vec![renewed.id]
    );
}

/// Two replacements decided against one revision: exactly one commits, the
/// other is `AssignmentSetChanged` and wrote nothing, an empty one included.
pub async fn test_concurrent_replacements_serialize(backend: &dyn StorageBackend) {
    let role = stored_role(backend).await;
    let grantor = grantor(backend, &role).await;
    for (left_creates, right_creates) in [(true, true), (true, false), (false, false)] {
        let holder = stored_profile(backend).await;
        let set = set_of(holder, None);
        let change = |creates: bool| AssignmentSetChange {
            set: set.clone(),
            expected_revision: 0,
            create: if creates {
                vec![(
                    granted(&grantor, holder, &role, None),
                    grantor.fence.clone(),
                )]
            } else {
                vec![]
            },
            delete: vec![],
            hold: vec![grantor.fence.clone()],
        };
        let (left, right) = (change(left_creates), change(right_creates));
        let (a, b) = tokio::join!(
            backend.replace_role_assignments(&left, test_audit()),
            backend.replace_role_assignments(&right, test_audit()),
        );
        let (won, lost) = match (a, b) {
            (Ok(r), Err(e)) => ((r, &left), e),
            (Err(e), Ok(r)) => ((r, &right), e),
            other => panic!("exactly one of two replacements commits: {other:?}"),
        };
        assert!(
            matches!(lost, Error::AssignmentSetChanged { .. }),
            "{lost:?}"
        );
        let (stored, held) = backend.role_assignment_set(&set).await.unwrap();
        assert_eq!(stored, won.0);
        assert_eq!(
            held.iter().map(|a| a.id).collect::<Vec<_>>(),
            won.1.create.iter().map(|(a, _)| a.id).collect::<Vec<_>>(),
            "only the winner's content"
        );
    }
}
