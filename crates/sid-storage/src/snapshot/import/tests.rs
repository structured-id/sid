use super::*;

/// Regression: the record a resumed import is recognized by is the same for
/// a snapshot and that snapshot read back from its own JSON, whose maps
/// iterate in another order. Before, the digest was taken over the
/// serialization as it came, so reopening an identical archive could give
/// another fingerprint and refuse the resume as an initialized target.
#[test]
fn a_reread_snapshot_resumes_under_the_same_record() {
    use sid_core::models::{Invite, InviteCreator, InviteId, ProfileId};
    let crypto = sid_crypto::RustCryptoPrimitives::new();
    let mut snapshot = Snapshot::new("test");
    snapshot.invites.push(Invite {
        id: InviteId::generate(),
        code: "ABCDEFGH".into(),
        created_by: InviteCreator::Profile(ProfileId::generate()),
        created_by_name: "admin".into(),
        metadata: (0..32)
            .map(|i| (format!("field-{i}"), i.to_string()))
            .collect(),
        max_uses: 1,
        use_count: 0,
        expires_at: None,
        active: true,
        created_at: chrono::Utc::now(),
    });
    let reread = Snapshot::parse(&snapshot.to_json().unwrap()).unwrap();
    assert_eq!(
        import_record(&snapshot, &crypto).unwrap().fingerprint,
        import_record(&reread, &crypto).unwrap().fingerprint
    );
}

/// A snapshot whose assignments depend on each other in a cycle cannot have
/// come from a store; it is refused instead of imported in some order.
#[test]
fn a_dependency_cycle_is_refused() {
    use sid_core::models::{
        AssignmentProvenance, Profile, RoleAssignment, RoleAssignmentPrincipal, RoleId,
    };
    let profile = Profile::new(Some("cycle")).id;
    let mut first = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(profile),
        RoleId::generate(),
    );
    let second = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(profile),
        RoleId::generate(),
    )
    .granted(AssignmentProvenance {
        granted_by: "user:a".into(),
        basis: Some(first.id),
        depends_on: Some(first.id),
        ceiling: None,
    });
    first = first.granted(AssignmentProvenance {
        granted_by: "user:b".into(),
        basis: Some(second.id),
        depends_on: Some(second.id),
        ceiling: None,
    });
    let err = references_first(
        &[first, second],
        |a| a.id,
        |a| a.provenance.as_ref().and_then(|p| p.depends_on),
        "role assignments",
    )
    .expect_err("a cycle");
    assert!(err.to_string().contains("cycle"), "{err}");
}

/// Each record comes after the one it references, through a chain listed in
/// reverse; a reference to itself or outside the snapshot orders nothing and
/// the listed order is otherwise kept.
#[test]
fn records_follow_their_references() {
    // (key, reference)
    let records = [
        (3, Some(2)),
        (2, Some(1)),
        (1, None),
        (4, Some(4)),
        (5, Some(9)),
    ];
    let ordered: Vec<i32> = references_first(&records, |r| r.0, |r| r.1, "records")
        .unwrap()
        .into_iter()
        .map(|r| r.0)
        .collect();
    assert_eq!(ordered, [1, 4, 5, 2, 3]);
}
