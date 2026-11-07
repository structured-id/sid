use super::*;

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
