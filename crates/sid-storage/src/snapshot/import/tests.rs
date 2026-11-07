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
    let err = sources_first(&[first, second]).expect_err("a cycle");
    assert!(err.to_string().contains("cycle"), "{err}");
}
