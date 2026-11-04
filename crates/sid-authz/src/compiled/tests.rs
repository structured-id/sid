use std::sync::Arc;

use super::*;

fn policy(id: &str, text: &str) -> (String, String) {
    (id.to_owned(), text.to_owned())
}

const PERMIT: &str = "permit(principal, action, resource);";
const FORBID: &str = "forbid(principal, action, resource);";

/// The same applicable set is compiled once and then shared; another text
/// under the same id, another id or another order of policies is another
/// set, never answered by the first.
#[test]
fn a_set_is_compiled_once_and_only_for_itself() {
    let cache = PolicySets::default();
    let first = cache.get(&[policy("a", PERMIT)]).unwrap();
    let again = cache.get(&[policy("a", PERMIT)]).unwrap();
    assert!(Arc::ptr_eq(&first, &again), "compiled again");

    let edited = cache.get(&[policy("a", FORBID)]).unwrap();
    assert!(!Arc::ptr_eq(&first, &edited));
    assert!(edited.policy(&cedar_policy::PolicyId::new("a")).is_some());
    assert_eq!(
        edited
            .policy(&cedar_policy::PolicyId::new("a"))
            .unwrap()
            .effect(),
        cedar_policy::Effect::Forbid
    );
    let other = cache.get(&[policy("b", PERMIT)]).unwrap();
    assert!(!Arc::ptr_eq(&first, &other));
    let two = cache
        .get(&[policy("a", PERMIT), policy("b", PERMIT)])
        .unwrap();
    let swapped = cache
        .get(&[policy("b", PERMIT), policy("a", PERMIT)])
        .unwrap();
    assert!(!Arc::ptr_eq(&two, &swapped));
}

/// A set holding a policy that does not parse fails every time it is
/// asked for, cached or not.
#[test]
fn an_unparsable_set_always_fails() {
    let cache = PolicySets::default();
    for _ in 0..2 {
        let failed = cache.get(&[policy("a", PERMIT), policy("bad", "permit(")]);
        assert!(
            matches!(&failed, Err(CedarError::InvalidPolicy(e)) if e.starts_with("bad: ")),
            "{failed:?}"
        );
    }
}

/// The cache holds a bounded number of sets: asking for more evicts, and
/// an evicted set is compiled again when next asked for.
#[test]
fn the_cache_is_bounded() {
    let cache = PolicySets::default();
    for i in 0..CAPACITY + 8 {
        cache.get(&[policy(&format!("p{i}"), PERMIT)]).unwrap();
        assert!(cache.sets.len() <= CAPACITY);
    }
    let set = cache.get(&[policy("p0", PERMIT)]).unwrap();
    assert!(set.policy(&cedar_policy::PolicyId::new("p0")).is_some());
}
