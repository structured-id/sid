use super::*;

/// An empty or blank scope is refused: every binding would otherwise share it.
#[test]
fn empty_scope_is_refused() {
    assert_eq!(
        BindingScope::try_from(String::new()),
        Err(EmptyBindingScope)
    );
    assert_eq!(
        BindingScope::try_from("  ".to_string()),
        Err(EmptyBindingScope)
    );
}

/// A scope round-trips through its string form, and JSON refuses an empty one.
#[test]
fn scope_round_trips() {
    let scope = BindingScope::try_from("org-1".to_string()).unwrap();
    assert_eq!(scope.as_str(), "org-1");
    let json = serde_json::to_string(&scope).unwrap();
    assert_eq!(serde_json::from_str::<BindingScope>(&json).unwrap(), scope);
    assert!(serde_json::from_str::<BindingScope>("\"\"").is_err());
}
