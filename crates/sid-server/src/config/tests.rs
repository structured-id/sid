use super::*;
use sid_core::models::authz::SodSeverity;

/// The documented `sid.yaml` governance section reads into the rules the
/// conflict evaluator takes.
#[test]
fn sod_warnings_are_read_from_the_configuration() {
    let config = parse(
        "governance:
  sod_warnings:
    - name: author_reviewer
      description: One user should not write and review the same change
      conflicting_roles:
        - author
        - reviewer
      severity: warning
",
    )
    .unwrap();
    assert_eq!(
        config.governance.sod_warnings,
        vec![SodConflictRule {
            name: "author_reviewer".into(),
            description: Some("One user should not write and review the same change".into()),
            conflicting_roles: vec!["author".into(), "reviewer".into()],
            severity: SodSeverity::Warning,
        }]
    );
}

/// No file named is no configuration; an empty one configures nothing.
#[test]
fn absent_configuration_has_no_warnings() {
    assert!(
        installation_config(None)
            .unwrap()
            .governance
            .sod_warnings
            .is_empty()
    );
    assert!(parse("{}").unwrap().governance.sod_warnings.is_empty());
}

/// A misspelled key or an unknown severity is refused, never read as no
/// warning.
#[test]
fn malformed_configuration_is_refused() {
    assert!(parse("governance:\n  sod_warning: []\n").is_err());
    assert!(
        parse(
            "governance:
  sod_warnings:
    - name: x
      conflicting_roles: [a, b]
      severity: maybe
"
        )
        .is_err()
    );
}

/// A named file that does not exist stops startup.
#[test]
fn missing_file_is_refused() {
    assert!(installation_config(Some("/nonexistent/sid.yaml")).is_err());
}
