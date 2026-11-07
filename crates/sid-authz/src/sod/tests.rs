use super::*;
use sid_core::models::authz::SodSeverity;

fn test_rules() -> Vec<SodConflictRule> {
    vec![
        SodConflictRule {
            id: uuid::Uuid::now_v7(),
            name: "payment_segregation".to_string(),
            description: Some("Payment creator cannot also approve".to_string()),
            conflicting_roles: vec![
                "payment_creator".to_string(),
                "payment_approver".to_string(),
            ],
            severity: SodSeverity::Warning,
        },
        SodConflictRule {
            id: uuid::Uuid::now_v7(),
            name: "admin_audit_segregation".to_string(),
            description: Some("User admin should not view audit logs".to_string()),
            conflicting_roles: vec!["user_admin".to_string(), "audit_viewer".to_string()],
            severity: SodSeverity::Warning,
        },
    ]
}

#[test]
fn test_no_conflict_on_non_conflicting_role() {
    let service = SodService::new(test_rules());
    let existing = vec!["editor".to_string()];
    let conflicts = service.check_conflicts(&existing, "viewer");
    assert!(conflicts.is_empty());
}

#[test]
fn test_conflict_detected() {
    let service = SodService::new(test_rules());
    let existing = vec!["payment_creator".to_string()];
    let conflicts = service.check_conflicts(&existing, "payment_approver");

    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].rule_name, "payment_segregation");
    assert_eq!(conflicts[0].severity, SodSeverity::Warning);
    assert!(
        conflicts[0]
            .conflicting_roles
            .contains(&"payment_creator".to_string())
    );
    assert!(
        conflicts[0]
            .conflicting_roles
            .contains(&"payment_approver".to_string())
    );
}

#[test]
fn test_no_conflict_same_role() {
    let service = SodService::new(test_rules());
    let existing = vec!["payment_creator".to_string()];
    // Assigning same role again — not a conflict.
    let conflicts = service.check_conflicts(&existing, "payment_creator");
    assert!(conflicts.is_empty());
}

#[test]
fn test_multiple_rules_checked() {
    let service = SodService::new(test_rules());
    let existing = vec!["payment_creator".to_string(), "user_admin".to_string()];
    // Assigning audit_viewer conflicts with user_admin.
    let conflicts = service.check_conflicts(&existing, "audit_viewer");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].rule_name, "admin_audit_segregation");
}

#[test]
fn test_check_all_conflicts_none() {
    let service = SodService::new(test_rules());
    let roles = vec!["editor".to_string(), "viewer".to_string()];
    let conflicts = service.check_all_conflicts(&roles);
    assert!(conflicts.is_empty());
}

#[test]
fn test_check_all_conflicts_found() {
    let service = SodService::new(test_rules());
    let roles = vec![
        "payment_creator".to_string(),
        "payment_approver".to_string(),
        "user_admin".to_string(),
        "audit_viewer".to_string(),
    ];
    let conflicts = service.check_all_conflicts(&roles);
    assert_eq!(conflicts.len(), 2);
}

#[test]
fn test_empty_rules() {
    let service = SodService::ce_default();
    let existing = vec!["admin".to_string()];
    let conflicts = service.check_conflicts(&existing, "superadmin");
    assert!(conflicts.is_empty());
}

#[test]
fn test_sod_severity_as_str() {
    assert_eq!(SodSeverity::Warning.as_str(), "warning");
    assert_eq!(SodSeverity::Block.as_str(), "block");
}
