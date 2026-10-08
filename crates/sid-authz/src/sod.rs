// SPDX-License-Identifier: AGPL-3.0-only
//! Separation of Duties (SoD) — CE conflict detection.
//!
//! CE: warning only. Admin can override.
//! See `arch/authz/governance.md` for full SoD architecture.

use sid_core::models::authz::{SodConflict, SodConflictRule};

#[cfg(test)]
use sid_core::models::authz::SodSeverity;

/// CE SoD service — checks role assignments against conflict rules.
///
/// Rules are provided at construction (from config or hardcoded defaults).
/// CE produces warnings only — no blocking.
pub struct SodService {
    rules: Vec<SodConflictRule>,
}

impl SodService {
    /// Create a new SoD service with the given conflict rules.
    pub fn new(rules: Vec<SodConflictRule>) -> Self {
        Self { rules }
    }

    /// Create with CE default rules (empty — no built-in conflicts).
    ///
    /// Operators configure SoD rules via `sid.yaml` or admin API.
    pub fn ce_default() -> Self {
        Self::new(Vec::new())
    }

    /// Check whether assigning `new_role_key` would conflict with `existing_role_keys`.
    ///
    /// Returns all detected conflicts (may be empty).
    pub fn check_conflicts(
        &self,
        existing_role_keys: &[String],
        new_role_key: &str,
    ) -> Vec<SodConflict> {
        let mut conflicts = Vec::new();

        for rule in &self.rules {
            // Check if new_role_key is in the conflicting set.
            if !rule.conflicting_roles.iter().any(|r| r == new_role_key) {
                continue;
            }

            // Check if any existing role is also in the conflicting set.
            let existing_matches: Vec<String> = existing_role_keys
                .iter()
                .filter(|r| rule.conflicting_roles.contains(r) && r.as_str() != new_role_key)
                .cloned()
                .collect();

            if !existing_matches.is_empty() {
                let mut involved = existing_matches;
                involved.push(new_role_key.to_string());
                conflicts.push(SodConflict {
                    rule_name: rule.name.clone(),
                    description: rule
                        .description
                        .clone()
                        .unwrap_or_else(|| format!("SoD conflict: {}", rule.name)),
                    severity: rule.severity,
                    conflicting_roles: involved,
                });
            }
        }

        conflicts
    }

    /// Check all roles assigned to a principal for any mutual conflicts.
    ///
    /// Returns all detected conflicts across all assigned roles.
    pub fn check_all_conflicts(&self, role_keys: &[String]) -> Vec<SodConflict> {
        let mut conflicts = Vec::new();
        let mut seen_rules = std::collections::HashSet::new();

        for rule in &self.rules {
            // Count how many of the assigned roles appear in this rule's conflict set.
            let matching: Vec<String> = role_keys
                .iter()
                .filter(|r| rule.conflicting_roles.contains(r))
                .cloned()
                .collect();

            if matching.len() >= 2 && seen_rules.insert(rule.name.clone()) {
                conflicts.push(SodConflict {
                    rule_name: rule.name.clone(),
                    description: rule
                        .description
                        .clone()
                        .unwrap_or_else(|| format!("SoD conflict: {}", rule.name)),
                    severity: rule.severity,
                    conflicting_roles: matching,
                });
            }
        }

        conflicts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rules() -> Vec<SodConflictRule> {
        vec![
            SodConflictRule {
                name: "payment_segregation".to_string(),
                description: Some("Payment creator cannot also approve".to_string()),
                conflicting_roles: vec![
                    "payment_creator".to_string(),
                    "payment_approver".to_string(),
                ],
                severity: SodSeverity::Warning,
            },
            SodConflictRule {
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
}
