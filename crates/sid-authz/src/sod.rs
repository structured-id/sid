// SPDX-License-Identifier: AGPL-3.0-only
//! Separation of Duties (SoD) — CE conflict detection.
//!
//! CE: warning only. Admin can override.

use sid_core::models::authz::{SodConflict, SodConflictRule};

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
mod tests;
