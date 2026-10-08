// SPDX-License-Identifier: AGPL-3.0-only
//! Policy Simulation Engine.
//!
//! Dry-run evaluation: applies proposed Cedar policy changes in-memory
//! and compares authorization decisions against the current state.
//!
//! Cedar policy dry-run over an EXPLICIT caller-provided check set
//! (subjects × actions): add/update/delete policies, compare current vs proposed.
//! The simulation stays limited to the explicit check set; it never scans the
//! population.

use std::collections::HashMap;
use std::sync::Arc;

use sid_core::models::{CedarPolicy, CedarPolicyId, PolicyEffect, ProjectId};
use sid_plugin::StorageBackend;
use sid_plugin::authz::{AuthzCheckRequest, AuthzCheckResponse, AuthzEngine};

use crate::cedar::CedarService;
use crate::engine::CeAuthzEngine;

/// A proposed Cedar policy change to simulate.
#[derive(Debug, Clone)]
pub enum ProposedChange {
    /// Add a new Cedar policy.
    CreatePolicy {
        name: String,
        policy_text: String,
        effect: PolicyEffect,
    },
    /// Update an existing Cedar policy (by ID).
    UpdatePolicy {
        id: CedarPolicyId,
        policy_text: Option<String>,
        effect: Option<PolicyEffect>,
        enabled: Option<bool>,
    },
    /// Delete a Cedar policy (by ID).
    DeletePolicy { id: CedarPolicyId },
}

/// Impact type for a single evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpactType {
    /// Access gained (deny → allow).
    Gained,
    /// Access lost (allow → deny).
    Lost,
    /// No change.
    Unchanged,
}

/// Single impact entry — one (subject, action, resource) triple.
#[derive(Debug, Clone)]
pub struct SimulationImpact {
    pub subject: String,
    pub action: String,
    pub resource: String,
    pub current_allowed: bool,
    pub proposed_allowed: bool,
    pub impact_type: ImpactType,
    pub current_reason: String,
    pub proposed_reason: String,
}

/// Simulation result.
#[derive(Debug, Clone)]
pub struct SimulationResult {
    pub impacts: Vec<SimulationImpact>,
    pub total_checked: usize,
    pub total_gained: usize,
    pub total_lost: usize,
    pub total_unchanged: usize,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Simulation error.
#[derive(Debug)]
pub enum SimulationError {
    Storage(String),
}

impl std::fmt::Display for SimulationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage error: {e}"),
        }
    }
}

impl std::error::Error for SimulationError {}

/// Policy Simulator.
///
/// Evaluates Cedar authorization under current and proposed policy sets,
/// producing a diff of impacts without persisting any changes.
///
/// Caller provides the subjects × actions × resources to check.
/// Use `SimulatePolicy` gRPC with `subject`/`action`/`resource` fields,
/// or omit them to get default checks.
pub struct PolicySimulator<S: StorageBackend + ?Sized> {
    engine: CeAuthzEngine<S>,
    cedar: CedarService,
    storage: Arc<S>,
}

impl<S: StorageBackend + ?Sized + 'static> PolicySimulator<S> {
    pub fn new(storage: Arc<S>) -> Self {
        Self {
            engine: CeAuthzEngine::new(storage.clone()),
            cedar: CedarService::new(),
            storage,
        }
    }

    /// Run simulation: compare current vs proposed Cedar policies.
    ///
    /// Steps:
    /// 1. Load current Cedar policies for the project.
    /// 2. Apply proposed changes in-memory (no DB writes).
    /// 3. For each subject × action × resource: evaluate both states.
    /// 4. Return diff of impacts.
    pub async fn simulate(
        &self,
        project_id: ProjectId,
        changes: &[ProposedChange],
        subjects: &[String],
        actions: &[String],
        resource: &str,
    ) -> Result<SimulationResult, SimulationError> {
        let mut errors = Vec::new();

        // 1. Load current policies.
        let current_policies = self
            .storage
            .list_cedar_policies(project_id)
            .await
            .map_err(|e| SimulationError::Storage(e.to_string()))?;

        // 2. Apply proposed changes in-memory.
        let proposed_policies = self.apply_changes(&current_policies, changes, &mut errors);

        // 3. Build policy pairs for Cedar evaluation.
        let proposed_pairs = Self::to_policy_pairs(&proposed_policies);

        // 4. Evaluate each combination.
        let mut impacts = Vec::new();
        let mut total_gained = 0;
        let mut total_lost = 0;
        let mut total_unchanged = 0;

        for subject in subjects {
            for action in actions {
                // Current state: full engine (RBAC + Cedar).
                let current_result = self
                    .engine
                    .check(&AuthzCheckRequest {
                        subject: subject.clone(),
                        action: action.clone(),
                        resource: resource.to_string(),
                        context: HashMap::new(),
                    })
                    .await;

                let (current_allowed, current_reason) = match current_result {
                    Ok(AuthzCheckResponse::Allow { reason }) => (true, reason),
                    Ok(AuthzCheckResponse::Deny { reason }) => (false, reason),
                    Err(e) => {
                        errors.push(format!("eval error for {subject}: {e}"));
                        continue;
                    }
                };

                // Proposed state: Cedar with modified policy set + RBAC unchanged.
                // For proposed, we check RBAC first (unchanged), then Cedar with proposed set.
                let proposed_cedar_allowed =
                    self.evaluate_cedar(subject, action, resource, &proposed_pairs);

                // RBAC is unchanged in CE simulation, so:
                // - If current was allowed by RBAC → still allowed (RBAC unchanged).
                // - If current was denied by RBAC → check proposed Cedar.
                let rbac_allowed = current_allowed && current_reason.contains("RBAC");
                let proposed_allowed = rbac_allowed || proposed_cedar_allowed;

                let proposed_reason = if rbac_allowed {
                    current_reason.clone() // RBAC unchanged
                } else if proposed_cedar_allowed {
                    "proposed Cedar policies permit".to_string()
                } else {
                    "no RBAC role grants and proposed Cedar policies deny".to_string()
                };

                let impact_type = match (current_allowed, proposed_allowed) {
                    (false, true) => {
                        total_gained += 1;
                        ImpactType::Gained
                    }
                    (true, false) => {
                        total_lost += 1;
                        ImpactType::Lost
                    }
                    _ => {
                        total_unchanged += 1;
                        ImpactType::Unchanged
                    }
                };

                // Only report changed impacts.
                if impact_type != ImpactType::Unchanged {
                    impacts.push(SimulationImpact {
                        subject: subject.clone(),
                        action: action.clone(),
                        resource: resource.to_string(),
                        current_allowed,
                        proposed_allowed,
                        impact_type,
                        current_reason,
                        proposed_reason,
                    });
                }
            }
        }

        let total_checked = subjects.len() * actions.len();

        Ok(SimulationResult {
            impacts,
            total_checked,
            total_gained,
            total_lost,
            total_unchanged,
            warnings: Vec::new(),
            errors,
        })
    }

    /// Apply Cedar policy changes in-memory.
    fn apply_changes(
        &self,
        current: &[CedarPolicy],
        changes: &[ProposedChange],
        errors: &mut Vec<String>,
    ) -> Vec<CedarPolicy> {
        let mut policies: Vec<CedarPolicy> = current.to_vec();

        for change in changes {
            match change {
                ProposedChange::CreatePolicy {
                    name,
                    policy_text,
                    effect,
                } => {
                    let validation = self.cedar.validate_policy(policy_text);
                    if !validation.valid {
                        errors.push(format!(
                            "proposed policy '{}': {}",
                            name,
                            validation.errors.join("; ")
                        ));
                        continue;
                    }
                    let mut p = CedarPolicy::new(ProjectId::new(), name, policy_text, *effect);
                    p.enabled = true;
                    policies.push(p);
                }
                ProposedChange::UpdatePolicy {
                    id,
                    policy_text,
                    effect,
                    enabled,
                } => {
                    if let Some(p) = policies.iter_mut().find(|p| p.id == *id) {
                        if let Some(text) = policy_text {
                            let validation = self.cedar.validate_policy(text);
                            if !validation.valid {
                                errors.push(format!(
                                    "proposed update for '{}': {}",
                                    p.name,
                                    validation.errors.join("; ")
                                ));
                                continue;
                            }
                            p.policy_text.clone_from(text);
                        }
                        if let Some(eff) = effect {
                            p.effect = *eff;
                        }
                        if let Some(en) = enabled {
                            p.enabled = *en;
                        }
                    } else {
                        errors.push(format!("policy {} not found for update", id.0));
                    }
                }
                ProposedChange::DeletePolicy { id } => {
                    let before = policies.len();
                    policies.retain(|p| p.id != *id);
                    if policies.len() == before {
                        errors.push(format!("policy {} not found for deletion", id.0));
                    }
                }
            }
        }

        policies
    }

    /// Convert Cedar policies to (id, text) pairs for evaluation.
    fn to_policy_pairs(policies: &[CedarPolicy]) -> Vec<(String, String)> {
        policies
            .iter()
            .filter(|p| p.enabled)
            .map(|p| (p.id.0.to_string(), p.policy_text.clone()))
            .collect()
    }

    /// Evaluate Cedar policies against a request.
    fn evaluate_cedar(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        policies: &[(String, String)],
    ) -> bool {
        if policies.is_empty() {
            return false;
        }

        let cedar_subject = if let Some(id) = subject.strip_prefix("machine:") {
            format!(r#"MachineUser::"{id}""#)
        } else {
            let id = subject.strip_prefix("user:").unwrap_or(subject);
            format!(r#"User::"{id}""#)
        };

        let cedar_action = format!(r#"Action::"{action}""#);

        // Extract UUID from resource string for Cedar.
        let resource_id = if let Some((_type, id)) = resource.split_once(':') {
            id
        } else {
            resource
        };
        let cedar_resource = format!(r#"Resource::"{resource_id}""#);

        match self.cedar.evaluate(
            policies,
            &cedar_subject,
            &cedar_action,
            &cedar_resource,
            &HashMap::new(),
        ) {
            Ok(result) => result.allowed,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_mock::MockStorage;
    use sid_core::models::AuditEntry;

    async fn setup() -> (PolicySimulator<MockStorage>, Arc<MockStorage>, ProjectId) {
        let storage = Arc::new(MockStorage::new());
        let simulator = PolicySimulator::new(storage.clone());
        let project_id = ProjectId::new();
        (simulator, storage, project_id)
    }

    /// Distinct subjects. The UUID is a valid v7: `ProfileId` refuses anything else.
    fn subject(n: u8) -> String {
        format!("user:0192b1e0-7c3a-7f4e-8a5d-3c2b1a0f000{n}")
    }

    fn resource(project_id: ProjectId) -> String {
        format!("project:{}", project_id.0)
    }

    // ── No changes ──

    #[tokio::test]
    async fn test_no_changes_no_impacts() {
        let (sim, _, pid) = setup().await;
        let result = sim
            .simulate(pid, &[], &[subject(1)], &["read".into()], &resource(pid))
            .await
            .unwrap();

        assert_eq!(result.total_gained, 0);
        assert_eq!(result.total_lost, 0);
        assert_eq!(result.total_checked, 1);
        assert!(result.impacts.is_empty());
    }

    // ── Add permit policy → access gained ──

    #[tokio::test]
    async fn test_add_permit_gains_access() {
        let (sim, _, pid) = setup().await;
        let changes = vec![ProposedChange::CreatePolicy {
            name: "allow_read".into(),
            policy_text: r#"permit(principal, action == Action::"read", resource);"#.into(),
            effect: PolicyEffect::Permit,
        }];

        let result = sim
            .simulate(
                pid,
                &changes,
                &[subject(1)],
                &["read".into()],
                &resource(pid),
            )
            .await
            .unwrap();

        assert_eq!(result.total_gained, 1);
        assert_eq!(result.total_lost, 0);
        assert_eq!(result.impacts.len(), 1);
        assert_eq!(result.impacts[0].impact_type, ImpactType::Gained);
    }

    // ── Delete existing policy → access lost ──

    #[tokio::test]
    async fn test_delete_policy_loses_access() {
        let (sim, storage, pid) = setup().await;
        let policy = CedarPolicy::new(
            pid,
            "allow_read",
            r#"permit(principal, action == Action::"read", resource);"#,
            PolicyEffect::Permit,
        );
        let policy_id = policy.id;
        storage
            .create_cedar_policy(&policy, AuditEntry::system("test", "test").into())
            .await
            .unwrap();

        let changes = vec![ProposedChange::DeletePolicy { id: policy_id }];
        let result = sim
            .simulate(
                pid,
                &changes,
                &[subject(1)],
                &["read".into()],
                &resource(pid),
            )
            .await
            .unwrap();

        assert_eq!(result.total_lost, 1);
        assert_eq!(result.impacts[0].impact_type, ImpactType::Lost);
    }

    // ── Invalid Cedar syntax → error reported ──

    #[tokio::test]
    async fn test_invalid_cedar_reports_error() {
        let (sim, _, pid) = setup().await;
        let changes = vec![ProposedChange::CreatePolicy {
            name: "bad".into(),
            policy_text: "not cedar!!!".into(),
            effect: PolicyEffect::Permit,
        }];

        let result = sim
            .simulate(
                pid,
                &changes,
                &[subject(1)],
                &["read".into()],
                &resource(pid),
            )
            .await
            .unwrap();

        assert!(!result.errors.is_empty());
        assert!(result.errors[0].contains("bad"));
    }

    // ── Update policy text ──

    #[tokio::test]
    async fn test_update_policy_changes_access() {
        let (sim, storage, pid) = setup().await;
        let policy = CedarPolicy::new(
            pid,
            "allow_read",
            r#"permit(principal, action == Action::"read", resource);"#,
            PolicyEffect::Permit,
        );
        let policy_id = policy.id;
        storage
            .create_cedar_policy(&policy, AuditEntry::system("test", "test").into())
            .await
            .unwrap();

        // Widen to all actions.
        let changes = vec![ProposedChange::UpdatePolicy {
            id: policy_id,
            policy_text: Some(r#"permit(principal, action, resource);"#.into()),
            effect: None,
            enabled: None,
        }];

        // "delete" was denied, now should be allowed.
        let result = sim
            .simulate(
                pid,
                &changes,
                &[subject(1)],
                &["delete".into()],
                &resource(pid),
            )
            .await
            .unwrap();

        assert_eq!(result.total_gained, 1);
    }

    // ── Disable policy → access lost ──

    #[tokio::test]
    async fn test_disable_policy_loses_access() {
        let (sim, storage, pid) = setup().await;
        let policy = CedarPolicy::new(
            pid,
            "allow_read",
            r#"permit(principal, action == Action::"read", resource);"#,
            PolicyEffect::Permit,
        );
        let policy_id = policy.id;
        storage
            .create_cedar_policy(&policy, AuditEntry::system("test", "test").into())
            .await
            .unwrap();

        let changes = vec![ProposedChange::UpdatePolicy {
            id: policy_id,
            policy_text: None,
            effect: None,
            enabled: Some(false),
        }];

        let result = sim
            .simulate(
                pid,
                &changes,
                &[subject(1)],
                &["read".into()],
                &resource(pid),
            )
            .await
            .unwrap();

        assert_eq!(result.total_lost, 1);
    }

    // ── Delete nonexistent policy → error ──

    #[tokio::test]
    async fn test_delete_nonexistent_reports_error() {
        let (sim, _, pid) = setup().await;
        let changes = vec![ProposedChange::DeletePolicy {
            id: CedarPolicyId::new(),
        }];

        let result = sim
            .simulate(
                pid,
                &changes,
                &[subject(1)],
                &["read".into()],
                &resource(pid),
            )
            .await
            .unwrap();

        assert!(result.errors.iter().any(|e| e.contains("not found")));
    }

    // ── Forbid overrides permit ──

    #[tokio::test]
    async fn test_forbid_overrides_permit() {
        let (sim, _, pid) = setup().await;
        let changes = vec![
            ProposedChange::CreatePolicy {
                name: "allow_all".into(),
                policy_text: r#"permit(principal, action, resource);"#.into(),
                effect: PolicyEffect::Permit,
            },
            ProposedChange::CreatePolicy {
                name: "deny_delete".into(),
                policy_text: r#"forbid(principal, action == Action::"delete", resource);"#.into(),
                effect: PolicyEffect::Forbid,
            },
        ];

        // read → gained.
        let result = sim
            .simulate(
                pid,
                &changes,
                &[subject(1)],
                &["read".into()],
                &resource(pid),
            )
            .await
            .unwrap();
        assert_eq!(result.total_gained, 1);

        // delete → unchanged (both deny).
        let result = sim
            .simulate(
                pid,
                &changes,
                &[subject(1)],
                &["delete".into()],
                &resource(pid),
            )
            .await
            .unwrap();
        assert_eq!(result.total_unchanged, 1);
        assert!(result.impacts.is_empty());
    }

    // ── Multiple subjects × actions ──

    #[tokio::test]
    async fn test_multiple_subjects_and_actions() {
        let (sim, _, pid) = setup().await;
        let changes = vec![ProposedChange::CreatePolicy {
            name: "allow_read".into(),
            policy_text: r#"permit(principal, action == Action::"read", resource);"#.into(),
            effect: PolicyEffect::Permit,
        }];

        let subjects = vec![subject(1), subject(2)];
        let actions = vec!["read".to_string(), "write".to_string()];

        let result = sim
            .simulate(pid, &changes, &subjects, &actions, &resource(pid))
            .await
            .unwrap();

        // 4 total checks (2 subjects × 2 actions).
        assert_eq!(result.total_checked, 4);
        // 2 gained (both subjects get "read" access).
        assert_eq!(result.total_gained, 2);
        // 2 unchanged (both subjects denied "write" before and after).
        assert_eq!(result.total_unchanged, 2);
    }

    // ── Multiple changes combined ──

    #[tokio::test]
    async fn test_combined_add_and_delete() {
        let (sim, storage, pid) = setup().await;
        let read_policy = CedarPolicy::new(
            pid,
            "allow_read",
            r#"permit(principal, action == Action::"read", resource);"#,
            PolicyEffect::Permit,
        );
        let read_id = read_policy.id;
        storage
            .create_cedar_policy(&read_policy, AuditEntry::system("test", "test").into())
            .await
            .unwrap();

        let changes = vec![
            ProposedChange::DeletePolicy { id: read_id },
            ProposedChange::CreatePolicy {
                name: "allow_write".into(),
                policy_text: r#"permit(principal, action == Action::"write", resource);"#.into(),
                effect: PolicyEffect::Permit,
            },
        ];

        // "read" → lost.
        let result = sim
            .simulate(
                pid,
                &changes,
                &[subject(1)],
                &["read".into()],
                &resource(pid),
            )
            .await
            .unwrap();
        assert_eq!(result.total_lost, 1);

        // "write" → gained.
        let result = sim
            .simulate(
                pid,
                &changes,
                &[subject(1)],
                &["write".into()],
                &resource(pid),
            )
            .await
            .unwrap();
        assert_eq!(result.total_gained, 1);
    }
}
