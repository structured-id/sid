// SPDX-License-Identifier: AGPL-3.0-only
//! Cedar Policy Engine integration.
//!
//! CE: hardcoded Cedar evaluator. ABAC conditions via context map.
//! Policies stored in PostgreSQL, loaded on evaluation.

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, Policy, PolicyId, PolicySet, Request,
};
use std::collections::HashMap;
use std::str::FromStr;

/// Result of Cedar policy evaluation.
#[derive(Debug, Clone)]
pub struct CedarEvalResult {
    /// Whether access is allowed.
    pub allowed: bool,
    /// Policies that contributed to the decision (ID + effect).
    pub matches: Vec<CedarPolicyMatch>,
    /// Diagnostics / errors from evaluation.
    pub errors: Vec<String>,
}

/// A policy that matched during evaluation.
#[derive(Debug, Clone)]
pub struct CedarPolicyMatch {
    pub policy_id: String,
    pub effect: CedarEffect,
}

/// Policy effect (Permit or Forbid).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CedarEffect {
    Permit,
    Forbid,
}

/// Result of Cedar policy validation.
#[derive(Debug, Clone)]
pub struct CedarValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

/// Cedar policy evaluation errors.
#[derive(Debug, Clone)]
pub enum CedarError {
    /// Policy text failed to parse.
    InvalidPolicy(String),
    /// The entity UID of request field `field` failed to parse.
    InvalidEntity { field: &'static str, error: String },
    /// Context construction failed.
    InvalidContext(String),
}

impl std::fmt::Display for CedarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPolicy(e) => write!(f, "invalid policy: {e}"),
            Self::InvalidEntity { field, error } => write!(f, "invalid entity {field}: {error}"),
            Self::InvalidContext(e) => write!(f, "invalid context: {e}"),
        }
    }
}

impl std::error::Error for CedarError {}

/// CE Cedar Policy Service.
///
/// Stateless evaluator. Policies and entities are provided per-request.
pub struct CedarService {
    authorizer: Authorizer,
}

impl CedarService {
    pub fn new() -> Self {
        Self {
            authorizer: Authorizer::new(),
        }
    }

    /// Validate Cedar policy text (syntax check).
    ///
    /// Returns validation result with any parse errors.
    pub fn validate_policy(&self, policy_text: &str) -> CedarValidationResult {
        match Policy::parse(None, policy_text) {
            Ok(_) => CedarValidationResult {
                valid: true,
                errors: Vec::new(),
            },
            Err(e) => CedarValidationResult {
                valid: false,
                errors: vec![e.to_string()],
            },
        }
    }

    /// Evaluate Cedar policies against a request.
    ///
    /// - `policies`: Cedar policy texts (ID → text).
    /// - `subject`: principal entity UID (e.g., `User::"alice"`, `Role::"admin"`).
    /// - `action`: action entity UID (e.g., `Action::"read"`).
    /// - `resource`: resource entity UID (e.g., `Resource::"doc_123"`).
    /// - `context`: ABAC context attributes (key-value pairs).
    pub fn evaluate(
        &self,
        policies: &[(String, String)],
        subject: &str,
        action: &str,
        resource: &str,
        context: &HashMap<String, String>,
    ) -> Result<CedarEvalResult, CedarError> {
        // Build PolicySet.
        let mut policy_set = PolicySet::new();
        for (id, text) in policies {
            let policy_id = PolicyId::new(id);
            let policy = Policy::parse(Some(policy_id), text)
                .map_err(|e| CedarError::InvalidPolicy(format!("{id}: {e}")))?;
            policy_set
                .add(policy)
                .map_err(|e| CedarError::InvalidPolicy(format!("duplicate policy {id}: {e}")))?;
        }

        // Parse entity UIDs.
        let entity = |field: &'static str, uid: &str| {
            EntityUid::from_str(uid).map_err(|e| CedarError::InvalidEntity {
                field,
                error: e.to_string(),
            })
        };
        let principal = entity("subject", subject)?;
        let action_uid = entity("action", action)?;
        let resource_uid = entity("resource", resource)?;

        // Build context from key-value pairs.
        let context_pairs: Vec<(String, cedar_policy::RestrictedExpression)> = context
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    cedar_policy::RestrictedExpression::new_string(v.clone()),
                )
            })
            .collect();

        let ctx = Context::from_pairs(context_pairs)
            .map_err(|e| CedarError::InvalidContext(e.to_string()))?;

        // Build request.
        let request = Request::new(principal, action_uid, resource_uid, ctx, None)
            .map_err(|e| CedarError::InvalidContext(format!("request: {e}")))?;

        // Empty entities for CE (no entity hierarchy).
        let entities = Entities::empty();

        // Evaluate.
        let response = self
            .authorizer
            .is_authorized(&request, &policy_set, &entities);

        let allowed = response.decision() == Decision::Allow;

        let mut matches = Vec::new();
        for reason in response.diagnostics().reason() {
            matches.push(CedarPolicyMatch {
                policy_id: reason.to_string(),
                effect: CedarEffect::Permit,
            });
        }

        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();

        Ok(CedarEvalResult {
            allowed,
            matches,
            errors,
        })
    }
}

impl Default for CedarService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> CedarService {
        CedarService::new()
    }

    #[test]
    fn test_validate_valid_policy() {
        let svc = service();
        let result = svc.validate_policy(r#"permit(principal, action, resource);"#);
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_invalid_policy() {
        let svc = service();
        let result = svc.validate_policy("not a valid cedar policy!!!");
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_validate_permit_with_condition() {
        let svc = service();
        let result = svc.validate_policy(
            r#"permit(
                principal == User::"alice",
                action == Action::"read",
                resource
            );"#,
        );
        assert!(result.valid);
    }

    #[test]
    fn test_validate_forbid_policy() {
        let svc = service();
        let result =
            svc.validate_policy(r#"forbid(principal, action == Action::"delete", resource);"#);
        assert!(result.valid);
    }

    #[test]
    fn test_evaluate_permit_all() {
        let svc = service();
        let policies = vec![(
            "allow_all".to_string(),
            r#"permit(principal, action, resource);"#.to_string(),
        )];

        let result = svc
            .evaluate(
                &policies,
                r#"User::"alice""#,
                r#"Action::"read""#,
                r#"Resource::"doc_1""#,
                &HashMap::new(),
            )
            .unwrap();

        assert!(result.allowed);
        assert!(!result.matches.is_empty());
    }

    #[test]
    fn test_evaluate_deny_by_default() {
        let svc = service();
        // No policies = default deny.
        let result = svc
            .evaluate(
                &[],
                r#"User::"alice""#,
                r#"Action::"read""#,
                r#"Resource::"doc_1""#,
                &HashMap::new(),
            )
            .unwrap();

        assert!(!result.allowed);
    }

    #[test]
    fn test_evaluate_specific_principal() {
        let svc = service();
        let policies = vec![(
            "alice_only".to_string(),
            r#"permit(
                principal == User::"alice",
                action == Action::"read",
                resource
            );"#
            .to_string(),
        )];

        // Alice → allowed.
        let result = svc
            .evaluate(
                &policies,
                r#"User::"alice""#,
                r#"Action::"read""#,
                r#"Resource::"doc_1""#,
                &HashMap::new(),
            )
            .unwrap();
        assert!(result.allowed);

        // Bob → denied.
        let result = svc
            .evaluate(
                &policies,
                r#"User::"bob""#,
                r#"Action::"read""#,
                r#"Resource::"doc_1""#,
                &HashMap::new(),
            )
            .unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn test_evaluate_forbid_overrides_permit() {
        let svc = service();
        let policies = vec![
            (
                "allow_all".to_string(),
                r#"permit(principal, action, resource);"#.to_string(),
            ),
            (
                "deny_delete".to_string(),
                r#"forbid(principal, action == Action::"delete", resource);"#.to_string(),
            ),
        ];

        // Read → allowed (permit matches, forbid doesn't).
        let result = svc
            .evaluate(
                &policies,
                r#"User::"alice""#,
                r#"Action::"read""#,
                r#"Resource::"doc_1""#,
                &HashMap::new(),
            )
            .unwrap();
        assert!(result.allowed);

        // Delete → denied (forbid overrides permit).
        let result = svc
            .evaluate(
                &policies,
                r#"User::"alice""#,
                r#"Action::"delete""#,
                r#"Resource::"doc_1""#,
                &HashMap::new(),
            )
            .unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn test_evaluate_with_context() {
        let svc = service();
        let policies = vec![(
            "dept_check".to_string(),
            r#"permit(
                principal,
                action == Action::"read",
                resource
            ) when {
                context.department == "engineering"
            };"#
            .to_string(),
        )];

        // With matching department → allowed.
        let mut ctx = HashMap::new();
        ctx.insert("department".to_string(), "engineering".to_string());
        let result = svc
            .evaluate(
                &policies,
                r#"User::"alice""#,
                r#"Action::"read""#,
                r#"Resource::"doc_1""#,
                &ctx,
            )
            .unwrap();
        assert!(result.allowed);

        // With non-matching department → denied.
        ctx.insert("department".to_string(), "marketing".to_string());
        let result = svc
            .evaluate(
                &policies,
                r#"User::"alice""#,
                r#"Action::"read""#,
                r#"Resource::"doc_1""#,
                &ctx,
            )
            .unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn test_evaluate_invalid_entity() {
        let svc = service();
        let result = svc.evaluate(
            &[],
            "not_a_valid_entity",
            r#"Action::"read""#,
            r#"Resource::"doc""#,
            &HashMap::new(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_invalid_policy_text() {
        let svc = service();
        let policies = vec![("bad".to_string(), "not valid cedar!!!".to_string())];
        let result = svc.evaluate(
            &policies,
            r#"User::"alice""#,
            r#"Action::"read""#,
            r#"Resource::"doc""#,
            &HashMap::new(),
        );
        assert!(result.is_err());
    }
}
