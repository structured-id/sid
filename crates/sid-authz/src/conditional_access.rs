// SPDX-License-Identifier: AGPL-3.0-only
//! CE Conditional Access Engine.
//!
//! Evaluates security policy against session state to produce an
//! `EnforcementDecision` (Allow, StepUp, Block).
//!
//! CE scope: `required_auth_level` + `enforcement_mode` (strictest wins merge).
//! EE extends with AMR, device assurance, identifier verification, grace periods.
//! See `arch/authz/conditional-access.md` for full architecture.

use sid_core::models::enforcement::{
    EnforcementAction, EnforcementDecision, PolicyViolation, RequiredAction,
};
use sid_core::models::oauth2_client::OAuth2Client;
use sid_core::models::security_policy::{EnforcementMode, SecurityPolicy};
use sid_core::models::session::{AuthLevel, Session};

/// Effective policy resolved from org SecurityPolicy + per-app OAuth2Client overrides.
///
/// CE merges only `min_acr` and `enforcement_mode` (strictest wins).
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    /// Minimum required authentication level.
    pub min_acr: AuthLevel,
    /// How to handle violations.
    pub enforcement_mode: EnforcementMode,
}

/// CE Conditional Access Engine.
///
/// Stateless evaluator. Takes policy + session → decision.
pub struct ConditionalAccessEngine;

impl ConditionalAccessEngine {
    /// Resolve effective policy by merging org policy with per-app overrides
    /// and the level the relying party asked for.
    ///
    /// Merge rule: strictest value wins per field.
    /// - `min_acr`: max(org, client, requested); `requested` is the level
    ///   mapped from the authorization request's `acr_values` (OpenID Connect
    ///   Core 1.0 §3.1.2.1)
    /// - `enforcement_mode`: max(org, client) where Audit < Soft < Hard
    pub fn resolve_effective_policy(
        org_policy: &SecurityPolicy,
        client: Option<&OAuth2Client>,
        requested: Option<AuthLevel>,
    ) -> EffectivePolicy {
        let mut min_acr = org_policy.auth.min_acr;
        let mut enforcement_mode = org_policy.enforcement.mode;
        if let Some(c) = client {
            min_acr = min_acr.max(c.required_acr.unwrap_or(min_acr));
            enforcement_mode = enforcement_mode.max(c.enforcement_mode);
        }
        if let Some(level) = requested {
            min_acr = min_acr.max(level);
        }
        EffectivePolicy {
            min_acr,
            enforcement_mode,
        }
    }

    /// Evaluate session against effective policy.
    ///
    /// Returns an `EnforcementDecision`:
    /// - `Allow` if session meets all requirements.
    /// - `StepUp` if session auth level is below required (can be elevated).
    /// - `Block` if enforcement is `Hard` and requirements not met.
    /// - `Allow` (log-only) if enforcement is `Audit` and requirements not met.
    pub fn evaluate(policy: &EffectivePolicy, session: &Session) -> EnforcementDecision {
        let mut violations = Vec::new();

        // Check the auth level in force now (a lapsed step-up no longer counts).
        let assurance = session.assurance_at(chrono::Utc::now());
        if assurance < policy.min_acr {
            violations.push(PolicyViolation {
                requirement: "min_acr".to_string(),
                current: format!("acr: {}", assurance),
                required: format!("acr: {}", policy.min_acr),
                action: RequiredAction::StepUpAuth {
                    target_acr: policy.min_acr,
                },
            });
        }

        if violations.is_empty() {
            return EnforcementDecision::allow();
        }

        // Violations exist — decide based on enforcement mode.
        match policy.enforcement_mode {
            EnforcementMode::Audit => {
                // Log only — allow access but include violations for observability.
                EnforcementDecision {
                    action: EnforcementAction::Allow,
                    required_actions: violations.iter().map(|v| v.action.clone()).collect(),
                    violations,
                    grace_deadline: None,
                    days_remaining: None,
                }
            }
            EnforcementMode::Soft => {
                // CE doesn't implement grace periods — treat as step-up.
                // EE would check grace period state here.
                let required_actions: Vec<RequiredAction> =
                    violations.iter().map(|v| v.action.clone()).collect();
                EnforcementDecision {
                    action: EnforcementAction::StepUp,
                    violations,
                    grace_deadline: None,
                    days_remaining: None,
                    required_actions,
                }
            }
            EnforcementMode::Hard => {
                // Can the user resolve via step-up? Check if it's an ACR issue.
                let can_step_up = violations
                    .iter()
                    .all(|v| matches!(v.action, RequiredAction::StepUpAuth { .. }));

                if can_step_up {
                    let required_actions: Vec<RequiredAction> =
                        violations.iter().map(|v| v.action.clone()).collect();
                    EnforcementDecision {
                        action: EnforcementAction::StepUp,
                        violations,
                        grace_deadline: None,
                        days_remaining: None,
                        required_actions,
                    }
                } else {
                    EnforcementDecision::block(violations)
                }
            }
        }
    }

    /// Convenience: resolve + evaluate in one call.
    pub fn check(
        org_policy: &SecurityPolicy,
        client: Option<&OAuth2Client>,
        requested: Option<AuthLevel>,
        session: &Session,
    ) -> EnforcementDecision {
        let effective = Self::resolve_effective_policy(org_policy, client, requested);
        Self::evaluate(&effective, session)
    }
}

#[cfg(test)]
mod tests;
