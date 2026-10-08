// SPDX-License-Identifier: AGPL-3.0-only
//! Policy enforcement decision model.
//!
//! Runtime result of evaluating a security policy against the current
//! session/profile state. Produced at login time and on step-up requests.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::device::DeviceAssurance;
use super::mfa::MfaMethod;
use super::principal::PrincipalType;
use super::session::AuthLevel;

/// Enforcement action — what to do with the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementAction {
    /// User meets all policy requirements. Proceed normally.
    Allow,
    /// User must complete additional authentication (MFA, re-auth).
    StepUp,
    /// Grace period active — allow access with compliance banner.
    Grace,
    /// Block access — hard enforcement or grace period expired.
    Block,
}

impl EnforcementAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::StepUp => "step_up",
            Self::Grace => "grace",
            Self::Block => "block",
        }
    }

    /// Whether the user is granted access (possibly with conditions).
    pub fn is_access_granted(&self) -> bool {
        matches!(self, Self::Allow | Self::Grace)
    }
}

impl std::fmt::Display for EnforcementAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the user must do to become compliant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RequiredAction {
    /// Enroll in MFA with one of the allowed methods.
    EnrollMfa { allowed_methods: Vec<MfaMethod> },
    /// Complete step-up authentication to reach target ACR.
    StepUpAuth { target_acr: AuthLevel },
    /// Register a device meeting minimum assurance.
    RegisterDevice { min_assurance: DeviceAssurance },
    /// Change password (expired or does not meet policy).
    ChangePassword,
    /// Verify a principal (email or phone).
    VerifyPrincipal { principal_type: PrincipalType },
}

/// A specific policy violation — what requirement was not met.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// Policy requirement key (e.g., "mfa_required", "min_acr", "device_assurance").
    pub requirement: String,

    /// Current state (e.g., "mfa: not_enrolled", "acr: aal1").
    pub current: String,

    /// Required state (e.g., "mfa: enrolled", "acr: aal2").
    pub required: String,

    /// Action the user must take to resolve this violation.
    pub action: RequiredAction,
}

/// Result of evaluating a security policy against the current session.
///
/// Produced by the enforcement engine at login and on sensitive operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementDecision {
    /// Overall action: allow, step-up, grace, or block.
    pub action: EnforcementAction,

    /// List of policy violations (empty if action is Allow).
    pub violations: Vec<PolicyViolation>,

    /// When the grace period expires (only set if action is Grace).
    pub grace_deadline: Option<DateTime<Utc>>,

    /// Days remaining until grace expiry.
    pub days_remaining: Option<u32>,

    /// Ordered list of actions the user should take to become compliant.
    pub required_actions: Vec<RequiredAction>,
}

impl EnforcementDecision {
    /// Create an "allow" decision with no violations.
    pub fn allow() -> Self {
        Self {
            action: EnforcementAction::Allow,
            violations: Vec::new(),
            grace_deadline: None,
            days_remaining: None,
            required_actions: Vec::new(),
        }
    }

    /// Create a "block" decision with violations.
    pub fn block(violations: Vec<PolicyViolation>) -> Self {
        let required_actions: Vec<RequiredAction> =
            violations.iter().map(|v| v.action.clone()).collect();
        Self {
            action: EnforcementAction::Block,
            violations,
            grace_deadline: None,
            days_remaining: None,
            required_actions,
        }
    }

    /// Whether the user is granted access.
    pub fn is_access_granted(&self) -> bool {
        self.action.is_access_granted()
    }

    /// Whether there are any violations.
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enforcement_action_as_str() {
        assert_eq!(EnforcementAction::Allow.as_str(), "allow");
        assert_eq!(EnforcementAction::StepUp.as_str(), "step_up");
        assert_eq!(EnforcementAction::Grace.as_str(), "grace");
        assert_eq!(EnforcementAction::Block.as_str(), "block");
    }

    #[test]
    fn test_enforcement_action_access_granted() {
        assert!(EnforcementAction::Allow.is_access_granted());
        assert!(EnforcementAction::Grace.is_access_granted());
        assert!(!EnforcementAction::StepUp.is_access_granted());
        assert!(!EnforcementAction::Block.is_access_granted());
    }

    #[test]
    fn test_enforcement_action_serde() {
        let a = EnforcementAction::StepUp;
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"step_up\"");
        let parsed: EnforcementAction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EnforcementAction::StepUp);
    }

    #[test]
    fn test_decision_allow() {
        let d = EnforcementDecision::allow();
        assert_eq!(d.action, EnforcementAction::Allow);
        assert!(d.violations.is_empty());
        assert!(d.required_actions.is_empty());
        assert!(d.grace_deadline.is_none());
        assert!(d.days_remaining.is_none());
        assert!(d.is_access_granted());
        assert!(!d.has_violations());
    }

    #[test]
    fn test_decision_block() {
        let violations = vec![PolicyViolation {
            requirement: "mfa_required".into(),
            current: "mfa: not_enrolled".into(),
            required: "mfa: enrolled".into(),
            action: RequiredAction::EnrollMfa {
                allowed_methods: vec![MfaMethod::WebAuthn, MfaMethod::Totp],
            },
        }];
        let d = EnforcementDecision::block(violations);
        assert_eq!(d.action, EnforcementAction::Block);
        assert_eq!(d.violations.len(), 1);
        assert_eq!(d.required_actions.len(), 1);
        assert!(!d.is_access_granted());
        assert!(d.has_violations());
    }

    #[test]
    fn test_decision_block_multiple_violations() {
        let violations = vec![
            PolicyViolation {
                requirement: "mfa_required".into(),
                current: "mfa: not_enrolled".into(),
                required: "mfa: enrolled".into(),
                action: RequiredAction::EnrollMfa {
                    allowed_methods: vec![MfaMethod::WebAuthn],
                },
            },
            PolicyViolation {
                requirement: "min_acr".into(),
                current: "acr: aal1".into(),
                required: "acr: aal2".into(),
                action: RequiredAction::StepUpAuth {
                    target_acr: AuthLevel::Standard,
                },
            },
            PolicyViolation {
                requirement: "verified_email".into(),
                current: "email: unverified".into(),
                required: "email: verified".into(),
                action: RequiredAction::VerifyPrincipal {
                    principal_type: PrincipalType::Email,
                },
            },
        ];
        let d = EnforcementDecision::block(violations);
        assert_eq!(d.violations.len(), 3);
        assert_eq!(d.required_actions.len(), 3);
    }

    #[test]
    fn test_required_action_enroll_mfa_serde() {
        let action = RequiredAction::EnrollMfa {
            allowed_methods: vec![MfaMethod::WebAuthn, MfaMethod::Totp],
        };
        let json = serde_json::to_string(&action).unwrap();
        let parsed: RequiredAction = serde_json::from_str(&json).unwrap();
        if let RequiredAction::EnrollMfa { allowed_methods } = parsed {
            assert_eq!(allowed_methods.len(), 2);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_required_action_step_up_serde() {
        let action = RequiredAction::StepUpAuth {
            target_acr: AuthLevel::Elevated,
        };
        let json = serde_json::to_string(&action).unwrap();
        let parsed: RequiredAction = serde_json::from_str(&json).unwrap();
        if let RequiredAction::StepUpAuth { target_acr } = parsed {
            assert_eq!(target_acr, AuthLevel::Elevated);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_required_action_register_device_serde() {
        let action = RequiredAction::RegisterDevice {
            min_assurance: DeviceAssurance::Trusted,
        };
        let json = serde_json::to_string(&action).unwrap();
        let parsed: RequiredAction = serde_json::from_str(&json).unwrap();
        if let RequiredAction::RegisterDevice { min_assurance } = parsed {
            assert_eq!(min_assurance, DeviceAssurance::Trusted);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_required_action_change_password_serde() {
        let action = RequiredAction::ChangePassword;
        let json = serde_json::to_string(&action).unwrap();
        let parsed: RequiredAction = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, RequiredAction::ChangePassword));
    }

    #[test]
    fn test_required_action_verify_principal_serde() {
        let action = RequiredAction::VerifyPrincipal {
            principal_type: PrincipalType::Phone,
        };
        let json = serde_json::to_string(&action).unwrap();
        let parsed: RequiredAction = serde_json::from_str(&json).unwrap();
        if let RequiredAction::VerifyPrincipal { principal_type } = parsed {
            assert_eq!(principal_type, PrincipalType::Phone);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_policy_violation_serde_roundtrip() {
        let v = PolicyViolation {
            requirement: "device_assurance".into(),
            current: "device: unknown".into(),
            required: "device: trusted".into(),
            action: RequiredAction::RegisterDevice {
                min_assurance: DeviceAssurance::Trusted,
            },
        };
        let json = serde_json::to_string(&v).unwrap();
        let parsed: PolicyViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.requirement, "device_assurance");
    }

    #[test]
    fn test_enforcement_decision_serde_roundtrip() {
        let d = EnforcementDecision {
            action: EnforcementAction::Grace,
            violations: vec![PolicyViolation {
                requirement: "mfa_required".into(),
                current: "mfa: not_enrolled".into(),
                required: "mfa: enrolled".into(),
                action: RequiredAction::EnrollMfa {
                    allowed_methods: vec![MfaMethod::Totp],
                },
            }],
            grace_deadline: Some(Utc::now() + chrono::Duration::days(30)),
            days_remaining: Some(30),
            required_actions: vec![RequiredAction::EnrollMfa {
                allowed_methods: vec![MfaMethod::Totp],
            }],
        };
        let json = serde_json::to_string(&d).unwrap();
        let parsed: EnforcementDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action, EnforcementAction::Grace);
        assert!(parsed.is_access_granted());
        assert!(parsed.has_violations());
        assert_eq!(parsed.days_remaining, Some(30));
    }
}
