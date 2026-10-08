// SPDX-License-Identifier: AGPL-3.0-only
//! Step-up authentication orchestration.
//!
//! Evaluates whether a session's current assurance level meets requirements
//! and determines what MFA methods to offer for elevation.
//!
//! CE built-in: evaluates session ACR vs target ACR, selects from available
//! MFA methods based on phishing resistance and session decay.

use sid_core::models::{
    AuthLevel, FactorProperties, MfaMethod, PhishingResistance, session::SessionDecayLevel,
};

/// Result of evaluating whether step-up is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepUpDecision {
    /// Current session satisfies the requirement.
    Satisfied,
    /// Step-up needed — MFA challenge required.
    StepUpRequired {
        /// Current session assurance level.
        current_acr: AuthLevel,
        /// Required assurance level.
        target_acr: AuthLevel,
        /// MFA methods available for step-up (ordered by preference).
        available_methods: Vec<MfaMethod>,
        /// Whether phishing-resistant method is required.
        require_phishing_resistant: bool,
    },
    /// Full re-authentication required (session too decayed).
    ReauthRequired,
}

/// Configuration for step-up evaluation.
#[derive(Debug, Clone)]
pub struct StepUpConfig {
    /// Whether phishing-resistant methods are required for elevated+ ACR.
    pub require_phishing_resistant_for_elevated: bool,
    /// Maximum decay level that allows step-up (vs requiring full re-auth).
    pub max_decay_for_step_up: SessionDecayLevel,
}

impl Default for StepUpConfig {
    fn default() -> Self {
        Self {
            require_phishing_resistant_for_elevated: true,
            max_decay_for_step_up: SessionDecayLevel::Medium,
        }
    }
}

/// Evaluate whether a step-up is required and what methods to offer.
///
/// # Arguments
/// * `current_acr` — Session's current assurance level.
/// * `target_acr` — Required assurance level for the operation.
/// * `decay_level` — Session's current decay level (time since authentication).
/// * `enrolled_methods` — MFA methods the user has enrolled.
/// * `config` — Step-up configuration.
pub fn evaluate_step_up(
    current_acr: AuthLevel,
    target_acr: AuthLevel,
    decay_level: SessionDecayLevel,
    enrolled_methods: &[MfaMethod],
    config: &StepUpConfig,
) -> StepUpDecision {
    // If current level already satisfies requirement, no step-up needed.
    if current_acr >= target_acr {
        return StepUpDecision::Satisfied;
    }

    // If session is too decayed, require full re-authentication.
    if decay_level > config.max_decay_for_step_up {
        return StepUpDecision::ReauthRequired;
    }

    // Determine if phishing-resistant is required for this target.
    let require_phishing_resistant =
        config.require_phishing_resistant_for_elevated && target_acr >= AuthLevel::Elevated;

    // Filter and sort available methods.
    let available_methods = select_methods(enrolled_methods, require_phishing_resistant);

    // If no methods available and phishing-resistant was required,
    // fall back to any enrolled methods.
    let available_methods = if available_methods.is_empty() && require_phishing_resistant {
        select_methods(enrolled_methods, false)
    } else {
        available_methods
    };

    StepUpDecision::StepUpRequired {
        current_acr,
        target_acr,
        available_methods,
        require_phishing_resistant,
    }
}

/// Select and order MFA methods for step-up.
///
/// Ordering priority:
/// 1. Phishing-resistant methods first (WebAuthn, HardwareKey)
/// 2. Standard methods (TOTP)
/// 3. Fallback methods (Recovery) — only if no other option
///
/// SMS OTP is excluded per `offer_only_as_fallback` unless it's the only option.
fn select_methods(enrolled: &[MfaMethod], require_phishing_resistant: bool) -> Vec<MfaMethod> {
    let mut methods: Vec<(MfaMethod, FactorProperties)> = enrolled
        .iter()
        .copied()
        .filter(|m| {
            // Skip recovery codes (emergency fallback, not for step-up).
            if *m == MfaMethod::Recovery {
                return false;
            }
            // If phishing-resistant required, only include those.
            if require_phishing_resistant {
                return m.factor_properties().resistance == PhishingResistance::PhishingResistant;
            }
            // Skip SMS OTP unless it's the only option (handled by caller fallback).
            if m.offer_only_as_fallback() {
                return false;
            }
            true
        })
        .map(|m| {
            let props = m.factor_properties();
            (m, props)
        })
        .collect();

    // Sort: phishing-resistant first, then by method priority.
    methods.sort_by(|a, b| {
        let a_pr = a.1.resistance == PhishingResistance::PhishingResistant;
        let b_pr = b.1.resistance == PhishingResistance::PhishingResistant;
        b_pr.cmp(&a_pr)
    });

    methods.into_iter().map(|(m, _)| m).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> StepUpConfig {
        StepUpConfig::default()
    }

    #[test]
    fn test_satisfied_when_acr_sufficient() {
        let result = evaluate_step_up(
            AuthLevel::Standard,
            AuthLevel::Standard,
            SessionDecayLevel::Full,
            &[MfaMethod::Totp],
            &default_config(),
        );
        assert_eq!(result, StepUpDecision::Satisfied);
    }

    #[test]
    fn test_satisfied_when_acr_exceeds() {
        let result = evaluate_step_up(
            AuthLevel::Elevated,
            AuthLevel::Standard,
            SessionDecayLevel::Full,
            &[MfaMethod::WebAuthn],
            &default_config(),
        );
        assert_eq!(result, StepUpDecision::Satisfied);
    }

    #[test]
    fn test_step_up_required_basic_to_standard() {
        let result = evaluate_step_up(
            AuthLevel::Basic,
            AuthLevel::Standard,
            SessionDecayLevel::Full,
            &[MfaMethod::Totp, MfaMethod::WebAuthn],
            &default_config(),
        );
        match result {
            StepUpDecision::StepUpRequired {
                current_acr,
                target_acr,
                available_methods,
                require_phishing_resistant,
            } => {
                assert_eq!(current_acr, AuthLevel::Basic);
                assert_eq!(target_acr, AuthLevel::Standard);
                assert!(!require_phishing_resistant);
                assert!(!available_methods.is_empty());
                // WebAuthn should be first (phishing-resistant preferred).
                assert_eq!(available_methods[0], MfaMethod::WebAuthn);
            }
            other => panic!("expected StepUpRequired, got {:?}", other),
        }
    }

    #[test]
    fn test_step_up_to_elevated_requires_phishing_resistant() {
        let result = evaluate_step_up(
            AuthLevel::Basic,
            AuthLevel::Elevated,
            SessionDecayLevel::Full,
            &[MfaMethod::Totp, MfaMethod::WebAuthn],
            &default_config(),
        );
        match result {
            StepUpDecision::StepUpRequired {
                available_methods,
                require_phishing_resistant,
                ..
            } => {
                assert!(require_phishing_resistant);
                // Only WebAuthn should be offered (phishing-resistant).
                assert_eq!(available_methods, vec![MfaMethod::WebAuthn]);
            }
            other => panic!("expected StepUpRequired, got {:?}", other),
        }
    }

    #[test]
    fn test_reauth_required_when_too_decayed() {
        let result = evaluate_step_up(
            AuthLevel::Basic,
            AuthLevel::Standard,
            SessionDecayLevel::Low,
            &[MfaMethod::Totp],
            &default_config(),
        );
        assert_eq!(result, StepUpDecision::ReauthRequired);
    }

    #[test]
    fn test_step_up_with_medium_decay() {
        // Medium decay is within max_decay_for_step_up (default).
        let result = evaluate_step_up(
            AuthLevel::Basic,
            AuthLevel::Standard,
            SessionDecayLevel::Medium,
            &[MfaMethod::Totp],
            &default_config(),
        );
        match result {
            StepUpDecision::StepUpRequired { .. } => {}
            other => panic!("expected StepUpRequired, got {:?}", other),
        }
    }

    #[test]
    fn test_recovery_codes_excluded_from_step_up() {
        let result = evaluate_step_up(
            AuthLevel::Basic,
            AuthLevel::Standard,
            SessionDecayLevel::Full,
            &[MfaMethod::Recovery, MfaMethod::Totp],
            &default_config(),
        );
        match result {
            StepUpDecision::StepUpRequired {
                available_methods, ..
            } => {
                assert!(!available_methods.contains(&MfaMethod::Recovery));
                assert!(available_methods.contains(&MfaMethod::Totp));
            }
            other => panic!("expected StepUpRequired, got {:?}", other),
        }
    }

    #[test]
    fn test_sms_otp_excluded_when_better_available() {
        let result = evaluate_step_up(
            AuthLevel::Basic,
            AuthLevel::Standard,
            SessionDecayLevel::Full,
            &[MfaMethod::SmsOtp, MfaMethod::Totp],
            &default_config(),
        );
        match result {
            StepUpDecision::StepUpRequired {
                available_methods, ..
            } => {
                assert!(!available_methods.contains(&MfaMethod::SmsOtp));
                assert!(available_methods.contains(&MfaMethod::Totp));
            }
            other => panic!("expected StepUpRequired, got {:?}", other),
        }
    }

    #[test]
    fn test_fallback_to_any_when_no_phishing_resistant() {
        // User only has TOTP, target requires elevated (phishing-resistant).
        // Should fall back to TOTP since no phishing-resistant available.
        let result = evaluate_step_up(
            AuthLevel::Basic,
            AuthLevel::Elevated,
            SessionDecayLevel::Full,
            &[MfaMethod::Totp],
            &default_config(),
        );
        match result {
            StepUpDecision::StepUpRequired {
                available_methods, ..
            } => {
                assert!(available_methods.contains(&MfaMethod::Totp));
            }
            other => panic!("expected StepUpRequired, got {:?}", other),
        }
    }

    #[test]
    fn test_custom_config_no_phishing_resistant_requirement() {
        let config = StepUpConfig {
            require_phishing_resistant_for_elevated: false,
            ..Default::default()
        };
        let result = evaluate_step_up(
            AuthLevel::Basic,
            AuthLevel::Elevated,
            SessionDecayLevel::Full,
            &[MfaMethod::Totp],
            &config,
        );
        match result {
            StepUpDecision::StepUpRequired {
                require_phishing_resistant,
                available_methods,
                ..
            } => {
                assert!(!require_phishing_resistant);
                assert!(available_methods.contains(&MfaMethod::Totp));
            }
            other => panic!("expected StepUpRequired, got {:?}", other),
        }
    }

    #[test]
    fn test_webauthn_ordered_first() {
        let result = evaluate_step_up(
            AuthLevel::Basic,
            AuthLevel::Standard,
            SessionDecayLevel::Full,
            &[MfaMethod::Totp, MfaMethod::WebAuthn, MfaMethod::SmsOtp],
            &default_config(),
        );
        match result {
            StepUpDecision::StepUpRequired {
                available_methods, ..
            } => {
                // WebAuthn (phishing-resistant) should be first.
                assert_eq!(available_methods[0], MfaMethod::WebAuthn);
                // SMS OTP should be excluded.
                assert!(!available_methods.contains(&MfaMethod::SmsOtp));
            }
            other => panic!("expected StepUpRequired, got {:?}", other),
        }
    }

    #[test]
    fn test_select_methods_empty_enrolled() {
        let methods = select_methods(&[], false);
        assert!(methods.is_empty());
    }

    #[test]
    fn test_select_methods_only_recovery() {
        let methods = select_methods(&[MfaMethod::Recovery], false);
        assert!(methods.is_empty());
    }
}
