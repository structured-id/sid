// SPDX-License-Identifier: AGPL-3.0-only
//! Passkey Registration Prompt Service.
//!
//! Decides whether and how to prompt users to register a passkey
//! after password-based authentication.
//!
//! Escalation: banner (skips 0-2) → modal (skips 3+) → stop (skip_limit).
//! Cooldown: skip counter resets after `skip_cooldown_days` of inactivity.
//! State persisted via ProfileMetadata (key = `passkey_prompt_state`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sid_core::models::security_policy::{PasskeyPromptConfig, PasskeyPromptMode};

/// ProfileMetadata key for passkey prompt state.
pub const PROFILE_METADATA_KEY: &str = "passkey_prompt_state";

/// Persisted state for a profile's passkey prompt interactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyPromptState {
    /// Number of times the user dismissed the prompt.
    pub skip_count: u32,
    /// When the user first dismissed the prompt.
    pub first_skipped_at: Option<DateTime<Utc>>,
    /// When the user last dismissed the prompt.
    pub last_skipped_at: Option<DateTime<Utc>>,
}

impl PasskeyPromptState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self {
            skip_count: 0,
            first_skipped_at: None,
            last_skipped_at: None,
        }
    }
}

impl Default for PasskeyPromptState {
    fn default() -> Self {
        Self::new()
    }
}

/// What kind of prompt to show the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptDecision {
    /// Dismissible banner at top of page.
    Banner,
    /// Modal dialog with benefits explanation.
    Modal,
    /// No prompt (has passkey, mode=none, or skip_limit exhausted).
    None,
}

impl PromptDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Banner => "banner",
            Self::Modal => "modal",
            Self::None => "none",
        }
    }
}

/// Decide what prompt to show based on policy, state, and credentials.
pub fn decide(
    config: &PasskeyPromptConfig,
    state: Option<&PasskeyPromptState>,
    has_passkey: bool,
) -> PromptDecision {
    // Already has passkey — no prompt needed.
    if has_passkey {
        return PromptDecision::None;
    }

    // Mode = none — voluntary only.
    if config.mode == PasskeyPromptMode::None {
        return PromptDecision::None;
    }

    let state = match state {
        Some(s) => s,
        // First time seeing this user — show banner.
        None => return PromptDecision::Banner,
    };

    // Check cooldown reset: if last skip was > cooldown_days ago, treat as fresh.
    if let Some(last) = state.last_skipped_at {
        let cooldown = chrono::Duration::days(config.skip_cooldown_days as i64);
        if Utc::now() - last > cooldown {
            return PromptDecision::Banner;
        }
    }

    // Exhausted skip limit — stop nagging.
    if state.skip_count >= config.skip_limit {
        return PromptDecision::None;
    }

    // Escalation: skips 0-2 → banner, 3+ → modal.
    if state.skip_count >= 3 {
        PromptDecision::Modal
    } else {
        PromptDecision::Banner
    }
}

/// Record a prompt dismissal. Returns updated state.
///
/// Handles cooldown reset: if last skip was > `cooldown_days` ago,
/// counter resets to 0 before incrementing.
pub fn record_dismissal(
    state: Option<PasskeyPromptState>,
    cooldown_days: u32,
) -> PasskeyPromptState {
    let now = Utc::now();
    match state {
        Some(mut s) => {
            // Check cooldown reset.
            if let Some(last) = s.last_skipped_at
                && (now - last).num_days() > cooldown_days as i64
            {
                s.skip_count = 0;
                s.first_skipped_at = Some(now);
            }
            s.skip_count += 1;
            s.last_skipped_at = Some(now);
            s
        }
        None => PasskeyPromptState {
            skip_count: 1,
            first_skipped_at: Some(now),
            last_skipped_at: Some(now),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> PasskeyPromptConfig {
        PasskeyPromptConfig {
            mode: PasskeyPromptMode::Encouraged,
            skip_limit: 5,
            skip_cooldown_days: 14,
        }
    }

    // ── decide() tests ──────────────────────────────────────────

    #[test]
    fn test_decide_no_passkey_first_time_returns_banner() {
        let config = default_config();
        assert_eq!(decide(&config, None, false), PromptDecision::Banner);
    }

    #[test]
    fn test_decide_has_passkey_returns_none() {
        let config = default_config();
        assert_eq!(decide(&config, None, true), PromptDecision::None);
    }

    #[test]
    fn test_decide_mode_none_returns_none() {
        let config = PasskeyPromptConfig {
            mode: PasskeyPromptMode::None,
            skip_limit: 5,
            skip_cooldown_days: 14,
        };
        assert_eq!(decide(&config, None, false), PromptDecision::None);
    }

    #[test]
    fn test_decide_mode_required_first_time_returns_banner() {
        let config = PasskeyPromptConfig {
            mode: PasskeyPromptMode::Required,
            skip_limit: 5,
            skip_cooldown_days: 14,
        };
        assert_eq!(decide(&config, None, false), PromptDecision::Banner);
    }

    #[test]
    fn test_decide_skips_0_to_2_returns_banner() {
        let config = default_config();
        for count in 0..3 {
            let state = PasskeyPromptState {
                skip_count: count,
                first_skipped_at: Some(Utc::now()),
                last_skipped_at: Some(Utc::now()),
            };
            assert_eq!(
                decide(&config, Some(&state), false),
                PromptDecision::Banner,
                "skip_count={} should return Banner",
                count
            );
        }
    }

    #[test]
    fn test_decide_skips_3_plus_returns_modal() {
        let config = default_config();
        for count in 3..5 {
            let state = PasskeyPromptState {
                skip_count: count,
                first_skipped_at: Some(Utc::now()),
                last_skipped_at: Some(Utc::now()),
            };
            assert_eq!(
                decide(&config, Some(&state), false),
                PromptDecision::Modal,
                "skip_count={} should return Modal",
                count
            );
        }
    }

    #[test]
    fn test_decide_skip_limit_exhausted_returns_none() {
        let config = default_config();
        let state = PasskeyPromptState {
            skip_count: 5,
            first_skipped_at: Some(Utc::now()),
            last_skipped_at: Some(Utc::now()),
        };
        assert_eq!(decide(&config, Some(&state), false), PromptDecision::None);
    }

    #[test]
    fn test_decide_cooldown_reset_returns_banner() {
        let config = default_config();
        let state = PasskeyPromptState {
            skip_count: 4,
            first_skipped_at: Some(Utc::now() - chrono::Duration::days(30)),
            last_skipped_at: Some(Utc::now() - chrono::Duration::days(15)),
        };
        // Last skip was 15 days ago, cooldown is 14 → reset → banner.
        assert_eq!(decide(&config, Some(&state), false), PromptDecision::Banner);
    }

    #[test]
    fn test_decide_within_cooldown_keeps_escalation() {
        let config = default_config();
        let state = PasskeyPromptState {
            skip_count: 4,
            first_skipped_at: Some(Utc::now() - chrono::Duration::days(10)),
            last_skipped_at: Some(Utc::now() - chrono::Duration::days(5)),
        };
        // Last skip was 5 days ago, cooldown is 14 → still active → modal.
        assert_eq!(decide(&config, Some(&state), false), PromptDecision::Modal);
    }

    // ── record_dismissal() tests ────────────────────────────────

    #[test]
    fn test_record_dismissal_first_time() {
        let result = record_dismissal(None, 14);
        assert_eq!(result.skip_count, 1);
        assert!(result.first_skipped_at.is_some());
        assert!(result.last_skipped_at.is_some());
    }

    #[test]
    fn test_record_dismissal_increments() {
        let state = PasskeyPromptState {
            skip_count: 2,
            first_skipped_at: Some(Utc::now()),
            last_skipped_at: Some(Utc::now()),
        };
        let result = record_dismissal(Some(state), 14);
        assert_eq!(result.skip_count, 3);
    }

    #[test]
    fn test_record_dismissal_cooldown_reset() {
        let old = Utc::now() - chrono::Duration::days(20);
        let state = PasskeyPromptState {
            skip_count: 4,
            first_skipped_at: Some(old),
            last_skipped_at: Some(old),
        };
        let result = record_dismissal(Some(state), 14);
        // Cooldown reset: counter goes to 0, then +1.
        assert_eq!(result.skip_count, 1);
    }

    // ── Serde tests ─────────────────────────────────────────────

    #[test]
    fn test_passkey_prompt_state_serde_roundtrip() {
        let state = PasskeyPromptState {
            skip_count: 3,
            first_skipped_at: Some(Utc::now()),
            last_skipped_at: Some(Utc::now()),
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: PasskeyPromptState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.skip_count, 3);
        assert!(parsed.first_skipped_at.is_some());
    }

    #[test]
    fn test_passkey_prompt_state_default() {
        let state = PasskeyPromptState::default();
        assert_eq!(state.skip_count, 0);
        assert!(state.first_skipped_at.is_none());
        assert!(state.last_skipped_at.is_none());
    }

    #[test]
    fn test_prompt_decision_as_str() {
        assert_eq!(PromptDecision::Banner.as_str(), "banner");
        assert_eq!(PromptDecision::Modal.as_str(), "modal");
        assert_eq!(PromptDecision::None.as_str(), "none");
    }
}
