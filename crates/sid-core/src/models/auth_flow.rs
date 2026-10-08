// SPDX-License-Identifier: AGPL-3.0-only
//! Auth flow configuration and actions.
//!
//! Auth flows are hardcoded type-state machines (compile-time guarantees).
//! This module defines the runtime *configuration* layer — admins can enable/disable
//! steps, set policies, and attach actions (webhook hooks), but cannot change flow structure.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::project::ProjectId;

// ── Flow Types ──

/// Built-in auth flow types. Each maps to a hardcoded Rust type-state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowType {
    /// Browser-based login (identification → password → MFA → consent → session).
    Authentication,
    /// New user registration.
    Registration,
    /// Account recovery (forgot password, recovery codes).
    Recovery,
    /// OAuth2 Device Authorization Grant (RFC 8628).
    DeviceGrant,
    /// Resource Owner Password Credentials (direct grant, no UI).
    DirectGrant,
    /// Post-login credential enrollment (add MFA, setup recovery).
    Enrollment,
}

impl FlowType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Registration => "registration",
            Self::Recovery => "recovery",
            Self::DeviceGrant => "device_grant",
            Self::DirectGrant => "direct_grant",
            Self::Enrollment => "enrollment",
        }
    }

    pub fn all() -> &'static [FlowType] {
        &[
            Self::Authentication,
            Self::Registration,
            Self::Recovery,
            Self::DeviceGrant,
            Self::DirectGrant,
            Self::Enrollment,
        ]
    }
}

impl std::fmt::Display for FlowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for FlowType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authentication" => Ok(Self::Authentication),
            "registration" => Ok(Self::Registration),
            "recovery" => Ok(Self::Recovery),
            "device_grant" => Ok(Self::DeviceGrant),
            "direct_grant" => Ok(Self::DirectGrant),
            "enrollment" => Ok(Self::Enrollment),
            _ => Err(format!("unknown flow type: {}", s)),
        }
    }
}

// ── Flow Configuration ──

/// Runtime configuration for a flow within a project.
///
/// Stored per (project_id, flow_type). Configures which steps are enabled
/// and their parameters — but flow structure is hardcoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowConfig {
    pub project_id: ProjectId,
    pub flow_type: FlowType,

    /// Per-step configuration (key = step type string, value = step config).
    pub steps: HashMap<String, StepConfig>,

    /// Flow-level timeout in seconds. Default: 300 (5 minutes).
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u32,

    pub updated_at: chrono::DateTime<chrono::Utc>,
}

fn default_timeout() -> u32 {
    300
}

/// Configuration for a single step within a flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepConfig {
    /// Whether this step is enabled. Disabled steps are skipped.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Step-specific parameters (e.g., identification fields, MFA methods).
    #[serde(default)]
    pub params: serde_json::Value,
}

fn default_true() -> bool {
    true
}

impl Default for StepConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            params: serde_json::Value::Null,
        }
    }
}

// ── Actions ──

/// Unique identifier for an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionId(pub Uuid);

impl ActionId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ActionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ActionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Hook points where actions can execute in the auth pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionPoint {
    /// Before credential verification.
    PreAuthentication,
    /// After successful authn, before MFA.
    PostAuthentication,
    /// After MFA challenge passed.
    PostMfa,
    /// Before JWT/session token issued.
    PreTokenCreation,
    /// After complete flow success.
    PostLogin,
    /// After profile created.
    PostRegistration,
    /// Before consent screen shown.
    PreConsent,
}

impl ActionPoint {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PreAuthentication => "pre_authentication",
            Self::PostAuthentication => "post_authentication",
            Self::PostMfa => "post_mfa",
            Self::PreTokenCreation => "pre_token_creation",
            Self::PostLogin => "post_login",
            Self::PostRegistration => "post_registration",
            Self::PreConsent => "pre_consent",
        }
    }

    pub fn all() -> &'static [ActionPoint] {
        &[
            Self::PreAuthentication,
            Self::PostAuthentication,
            Self::PostMfa,
            Self::PreTokenCreation,
            Self::PostLogin,
            Self::PostRegistration,
            Self::PreConsent,
        ]
    }
}

impl std::fmt::Display for ActionPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ActionPoint {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pre_authentication" => Ok(Self::PreAuthentication),
            "post_authentication" => Ok(Self::PostAuthentication),
            "post_mfa" => Ok(Self::PostMfa),
            "pre_token_creation" => Ok(Self::PreTokenCreation),
            "post_login" => Ok(Self::PostLogin),
            "post_registration" => Ok(Self::PostRegistration),
            "pre_consent" => Ok(Self::PreConsent),
            _ => Err(format!("unknown action point: {}", s)),
        }
    }
}

/// Action type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    /// HTTP POST to external URL (CE).
    Webhook,
}

impl ActionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
        }
    }
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Behavior when action execution fails.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionOnError {
    /// Skip the failed action and continue the flow.
    #[default]
    Continue,
    /// Deny the entire auth flow.
    Deny,
}

/// An action attached to a flow at a specific hook point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowAction {
    pub id: ActionId,

    /// Project this action belongs to.
    pub project_id: ProjectId,

    /// Which flow type this action is attached to.
    pub flow_type: FlowType,

    /// Hook point where this action executes.
    pub action_point: ActionPoint,

    /// Human-readable name.
    pub name: String,

    /// Action type (webhook for CE).
    pub action_type: ActionType,

    /// Type-specific configuration.
    pub config: ActionConfig,

    /// Execution order within the hook point (lower = first).
    pub order: i32,

    /// Behavior on execution failure.
    #[serde(default)]
    pub on_error: ActionOnError,

    /// Whether this action is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Stored revision: 0 for a new action, moved on by every update. An
    /// update applies only over the revision it was read at.
    #[serde(default)]
    pub revision: u64,

    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Action-type-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ActionConfig {
    /// Webhook: HTTP POST to URL.
    Webhook {
        /// Target URL.
        url: String,

        /// Request timeout in seconds (default: 5, max: 30).
        #[serde(default = "default_webhook_timeout")]
        timeout_seconds: u32,

        /// Number of retries on failure (default: 0, max: 3).
        #[serde(default)]
        retry_count: u32,

        /// Additional headers to send with the webhook request.
        #[serde(default)]
        headers: HashMap<String, String>,
    },
}

fn default_webhook_timeout() -> u32 {
    5
}

impl ActionConfig {
    /// Validate action config constraints.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            ActionConfig::Webhook {
                url,
                timeout_seconds,
                retry_count,
                ..
            } => {
                if url.is_empty() {
                    return Err("webhook URL is required".into());
                }
                if !url.starts_with("https://") && !url.starts_with("http://") {
                    return Err("webhook URL must start with http:// or https://".into());
                }
                if *timeout_seconds == 0 || *timeout_seconds > 30 {
                    return Err("webhook timeout must be between 1 and 30 seconds".into());
                }
                if *retry_count > 3 {
                    return Err("webhook retry count must be between 0 and 3".into());
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_type_roundtrip() {
        for ft in FlowType::all() {
            let s = ft.as_str();
            let parsed: FlowType = s.parse().unwrap();
            assert_eq!(&parsed, ft);
        }
    }

    #[test]
    fn test_flow_type_unknown() {
        assert!("unknown".parse::<FlowType>().is_err());
    }

    #[test]
    fn test_action_point_roundtrip() {
        for ap in ActionPoint::all() {
            let s = ap.as_str();
            let parsed: ActionPoint = s.parse().unwrap();
            assert_eq!(&parsed, ap);
        }
    }

    #[test]
    fn test_action_point_unknown() {
        assert!("unknown".parse::<ActionPoint>().is_err());
    }

    #[test]
    fn test_flow_config_serde() {
        let mut steps = HashMap::new();
        steps.insert(
            "identification".to_string(),
            StepConfig {
                enabled: true,
                params: serde_json::json!({
                    "fields": ["username", "email"],
                    "passkey_autofill": true
                }),
            },
        );
        steps.insert(
            "password".to_string(),
            StepConfig {
                enabled: true,
                params: serde_json::json!({"method": "opaque"}),
            },
        );

        let config = FlowConfig {
            project_id: ProjectId::new(),
            flow_type: FlowType::Authentication,
            steps,
            timeout_seconds: 300,
            updated_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: FlowConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.flow_type, FlowType::Authentication);
        assert_eq!(parsed.steps.len(), 2);
        assert!(parsed.steps.contains_key("identification"));
    }

    #[test]
    fn test_step_config_default() {
        let step = StepConfig::default();
        assert!(step.enabled);
        assert!(step.params.is_null());
    }

    #[test]
    fn test_flow_action_serde() {
        let action = FlowAction {
            id: ActionId::new(),
            project_id: ProjectId::new(),
            flow_type: FlowType::Authentication,
            action_point: ActionPoint::PostAuthentication,
            name: "Enrich context".into(),
            action_type: ActionType::Webhook,
            config: ActionConfig::Webhook {
                url: "https://risk.example.com/evaluate".into(),
                timeout_seconds: 3,
                retry_count: 1,
                headers: HashMap::new(),
            },
            order: 1,
            on_error: ActionOnError::Continue,
            enabled: true,
            revision: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&action).unwrap();
        let parsed: FlowAction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "Enrich context");
        assert_eq!(parsed.action_point, ActionPoint::PostAuthentication);
        assert_eq!(parsed.order, 1);
    }

    #[test]
    fn test_action_config_validate_valid() {
        let config = ActionConfig::Webhook {
            url: "https://example.com/hook".into(),
            timeout_seconds: 5,
            retry_count: 1,
            headers: HashMap::new(),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_action_config_validate_empty_url() {
        let config = ActionConfig::Webhook {
            url: "".into(),
            timeout_seconds: 5,
            retry_count: 0,
            headers: HashMap::new(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_action_config_validate_invalid_scheme() {
        let config = ActionConfig::Webhook {
            url: "ftp://example.com".into(),
            timeout_seconds: 5,
            retry_count: 0,
            headers: HashMap::new(),
        };
        assert!(config.validate().unwrap_err().contains("http"));
    }

    #[test]
    fn test_action_config_validate_timeout_zero() {
        let config = ActionConfig::Webhook {
            url: "https://example.com".into(),
            timeout_seconds: 0,
            retry_count: 0,
            headers: HashMap::new(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_action_config_validate_timeout_too_high() {
        let config = ActionConfig::Webhook {
            url: "https://example.com".into(),
            timeout_seconds: 31,
            retry_count: 0,
            headers: HashMap::new(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_action_config_validate_retry_too_high() {
        let config = ActionConfig::Webhook {
            url: "https://example.com".into(),
            timeout_seconds: 5,
            retry_count: 4,
            headers: HashMap::new(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_action_on_error_default() {
        assert_eq!(ActionOnError::default(), ActionOnError::Continue);
    }

    #[test]
    fn test_action_id_unique() {
        let id1 = ActionId::new();
        let id2 = ActionId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_flow_config_default_timeout() {
        let json = r#"{"project_id":"550e8400-e29b-41d4-a716-446655440000","flow_type":"authentication","steps":{},"updated_at":"2026-03-10T00:00:00Z"}"#;
        let config: FlowConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.timeout_seconds, 300);
    }
}
