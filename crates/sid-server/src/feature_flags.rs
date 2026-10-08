// SPDX-License-Identifier: AGPL-3.0-only
//! Feature flag service — polls GitLab Unleash API for runtime toggles.
//!
//! Direct HTTP polling (no SDK). Simple boolean flags for operational control:
//! - `maintenance_mode` (default: OFF) — 503 everything except SaaS Admin
//! - `registration_enabled` (default: ON) — toggle user registration
//!
//! See `arch/infra/feature-flags.md` for full architecture.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};
use tracing;

/// Configuration for GitLab Unleash feature flag polling.
#[derive(Debug, Clone)]
pub struct FeatureFlagConfig {
    /// GitLab Unleash endpoint URL.
    /// e.g., `https://git.private.systems/api/v4/feature_flags/unleash/42`
    pub api_url: String,

    /// Instance ID from GitLab (Deploy → Feature Flags → Configure).
    pub instance_id: String,

    /// Environment name sent as `unleash-appname` header.
    /// e.g., "production", "staging", "development"
    pub app_name: String,

    /// Polling interval in seconds (default: 15).
    pub poll_interval_secs: u64,
}

/// Well-known feature flag names.
pub mod flags {
    /// When ON: all interfaces return 503 except SaaS Admin.
    pub const MAINTENANCE_MODE: &str = "maintenance_mode";

    /// When OFF: user self-registration forms hidden, endpoints return 403.
    /// Invitation-based registration still works.
    /// Does NOT affect org/trial creation (see TRIAL_CREATION_ENABLED).
    pub const REGISTRATION_ENABLED: &str = "registration_enabled";

    /// When ON: SaaS CE/EE org creation open to public (post-launch).
    /// When OFF: org creation hidden for general public.
    /// Feature Access rules (token, IP allowlist) still apply — closed beta
    /// testers can create orgs even when this flag is OFF.
    /// See `arch/infra/feature-flags.md` → Feature Access section.
    pub const TRIAL_CREATION_ENABLED: &str = "trial_creation_enabled";
}

/// Runtime feature flag service.
///
/// Thread-safe, cheaply cloneable. Holds an in-memory cache of flag values
/// that is updated by a background polling task.
#[derive(Clone)]
pub struct FeatureFlagService {
    flags: Arc<RwLock<HashMap<String, bool>>>,
    config: Option<FeatureFlagConfig>,
}

impl FeatureFlagService {
    /// Create a new feature flag service with configuration.
    pub fn new(config: FeatureFlagConfig) -> Self {
        Self {
            flags: Arc::new(RwLock::new(HashMap::new())),
            config: Some(config),
        }
    }

    /// Create a disabled feature flag service (all flags return defaults).
    /// Used when `SID_FEATURE_FLAGS_ENABLED` is not set.
    pub fn disabled() -> Self {
        Self {
            flags: Arc::new(RwLock::new(HashMap::new())),
            config: None,
        }
    }

    /// Check if a feature flag is enabled.
    ///
    /// Returns `default` if the flag is unknown or has never been fetched.
    pub async fn is_enabled(&self, flag: &str, default: bool) -> bool {
        self.flags
            .read()
            .await
            .get(flag)
            .copied()
            .unwrap_or(default)
    }

    /// Check if maintenance mode is active (convenience method).
    pub async fn is_maintenance_mode(&self) -> bool {
        self.is_enabled(flags::MAINTENANCE_MODE, false).await
    }

    /// Check if user self-registration is enabled (convenience method).
    pub async fn is_registration_enabled(&self) -> bool {
        self.is_enabled(flags::REGISTRATION_ENABLED, true).await
    }

    /// Check if SaaS org/trial creation is publicly enabled (convenience method).
    ///
    /// When false, org creation is gated by Feature Access rules (token, IP).
    /// Default is false (closed beta until public launch).
    pub async fn is_trial_creation_enabled(&self) -> bool {
        self.is_enabled(flags::TRIAL_CREATION_ENABLED, false).await
    }

    /// Set a flag value directly. Used by tests and local development.
    pub async fn set_flag(&self, flag: &str, value: bool) {
        self.flags.write().await.insert(flag.to_string(), value);
    }

    /// Start background polling task (call once at startup).
    ///
    /// Does nothing if the service is disabled (no config).
    pub fn start_polling(&self) {
        let config = match &self.config {
            Some(c) => c.clone(),
            None => {
                tracing::info!("Feature flags disabled — not polling");
                return;
            }
        };

        let flags = self.flags.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(config.poll_interval_secs));
            let client = sid_plugin::client_builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client for feature flags");

            tracing::info!(
                url = %config.api_url,
                interval_secs = config.poll_interval_secs,
                "Feature flag polling started"
            );

            loop {
                tick.tick().await;
                match fetch_flags(&client, &config).await {
                    Ok(new_flags) => {
                        let mut guard = flags.write().await;
                        // Log changes
                        for (key, value) in &new_flags {
                            if guard.get(key) != Some(value) {
                                tracing::info!(flag = %key, enabled = %value, "Feature flag changed");
                            }
                        }
                        *guard = new_flags;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Feature flag poll failed — keeping last known state"
                        );
                    }
                }
            }
        });
    }
}

/// GitLab Unleash API response structure.
#[derive(serde::Deserialize)]
struct UnleashResponse {
    features: Vec<UnleashFeature>,
}

#[derive(serde::Deserialize)]
struct UnleashFeature {
    name: String,
    enabled: bool,
}

/// Fetch flags from GitLab Unleash API.
async fn fetch_flags(
    client: &reqwest::Client,
    config: &FeatureFlagConfig,
) -> Result<HashMap<String, bool>, String> {
    let url = format!("{}/features", config.api_url);
    let response = client
        .get(&url)
        .header("unleash-instanceid", &config.instance_id)
        .header("unleash-appname", &config.app_name)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("GitLab returned status {}", response.status()));
    }

    let body: UnleashResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    Ok(body
        .features
        .into_iter()
        .map(|f| (f.name, f.enabled))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_disabled_service_returns_defaults() {
        let svc = FeatureFlagService::disabled();

        // Default for maintenance_mode is false
        assert!(!svc.is_maintenance_mode().await);
        // Default for registration_enabled is true
        assert!(svc.is_registration_enabled().await);
        // Default for trial_creation_enabled is false (closed beta)
        assert!(!svc.is_trial_creation_enabled().await);
    }

    #[tokio::test]
    async fn test_is_enabled_returns_default_for_unknown_flag() {
        let svc = FeatureFlagService::disabled();

        assert!(svc.is_enabled("unknown_flag", true).await);
        assert!(!svc.is_enabled("unknown_flag", false).await);
    }

    #[tokio::test]
    async fn test_flags_can_be_set_directly() {
        let svc = FeatureFlagService::disabled();
        {
            let mut flags = svc.flags.write().await;
            flags.insert("maintenance_mode".into(), true);
            flags.insert("registration_enabled".into(), false);
        }

        assert!(svc.is_maintenance_mode().await);
        assert!(!svc.is_registration_enabled().await);
    }

    #[tokio::test]
    async fn test_flag_names_are_correct() {
        assert_eq!(flags::MAINTENANCE_MODE, "maintenance_mode");
        assert_eq!(flags::REGISTRATION_ENABLED, "registration_enabled");
        assert_eq!(flags::TRIAL_CREATION_ENABLED, "trial_creation_enabled");
    }

    #[tokio::test]
    async fn test_service_is_clone() {
        let svc = FeatureFlagService::disabled();
        let svc2 = svc.clone();

        // Shared state
        {
            svc.flags.write().await.insert("test".into(), true);
        }
        assert!(svc2.is_enabled("test", false).await);
    }

    #[test]
    fn test_config_creation() {
        let config = FeatureFlagConfig {
            api_url: "https://git.private.systems/api/v4/feature_flags/unleash/42".into(),
            instance_id: "test-instance-id".into(),
            app_name: "development".into(),
            poll_interval_secs: 15,
        };
        assert_eq!(config.poll_interval_secs, 15);
        assert_eq!(config.app_name, "development");
    }

    #[test]
    fn test_unleash_response_deserialization() {
        let json = r#"{
            "version": 1,
            "features": [
                { "name": "maintenance_mode", "enabled": true, "strategies": [] },
                { "name": "registration_enabled", "enabled": false, "strategies": [] }
            ]
        }"#;
        let response: UnleashResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.features.len(), 2);
        assert_eq!(response.features[0].name, "maintenance_mode");
        assert!(response.features[0].enabled);
        assert_eq!(response.features[1].name, "registration_enabled");
        assert!(!response.features[1].enabled);
    }

    #[test]
    fn test_unleash_response_empty_features() {
        let json = r#"{ "version": 1, "features": [] }"#;
        let response: UnleashResponse = serde_json::from_str(json).unwrap();
        assert!(response.features.is_empty());
    }
}
