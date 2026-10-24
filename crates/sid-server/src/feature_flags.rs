// SPDX-License-Identifier: AGPL-3.0-only
//! Feature flag service — polls GitLab Unleash API for runtime toggles.
//!
//! Direct HTTP polling (no SDK). Simple boolean flags for operational control:
//! - `maintenance_mode` (default: OFF) — 503 everything except SaaS Admin
//! - `registration_enabled` (default: ON) — toggle user registration

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};
use tracing;

/// Configuration for GitLab Unleash feature flag polling.
#[derive(Debug, Clone)]
pub struct FeatureFlagConfig {
    /// GitLab Unleash endpoint URL.
    /// e.g., `https://gitlab.example.com/api/v4/feature_flags/unleash/42`
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

    /// When ON: organization creation is open to the public.
    /// When OFF: org creation hidden for general public.
    /// Feature Access rules (token, IP allowlist) still apply — closed beta
    /// testers can create orgs even when this flag is OFF.
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
    pub fn start_polling(&self) -> Result<(), sid_plugin::http::HttpClientError> {
        let config = match &self.config {
            Some(c) => c.clone(),
            None => {
                tracing::info!("Feature flags disabled — not polling");
                return Ok(());
            }
        };

        let client = sid_plugin::client_builder()?
            .timeout(Duration::from_secs(10))
            .build()?;
        let flags = self.flags.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(config.poll_interval_secs));
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
        Ok(())
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
mod tests;
