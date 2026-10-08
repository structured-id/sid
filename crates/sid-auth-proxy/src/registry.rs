// SPDX-License-Identifier: AGPL-3.0-only
//! Application registry — YAML-based protected app definitions.
//!
//! Informational (logging, metrics per-app). Actual protection via route policies.

use serde::Deserialize;

use super::translation::AuthTranslation;

/// Application registry loaded from YAML.
#[derive(Debug, Deserialize)]
pub struct AppRegistry {
    #[serde(default)]
    pub applications: Vec<AppDefinition>,
}

/// A protected application definition.
#[derive(Debug, Clone, Deserialize)]
pub struct AppDefinition {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub external_url: Option<String>,
    #[serde(default)]
    pub auth_translation: Option<AuthTranslation>,
    #[serde(default)]
    pub policy: Option<AppPolicy>,
    #[serde(default)]
    pub health_check: Option<HealthCheck>,
}

/// App-level policy (simplified, real enforcement via route policies).
#[derive(Debug, Clone, Deserialize)]
pub struct AppPolicy {
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub require: Option<AppRequirements>,
}

/// App requirements.
#[derive(Debug, Clone, Deserialize)]
pub struct AppRequirements {
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Health check configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheck {
    pub path: String,
    #[serde(default = "default_interval")]
    pub interval: String,
}

fn default_interval() -> String {
    "30s".into()
}

impl AppRegistry {
    /// Load application registry from a YAML file.
    pub fn load(path: &str) -> Result<Self, RegistryError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| RegistryError::IoError(path.into(), e))?;
        Self::from_yaml(&content)
    }

    /// Parse from YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, RegistryError> {
        serde_yaml::from_str(yaml).map_err(RegistryError::YamlError)
    }

    /// Find an application by ID.
    pub fn get(&self, id: &str) -> Option<&AppDefinition> {
        self.applications.iter().find(|a| a.id == id)
    }

    /// Number of registered applications.
    pub fn len(&self) -> usize {
        self.applications.len()
    }

    /// Check if registry is empty.
    pub fn is_empty(&self) -> bool {
        self.applications.is_empty()
    }
}

/// Registry loading error.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("failed to read registry file {0}: {1}")]
    IoError(String, std::io::Error),
    #[error("invalid YAML: {0}")]
    YamlError(#[from] serde_yaml::Error),
}

#[cfg(test)]
mod tests;
