// SPDX-License-Identifier: AGPL-3.0-only
//! The installation configuration file the service host reads (`sid.yaml`):
//! what belongs to the installation's configuration rather than its store.

use anyhow::Context;
use serde::Deserialize;
use sid_core::models::SodConflictRule;

/// The installation configuration. A host that names no file has none.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationConfig {
    #[serde(default)]
    pub governance: Governance,
}

/// Governance settings of the installation.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Governance {
    /// The role conflicts an administrator is warned of when assigning.
    #[serde(default)]
    pub sod_warnings: Vec<SodConflictRule>,
}

/// The configuration in the file at `path`; none when no file is named. A
/// named file that cannot be read or parsed stops startup.
pub fn installation_config(path: Option<&str>) -> anyhow::Result<InstallationConfig> {
    let Some(path) = path.filter(|p| !p.is_empty()) else {
        return Ok(InstallationConfig::default());
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("installation configuration {path}"))?;
    parse(&text).with_context(|| format!("installation configuration {path}"))
}

fn parse(text: &str) -> anyhow::Result<InstallationConfig> {
    Ok(serde_saphyr::from_str(text)?)
}

#[cfg(test)]
mod tests;
