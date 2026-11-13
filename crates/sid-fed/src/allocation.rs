// SPDX-License-Identifier: AGPL-3.0-only
//! Which identifier allocation an installation reads and writes SID
//! certificate identifiers under.

use serde::{Deserialize, Serialize};

/// The identifier allocation of an installation. The development identifiers
/// are a temporary allocation in the arc reserved for documentation
/// (RFC 5612); they are never accepted under the production allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextAllocation {
    /// The temporary documentation-arc identifiers, for development only.
    Development,
    /// The registered structured.id identifiers.
    Production,
}

impl ContextAllocation {
    /// The allocation `name` names.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "development" => Some(Self::Development),
            "production" => Some(Self::Production),
            _ => None,
        }
    }
}
