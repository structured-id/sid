// SPDX-License-Identifier: AGPL-3.0-only
//! A Profile's pairwise identity at one organization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::ProfileId;

/// Validated UUIDv7 identifier of a binding; construction and decoding go through `sid_ids`.
pub use sid_ids::BindingId;

/// The organization a binding belongs to: every client of one scope sees the
/// same BindingId for a Profile, clients of different scopes see unlinkable ones.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BindingScope(String);

/// A binding scope must name something.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a binding scope cannot be empty")]
pub struct EmptyBindingScope;

impl BindingScope {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for BindingScope {
    type Error = EmptyBindingScope;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.trim().is_empty() {
            return Err(EmptyBindingScope);
        }
        Ok(Self(value))
    }
}

impl From<BindingScope> for String {
    fn from(scope: BindingScope) -> Self {
        scope.0
    }
}

impl std::fmt::Display for BindingScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One Profile's binding to one scope, allocated on the first visit and
/// stable afterwards. `profile_id` never leaves the instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceBinding {
    pub binding_id: BindingId,
    pub profile_id: ProfileId,
    pub scope: BindingScope,
    /// Per-profile allocation counter, the last index of the binding's HD
    /// derivation path; unique within the profile.
    pub binding_index: u32,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests;
