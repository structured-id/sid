// SPDX-License-Identifier: AGPL-3.0-only
//! A permission check and its decision, as [`crate::CeAuthzEngine`] takes
//! and answers them.

use std::collections::HashMap;

use thiserror::Error;

/// Why a permission check could not be decided.
#[derive(Debug, Error)]
pub enum AuthzError {
    #[error("permission check failed: {0}")]
    CheckFailed(String),

    #[error("invalid subject format: {0}")]
    InvalidSubject(String),

    #[error("invalid resource format: {0}")]
    InvalidResource(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("authorization error: {0}")]
    Other(String),
}

/// One permission check.
///
/// Subject and resource use typed prefixes: `user:<id>`, `machine:<id>`,
/// `project:<id>`, `oauth_resource:<id>`.
#[derive(Debug, Clone)]
pub struct AuthzCheckRequest {
    /// Who is requesting access, e.g. `user:<profile_id>`.
    pub subject: String,
    /// The action, `<resource_type>:<action>` (e.g. `profiles:read`).
    pub action: String,
    /// The resource, `project:<uuid>` or `<type>:<id>`.
    pub resource: String,
    /// Attributes for the Cedar policies (IP, device, time, custom).
    pub context: HashMap<String, String>,
}

/// The decision, with its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzCheckResponse {
    Allow {
        /// Why access was granted (e.g. "role:admin grants profiles:read").
        reason: String,
    },
    Deny {
        /// Why access was denied.
        reason: String,
    },
}

impl AuthzCheckResponse {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    pub fn reason(&self) -> &str {
        match self {
            Self::Allow { reason } | Self::Deny { reason } => reason,
        }
    }
}

#[cfg(test)]
mod tests;
