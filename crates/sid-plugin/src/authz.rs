// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization engine abstraction.
//!
//! `AuthzEngine` is the entry point for all permission checks across the system:
//! - SID internal (sid-identity → sid-authz)
//! - sid-auth route protection (forward auth → sid-authz)
//! - Customer application integration (direct gRPC/REST)

use std::collections::HashMap;

use async_trait::async_trait;
use thiserror::Error;

/// Errors from authorization operations.
#[derive(Debug, Error)]
pub enum AuthzError {
    #[error("permission check failed: {0}")]
    CheckFailed(String),

    #[error("invalid subject format: {0}")]
    InvalidSubject(String),

    #[error("invalid resource format: {0}")]
    InvalidResource(String),

    #[error("not supported in CE: {0}")]
    NotSupported(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("authorization error: {0}")]
    Other(String),
}

/// Authorization check request.
///
/// Subject and resource use typed prefixes: `user:<id>`, `service:<spiffe>`, `project:<id>`.
#[derive(Debug, Clone)]
pub struct AuthzCheckRequest {
    /// Who is requesting access. Format: `user:<profile_id>` or `service:<spiffe_id>`.
    pub subject: String,
    /// What action is being performed. Format: `<resource_type>:<action>` (e.g., `profiles:read`).
    pub action: String,
    /// What resource is being accessed. Format: `project:<uuid>` or `<type>:<id>`.
    pub resource: String,
    /// Additional context for ABAC/Cedar evaluation (IP, device, time, custom attributes).
    pub context: HashMap<String, String>,
}

/// Authorization decision with reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzCheckResponse {
    /// Access allowed.
    Allow {
        /// Why access was granted (e.g., "role:admin grants profiles:read").
        reason: String,
    },
    /// Access denied.
    Deny {
        /// Why access was denied.
        reason: String,
    },
}

impl AuthzCheckResponse {
    /// Returns true if access is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Returns the reason string for the decision.
    pub fn reason(&self) -> &str {
        match self {
            Self::Allow { reason } => reason,
            Self::Deny { reason } => reason,
        }
    }
}

/// Main authorization engine trait.
///
/// CE: RBAC (flat roles + groups) + ABAC (Cedar policies), all checks flat SQL queries,
/// implemented by `CeAuthzEngine` in `sid-authz` over `RbacService` + `CedarService`.
#[async_trait]
pub trait AuthzEngine: Send + Sync {
    /// Check if a subject is authorized to perform an action on a resource.
    ///
    /// Pipeline: RBAC role check → Cedar policy evaluation.
    async fn check(&self, request: &AuthzCheckRequest) -> Result<AuthzCheckResponse, AuthzError>;

    /// Batch permission check. Returns one response per request, in order.
    ///
    /// Default implementation iterates `check()`. Implementations may optimize.
    async fn batch_check(
        &self,
        requests: &[AuthzCheckRequest],
    ) -> Result<Vec<AuthzCheckResponse>, AuthzError> {
        let mut results = Vec::with_capacity(requests.len());
        for req in requests {
            results.push(self.check(req).await?);
        }
        Ok(results)
    }

    /// List all objects of a given type that a subject can access with a given permission.
    ///
    /// CE: returns `Err(AuthzError::NotSupported)`.
    async fn list_accessible_objects(
        &self,
        subject: &str,
        permission: &str,
        object_type: &str,
    ) -> Result<Vec<String>, AuthzError>;

    /// List all subjects that have a given permission on an object.
    ///
    /// CE: returns `Err(AuthzError::NotSupported)`.
    async fn list_subjects_with_access(
        &self,
        permission: &str,
        object: &str,
    ) -> Result<Vec<String>, AuthzError>;
}

#[cfg(test)]
mod tests;
