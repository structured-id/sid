// SPDX-License-Identifier: AGPL-3.0-only
//! Core error types for StructuredID.
//!
//! Domain-level errors used across all service crates.
//! Service-specific errors (gRPC codes, delivery errors) belong in their respective crates.

use thiserror::Error;

/// Core error type for StructuredID operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Resource not found (profile, credential, session, etc.).
    #[error("Not found: {0}")]
    NotFound(String),

    /// Input validation failed (format, length, constraints).
    #[error("Validation error: {0}")]
    Validation(String),

    /// Authentication failed (wrong password, invalid WebAuthn assertion, etc.).
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Authorization denied (insufficient permissions, Cedar policy denied).
    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

    /// Resource already exists or state conflict (duplicate username, SoD violation).
    #[error("Conflict: {0}")]
    Conflict(String),

    /// The caller's keyed command is already completed: this attempt
    /// committed nothing, and the caller resolves the recorded result.
    #[error("Operation already completed: {0}")]
    OperationCompleted(String),

    /// The authority a mutation was authorized under changed before it
    /// committed (a connector disabled, a grant or credential revoked): the
    /// mutation committed nothing and is decided again from the start.
    #[error("Fenced: {0}")]
    Fenced(String),

    /// Resource has expired (session, token, challenge, OTP code).
    #[error("Expired: {0}")]
    Expired(String),

    /// Resource has been revoked (credential, token, session).
    #[error("Revoked: {0}")]
    Revoked(String),

    /// Rate limit exceeded (OTP requests, login attempts, API calls).
    #[error("Rate limited: {0}")]
    RateLimited(String),

    /// Invalid state transition (e.g., closing an already closed profile).
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Security policy violation (MFA not enrolled, password too weak, etc.).
    /// The enforcement engine produces `EnforcementDecision` with details;
    /// this error is for cases where access must be blocked.
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// A bounded resource is full (pending work queue): the operation is not
    /// accepted rather than accepted without its required work.
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    /// Upstream dependency unavailable (database, cache, external service).
    #[error("Unavailable: {0}")]
    Unavailable(String),

    /// Storage layer error (database, cache, blob store).
    #[error("Storage error: {0}")]
    Storage(String),

    /// Unrecoverable internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Whether this error indicates the operation can be retried.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Unavailable(_) | Self::RateLimited(_) | Self::Fenced(_)
        )
    }

    /// Whether this error is a client error (4xx equivalent).
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::NotFound(_)
                | Self::Validation(_)
                | Self::AuthenticationFailed(_)
                | Self::AuthorizationDenied(_)
                | Self::Conflict(_)
                | Self::OperationCompleted(_)
                | Self::Fenced(_)
                | Self::Expired(_)
                | Self::Revoked(_)
                | Self::RateLimited(_)
                | Self::InvalidState(_)
                | Self::PolicyViolation(_)
        )
    }

    /// Whether this error is a server error (5xx equivalent).
    pub fn is_server_error(&self) -> bool {
        matches!(
            self,
            Self::Unavailable(_) | Self::Storage(_) | Self::Internal(_)
        )
    }
}

/// Result type alias using the core Error.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
