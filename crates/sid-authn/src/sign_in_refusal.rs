// SPDX-License-Identifier: AGPL-3.0-only
//! How every authority answers a refused password sign-in: one answer for
//! every failed credential, and the reason in `ErrorInfo` with what the
//! client must do as typed details, never in the status message.

use std::time::Duration;

use sid_core::grpc_error::refuse::storage_failure;
use sid_core::grpc_error::{ApiError, ErrorReason};
use tonic::Status;
use tracing::warn;

use crate::password_sign_in::PasswordSignInError;

/// How long a client waits before retrying a sign-in whose anomaly state
/// could not be read.
const ANOMALY_RETRY_AFTER: Duration = Duration::from_secs(5);

/// AUTHENTICATION_FAILED: the credential, code or proof does not verify. One
/// answer for every cause (unknown account, wrong secret, replayed code), so
/// the refusal tells nothing about which.
pub fn authentication_failed() -> Status {
    ApiError::new(ErrorReason::AuthenticationFailed, "authentication failed").into()
}

/// INVALID_STATE: the `ceremony` step names state that has expired or was
/// never issued (a sign-in, registration or enrollment between its steps);
/// the client starts the ceremony again.
pub fn ceremony_expired(ceremony: &'static str) -> Status {
    ApiError::new(
        ErrorReason::InvalidState,
        format!("the {ceremony} has expired; start it again"),
    )
    .with_precondition("CEREMONY_STATE", ceremony, "expired")
    .into()
}

/// RATE_LIMIT_EXCEEDED: too many sign-in attempts; QuotaFailure names the
/// limit and RetryInfo the longest wait (a lockout started earlier ends
/// sooner).
pub fn too_many_attempts(retry_after: Duration) -> Status {
    ApiError::new(ErrorReason::RateLimitExceeded, "too many sign-in attempts")
        .with_quota_violation("sign_in_attempts", "failed sign-in attempts per account")
        .with_retry_after(retry_after)
        .into()
}

/// DEPENDENCY_UNAVAILABLE for a sign-in whose anomaly state cannot be read.
pub fn anomaly_unavailable(e: impl std::fmt::Display) -> Status {
    warn!(error = %e, "anomaly state unavailable");
    ApiError::new(
        ErrorReason::DependencyUnavailable,
        "sign-in is temporarily unavailable",
    )
    .with_retry_after(ANOMALY_RETRY_AFTER)
    .into()
}

impl From<PasswordSignInError> for Status {
    fn from(e: PasswordSignInError) -> Self {
        match e {
            PasswordSignInError::AuthenticationFailed => authentication_failed(),
            PasswordSignInError::MigrationRequired => ApiError::new(
                ErrorReason::LegacyMigrationRequired,
                "the password must be migrated before signing in",
            )
            .with_precondition(
                "legacy_migration",
                "credential",
                "complete the password migration flow",
            )
            .into(),
            PasswordSignInError::Expired => ceremony_expired("sign-in"),
            PasswordSignInError::Storage(e) => storage_failure(e),
            PasswordSignInError::State(e) => e.into(),
        }
    }
}

#[cfg(test)]
mod tests;
