// SPDX-License-Identifier: AGPL-3.0-only
//! Refusals every service gives the same way. Each carries `ErrorInfo` and
//! the detail its code calls for (`BadRequest`, `ResourceInfo`, `RetryInfo`);
//! an internal cause goes to the log, never to the client.

use std::time::Duration;

use tonic::Status;
use tracing::error;

use super::{ApiError, ErrorReason, Reason};

/// How long a client waits before retrying when shared state is unreachable.
pub const DEPENDENCY_RETRY_AFTER: Duration = Duration::from_secs(5);

/// An internal failure (storage, a broken invariant) of `operation`: logged
/// with its cause, answered with a generic INTERNAL_ERROR.
pub fn internal(operation: &'static str, cause: impl std::fmt::Display) -> Status {
    error!(operation, error = %cause, "internal failure");
    ApiError::internal().into()
}

/// A storage failure, for `map_err(storage_failure)`: logged with its cause,
/// answered with a generic INTERNAL_ERROR.
pub fn storage_failure(cause: impl std::fmt::Display) -> Status {
    internal("storage", cause)
}

/// REQUIRED_FIELD_MISSING for `field`.
pub fn missing_field(field: &'static str) -> Status {
    ApiError::new(
        ErrorReason::RequiredFieldMissing,
        format!("{field} is required"),
    )
    .with_field_violation(field, "required")
    .into()
}

/// INVALID_FIELD_VALUE for `field`, with what is wrong with it. The
/// description never repeats the submitted value.
pub fn invalid_field(field: &'static str, description: impl Into<String>) -> Status {
    let description = description.into();
    ApiError::new(ErrorReason::InvalidFieldValue, description.clone())
        .with_field_violation(field, description)
        .into()
}

/// A `*_NOT_FOUND` refusal naming the resource, in the vocabulary of
/// `reason`. Only for resources whose existence the caller may learn; account
/// lookups use the generic authentication refusal instead.
pub fn not_found<R: Reason>(
    reason: R,
    resource_type: &'static str,
    name: impl Into<String>,
) -> Status {
    ApiError::new(reason, format!("{resource_type} not found"))
        .with_resource(resource_type, name)
        .into()
}

/// A write that did not apply because the record changed since it was read;
/// the caller reads it again and retries at once.
pub fn changed_concurrently() -> Status {
    ApiError::new(
        ErrorReason::ConcurrentModification,
        "the record changed while it was being updated",
    )
    .with_retry_after(Duration::ZERO)
    .into()
}

/// The caller's authority changed between its check and the write: nothing
/// was written, and a repeated request is authenticated and authorized anew.
pub fn authority_changed() -> Status {
    ApiError::new(
        ErrorReason::ConcurrentModification,
        "the caller's authority changed while the request was being applied",
    )
    .with_retry_after(Duration::ZERO)
    .into()
}

/// FEATURE_NOT_AVAILABLE: `feature` is not part of this server build. The
/// contract names no edition; InstanceInfo.edition names the build.
pub fn not_in_this_build(feature: &'static str) -> Status {
    ApiError::new(
        ErrorReason::FeatureNotAvailable,
        "this feature is not part of this server build",
    )
    .with_metadata("feature", feature)
    .into()
}

/// FEATURE_NOT_CONFIGURED: `feature` is part of this build but this
/// installation has it switched off; an administrator can enable it.
pub fn not_configured(feature: &'static str) -> Status {
    ApiError::new(
        ErrorReason::FeatureNotConfigured,
        format!("{feature} is not enabled on this installation"),
    )
    .with_metadata("feature", feature)
    .into()
}

/// How long a client waits before retrying during maintenance; the end of a
/// maintenance window is not known in advance, so this is a polling interval.
pub const MAINTENANCE_RETRY_AFTER: Duration = Duration::from_secs(60);

/// SERVICE_MAINTENANCE: the installation is in maintenance mode.
pub fn maintenance() -> Status {
    ApiError::new(
        ErrorReason::ServiceMaintenance,
        "the service is in maintenance mode",
    )
    .with_retry_after(MAINTENANCE_RETRY_AFTER)
    .into()
}

/// DEPENDENCY_UNAVAILABLE: `what` cannot be reached now; logged with its
/// cause, retried after [`DEPENDENCY_RETRY_AFTER`].
pub fn dependency_unavailable(what: &'static str, cause: impl std::fmt::Display) -> Status {
    tracing::warn!(dependency = what, error = %cause, "dependency unavailable");
    ApiError::new(
        ErrorReason::DependencyUnavailable,
        format!("{what} is temporarily unavailable"),
    )
    .with_retry_after(DEPENDENCY_RETRY_AFTER)
    .into()
}

#[cfg(test)]
mod tests;
