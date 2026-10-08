// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM refusals. Each carries the canonical `ErrorInfo` and, where RFC 7644
//! §3.12 defines one, the `scimType` as `ErrorInfo` metadata, so an HTTP
//! rendering can produce the SCIM error body from the status alone.

use sid_core::Error as SidError;
use sid_core::grpc_error::refuse::{
    authority_changed, changed_concurrently, internal, not_found, storage_failure,
};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::{GroupId, ProfileId};
use tonic::Status;

use crate::mapping::MappingError;
use crate::patch::PatchError;

/// `ErrorInfo` metadata key of the RFC 7644 §3.12 `scimType`.
pub(crate) const SCIM_TYPE: &str = "scimType";

/// A value the schema refuses, RFC 7644 §3.12 `invalidValue`. The
/// description never repeats the submitted value.
fn invalid(reason: ErrorReason, scim_type: &'static str, field: &str, description: &str) -> Status {
    ApiError::new(reason, description.to_string())
        .with_field_violation(field, description)
        .with_metadata(SCIM_TYPE, scim_type)
        .into()
}

/// A required attribute is absent: `invalidValue` (RFC 7644 §3.12).
pub(crate) fn required(attribute: &str) -> Status {
    invalid(
        ErrorReason::RequiredFieldMissing,
        "invalidValue",
        attribute,
        "required",
    )
}

/// An identifier in the request path or body that names no SCIM resource of
/// its kind: `invalidValue`.
pub(crate) fn invalid_id(attribute: &str) -> Status {
    invalid(
        ErrorReason::InvalidFieldValue,
        "invalidValue",
        attribute,
        "not a resource identifier",
    )
}

/// A filter that does not parse: `invalidFilter` (RFC 7644 §3.4.2.2).
pub(crate) fn invalid_filter() -> Status {
    invalid(
        ErrorReason::InvalidFieldValue,
        "invalidFilter",
        "filter",
        "not a valid SCIM filter",
    )
}

/// A mapping failure: the schema refuses a value (`invalidValue`).
pub(crate) fn mapping(e: MappingError) -> Status {
    match e {
        MappingError::MultiplePrimary(attribute) => invalid(
            ErrorReason::InvalidFieldValue,
            "invalidValue",
            attribute,
            "more than one value is primary",
        ),
        MappingError::InvalidPhone(_) => invalid(
            ErrorReason::InvalidFieldValue,
            "invalidValue",
            "phoneNumbers",
            "not a telephone number",
        ),
        MappingError::InvalidEmail(..) => invalid(
            ErrorReason::InvalidFieldValue,
            "invalidValue",
            "emails",
            "not an admissible email address",
        ),
    }
}

/// A PATCH that cannot be applied, with the RFC 7644 §3.12 type of each
/// cause: an unknown operation is `invalidSyntax`, an unknown path
/// `invalidPath`, a refused value `invalidValue`, an immutable attribute
/// `mutability`. The submitted path and value are not repeated.
pub(crate) fn patch(e: PatchError) -> Status {
    let (scim_type, description) = match e {
        PatchError::UnsupportedOp(_) => ("invalidSyntax", "unsupported operation"),
        PatchError::InvalidPath(_) => ("invalidPath", "the path names no attribute"),
        PatchError::InvalidValue { .. } => ("invalidValue", "a value the attribute refuses"),
        PatchError::ImmutableAttribute(_) => ("mutability", "the attribute is immutable"),
    };
    invalid(
        ErrorReason::InvalidFieldValue,
        scim_type,
        "Operations",
        description,
    )
}

/// The user `id` does not exist (404).
pub(crate) fn user_not_found(id: ProfileId) -> Status {
    not_found(ErrorReason::ProfileNotFound, "User", id.to_string())
}

/// The group `id` does not exist (404).
pub(crate) fn group_not_found(id: GroupId) -> Status {
    not_found(ErrorReason::GroupNotFound, "Group", id.0.to_string())
}

/// A user write refused by storage. The only unique attribute a user write
/// can collide on is its login handle, `userName` (RFC 7644 §3.3,
/// `uniqueness`).
pub(crate) fn user_write(id: ProfileId, e: SidError) -> Status {
    match e {
        SidError::Conflict(_) => ApiError::new(
            ErrorReason::UsernameAlreadyTaken,
            "the userName is held by another user",
        )
        .with_field_violation("userName", "held by another user")
        .with_metadata(SCIM_TYPE, "uniqueness")
        .into(),
        SidError::NotFound(_) => user_not_found(id),
        // A user write is built here, so a refused write is a broken
        // invariant, not the client's value.
        SidError::Validation(rule) => internal("scim user write", rule),
        other => shared_write(other),
    }
}

/// A group write refused by storage: a name already used in the project is
/// `uniqueness` (RFC 7644 §3.3).
pub(crate) fn group_write(id: GroupId, e: SidError) -> Status {
    match e {
        SidError::Conflict(_) => ApiError::new(
            ErrorReason::GroupAlreadyExists,
            "the displayName is used by another group",
        )
        .with_field_violation("displayName", "used by another group")
        .with_metadata(SCIM_TYPE, "uniqueness")
        .into(),
        SidError::NotFound(_) => group_not_found(id),
        // A member that is no existing user.
        SidError::Validation(_) => invalid(
            ErrorReason::InvalidFieldValue,
            "invalidValue",
            "members",
            "not an existing user",
        ),
        // A member that granted this group a role: it would reach itself.
        SidError::PolicyViolation(_) => invalid(
            ErrorReason::InvalidFieldValue,
            "invalidValue",
            "members",
            "a user that granted this group a role cannot join it",
        ),
        other => shared_write(other),
    }
}

/// Write refusals common to users and groups.
fn shared_write(e: SidError) -> Status {
    match e {
        // The record changed between the read and this write: nothing was
        // written, and the client repeats the request against the new state.
        SidError::InvalidState(_) => changed_concurrently(),
        SidError::Fenced(_) => authority_changed(),
        other => storage_failure(other),
    }
}

#[cfg(test)]
mod tests;
