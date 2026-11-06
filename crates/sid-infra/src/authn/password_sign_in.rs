// SPDX-License-Identifier: AGPL-3.0-only
//! The wire fields of a password sign-in.

use sid_ids::OpaqueLoginId;
use tonic::Status;

use crate::grpc_error::{ApiError, ErrorReason};

/// The login a finish names, or `INVALID_ARGUMENT` before anything is
/// looked up: absent, of another length, nil, max or not a UUIDv7.
#[allow(clippy::result_large_err)]
pub fn login_id(field: Option<&sid_ids_proto::OpaqueLoginId>) -> Result<OpaqueLoginId, Status> {
    sid_ids_proto::required(field).map_err(|e| {
        ApiError::new(ErrorReason::InvalidFieldValue, e.to_string())
            .with_field_violation("login_id", "an OPAQUE login id")
            .into()
    })
}
