// SPDX-License-Identifier: AGPL-3.0-only
//! The wire fields of a password sign-in, and its refusals as a host
//! answering with a status gives them.

use sid_authn::password_sign_in::PasswordSignInError;
use sid_ids::OpaqueLoginId;
use tonic::Status;

use crate::grpc_error::{ApiError, ErrorReason, IntoStatus};

/// A sign-in refusal or failure as a host answering with a status gives it:
/// the error of its [`sid_authn::password_sign_in::PasswordSignInHost`].
#[derive(Debug)]
pub struct SignInStatus(pub Status);

impl From<Status> for SignInStatus {
    fn from(status: Status) -> Self {
        Self(status)
    }
}

impl From<PasswordSignInError> for SignInStatus {
    fn from(e: PasswordSignInError) -> Self {
        Self(e.into_status())
    }
}

impl From<SignInStatus> for Status {
    fn from(e: SignInStatus) -> Self {
        e.0
    }
}

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

#[cfg(test)]
mod tests;
