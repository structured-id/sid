// SPDX-License-Identifier: AGPL-3.0-only
//! The status a credential-binding refusal answers with; `continuation`
//! tells the client what to do next.

use sid_authn::credential_enrollment::{EnrollmentError, EnrollmentRefusal};
use tonic::Status;

use crate::grpc_error::refuse::storage_failure;
use crate::grpc_error::{ApiError, ErrorReason, IntoStatus};

impl IntoStatus for EnrollmentRefusal {
    fn into_status(self) -> Status {
        match self {
            EnrollmentRefusal::Provisional => ApiError::new(
                ErrorReason::MfaRequired,
                "sign in to the account, or recover it, before changing its credentials",
            )
            .with_metadata("continuation", "authenticate"),
            EnrollmentRefusal::Insufficient { required } => ApiError::new(
                ErrorReason::MfaRequired,
                "a stronger authentication is required to change this credential",
            )
            .with_metadata("required_acr", required.acr_value())
            .with_metadata("continuation", "step_up"),
            EnrollmentRefusal::Stale { required } => ApiError::new(
                ErrorReason::MfaRequired,
                "authenticate again to change this credential",
            )
            .with_metadata("required_acr", required.acr_value())
            .with_metadata("continuation", "reauthenticate"),
            EnrollmentRefusal::CurrentPasswordRequired => ApiError::new(
                ErrorReason::StepUpRequired,
                "enter the current password to change it",
            )
            .with_metadata("continuation", "current_password")
            // The canonical STEP_UP_REQUIRED detail: the method to add, the
            // password (RFC 8176 §2 `pwd`).
            .with_precondition("amr", "pwd", "prove the current password"),
        }
        .into()
    }
}

impl IntoStatus for EnrollmentError {
    fn into_status(self) -> Status {
        match self {
            EnrollmentError::Refused(refusal) => refusal.into_status(),
            EnrollmentError::Caller(e) => e.into_status(),
            EnrollmentError::SessionInvalid => {
                ApiError::new(ErrorReason::TokenInvalid, "authentication required").into()
            }
            EnrollmentError::Storage(e) => storage_failure(e),
        }
    }
}

#[cfg(test)]
mod tests;
