// SPDX-License-Identifier: AGPL-3.0-only
//! Each credential-binding refusal tells the client how to continue.

use sid_core::models::session::AuthLevel;
use tonic::Code;

use super::*;
use crate::grpc_error::extract_error_info;

fn info(status: &Status) -> (String, std::collections::HashMap<String, String>) {
    let (reason, _, metadata) = extract_error_info(status).expect("ErrorInfo is set");
    (reason, metadata)
}

#[test]
fn each_refusal_names_its_continuation() {
    for (refusal, reason, continuation) in [
        (
            EnrollmentRefusal::Provisional,
            "MFA_REQUIRED",
            "authenticate",
        ),
        (
            EnrollmentRefusal::Insufficient {
                required: AuthLevel::Standard,
            },
            "MFA_REQUIRED",
            "step_up",
        ),
        (
            EnrollmentRefusal::Stale {
                required: AuthLevel::Standard,
            },
            "MFA_REQUIRED",
            "reauthenticate",
        ),
        (
            EnrollmentRefusal::CurrentPasswordRequired,
            "STEP_UP_REQUIRED",
            "current_password",
        ),
    ] {
        let status = refusal.into_status();
        assert_eq!(status.code(), Code::FailedPrecondition, "{refusal:?}");
        let (got, metadata) = info(&status);
        assert_eq!(got, reason, "{refusal:?}");
        assert_eq!(metadata["continuation"], continuation, "{refusal:?}");
    }
    let (_, metadata) = info(
        &EnrollmentRefusal::Insufficient {
            required: AuthLevel::Standard,
        }
        .into_status(),
    );
    assert_eq!(metadata["required_acr"], AuthLevel::Standard.acr_value());
}

/// A token without its own live session is unauthenticated; a caller that is
/// no sign-in of its own is denied.
#[test]
fn the_callers_session_refusals() {
    let invalid = EnrollmentError::SessionInvalid.into_status();
    assert_eq!(invalid.code(), Code::Unauthenticated);
    assert_eq!(info(&invalid).0, "TOKEN_INVALID");
    let denied = EnrollmentError::Caller(sid_authn::caller::CallerError::Denied).into_status();
    assert_eq!(denied.code(), Code::PermissionDenied);
}
