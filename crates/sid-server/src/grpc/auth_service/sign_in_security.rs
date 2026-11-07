// SPDX-License-Identifier: AGPL-3.0-only
//! The answers to the engine library's sign-in refusals.

use sid::sign_in::SignInError;
use sid_authn::sign_in_security::SignInRefusal;
use sid_infra::grpc_error::refuse::{dependency_unavailable, invalid_field, storage_failure};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use tonic::Status;

use super::refusal::{
    anomaly_unavailable, authentication_failed, captcha_required, ceremony_expired, session_ended,
    sign_in_refused, step_up_after_anomaly, step_up_required, too_many_attempts,
};

/// The answer to a refused or failed sign-in: the rules' refusal with what
/// the client must do first, a sign-in whose proof or policy changed as a
/// failed authentication (it is started again), a completed keyed sign-in as
/// a concurrent modification (its session is delivered again).
pub(crate) fn sign_in_refusal(e: SignInError) -> Status {
    match e {
        SignInError::Rules(refusal) => rules_refusal(refusal),
        SignInError::Fenced => authentication_failed(),
        SignInError::AlreadyCompleted => ApiError::new(
            ErrorReason::ConcurrentModification,
            "the sign-in already completed",
        )
        .into(),
        SignInError::Native(e) => super::super::native_session::refusal(e),
        SignInError::Password(e) => e.into_status(),
        SignInError::InvalidIdentifier(detail) => invalid_field("identifier", detail),
        SignInError::SessionEnded => session_ended(),
        SignInError::Expired => ceremony_expired("sign-in"),
        SignInError::AuthenticationFailed => authentication_failed(),
        SignInError::Ceremony(e) => e.into_status(),
        SignInError::Unavailable { what, cause } => dependency_unavailable(what, cause),
        SignInError::Store(e) => storage_failure(e),
        SignInError::Internal => ApiError::internal().into(),
    }
}

/// The answer to a refusal of the sign-in rules.
fn rules_refusal(r: SignInRefusal) -> Status {
    match r {
        SignInRefusal::StepUp(unmet) => step_up_required(&unmet).into(),
        SignInRefusal::StepUpAfterAnomaly(rule) => step_up_after_anomaly(rule).into(),
        SignInRefusal::Refused => sign_in_refused(),
        SignInRefusal::TooManyAttempts(retry_after) => too_many_attempts(retry_after),
        SignInRefusal::CaptchaRequired(challenge) => match captcha_required(&challenge) {
            Ok(refusal) | Err(refusal) => refusal.into(),
        },
        SignInRefusal::Unavailable(cause) => anomaly_unavailable(cause),
    }
}
