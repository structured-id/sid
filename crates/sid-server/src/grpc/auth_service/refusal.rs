// SPDX-License-Identifier: AGPL-3.0-only
//! Sign-in refusals that ask the client to do something first: each carries
//! its reason in `ErrorInfo` and what is needed as typed details, never in the
//! status message.

use std::time::Duration;

use sid_authn::captcha::CaptchaChallenge as IssuedChallenge;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_proto::sid::v1::{CaptchaChallenge, CaptchaKind};
use tracing::{error, warn};

/// Canonical type URL of the `CaptchaChallenge` detail.
pub(super) const CAPTCHA_CHALLENGE_TYPE_URL: &str =
    "type.googleapis.com/sid.v1.common.CaptchaChallenge";

/// How long a client waits before retrying a sign-in whose anomaly state
/// could not be read.
const ANOMALY_RETRY_AFTER: Duration = Duration::from_secs(5);

/// CAPTCHA_REQUIRED carrying the issued challenge. A provider the proto has
/// no kind for is a programming error of this deployment, reported as an
/// internal error rather than a challenge the client cannot solve.
pub(super) fn captcha_required(challenge: &IssuedChallenge) -> Result<ApiError, ApiError> {
    let kind = match challenge.provider.as_str() {
        "sid_pow" => CaptchaKind::SidPow,
        "hcaptcha" => CaptchaKind::Hcaptcha,
        "turnstile" => CaptchaKind::Turnstile,
        other => {
            error!(provider = other, "CAPTCHA provider has no CaptchaKind");
            return Err(ApiError::internal());
        }
    };
    let detail = CaptchaChallenge {
        challenge_id: challenge.challenge_id.clone(),
        kind: kind as i32,
        site_key: challenge.site_key.clone().unwrap_or_default(),
        difficulty: challenge.difficulty.unwrap_or_default(),
    };
    Ok(ApiError::new(
        ErrorReason::CaptchaRequired,
        "solve the CAPTCHA, then retry",
    )
    .with_precondition("captcha", "sign-in", "a CAPTCHA must be solved first")
    .with_detail(CAPTCHA_CHALLENGE_TYPE_URL, &detail))
}

/// STEP_UP_REQUIRED: the sign-in needs a stronger authentication, named by
/// its acr value.
pub(super) fn step_up_to_acr(acr: &str) -> ApiError {
    ApiError::new(
        ErrorReason::StepUpRequired,
        "a stronger sign-in is required",
    )
    .with_precondition("acr", acr, "authenticate at this level")
}

/// STEP_UP_REQUIRED: the session lacks the given authentication methods
/// (`amr` values), every one of which is required.
pub(super) fn step_up_to_amr<'a>(methods: impl IntoIterator<Item = &'a str>) -> ApiError {
    methods.into_iter().fold(
        ApiError::new(
            ErrorReason::StepUpRequired,
            "another authentication method is required",
        ),
        |err, method| err.with_precondition("amr", method, "authenticate with this method"),
    )
}

/// STEP_UP_REQUIRED raised by an anomaly rule: a second factor is needed. The
/// rule name stays in the log; the client learns only what to do.
pub(super) fn step_up_after_anomaly(rule: &str) -> ApiError {
    warn!(rule, "anomaly rule requires a second factor");
    ApiError::new(ErrorReason::StepUpRequired, "verify with a second factor").with_precondition(
        "amr",
        "mfa",
        "verify with a second factor",
    )
}

/// AUTHENTICATION_FAILED: the credential, code or proof does not verify. One
/// answer for every cause (unknown account, wrong secret, replayed code), so
/// the refusal tells nothing about which.
pub(super) fn authentication_failed() -> tonic::Status {
    ApiError::new(ErrorReason::AuthenticationFailed, "authentication failed").into()
}

/// TOKEN_EXPIRED: the session the call acts on has ended or expired; the
/// client signs in again.
pub(super) fn session_ended() -> tonic::Status {
    ApiError::new(ErrorReason::TokenExpired, "the session has ended").into()
}

/// INVALID_STATE: a provisional session (one that only continues a sign-in)
/// cannot do this.
pub(super) fn session_provisional(id: sid_core::models::SessionId) -> tonic::Status {
    ApiError::new(
        ErrorReason::InvalidState,
        "a provisional session cannot do this",
    )
    .with_precondition("SESSION_STATE", id.to_string(), "provisional")
    .into()
}

/// MFA_REQUIRED: the profile has no second factor of the kind the call needs;
/// it enrolls one first.
pub(super) fn mfa_not_enrolled(kind: &'static str) -> tonic::Status {
    ApiError::new(ErrorReason::MfaRequired, format!("no {kind} is enrolled"))
        .with_precondition("MFA_ENROLLMENT", kind, "enroll it first")
        .into()
}

/// INVALID_STATE: the `ceremony` step names state that has expired or was
/// never issued (a sign-in, registration or enrollment between its steps);
/// the client starts the ceremony again.
pub(super) fn ceremony_expired(ceremony: &'static str) -> tonic::Status {
    ApiError::new(
        ErrorReason::InvalidState,
        format!("the {ceremony} has expired; start it again"),
    )
    .with_precondition("CEREMONY_STATE", ceremony, "expired")
    .into()
}

/// REGISTRATION_RESTRICTED: self-registration needs `requirement` first
/// (`instance_claim`, `admin_only`, `invite`, `email`, `email_domain`).
pub(super) fn registration_restricted(requirement: &'static str) -> tonic::Status {
    ApiError::new(
        ErrorReason::RegistrationRestricted,
        "self-registration is restricted on this installation",
    )
    .with_metadata("requirement", requirement)
    .into()
}

/// SIGN_IN_REFUSED: a sign-in policy refuses this sign-in outright. The rule
/// stays in the log and the security event; the client learns no rule.
pub(super) fn sign_in_refused() -> tonic::Status {
    ApiError::new(ErrorReason::SignInRefused, "sign-in refused").into()
}

/// RATE_LIMIT_EXCEEDED: too many sign-in attempts; QuotaFailure names the
/// limit and RetryInfo the longest wait (a lockout started earlier ends
/// sooner).
pub(super) fn too_many_attempts(retry_after: Duration) -> tonic::Status {
    ApiError::new(ErrorReason::RateLimitExceeded, "too many sign-in attempts")
        .with_quota_violation("sign_in_attempts", "failed sign-in attempts per account")
        .with_retry_after(retry_after)
        .into()
}

/// DEPENDENCY_UNAVAILABLE for a sign-in whose anomaly state cannot be read.
pub(super) fn anomaly_unavailable(e: impl std::fmt::Display) -> tonic::Status {
    warn!(error = %e, "anomaly state unavailable");
    ApiError::new(
        ErrorReason::DependencyUnavailable,
        "sign-in is temporarily unavailable",
    )
    .with_retry_after(ANOMALY_RETRY_AFTER)
    .into()
}
