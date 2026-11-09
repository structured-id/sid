// SPDX-License-Identifier: AGPL-3.0-only
//! Sign-in refusals that ask the client to do something first: each carries
//! its reason in `ErrorInfo` and what is needed as typed details, never in the
//! status message.

use sid_authn::captcha::CaptchaChallenge as IssuedChallenge;
use sid_infra::grpc_error::{ApiError, ErrorReason};
use sid_proto::sid::v1::{CaptchaChallenge, CaptchaKind};
use tracing::{error, warn};

// The sign-in and second-factor refusals every authority answers alike.
pub(super) use sid_infra::authn::second_factor::{
    credential_not_found, mfa_not_enrolled, recovery_codes_issued, session_ended, step_up_required,
    totp_already_enrolled,
};
pub(super) use sid_infra::authn::sign_in_refusal::{
    anomaly_unavailable, authentication_failed, ceremony_expired, too_many_attempts,
};

/// Canonical type URL of the `CaptchaChallenge` detail.
pub(super) const CAPTCHA_CHALLENGE_TYPE_URL: &str =
    "type.googleapis.com/sid.v1.common.CaptchaChallenge";

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
