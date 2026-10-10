// SPDX-License-Identifier: AGPL-3.0-only
//! Who may bind a new credential to an existing account.
//!
//! Binding needs the lower of the account's highest established assurance and
//! the assurance the new credential will be used at, reached by a fresh
//! authentication of the current session (NIST SP 800-63B-4 §4.1.2.1: an
//! additional authenticator is bound under an authenticated session at the
//! required level). A provisional session (email OTP, magic link) proves only
//! the mailbox and never binds a credential to an existing account. A new
//! registration binds its first credential inside its own ceremony, not here.

use chrono::{DateTime, Utc};
use sid_core::models::session::{AuthLevel, FULL_TRUST_HOURS};
use sid_core::models::{Credential, CredentialType, CurrentPasswordRule, Session};

/// Why the caller may not bind the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentRefusal {
    /// Mailbox possession alone: continue through the account's existing
    /// authentication or its recovery.
    Provisional,
    /// The session's assurance is below `required`: step up first.
    Insufficient { required: AuthLevel },
    /// The sufficient authentication is older than the freshness window:
    /// authenticate again.
    Stale { required: AuthLevel },
    /// A password change must prove the current password now.
    CurrentPasswordRequired,
}

/// The assurance a credential of `credential_type` is used at.
pub fn credential_assurance(
    credential_type: CredentialType,
    passkey_satisfies_mfa: bool,
) -> AuthLevel {
    match credential_type {
        CredentialType::Opaque | CredentialType::LegacyHash => AuthLevel::Basic,
        // A second factor and recovery codes reach Standard through step-up.
        CredentialType::Totp | CredentialType::Recovery => AuthLevel::Standard,
        CredentialType::WebAuthn if passkey_satisfies_mfa => AuthLevel::Standard,
        CredentialType::WebAuthn => AuthLevel::Basic,
    }
}

/// The highest assurance the account's active credentials establish.
pub fn established_assurance(active: &[Credential], passkey_satisfies_mfa: bool) -> AuthLevel {
    active
        .iter()
        .map(|c| credential_assurance(c.credential_type, passkey_satisfies_mfa))
        .max()
        .unwrap_or(AuthLevel::Basic)
}

/// Check that `session` may bind a new `credential_type` credential to an
/// account whose active credentials are `active`, at `now`.
pub fn check_enrollment(
    session: &Session,
    active: &[Credential],
    credential_type: CredentialType,
    passkey_satisfies_mfa: bool,
    now: DateTime<Utc>,
) -> Result<(), EnrollmentRefusal> {
    if session.is_provisional {
        return Err(EnrollmentRefusal::Provisional);
    }
    let required = established_assurance(active, passkey_satisfies_mfa)
        .min(credential_assurance(credential_type, passkey_satisfies_mfa));
    if session.assurance_at(now) < required {
        return Err(EnrollmentRefusal::Insufficient { required });
    }
    if now - session.authenticated_at >= chrono::Duration::hours(FULL_TRUST_HOURS) {
        return Err(EnrollmentRefusal::Stale { required });
    }
    Ok(())
}

/// How long from `now` a password change of `session` may still go without
/// the current password; zero when it needs it now. A relaxed rule counts
/// from the session's last authentication and never outlasts the
/// credential-binding freshness window.
pub fn current_password_required_in(
    session: &Session,
    rule: CurrentPasswordRule,
    now: DateTime<Utc>,
) -> chrono::Duration {
    let window = match rule {
        CurrentPasswordRule::Always => return chrono::Duration::zero(),
        CurrentPasswordRule::AfterMinutes(minutes) => chrono::Duration::minutes(i64::from(minutes))
            .min(chrono::Duration::hours(FULL_TRUST_HOURS)),
    };
    (session.authenticated_at + window - now).max(chrono::Duration::zero())
}

/// Check that `session` may replace the account's password at `now`.
/// `proven` says the change carries a successful sign-in with the current
/// password: that is a fresh authentication at the password's level, so it
/// satisfies freshness whenever it is sent, required or not. It lifts no
/// other condition.
pub fn check_password_change(
    session: &Session,
    active: &[Credential],
    passkey_satisfies_mfa: bool,
    rule: CurrentPasswordRule,
    proven: bool,
    now: DateTime<Utc>,
) -> Result<(), EnrollmentRefusal> {
    if session.is_provisional {
        return Err(EnrollmentRefusal::Provisional);
    }
    let required = established_assurance(active, passkey_satisfies_mfa).min(credential_assurance(
        CredentialType::Opaque,
        passkey_satisfies_mfa,
    ));
    if session.assurance_at(now) < required {
        return Err(EnrollmentRefusal::Insufficient { required });
    }
    if proven || current_password_required_in(session, rule, now) > chrono::Duration::zero() {
        Ok(())
    } else {
        Err(EnrollmentRefusal::CurrentPasswordRequired)
    }
}

/// Refuse unless `caller`'s own interactive session may bind a new
/// `credential_type` credential to the caller's account now, judged by the
/// stored session and the account's current active credentials. Ceremonies
/// call it at their start and again at their finish.
#[cfg(feature = "grpc")]
#[allow(clippy::result_large_err)]
pub async fn authorize(
    storage: &dyn sid_plugin::StorageBackend,
    caller: &crate::caller::Caller,
    credential_type: CredentialType,
    passkey_satisfies_mfa: bool,
) -> Result<(), tonic::Status> {
    let session = own_session(storage, caller).await?;
    let active = active_credentials(storage, caller).await?;
    check_enrollment(
        &session,
        &active,
        credential_type,
        passkey_satisfies_mfa,
        Utc::now(),
    )
    .map_err(refusal_status)
}

/// Refuse unless `caller`'s own interactive session may replace the
/// caller's password under `rule` (see [`check_password_change`]); answer
/// whether the change must prove the current password now. Every
/// password-change step calls it; the finish checks the answer against the
/// operation it commits.
#[cfg(feature = "grpc")]
#[allow(clippy::result_large_err)]
pub async fn password_change_authority(
    storage: &dyn sid_plugin::StorageBackend,
    caller: &crate::caller::Caller,
    passkey_satisfies_mfa: bool,
    rule: CurrentPasswordRule,
) -> Result<bool, tonic::Status> {
    let session = own_session(storage, caller).await?;
    let active = active_credentials(storage, caller).await?;
    match check_password_change(
        &session,
        &active,
        passkey_satisfies_mfa,
        rule,
        false,
        Utc::now(),
    ) {
        Ok(()) => Ok(false),
        Err(EnrollmentRefusal::CurrentPasswordRequired) => Ok(true),
        Err(refusal) => Err(refusal_status(refusal)),
    }
}

/// The refusal of a password change that needed the current password and
/// did not prove it.
#[cfg(feature = "grpc")]
pub fn current_password_required() -> tonic::Status {
    refusal_status(EnrollmentRefusal::CurrentPasswordRequired)
}

/// How long the caller's session may still change its password without the
/// current password, by this server's clock now (see
/// [`current_password_required_in`]).
#[cfg(feature = "grpc")]
#[allow(clippy::result_large_err)]
pub async fn password_change_requirement(
    storage: &dyn sid_plugin::StorageBackend,
    caller: &crate::caller::Caller,
    rule: CurrentPasswordRule,
) -> Result<chrono::Duration, tonic::Status> {
    let session = own_session(storage, caller).await?;
    Ok(current_password_required_in(&session, rule, Utc::now()))
}

/// The caller's own live interactive session, as stored.
#[cfg(feature = "grpc")]
#[allow(clippy::result_large_err)]
async fn own_session(
    storage: &dyn sid_plugin::StorageBackend,
    caller: &crate::caller::Caller,
) -> Result<Session, tonic::Status> {
    use sid_core::grpc_error::{ApiError, ErrorReason};
    use sid_core::models::SessionId;

    caller.require_interactive()?;
    let invalid = || tonic::Status::from(ApiError::new(ErrorReason::TokenInvalid, ""));
    let session_id = SessionId::parse(&caller.session_id).map_err(|_| invalid())?;
    storage
        .get_session(session_id)
        .await
        .map_err(storage_failure)?
        .filter(|s| s.profile_id == caller.profile_id && !s.is_expired())
        .ok_or_else(invalid)
}

/// The caller's active credentials.
#[cfg(feature = "grpc")]
#[allow(clippy::result_large_err)]
async fn active_credentials(
    storage: &dyn sid_plugin::StorageBackend,
    caller: &crate::caller::Caller,
) -> Result<Vec<Credential>, tonic::Status> {
    Ok(storage
        .get_credentials_by_profile(caller.profile_id, None)
        .await
        .map_err(storage_failure)?
        .into_iter()
        .filter(|c| c.status.is_active())
        .collect())
}

#[cfg(feature = "grpc")]
fn storage_failure(e: sid_core::Error) -> tonic::Status {
    tracing::warn!("Storage error: {}", e);
    tonic::Status::from(sid_core::grpc_error::ApiError::internal())
}

/// The status a refusal answers with; `continuation` tells the client what
/// to do next.
#[cfg(feature = "grpc")]
fn refusal_status(refusal: EnrollmentRefusal) -> tonic::Status {
    use sid_core::grpc_error::{ApiError, ErrorReason};

    let err = match refusal {
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
    };
    tonic::Status::from(err)
}

#[cfg(test)]
mod tests;
