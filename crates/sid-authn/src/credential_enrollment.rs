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
use sid_core::models::{
    Credential, CredentialType, CurrentPasswordRule, ProfileId, Session, SessionId,
};

use crate::caller::{Caller, CallerError};

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
pub fn established_assurance<O>(
    active: &[Credential<O>],
    passkey_satisfies_mfa: bool,
) -> AuthLevel {
    active
        .iter()
        .map(|c| credential_assurance(c.credential_type, passkey_satisfies_mfa))
        .max()
        .unwrap_or(AuthLevel::Basic)
}

/// Check that `session` may bind a new `credential_type` credential to an
/// account whose active credentials are `active`, at `now`.
pub fn check_enrollment<O>(
    session: &Session<O>,
    active: &[Credential<O>],
    credential_type: CredentialType,
    passkey_satisfies_mfa: bool,
    now: DateTime<Utc>,
) -> Result<(), EnrollmentRefusal> {
    check_binding(
        session,
        active,
        credential_assurance(credential_type, passkey_satisfies_mfa),
        passkey_satisfies_mfa,
        now,
    )
}

/// Check that `session` may bind a key used at `assurance` (a device key,
/// whose possession alone raises no assurance) to an account whose active
/// credentials are `active`, at `now`.
pub fn check_binding<O>(
    session: &Session<O>,
    active: &[Credential<O>],
    assurance: AuthLevel,
    passkey_satisfies_mfa: bool,
    now: DateTime<Utc>,
) -> Result<(), EnrollmentRefusal> {
    // A provisional session, a sign-in still owing its second factor among
    // them, binds nothing here.
    if session.is_provisional {
        return Err(EnrollmentRefusal::Provisional);
    }
    let required = established_assurance(active, passkey_satisfies_mfa).min(assurance);
    if session.assurance_at(now) < required {
        return Err(EnrollmentRefusal::Insufficient { required });
    }
    if now - session.authenticated_at >= chrono::Duration::hours(FULL_TRUST_HOURS) {
        return Err(EnrollmentRefusal::Stale { required });
    }
    Ok(())
}

/// Check that `pending`, a sign-in's context owing its second factor, may bind
/// the first one to an account whose active credentials are `active`: only
/// with no stronger protection established, which stays out of its reach.
pub fn check_sign_in_enrollment<O>(
    pending: &Session<O>,
    active: &[Credential<O>],
    passkey_satisfies_mfa: bool,
) -> Result<(), EnrollmentRefusal> {
    if !pending.awaits_second_factor() || pending.is_expired() {
        return Err(EnrollmentRefusal::Provisional);
    }
    match established_assurance(active, passkey_satisfies_mfa) {
        AuthLevel::Basic => Ok(()),
        required => Err(EnrollmentRefusal::Insufficient { required }),
    }
}

/// How long from `now` a password change of `session` may still go without
/// the current password; zero when it needs it now. A relaxed rule counts
/// from the session's last authentication and never outlasts the
/// credential-binding freshness window.
pub fn current_password_required_in<O>(
    session: &Session<O>,
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
pub fn check_password_change<O>(
    session: &Session<O>,
    active: &[Credential<O>],
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

/// Why an enrollment step against the stored account was refused.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    /// The session may not bind the credential now.
    #[error("credential binding refused: {0:?}")]
    Refused(EnrollmentRefusal),
    /// The caller is not a user's own sign-in session.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The caller's token names no live session of its own Profile.
    #[error("the caller's session is not its own live session")]
    SessionInvalid,
    /// The stored session or credentials could not be read.
    #[error("storage: {0}")]
    Storage(sid_core::Error),
}

impl From<EnrollmentRefusal> for EnrollmentError {
    fn from(refusal: EnrollmentRefusal) -> Self {
        Self::Refused(refusal)
    }
}

/// Refuse unless `caller`'s own interactive session may bind a new
/// `credential_type` credential to the caller's account now, judged by the
/// stored session and the account's current active credentials. Ceremonies
/// call it at their start and again at their finish.
pub async fn authorize(
    storage: &dyn sid_plugin::StorageBackend,
    caller: &Caller,
    credential_type: CredentialType,
    passkey_satisfies_mfa: bool,
) -> Result<(), EnrollmentError> {
    let session = own_session(storage, caller).await?;
    let active = active_credentials(storage, caller.profile_id).await?;
    Ok(check_enrollment(
        &session,
        &active,
        credential_type,
        passkey_satisfies_mfa,
        Utc::now(),
    )?)
}

/// Refuse unless `session`, the stored own sign-in of `profile`, may bind a
/// key used at `assurance` now (see [`check_binding`]); the session as it
/// stands. A ceremony calls it at its start and again at its finish.
pub async fn authorize_binding(
    storage: &dyn sid_plugin::StorageBackend,
    profile: ProfileId,
    session: SessionId,
    assurance: AuthLevel,
    passkey_satisfies_mfa: bool,
) -> Result<Session, EnrollmentError> {
    let session = storage
        .get_session(session)
        .await
        .map_err(EnrollmentError::Storage)?
        .filter(|s| s.profile_id == profile && !s.is_expired())
        .ok_or(EnrollmentError::SessionInvalid)?;
    let active = active_credentials(storage, profile).await?;
    check_binding(
        &session,
        &active,
        assurance,
        passkey_satisfies_mfa,
        Utc::now(),
    )?;
    Ok(session)
}

/// Refuse unless `pending` may bind the account's first second factor now,
/// judged by the account's current active credentials (see
/// [`check_sign_in_enrollment`]).
pub async fn authorize_sign_in(
    storage: &dyn sid_plugin::StorageBackend,
    pending: &Session,
    passkey_satisfies_mfa: bool,
) -> Result<(), EnrollmentError> {
    let active = active_credentials(storage, pending.profile_id).await?;
    Ok(check_sign_in_enrollment(
        pending,
        &active,
        passkey_satisfies_mfa,
    )?)
}

/// Refuse unless `caller`'s own interactive session may replace the
/// caller's password under `rule` (see [`check_password_change`]); answer
/// whether the change must prove the current password now. Every
/// password-change step calls it; the finish checks the answer against the
/// operation it commits.
pub async fn password_change_authority(
    storage: &dyn sid_plugin::StorageBackend,
    caller: &Caller,
    passkey_satisfies_mfa: bool,
    rule: CurrentPasswordRule,
) -> Result<bool, EnrollmentError> {
    let session = own_session(storage, caller).await?;
    let active = active_credentials(storage, caller.profile_id).await?;
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
        Err(refusal) => Err(refusal.into()),
    }
}

/// How long the caller's session may still change its password without the
/// current password, by this server's clock now (see
/// [`current_password_required_in`]).
pub async fn password_change_requirement(
    storage: &dyn sid_plugin::StorageBackend,
    caller: &Caller,
    rule: CurrentPasswordRule,
) -> Result<chrono::Duration, EnrollmentError> {
    let session = own_session(storage, caller).await?;
    Ok(current_password_required_in(&session, rule, Utc::now()))
}

/// The caller's own live interactive session, as stored.
async fn own_session(
    storage: &dyn sid_plugin::StorageBackend,
    caller: &Caller,
) -> Result<Session, EnrollmentError> {
    caller.require_interactive()?;
    let session_id =
        SessionId::parse(&caller.session_id).map_err(|_| EnrollmentError::SessionInvalid)?;
    storage
        .get_session(session_id)
        .await
        .map_err(EnrollmentError::Storage)?
        .filter(|s| s.profile_id == caller.profile_id && !s.is_expired())
        .ok_or(EnrollmentError::SessionInvalid)
}

/// The active credentials of `profile`.
async fn active_credentials(
    storage: &dyn sid_plugin::StorageBackend,
    profile: ProfileId,
) -> Result<Vec<Credential>, EnrollmentError> {
    Ok(storage
        .get_credentials_by_profile(profile, None)
        .await
        .map_err(EnrollmentError::Storage)?
        .into_iter()
        .filter(|c| c.status.is_active())
        .collect())
}

#[cfg(test)]
mod tests;
