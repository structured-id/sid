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
use sid_core::models::{Credential, CredentialType, Session};

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
    use sid_core::grpc_error::{ApiError, ErrorReason};
    use sid_core::models::SessionId;

    caller.require_interactive()?;
    let internal = |e: sid_core::Error| {
        tracing::warn!("Storage error: {}", e);
        tonic::Status::from(ApiError::internal())
    };
    let invalid = || tonic::Status::from(ApiError::new(ErrorReason::TokenInvalid, ""));
    let session_id = SessionId::parse(&caller.session_id).map_err(|_| invalid())?;
    let session = storage
        .get_session(session_id)
        .await
        .map_err(internal)?
        .filter(|s| s.profile_id == caller.profile_id && !s.is_expired())
        .ok_or_else(invalid)?;
    let active: Vec<Credential> = storage
        .get_credentials_by_profile(caller.profile_id, None)
        .await
        .map_err(internal)?
        .into_iter()
        .filter(|c| c.status.is_active())
        .collect();
    check_enrollment(
        &session,
        &active,
        credential_type,
        passkey_satisfies_mfa,
        Utc::now(),
    )
    .map_err(|refusal| {
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
        };
        tonic::Status::from(err)
    })
}

#[cfg(test)]
mod tests;
