// SPDX-License-Identifier: AGPL-3.0-only
//! A second factor over gRPC, as every authority answers it: the refusals
//! of the shared ceremonies ([`sid_authn::second_factor`]) and the context a
//! browser sign-in page's verification presents, by the authority's session
//! cookie and the CSRF token its pending context was given.

use sid_authn::browser_session::{BrowserCookie, BrowserCsrf, CSRF_HEADER};
use sid_authn::login_policy::Unmet;
use sid_authn::second_factor::FactorError;
use sid_authn::second_factor::pending::{CompletedContext, PendingError};
use sid_core::models::{CredentialId, Session};
use sid_plugin::GrantStore;
use tonic::Status;
use tonic::metadata::MetadataMap;

use super::operation::Effect;
use super::sign_in_refusal::{authentication_failed, ceremony_expired};
use crate::grpc_error::refuse::{
    dependency_unavailable, internal, invalid_field, not_found, storage_failure,
};
use crate::grpc_error::{ApiError, ErrorReason, IntoStatus};

/// TOKEN_EXPIRED: the session the call acts on has ended or expired; the
/// client signs in again.
pub fn session_ended() -> Status {
    ApiError::new(ErrorReason::TokenExpired, "the session has ended").into()
}

/// STEP_UP_REQUIRED naming every requirement `unmet` leaves: the level by
/// its acr value, each missing method by its `amr` value (RFC 8176), and an
/// authentication too old by the age in seconds it must not exceed (the
/// `max_age` of OpenID Connect Core 1.0 §3.1.2.1).
pub fn step_up_required(unmet: &Unmet) -> ApiError {
    let mut err = ApiError::new(
        ErrorReason::StepUpRequired,
        "a stronger or more recent sign-in is required",
    );
    if let Some(level) = unmet.acr {
        err = err.with_precondition("acr", level.acr_value(), "authenticate at this level");
    }
    for method in &unmet.amr {
        err = err.with_precondition("amr", method, "authenticate with this method");
    }
    if let Some(age) = unmet.max_authentication_age {
        err = err.with_precondition(
            "max_age",
            age.as_secs().to_string(),
            "authenticate again, no longer ago than this many seconds",
        );
    }
    err
}

/// MFA_REQUIRED: the account has no second factor of the kind the call
/// needs; it enrolls one first.
pub fn mfa_not_enrolled(kind: &'static str) -> Status {
    ApiError::new(ErrorReason::MfaRequired, format!("no {kind} is enrolled"))
        .with_precondition("MFA_ENROLLMENT", kind, "enroll it first")
        .into()
}

/// INVALID_STATE: a TOTP authenticator is already enrolled.
pub fn totp_already_enrolled() -> Status {
    ApiError::new(
        ErrorReason::InvalidState,
        "a TOTP authenticator is already enrolled",
    )
    .with_precondition("MFA_ENROLLMENT", "TOTP", "already enrolled")
    .into()
}

/// OPERATION_RESULT_UNAVAILABLE for a retried recovery-code generation:
/// the set `recorded` names was issued, and its codes are shown only once.
pub fn recovery_codes_issued(recorded: &[u8]) -> Status {
    let set = match uuid::Uuid::from_slice(recorded) {
        Ok(id) => id.to_string(),
        Err(e) => return internal("read the issued recovery code set", e),
    };
    ApiError::new(
        ErrorReason::OperationResultUnavailable,
        "these recovery codes were issued once; generate a new set to replace them",
    )
    .with_precondition(
        "RECOVERY_CODES_ISSUED",
        set,
        "the codes are shown only once",
    )
    .into()
}

/// CREDENTIAL_NOT_FOUND for `id`: also the answer for a credential the caller
/// does not own, so a foreign id reveals nothing.
pub fn credential_not_found(id: CredentialId) -> Status {
    not_found(
        ErrorReason::CredentialNotFound,
        "Credential",
        id.0.to_string(),
    )
}

/// INVALID_STATE: the credential `id` is the account's last way to sign in
/// and stays; another is added first.
pub fn last_sign_in_method(id: CredentialId) -> Status {
    ApiError::new(
        ErrorReason::InvalidState,
        "the account's last way to sign in cannot be removed; add another first",
    )
    .with_precondition(
        "LAST_PRIMARY_CREDENTIAL",
        id.0.to_string(),
        "the account has no other active primary credential",
    )
    .into()
}

/// A second-factor step inside a keyed command's effect: a store failure
/// stays the store's, for the command to resolve against a concurrent
/// attempt; any other refusal is answered with its status.
impl From<FactorError> for Effect {
    fn from(e: FactorError) -> Self {
        match e {
            FactorError::Store(e) => Self::Store(e),
            FactorError::Operation(e) => Self::Operation(e),
            e => Self::Refused(e.into_status()),
        }
    }
}

impl IntoStatus for FactorError {
    fn into_status(self) -> Status {
        match self {
            FactorError::InvalidField { field, reason } => invalid_field(field, reason),
            FactorError::AlreadyEnrolled => totp_already_enrolled(),
            FactorError::NotEnrolled(what) => mfa_not_enrolled(what),
            FactorError::Expired(ceremony) => ceremony_expired(ceremony),
            FactorError::AuthenticationFailed => authentication_failed(),
            FactorError::CredentialNotFound(id) => credential_not_found(id),
            FactorError::LastSignInMethod(id) => last_sign_in_method(id),
            FactorError::Unavailable { what, cause } => dependency_unavailable(what, cause),
            FactorError::RecoveryCodesIssued(recorded) => recovery_codes_issued(&recorded),
            FactorError::Operation(e) => e.into_status(),
            FactorError::State(e) => e.into_status(),
            FactorError::Store(e) => storage_failure(e),
            e @ (FactorError::Sealed(_) | FactorError::Corrupt(_)) => {
                internal("a second-factor credential", e)
            }
        }
    }
}

impl IntoStatus for PendingError {
    fn into_status(self) -> Status {
        match self {
            PendingError::SessionEnded => session_ended(),
            // The proof, the policy or the context changed under the
            // completion: it is started again.
            PendingError::Fenced => ceremony_expired("sign-in"),
            PendingError::StepUp(unmet) => step_up_required(&unmet).into(),
            PendingError::AuthenticationFailed => authentication_failed(),
            PendingError::State(e) => e.into_status(),
            PendingError::Store(e) => storage_failure(e),
            e @ (PendingError::Sealed(_) | PendingError::Internal(_)) => {
                internal("a second-factor completion", e)
            }
        }
    }
}

/// What a second-factor verification from the browser sign-in page
/// presents.
pub enum BrowserFactor<O> {
    /// A live pending context, its CSRF token matched.
    Pending(Session<O>),
    /// The context of a completion that committed: a cookie no session holds
    /// any more, with the CSRF token it was given, which the completion's
    /// record checks. It may only receive that sign-in again.
    Completed(CompletedContext),
    /// The browser's own session a completion already installed before its
    /// response was lost, its CSRF token matched.
    SignedIn(Session<O>),
}

/// CSRF_TOKEN_INVALID: the sign-in's CSRF token is missing or wrong.
fn csrf_invalid() -> Status {
    ApiError::new(
        ErrorReason::CsrfTokenInvalid,
        "the sign-in's CSRF token is missing or wrong",
    )
    .into()
}

/// What the browser request with `metadata` presents to a second-factor
/// verification: the session `cookie` names among its cookies in `grants`,
/// with the CSRF token that session was given; or, for a cookie no live
/// session holds, the completed context it names. The caller has checked
/// that the request is the sign-in page's.
pub async fn browser_factor<O: Send + Sync>(
    metadata: &MetadataMap,
    cookie: &BrowserCookie,
    grants: &dyn GrantStore<Owner = O>,
) -> Result<BrowserFactor<O>, Status> {
    let values = |name| {
        metadata
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
    };
    let secret = cookie.secret(values("cookie")).ok_or_else(session_ended)?;
    let hash = secret.hash();
    let session = grants
        .get_session_by_browser_secret(&hash)
        .await
        .map_err(storage_failure)?
        .filter(|session| !session.is_expired());
    let Some(session) = session else {
        let mut tokens = values(CSRF_HEADER);
        let (Some(csrf), None) = (tokens.next(), tokens.next()) else {
            return Err(csrf_invalid());
        };
        return Ok(BrowserFactor::Completed(CompletedContext::Browser {
            secret: hash,
            csrf: csrf.to_owned(),
        }));
    };
    let csrf = session.browser_csrf.as_ref().ok_or_else(session_ended)?;
    if !BrowserCsrf::matches(values(CSRF_HEADER), csrf) {
        return Err(csrf_invalid());
    }
    Ok(if session.awaits_second_factor() {
        BrowserFactor::Pending(session)
    } else {
        BrowserFactor::SignedIn(session)
    })
}

#[cfg(test)]
mod tests;
