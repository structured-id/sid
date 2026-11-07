// SPDX-License-Identifier: AGPL-3.0-only
//! Passkeys (WebAuthn): binding one to the caller's own account under its
//! session's authority, and signing in with one, by an identifier or by the
//! authenticator's discoverable credential, as a first factor under the
//! login requirements.

use std::sync::Arc;

use sid_authn::caller::Caller;
use sid_authn::challenge_store::ChallengeStore;
use sid_authn::credential_enrollment::EnrollmentError;
use sid_authn::login_policy::LoginPolicySource;
use sid_authn::sign_in_delivery::CeremonyClient;
use sid_authn::webauthn::{
    AssertionPurpose, AssertionResponse, DiscoverableAssertionResponse, RegistrationResponse,
    VerifiedAssertion, WebAuthnServer,
};
use sid_core::Error as SidError;
use sid_core::models::{
    AuditEntry, Credential, CredentialFence, CredentialType, Profile, ProfileId, WebAuthnUserHandle,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::{
    WebAuthnAuthenticationStartRequest, WebAuthnAuthenticationStartResponse,
    WebAuthnRegistrationFinishRequest, WebAuthnRegistrationFinishResponse,
    WebAuthnRegistrationStartResponse,
};
use tracing::{info, warn};

use crate::sign_in::{AttemptContext, FirstFactorSignedIn, LoginMethod, SignIn, SignInError};

/// Why a passkey ceremony is refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("{field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    /// The caller's profile is gone.
    #[error("profile not found")]
    ProfileNotFound(ProfileId),
    /// The `ceremony` (`passkey registration`, `passkey sign-in`) is
    /// unknown, expired or another profile's; it starts again.
    #[error("the {0} expired")]
    Expired(&'static str),
    /// The assertion does not sign anyone in; one answer whatever the
    /// reason, so it tells nothing about the account.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The caller's session may not bind a passkey now.
    #[error(transparent)]
    Enrollment(#[from] EnrollmentError),
    /// The sign-in rules, its counters or its kept state refused.
    #[error(transparent)]
    SignIn(#[from] SignInError),
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation; its cause is in the log.
    #[error("internal error")]
    Internal,
}

fn internal(operation: &'static str, cause: impl std::fmt::Display) -> PasskeyError {
    tracing::error!(operation, error = %cause, "internal failure");
    PasskeyError::Internal
}

/// The profile's passkeys that may still sign in (revoked ones never do).
pub async fn active(
    storage: &dyn StorageBackend,
    profile_id: ProfileId,
) -> sid_core::Result<Vec<Credential>> {
    Ok(storage
        .get_credentials_by_profile(profile_id, Some(CredentialType::WebAuthn))
        .await?
        .into_iter()
        .filter(|c| c.status.is_active())
        .collect())
}

/// Record a successful assertion on the passkey that made it (see
/// [`sid_authn::webauthn::record_passkey_use`]): a lost race or a revoked
/// passkey fails the sign-in. Returns the RFC 8176 method of the key and the
/// fence that proved this sign-in's first factor.
pub async fn record_use(
    storage: &dyn StorageBackend,
    passkeys: &[Credential],
    verified: &VerifiedAssertion,
) -> Result<(&'static str, CredentialFence), PasskeyError> {
    sid_authn::webauthn::record_passkey_use(storage, passkeys, verified)
        .await?
        .map(|fence| (verified.key_amr, fence))
        .ok_or(PasskeyError::AuthenticationFailed)
}

/// A passkey sign-in's assertion, parsed: for the account an identifier
/// names, or a discoverable credential naming its account by user handle.
pub enum Assertion {
    Identified {
        principal: String,
        response: AssertionResponse,
    },
    Discoverable(DiscoverableAssertionResponse),
}

impl Assertion {
    /// The assertion `credential` carries, for `principal` when one is given.
    pub fn parse(principal: Option<String>, credential: &[u8]) -> Result<Self, PasskeyError> {
        let not_an_assertion = || PasskeyError::InvalidField {
            field: "credential",
            reason: "not a WebAuthn assertion",
        };
        Ok(match principal {
            Some(principal) => Self::Identified {
                principal,
                response: AssertionResponse::parse(credential).map_err(|_| not_an_assertion())?,
            },
            None => Self::Discoverable(
                DiscoverableAssertionResponse::parse(credential).map_err(|_| not_an_assertion())?,
            ),
        })
    }

    /// The ceremony the assertion answers: its start's `challenge`, taken
    /// from the assertion's own challenge.
    pub fn ceremony(&self) -> Result<String, PasskeyError> {
        match self {
            Self::Identified { response, .. } => response.state_key(),
            Self::Discoverable(response) => response.state_key(),
        }
        .map_err(|_| PasskeyError::Expired("passkey sign-in"))
    }
}

/// Passkey ceremonies at one relying party, with the ceremonies started and
/// not yet finished.
pub struct Passkeys {
    webauthn: Arc<WebAuthnServer>,
    /// The profile each started ceremony binds a passkey to or signs in:
    /// only that profile may finish it.
    ceremonies: ChallengeStore<ProfileId>,
}

/// How long a started ceremony may be finished.
const CEREMONY_TTL: std::time::Duration = std::time::Duration::from_secs(300);

impl Passkeys {
    /// Ceremonies of `webauthn`, kept in `ceremonies` sealed by `keys`.
    pub fn new(
        webauthn: Arc<WebAuthnServer>,
        ceremonies: Arc<dyn sid_plugin::CeremonyStateStore>,
        keys: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            webauthn,
            ceremonies: ChallengeStore::new(ceremonies, keys, "webauthn-binding", CEREMONY_TTL),
        }
    }

    /// Refuse unless `caller`'s own interactive session may bind a passkey
    /// now, against the stored session and the account's credentials.
    async fn binding_authority(
        &self,
        sign_in: &SignIn,
        caller: &Caller,
    ) -> Result<(), PasskeyError> {
        Ok(sid_authn::credential_enrollment::authorize(
            sign_in.storage().as_ref(),
            caller,
            CredentialType::WebAuthn,
            sign_in.policy().auth.passkey_satisfies_mfa,
        )
        .await?)
    }

    /// Start binding a passkey to `caller`'s own account: the account's
    /// passkeys are excluded, so one authenticator does not register twice.
    pub async fn registration_start(
        &self,
        sign_in: &SignIn,
        caller: &Caller,
    ) -> Result<WebAuthnRegistrationStartResponse, PasskeyError> {
        self.binding_authority(sign_in, caller).await?;
        let storage = sign_in.storage();
        let profile_id = caller.profile_id;
        let profile = storage
            .get_profile(profile_id)
            .await?
            .ok_or(PasskeyError::ProfileNotFound(profile_id))?;
        let existing = active(storage.as_ref(), profile.id).await?;

        // The profile's account handle at this RP: created by its first
        // authorized enrollment and kept for every later passkey.
        let user_handle = storage
            .ensure_webauthn_user_handle(
                profile.id,
                self.webauthn.rp_id(),
                WebAuthnUserHandle(rand::random()),
                AuditEntry::user(
                    profile.id.to_string(),
                    "webauthn.user_handle",
                    profile.id.to_string(),
                )
                .into(),
            )
            .await?;
        let result = self
            .webauthn
            .registration_start(
                user_handle,
                profile.username.as_deref().unwrap_or(""),
                &existing,
            )
            .await
            .map_err(|e| internal("start passkey registration", e))?;

        // Only the profile that started the ceremony may finish it.
        self.ceremonies
            .insert(&result.state_key, &profile.id)
            .await
            .map_err(SignInError::from)?;
        Ok(WebAuthnRegistrationStartResponse {
            challenge: result.state_key.into_bytes(),
            options: result.options,
        })
    }

    /// Finish binding the passkey `request` registers to `caller`'s account:
    /// the ceremony must be the caller's own, and the session's authority is
    /// checked again (the account may have changed since the start).
    pub async fn registration_finish(
        &self,
        sign_in: &SignIn,
        caller: &Caller,
        request: WebAuthnRegistrationFinishRequest,
    ) -> Result<WebAuthnRegistrationFinishResponse, PasskeyError> {
        let profile_id = caller.profile_id;
        let credential = RegistrationResponse::parse(&request.credential).map_err(|_| {
            PasskeyError::InvalidField {
                field: "credential",
                reason: "not a WebAuthn registration response",
            }
        })?;
        // Another profile's pending ceremony reads as expired.
        let expired = || PasskeyError::Expired("passkey registration");
        let state_key = credential.state_key().map_err(|_| expired())?;
        let started_by = self
            .ceremonies
            .take(&state_key)
            .await
            .map_err(SignInError::from)?
            .ok_or_else(expired)?;
        if started_by != profile_id {
            return Err(expired());
        }
        self.binding_authority(sign_in, caller).await?;

        let passkey = self
            .webauthn
            .registration_finish(&credential)
            .await
            .map_err(|e| match e {
                SidError::AuthenticationFailed(_) => {
                    warn!("WebAuthn registration finish failed: {}", e);
                    PasskeyError::InvalidField {
                        field: "credential",
                        reason: "the passkey registration does not verify",
                    }
                }
                other => internal("finish passkey registration", other),
            })?;
        let label = request.label.unwrap_or_else(|| "Passkey".to_string());
        let stored = Credential::new(
            profile_id,
            CredentialType::WebAuthn,
            passkey.data,
            Some(label),
        );
        sign_in
            .storage()
            .create_credential(
                &stored,
                AuditEntry::user(
                    profile_id.to_string(),
                    "credential.save",
                    stored.id.0.to_string(),
                )
                .into(),
            )
            .await?;
        info!(
            "Registered passkey {} for profile {}",
            stored.id.0, profile_id
        );
        Ok(WebAuthnRegistrationFinishResponse {
            credential_id: crate::wire::stored_id::<sid_ids::CredentialId, _>(stored.id.0)
                .map_err(|e| internal("stored identifier", e))?,
        })
    }

    /// Start a passkey sign-in: for the account `request`'s identifier
    /// names, against its passkeys, or, without one, a discoverable
    /// credential that names its account at finish. An account without
    /// passkeys is answered like an unknown one.
    pub async fn authentication_start(
        &self,
        sign_in: &SignIn,
        request: WebAuthnAuthenticationStartRequest,
    ) -> Result<WebAuthnAuthenticationStartResponse, PasskeyError> {
        let result = if let Some(identifier) = &request.principal {
            let profile = resolve(sign_in, identifier).await?;
            let passkeys = active(sign_in.storage().as_ref(), profile.id).await?;
            if passkeys.is_empty() {
                return Err(PasskeyError::AuthenticationFailed);
            }
            let started = self
                .webauthn
                .authentication_start(AssertionPurpose::SignIn, &passkeys)
                .await
                .map_err(|e| internal("start passkey sign-in", e))?;
            // The ceremony signs in this profile only.
            self.ceremonies
                .insert(&started.state_key, &profile.id)
                .await
                .map_err(SignInError::from)?;
            started
        } else {
            // Conditional UI: the profile comes from the authenticator's user
            // handle at finish; the ceremony state itself is single-use.
            self.webauthn
                .discoverable_authentication_start()
                .await
                .map_err(|e| internal("start discoverable passkey sign-in", e))?
        };
        Ok(WebAuthnAuthenticationStartResponse {
            challenge: result.state_key.into_bytes(),
            options: result.options,
        })
    }

    /// Finish a passkey sign-in with `assertion`: the ceremony it answers is
    /// consumed, the assertion verified against the account's passkeys and
    /// the asserting passkey's use recorded (a refused assertion counts as a
    /// failed sign-in from `client_ip`), then the account signs in to
    /// `client` as a first factor under the requirements `login_policy`
    /// states, pending its second factor when one is owed. A native client
    /// that proved the application key `native_key` for this ceremony gets
    /// its refresh generation.
    #[allow(clippy::too_many_arguments)]
    pub async fn authentication_finish(
        &self,
        sign_in: &SignIn,
        login_policy: &dyn LoginPolicySource,
        assertion: Assertion,
        client: CeremonyClient,
        client_ip: Option<std::net::IpAddr>,
        context: AttemptContext<'_>,
        native_key: Option<&str>,
    ) -> Result<FirstFactorSignedIn, PasskeyError> {
        let expired = || PasskeyError::Expired("passkey sign-in");
        let storage = sign_in.storage();
        let state_key = assertion.ceremony()?;
        let (profile, passkeys, finished) = match assertion {
            Assertion::Identified {
                principal,
                response,
            } => {
                let profile = resolve(sign_in, &principal).await?;
                // The ceremony the assertion answers, started for this profile.
                let started_for = self
                    .ceremonies
                    .take(&state_key)
                    .await
                    .map_err(SignInError::from)?
                    .ok_or_else(expired)?;
                if started_for != profile.id {
                    return Err(expired());
                }
                let passkeys = active(storage.as_ref(), profile.id).await?;
                let finished = self
                    .webauthn
                    .authentication_finish(AssertionPurpose::SignIn, &response, &passkeys)
                    .await;
                (profile, passkeys, finished)
            }
            Assertion::Discoverable(response) => {
                // The returned handle names an account only through the
                // stored association at this RP; an unknown one authenticates
                // nobody and creates nothing. The finish consumes the
                // ceremony state (single use).
                let user_handle = response.user_handle();
                let profile_id = storage
                    .get_profile_by_webauthn_user_handle(self.webauthn.rp_id(), user_handle)
                    .await?
                    .ok_or(PasskeyError::AuthenticationFailed)?;
                let profile = storage
                    .get_profile(profile_id)
                    .await?
                    .ok_or(PasskeyError::AuthenticationFailed)?;
                let passkeys = active(storage.as_ref(), profile.id).await?;
                let finished = self
                    .webauthn
                    .discoverable_authentication_finish(&response, user_handle, &passkeys)
                    .await;
                (profile, passkeys, finished)
            }
        };
        let verified = match finished {
            Ok(verified) => verified,
            Err(SidError::AuthenticationFailed(why)) => {
                warn!("WebAuthn authentication failed: {why}");
                sign_in
                    .record_failed_login(&profile.id.to_string(), client_ip)
                    .await?;
                return Err(PasskeyError::AuthenticationFailed);
            }
            Err(other) => return Err(internal("finish passkey sign-in", other)),
        };
        let (key_amr, proved_by) = record_use(storage.as_ref(), &passkeys, &verified).await?;

        let method = LoginMethod::Passkey {
            user_verified: verified.user_verified,
            key_amr,
        };
        let requirements = crate::sign_in::organization_requirements(login_policy).await?;
        let admission = sign_in
            .first_factor(
                profile.id,
                client_ip,
                (
                    "webauthn",
                    method.auth_level(sign_in.policy().auth.passkey_satisfies_mfa),
                    &method.amr(),
                ),
                context,
                &requirements,
            )
            .await?;
        let signed_in = sign_in
            .complete_first_factor(
                &profile,
                method,
                context
                    .user_agent
                    .map(sid_authn::sign_in_security::device_id),
                client_ip,
                client,
                native_key,
                // The asserting passkey, as it holds after this use, fences
                // the session's commit (or the pending context's completion).
                Some(&proved_by),
                admission,
            )
            .await?;
        info!("WebAuthn login for profile {}", profile.id);
        Ok(signed_in)
    }
}

/// The active account `identifier` signs in to, or the same refusal as a
/// failed assertion whatever keeps it from resolving.
async fn resolve(sign_in: &SignIn, identifier: &str) -> Result<Profile, PasskeyError> {
    sign_in
        .resolve_profile(identifier)
        .await?
        .ok_or(PasskeyError::AuthenticationFailed)
}

#[cfg(test)]
mod tests;
