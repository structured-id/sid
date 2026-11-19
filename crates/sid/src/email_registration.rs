// SPDX-License-Identifier: AGPL-3.0-only
//! Passwordless self-registration: an email code confirms the address of a
//! new account, and the registration's context that the code opens admits
//! only that registration's first passkey, committed with the account.
//!
//! Admission is the self-registration's own ([`Registration::begin`]):
//! decided before anything about the address is told, so a closed or
//! restricted policy answers a held and a free address alike. Once
//! admitted, a held address is refused before any code is created or sent.
//! Every later step decides admission again, and the commit decides it once
//! more in the account's transaction.
//!
//! The context is a random secret held by the registrant (an HttpOnly cookie
//! with a CSRF token for a browser, a bearer for a native client); the store
//! keeps it under its hash only. It opens no account call and no session: the
//! account signs in afterwards with its passkey.

use serde::{Deserialize, Serialize};
use sid_authn::browser_session::{BrowserCsrf, BrowserSecret};
use sid_authn::challenge_store::ChallengeStore;
use sid_authn::otp::{CodeDestination, OtpError, OtpPurpose, OtpService, OtpVerifyResult};
use sid_authn::sign_in_delivery::CeremonyClient;
use sid_core::Error as SidError;
use sid_core::models::{
    BrowserCsrfToken, Credential, CredentialType, NewUserHandle, OperationCompletion, OperationKey,
    WebAuthnUserHandle,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::{
    PasskeyRegistrationFinishResponse, PasskeyRegistrationStartResponse,
    ResendEmailRegistrationResponse, StartEmailRegistrationResponse,
};
use std::sync::Arc;
use tracing::info;

use crate::passkey::{PasskeyError, Passkeys};
use crate::registration::{PendingRegistration, Registration, RegistrationError};
use crate::wire::{FieldError, wire_id};

/// How long a started registration waits for its address to be confirmed:
/// the code's own lifetime bounds each code, resends included.
const PENDING_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// How long a confirmed registration's context admits its first passkey.
const CONTEXT_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// How long a committed registration's result answers a retried finish
/// after its context would have expired.
const RESULT_RETENTION: jiff::SignedDuration = jiff::SignedDuration::from_hours(24);

/// The namespace and method a committed finish records its result under.
const RESULT_NAMESPACE: &str = "registration:first-passkey";
const FINISH_METHOD: &str = "sid.v1.AuthService/PasskeyRegistrationFinish";

/// Why a passwordless registration step is refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum EmailRegistrationError {
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// The registration is not admitted, or the address is held.
    #[error(transparent)]
    Registration(#[from] RegistrationError),
    /// The code request was refused (its limit, the delivery backlog).
    #[error(transparent)]
    Code(#[from] OtpError),
    /// The code's registration is unknown or gone; the registration starts
    /// again.
    #[error("the email code expired")]
    CodeSessionExpired,
    /// The code has expired; a new one is requested.
    #[error("the code has expired")]
    CodeExpired,
    /// Too many wrong codes for this registration; it starts again.
    #[error("too many wrong codes")]
    TooManyCodes,
    /// The code is wrong.
    #[error("the code is wrong")]
    WrongCode,
    /// The registration's context is unknown, expired or spent: it starts
    /// again.
    #[error("the registration's context ended")]
    ContextEnded,
    /// A browser context's CSRF token is missing or wrong.
    #[error("the registration's CSRF token is missing or wrong")]
    CsrfInvalid,
    /// The passkey ceremony refused.
    #[error(transparent)]
    Passkey(#[from] PasskeyError),
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation; its cause is in the log.
    #[error("internal error")]
    Internal,
}

impl From<FieldError> for EmailRegistrationError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

fn internal(operation: &'static str, cause: impl std::fmt::Display) -> EmailRegistrationError {
    tracing::error!(operation, error = %cause, "internal failure");
    EmailRegistrationError::Internal
}

/// A confirmed registration, as its context holds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Context {
    pending: PendingRegistration,
    /// The new account's WebAuthn user handle, fixed when the address is
    /// confirmed so every passkey ceremony of the registration names it.
    user_handle: [u8; 16],
    /// The name the passkey shows the registrant: the address as typed.
    name: String,
    /// The CSRF token of a browser context; a native context has none.
    csrf: Option<[u8; 32]>,
}

/// The secret a client presents for its registration's context.
pub enum Presented<'a> {
    /// A browser's cookie, with the CSRF header values it sent.
    Cookie {
        secret: BrowserSecret,
        csrf: Vec<&'a str>,
    },
    /// A native client's bearer.
    Bearer(BrowserSecret),
}

impl Presented<'_> {
    fn secret(&self) -> &BrowserSecret {
        match self {
            Self::Cookie { secret, .. } | Self::Bearer(secret) => secret,
        }
    }
}

/// A verified address: the context the client holds from now on.
pub struct Opened {
    /// The context's secret, for its cookie or bearer.
    pub secret: BrowserSecret,
    /// The browser's CSRF token for the later steps; none for a native client.
    pub csrf: Option<String>,
    /// Seconds the context admits its first passkey.
    pub expires_in: i64,
}

/// The store key of a context: its secret's hash, never the secret.
fn context_key(secret: &BrowserSecret) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hash = secret.hash();
    let mut key = String::with_capacity(64);
    for byte in hash.as_bytes() {
        key.push(char::from(HEX[usize::from(byte >> 4)]));
        key.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    key
}

/// Passwordless registrations on one installation.
pub struct EmailRegistrations {
    storage: Arc<dyn StorageBackend>,
    /// Started registrations awaiting their code, by code session.
    pending: ChallengeStore<PendingRegistration>,
    /// Confirmed registrations awaiting their first passkey, by context.
    contexts: ChallengeStore<Context>,
}

impl EmailRegistrations {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        ceremonies: Arc<dyn sid_plugin::CeremonyStateStore>,
        keys: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            storage,
            pending: ChallengeStore::new(
                ceremonies.clone(),
                keys.clone(),
                "email-registration-code",
                PENDING_TTL,
            ),
            contexts: ChallengeStore::new(ceremonies, keys, "email-registration", CONTEXT_TTL),
        }
    }

    /// Start a registration of the address `principal`: admitted under the
    /// enrollment policy (`enabled` is the registration switch) before
    /// anything about the address is told; when admitted, a held address
    /// is refused before any code exists. A free address gets a code.
    pub async fn start(
        &self,
        registration: &Registration,
        codes: &OtpService,
        principal: &str,
        claim_token: Option<&str>,
        invite_code: Option<&str>,
        enabled: bool,
    ) -> Result<StartEmailRegistrationResponse, EmailRegistrationError> {
        let handle = sid_authn::normalize::normalize_principal(principal).map_err(|e| {
            EmailRegistrationError::InvalidField {
                field: "principal",
                reason: e.to_string(),
            }
        })?;
        if handle.email.is_none() {
            return Err(EmailRegistrationError::InvalidField {
                field: "principal",
                reason: "a code is sent to an email address".to_string(),
            });
        }
        let pending = registration
            .begin(principal, claim_token, invite_code, enabled)
            .await?;
        let PendingRegistration::NewAccount {
            value,
            email: Some(email),
            ..
        } = &pending
        else {
            return Err(registration.refuse_held(&pending, enabled).await.into());
        };
        let masked =
            sid_plugin::otp::mask_target(&email.delivery, sid_plugin::otp::OtpChannel::Email);
        let (result, _code) = codes
            .request_otp(
                OtpPurpose::Registration,
                value,
                CodeDestination::Email(&email.delivery),
            )
            .await?;
        self.pending
            .insert(&result.session_id.to_string(), &pending)
            .await
            .map_err(|e| internal("store a started registration", e))?;
        info!(session_id = %result.session_id, "passwordless registration started");
        let otp_session_id = sid_ids::OtpSessionId::from_uuid(result.session_id)
            .map_err(|e| internal("email code session id", e))?;
        Ok(StartEmailRegistrationResponse {
            otp_session_id: Some(otp_session_id.into()),
            masked_target: masked,
            expires_in_seconds: result.expires_in_seconds,
            code_length: result.code_length,
        })
    }

    /// The registration a code session started, admitted again now.
    async fn admitted(
        &self,
        registration: &Registration,
        session: uuid::Uuid,
        enabled: bool,
    ) -> Result<PendingRegistration, EmailRegistrationError> {
        let pending = self
            .pending
            .read(&session.to_string())
            .await
            .map_err(|e| internal("read a started registration", e))?
            .ok_or(EmailRegistrationError::CodeSessionExpired)?;
        registration.readmit(&pending, enabled).await?;
        Ok(pending)
    }

    /// A new code for the registration `session` started, replacing its
    /// previous one; refused like a start while registration is not
    /// admitted.
    pub async fn resend(
        &self,
        registration: &Registration,
        codes: &OtpService,
        session: Option<&sid_ids_proto::OtpSessionId>,
        enabled: bool,
    ) -> Result<ResendEmailRegistrationResponse, EmailRegistrationError> {
        let session = wire_id(session, "otp_session_id")?.into_uuid();
        self.admitted(registration, session, enabled).await?;
        let (result, _code) = codes
            .resend_otp(OtpPurpose::Registration, &session)
            .await?
            .ok_or(EmailRegistrationError::CodeSessionExpired)?;
        info!(session_id = %result.session_id, "passwordless registration code resent");
        Ok(ResendEmailRegistrationResponse {
            expires_in_seconds: result.expires_in_seconds,
        })
    }

    /// Confirm the address of the registration `session` started with
    /// `code` and open its context for `client`: a browser's carries a CSRF
    /// token its later steps send. The started registration is spent.
    pub async fn verify(
        &self,
        registration: &Registration,
        codes: &OtpService,
        session: Option<&sid_ids_proto::OtpSessionId>,
        code: &str,
        client: CeremonyClient,
        enabled: bool,
    ) -> Result<Opened, EmailRegistrationError> {
        let session = wire_id(session, "otp_session_id")?.into_uuid();
        let pending = self.admitted(registration, session, enabled).await?;
        match codes
            .verify_otp(OtpPurpose::Registration, &session, code)
            .await
            .map_err(|e| internal("verify a registration code", e))?
        {
            OtpVerifyResult::Success { .. } => {}
            OtpVerifyResult::InvalidCode { .. } => return Err(EmailRegistrationError::WrongCode),
            OtpVerifyResult::Expired => return Err(EmailRegistrationError::CodeExpired),
            OtpVerifyResult::MaxAttempts => return Err(EmailRegistrationError::TooManyCodes),
            OtpVerifyResult::SessionNotFound => {
                return Err(EmailRegistrationError::CodeSessionExpired);
            }
        }
        // The code was spent by this verification alone, so its started
        // registration is this one's to open.
        self.pending
            .take(&session.to_string())
            .await
            .map_err(|e| internal("take a started registration", e))?;
        let PendingRegistration::NewAccount {
            email: Some(email), ..
        } = &pending
        else {
            return Err(internal(
                "open a registration context",
                "a started registration is a new email account",
            ));
        };
        let name = email.delivery.clone();
        let csrf = match client {
            CeremonyClient::Browser => Some(BrowserCsrf::generate()),
            CeremonyClient::Native => None,
        };
        let secret = BrowserSecret::generate();
        self.contexts
            .insert(
                &context_key(&secret),
                &Context {
                    pending,
                    user_handle: rand::random(),
                    name,
                    csrf: csrf.as_ref().map(|token| *token.as_bytes()),
                },
            )
            .await
            .map_err(|e| internal("store a registration context", e))?;
        info!("passwordless registration address confirmed");
        Ok(Opened {
            secret,
            csrf: csrf.as_ref().map(BrowserCsrf::encode),
            expires_in: CONTEXT_TTL.as_secs() as i64,
        })
    }

    /// The live context `presented` names, checked against how it was
    /// opened: a browser's by its cookie with its CSRF token, a native
    /// client's by its bearer.
    async fn context(
        &self,
        presented: &Presented<'_>,
    ) -> Result<
        Option<(String, sid_authn::challenge_store::Versioned<Context>)>,
        EmailRegistrationError,
    > {
        let key = context_key(presented.secret());
        let Some(read) = self
            .contexts
            .read_versioned(&key)
            .await
            .map_err(|e| internal("read a registration context", e))?
        else {
            return Ok(None);
        };
        match (presented, read.value.csrf) {
            (Presented::Cookie { csrf, .. }, Some(token)) => {
                if !BrowserCsrf::matches(csrf.iter().copied(), &BrowserCsrfToken::from_bytes(token))
                {
                    return Err(EmailRegistrationError::CsrfInvalid);
                }
            }
            (Presented::Bearer(_), None) => {}
            // A context is presented only the way it was delivered.
            _ => return Err(EmailRegistrationError::ContextEnded),
        }
        Ok(Some((key, read)))
    }

    /// Start the registration's first passkey, admitted by its context and
    /// by the registration's admission now.
    pub async fn passkey_start(
        &self,
        registration: &Registration,
        passkeys: &Passkeys,
        presented: &Presented<'_>,
        enabled: bool,
    ) -> Result<PasskeyRegistrationStartResponse, EmailRegistrationError> {
        let (key, read) = self
            .context(presented)
            .await?
            .ok_or(EmailRegistrationError::ContextEnded)?;
        registration.readmit(&read.value.pending, enabled).await?;
        Ok(passkeys
            .first_passkey_start(
                &key,
                WebAuthnUserHandle(read.value.user_handle),
                &read.value.name,
            )
            .await?)
    }

    /// The result a committed finish of the context `key` recorded.
    async fn recorded(
        &self,
        key: &str,
    ) -> Result<Option<PasskeyRegistrationFinishResponse>, EmailRegistrationError> {
        let key = OperationKey::parse(key).map_err(|e| internal("registration result key", e))?;
        let Some(record) = self
            .storage
            .get_operation_result(RESULT_NAMESPACE, &key)
            .await?
        else {
            return Ok(None);
        };
        prost::Message::decode(record.completion.result.as_slice())
            .map(Some)
            .map_err(|e| internal("decode a recorded registration result", e))
    }

    /// Commit the account with its confirmed address and the first passkey
    /// `credential` registers, spending the context. A retry by the same
    /// context answers the credential it committed: no second key and no
    /// session.
    pub async fn passkey_finish(
        &self,
        registration: &Registration,
        passkeys: &Passkeys,
        presented: &Presented<'_>,
        credential: &[u8],
        label: Option<String>,
        enabled: bool,
    ) -> Result<PasskeyRegistrationFinishResponse, EmailRegistrationError> {
        let Some((key, read)) = self.context(presented).await? else {
            return self
                .recorded(&context_key(presented.secret()))
                .await?
                .ok_or(EmailRegistrationError::ContextEnded);
        };
        registration.readmit(&read.value.pending, enabled).await?;
        let PendingRegistration::NewAccount { profile_id, .. } = &read.value.pending else {
            return Err(internal(
                "finish a registration",
                "a confirmed registration is a new account",
            ));
        };
        let profile_id = *profile_id;
        let user_handle = WebAuthnUserHandle(read.value.user_handle);
        let passkey = match passkeys
            .first_passkey_finish(&key, user_handle, credential)
            .await
        {
            Ok(passkey) => passkey,
            // A concurrent finish took the ceremony: its commit, once
            // recorded, is this call's answer too.
            Err(PasskeyError::Expired(ceremony)) => {
                return self
                    .recorded(&key)
                    .await?
                    .ok_or(PasskeyError::Expired(ceremony).into());
            }
            Err(e) => return Err(e.into()),
        };
        let stored = Credential::new(
            profile_id,
            CredentialType::WebAuthn,
            passkey.data,
            Some(label.unwrap_or_else(|| "Passkey".to_string())),
        );
        let response = PasskeyRegistrationFinishResponse {
            credential_id: crate::wire::stored_id::<sid_ids::CredentialId, _>(stored.id.0)
                .map_err(|e| internal("encode the credential id", e))?,
        };
        let completion = OperationCompletion::new(
            RESULT_NAMESPACE,
            OperationKey::parse(&key).map_err(|e| internal("registration result key", e))?,
            FINISH_METHOD,
            key.as_bytes(),
            prost::Message::encode_to_vec(&response),
        )
        .retained_until(
            jiff::Timestamp::now()
                .checked_add(RESULT_RETENTION)
                .map_err(|e| internal("registration result retention", e))?,
        );
        match registration
            .commit_first_passkey(
                read.value.pending.clone(),
                stored,
                NewUserHandle {
                    rp_id: passkeys.rp_id().to_owned(),
                    handle: user_handle,
                },
                completion,
                self.contexts.consumption(&key, &read),
                enabled,
            )
            .await
        {
            Ok(_) => {
                info!("passwordless registration committed for profile {profile_id}");
                Ok(response)
            }
            // A concurrent finish of the same context committed first: its
            // result is this retry's answer.
            Err(RegistrationError::ContextEnded) => self
                .recorded(&key)
                .await?
                .ok_or(EmailRegistrationError::ContextEnded),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests;
