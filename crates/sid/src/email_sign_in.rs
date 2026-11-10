// SPDX-License-Identifier: AGPL-3.0-only
//! Signing in by possession of a mailbox: a code mailed to the address, or,
//! for a Corporate Profile, a link. Either proves the mailbox over a second
//! channel (RFC 8176 `mca`), never a stored credential, so it signs an
//! account in only provisionally. No answer tells whether an address has an
//! account: every address gets the same answer, and only an account's
//! mailbox receives anything.

use sid_authn::login_policy::LoginPolicySource;
use sid_authn::magic_link::{MagicLinkError, MagicLinkService, MagicLinkVerifyResult};
use sid_authn::otp::{CodeDestination, OtpError, OtpService, OtpVerifyResult};
use sid_authn::sign_in_delivery::{CeremonyClient, SignedIn};
use sid_authn::sign_in_security::AttemptAuthentication;
use sid_core::Error as SidError;
use sid_core::models::session::AuthLevel;
use sid_core::models::{ActorFence, Profile, ProfileId, ProfileType, Session};
use sid_proto::sid::v1::{
    RequestMagicLinkResponse, RequestOtpResponse, ResendOtpResponse, VerifyMagicLinkRequest,
    VerifyOtpRequest,
};
use tracing::{info, warn};

use crate::sign_in::{AttemptContext, SignIn, SignInError};
use crate::wire::{FieldError, wire_id};

/// Why a mailbox sign-in step is refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum EmailSignInError {
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// The code request was refused (its limit, the delivery backlog).
    #[error(transparent)]
    Code(#[from] OtpError),
    /// The code's session is unknown or gone; a new code is requested.
    #[error("the email code expired")]
    CodeSessionExpired,
    /// The code has expired; a new one is requested.
    #[error("the code has expired")]
    CodeExpired,
    /// Too many wrong codes for this one; a new one is requested.
    #[error("too many wrong codes")]
    TooManyCodes,
    /// The link has expired; a new one is requested.
    #[error("the link has expired")]
    LinkExpired,
    /// The link was already used; a new one is requested.
    #[error("the link was already used")]
    LinkUsed,
    /// The mailbox proof signs nobody in; one answer whatever the reason.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The sign-in rules, its counters or its delivery refused.
    #[error(transparent)]
    SignIn(#[from] SignInError),
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation; its cause is in the log.
    #[error("internal error")]
    Internal,
}

impl From<FieldError> for EmailSignInError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

fn internal(operation: &'static str, cause: impl std::fmt::Display) -> EmailSignInError {
    tracing::error!(operation, error = %cause, "internal failure");
    EmailSignInError::Internal
}

/// What a mailbox sign-in step knows about who completes it.
pub struct Attempt<'a> {
    pub client: CeremonyClient,
    pub client_ip: Option<std::net::IpAddr>,
    pub context: AttemptContext<'a>,
}

/// Mailbox sign-ins over one installation's sign-ins.
pub struct EmailSignIn<'a> {
    sign_in: &'a SignIn,
    /// The organization's login requirements the sign-in passes.
    login_policy: &'a dyn LoginPolicySource,
}

impl<'a> EmailSignIn<'a> {
    pub fn new(sign_in: &'a SignIn, login_policy: &'a dyn LoginPolicySource) -> Self {
        Self {
            sign_in,
            login_policy,
        }
    }

    /// Mail a code for `principal`, an email address. Every address gets a
    /// real pending code, whether or not it routes to an account, so no
    /// answer tells whether the account exists; only an account's code is
    /// mailed, to the mailbox its assignment was bound with.
    pub async fn request_code(
        &self,
        codes: &OtpService,
        principal: &str,
    ) -> Result<RequestOtpResponse, EmailSignInError> {
        let handle = sid_authn::normalize::normalize_principal(principal).map_err(|e| {
            EmailSignInError::InvalidField {
                field: "identifier",
                reason: e.to_string(),
            }
        })?;
        let Some(email) = handle.email.as_ref() else {
            return Err(EmailSignInError::InvalidField {
                field: "principal",
                reason: "a code is sent to an email address".to_string(),
            });
        };
        let normalized = &handle.normalized;
        // The caller sees the address as they typed it; the key only limits
        // requests across every spelling.
        let masked =
            sid_plugin::otp::mask_target(&email.delivery, sid_plugin::otp::OtpChannel::Email);
        // Neither the resolution key nor a caller's equivalent spelling
        // (another mailbox where the key folds dots or tags) ever receives
        // the code. It leaves this service only inside that mail; it is
        // never logged or put into an event.
        let destination = match self.sign_in.resolve_profile(normalized).await? {
            Some(account) => {
                self.sign_in
                    .login_mail_destination(account.id, normalized)
                    .await?
            }
            None => None,
        };
        if destination.is_none() {
            tracing::debug!("email code requested for an address with no login mailbox: no mail");
        }
        let destination = match destination.as_deref() {
            Some(mailbox) => CodeDestination::Email(mailbox),
            None => CodeDestination::None,
        };
        let (result, _code) = codes.request_otp(normalized, destination).await?;
        info!(session_id = %result.session_id, "OTP code requested");
        let otp_session_id = sid_ids::OtpSessionId::from_uuid(result.session_id)
            .map_err(|e| internal("email code session id", e))?;
        Ok(RequestOtpResponse {
            otp_session_id: Some(otp_session_id.into()),
            masked_target: masked,
            expires_in_seconds: result.expires_in_seconds,
            code_length: result.code_length,
        })
    }

    /// A new code in the same session, the one the client verifies against,
    /// sent to the mailbox bound at the request.
    pub async fn resend_code(
        &self,
        codes: &OtpService,
        session: Option<&sid_ids_proto::OtpSessionId>,
    ) -> Result<ResendOtpResponse, EmailSignInError> {
        let session_id = wire_id(session, "otp_session_id")?.into_uuid();
        let (result, _code) = codes
            .resend_otp(&session_id)
            .await?
            .ok_or(EmailSignInError::CodeSessionExpired)?;
        info!(session_id = %result.session_id, "OTP code resent");
        Ok(ResendOtpResponse {
            expires_in: result.expires_in_seconds as i32,
        })
    }

    /// Verify a mailed code and sign the account it routes to in,
    /// provisionally. A wrong code, and an address that routes nowhere,
    /// answer `None` alike; wrong codes count against the client's address.
    pub async fn verify_code(
        &self,
        codes: &OtpService,
        attempt: Attempt<'_>,
        request: VerifyOtpRequest,
    ) -> Result<Option<SignedIn>, EmailSignInError> {
        let session_id = wire_id(request.otp_session_id.as_ref(), "otp_session_id")?.into_uuid();
        let verified = codes
            .verify_otp(&session_id, &request.code)
            .await
            .map_err(|e| internal("verify email code", e))?;
        match verified {
            OtpVerifyResult::Success { target } => {
                let Some(profile) = self.sign_in.resolve_profile(&target).await? else {
                    return Ok(None);
                };
                let signed_in = self.provisional(&profile, "otp", attempt).await?;
                info!("OTP verified for profile {}", profile.id);
                Ok(Some(signed_in))
            }
            OtpVerifyResult::InvalidCode { remaining_attempts } => {
                self.sign_in.record_ip_attempt(attempt.client_ip).await?;
                warn!(
                    session_id = %session_id,
                    remaining_attempts = remaining_attempts,
                    "OTP verification failed: invalid code"
                );
                Ok(None)
            }
            OtpVerifyResult::Expired => Err(EmailSignInError::CodeExpired),
            OtpVerifyResult::MaxAttempts => {
                self.sign_in.record_ip_attempt(attempt.client_ip).await?;
                Err(EmailSignInError::TooManyCodes)
            }
            OtpVerifyResult::SessionNotFound => {
                self.sign_in.record_ip_attempt(attempt.client_ip).await?;
                Err(EmailSignInError::CodeSessionExpired)
            }
        }
    }

    /// Mail a sign-in link for `principal`, an email address, when it routes
    /// to a Corporate Profile. An unknown address, an account that may not
    /// use links and one past its request limit get the same answer as a
    /// mailed link.
    pub async fn request_link(
        &self,
        links: &MagicLinkService,
        principal: &str,
    ) -> Result<RequestMagicLinkResponse, EmailSignInError> {
        let unsent = || {
            Ok(RequestMagicLinkResponse {
                magic_link_id: Some(sid_ids::MagicLinkId::generate().into()),
                expires_in: sid_core::models::MAGIC_LINK_EXPIRY_SECS as i32,
            })
        };
        // Links go to an email address, to the account its sign-in
        // assignment routes to, under the normalized address (one request
        // limit for every spelling of it).
        let handle = sid_authn::normalize::normalize_principal(principal).map_err(|e| {
            EmailSignInError::InvalidField {
                field: "identifier",
                reason: e.to_string(),
            }
        })?;
        if handle.principal_type.to_principal_type()
            != sid_core::models::principal::PrincipalType::Email
        {
            return unsent();
        }
        let address = handle.normalized;
        let Some(profile) = self
            .sign_in
            .resolve_profile(&address)
            .await?
            .filter(|p| p.profile_type == ProfileType::Corporate)
        else {
            return unsent();
        };
        // The link goes to the mailbox the account bound the address with,
        // never the key or the caller's spelling of it.
        let Some(destination) = self
            .sign_in
            .login_mail_destination(profile.id, &address)
            .await?
        else {
            info!("magic link requested for an account with no login mailbox: no link sent");
            return unsent();
        };
        // The session and the work mailing its link commit together; the
        // token leaves this service only inside that mail, never logged or
        // put into an event.
        let (result, _token) = match links.request_magic_link(&address, &destination).await {
            Ok(sent) => sent,
            Err(MagicLinkError::RateLimited { .. }) => {
                info!("Magic link request past the per-address limit: no link sent");
                return unsent();
            }
            Err(e @ (MagicLinkError::Internal(_) | MagicLinkError::Sealed(_))) => {
                return Err(internal("request magic link", e));
            }
        };
        info!(session_id = %result.session_id, "Magic link requested");
        let magic_link_id = sid_ids::MagicLinkId::from_uuid(result.session_id)
            .map_err(|e| internal("magic link id", e))?;
        Ok(RequestMagicLinkResponse {
            magic_link_id: Some(magic_link_id.into()),
            expires_in: result.expires_in_seconds as i32,
        })
    }

    /// Verify a mailed link and sign in, provisionally, the Corporate
    /// Profile its address routes to now (not the one it routed to when the
    /// link was mailed).
    pub async fn verify_link(
        &self,
        links: &MagicLinkService,
        attempt: Attempt<'_>,
        request: VerifyMagicLinkRequest,
    ) -> Result<SignedIn, EmailSignInError> {
        let session_id = wire_id(request.magic_link_id.as_ref(), "magic_link_id")?.into_uuid();
        let verified = links
            .verify_magic_link(session_id, &request.token)
            .await
            .map_err(|e| internal("verify magic link", e))?;
        match verified {
            MagicLinkVerifyResult::Success { email } => {
                let profile = self
                    .sign_in
                    .resolve_profile(&email)
                    .await?
                    .filter(|p| p.profile_type == ProfileType::Corporate)
                    .ok_or(EmailSignInError::AuthenticationFailed)?;
                let signed_in = self.provisional(&profile, "magic_link", attempt).await?;
                info!("Magic link verified for profile {}", profile.id);
                Ok(signed_in)
            }
            // No account is known for a failed link: its address counts.
            MagicLinkVerifyResult::InvalidToken | MagicLinkVerifyResult::SessionNotFound => {
                self.sign_in.record_ip_attempt(attempt.client_ip).await?;
                Err(EmailSignInError::AuthenticationFailed)
            }
            MagicLinkVerifyResult::Expired => Err(EmailSignInError::LinkExpired),
            MagicLinkVerifyResult::AlreadyConsumed => Err(EmailSignInError::LinkUsed),
        }
    }

    /// Sign `profile` in by its proved mailbox (`method` names the
    /// ceremony): the sign-in rules judge it, then a provisional session
    /// (minutes, provisional scopes only) is delivered. Mailbox possession
    /// alone never grants a full session to an existing account, proves no
    /// stored credential and is not renewable.
    async fn provisional(
        &self,
        profile: &Profile,
        method: &str,
        attempt: Attempt<'_>,
    ) -> Result<SignedIn, EmailSignInError> {
        // The mailbox is confirmed over a second channel: `mca` (RFC 8176
        // §2), not `otp`, which names a code generator.
        let amr = ["mca".to_string()];
        let policy = self
            .admitted(profile.id, attempt.client_ip, method, &amr, attempt.context)
            .await?;
        let mut session = Session::new_provisional(profile.id, attempt.client_ip);
        session.device_id = attempt
            .context
            .user_agent
            .map(sid_authn::sign_in_security::device_id);
        session.amr = amr.to_vec();
        Ok(self
            .sign_in
            .sign_in(profile, session, attempt.client, None, None, policy, None)
            .await?)
    }

    /// The sign-in rules for `profile_id`'s mailbox sign-in under the
    /// organization's requirements: the policy fence the session commits
    /// under.
    async fn admitted(
        &self,
        profile_id: ProfileId,
        client_ip: Option<std::net::IpAddr>,
        method: &str,
        amr: &[String],
        context: AttemptContext<'_>,
    ) -> Result<Option<ActorFence>, EmailSignInError> {
        let requirements = crate::sign_in::organization_requirements(self.login_policy).await?;
        self.sign_in
            .evaluate(
                profile_id,
                client_ip,
                (
                    AttemptAuthentication::Local {
                        method,
                        assurance: AuthLevel::Basic,
                        amr,
                    },
                    context,
                ),
                &requirements,
            )
            .await?;
        Ok(requirements.fence)
    }
}

#[cfg(test)]
mod tests;
