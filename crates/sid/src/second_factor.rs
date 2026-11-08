// SPDX-License-Identifier: AGPL-3.0-only
//! Second factors: enrolling a TOTP authenticator and recovery codes,
//! verifying a factor to complete a sign-in's pending context or to step an
//! installation session up, and removing a factor. Each verification spends
//! what it uses (a TOTP step, a recovery code, a passkey assertion) once.

use std::sync::Arc;

use sid_authn::caller::{Caller, CallerError, Verified};
use sid_authn::challenge_store::ChallengeStore;
use sid_authn::credential_enrollment::EnrollmentError;
use sid_authn::login_policy::{LoginPolicySource, Unmet};
use sid_authn::operation::{CommandError, Effect, OperationError};
use sid_authn::second_factor::pending::CompletedContext;
use sid_authn::second_factor::{
    FactorCeremonies, FactorError, FactorSpend, RECOVERY_CODE_AMR, TOTP_AMR,
};
use sid_authn::sign_in_delivery::{CeremonyClient, Delivery, SignedIn};
use sid_authn::webauthn::{AssertionPurpose, AssertionResponse, WebAuthnServer};
use sid_core::Error as SidError;
use sid_core::models::session::{AuthLevel, SessionDecayLevel};
use sid_core::models::{
    AuditEntry, Credential, CredentialId, CredentialType, MutationContext, OperationContext,
    ProfileId, Session, SessionId,
};
use sid_plugin::CredentialStore;
use sid_proto::sid::v1::{
    CompleteStepUpRequest, CompleteStepUpResponse, DeleteMfaCredentialRequest,
    DeleteMfaCredentialResponse, FinishTotpEnrollmentResponse, GenerateRecoveryCodesRequest,
    GenerateRecoveryCodesResponse, StepUpChallenge, StepUpMethod, TotpEnrollmentChallenge,
    complete_step_up_request, step_up_challenge,
};
use tracing::{info, warn};

use crate::sign_in::{SignIn, SignInError};
use crate::wire::{FieldError, wire_id};

/// Why a second-factor step is refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum SecondFactorError {
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A TOTP authenticator is already enrolled.
    #[error("a TOTP authenticator is already enrolled")]
    AlreadyEnrolled,
    /// The account has no active `0` (a TOTP authenticator, recovery codes,
    /// a passkey, any factor usable for a step-up).
    #[error("no {0} is enrolled")]
    NotEnrolled(&'static str),
    #[error("profile not found")]
    ProfileNotFound(ProfileId),
    /// The `0` ceremony is unknown, expired or another's; it starts again.
    #[error("the {0} expired")]
    Expired(&'static str),
    /// The factor does not verify; one answer whatever the reason.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The session ended or expired.
    #[error("the session has ended")]
    SessionEnded,
    /// The session is provisional: it is completed, not stepped up.
    #[error("the session is provisional")]
    SessionProvisional(SessionId),
    /// The session was authenticated again in between, or the recovery
    /// code set kept changing under the spend.
    #[error("changed concurrently")]
    ChangedConcurrently,
    /// The session is too old for a step-up: full re-authentication.
    #[error("the session is too old for a step-up")]
    SessionTooOld,
    /// `0` cannot step up a session as old as `1` describes.
    #[error("the step-up method is unavailable")]
    MethodUnavailable(StepUpMethod, &'static str),
    /// The operation needs a stronger session first.
    #[error("a step-up is required")]
    StepUpRequired(Unmet),
    /// A retried recovery code generation whose set was issued: the set's
    /// credential id, recorded with the completion.
    #[error("these recovery codes were already issued")]
    RecoveryCodesIssued(Vec<u8>),
    #[error("credential not found")]
    CredentialNotFound(CredentialId),
    /// The operation is keyed and its request named no operation context;
    /// the host answers with that context's own refusal.
    #[error("the operation context is required")]
    ContextRequired,
    /// The account's last way to sign in stays.
    #[error(transparent)]
    Identity(#[from] crate::identity::IdentityError),
    /// The caller's token may not do this.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The caller's session may not bind the factor now.
    #[error(transparent)]
    Enrollment(#[from] EnrollmentError),
    /// The keyed operation's record refused or failed.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The sign-in the factor completes, its counters or kept state.
    #[error(transparent)]
    SignIn(#[from] SignInError),
    /// A dependency cannot answer now; the client retries.
    #[error("{what} unavailable: {cause}")]
    Unavailable { what: &'static str, cause: String },
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation; its cause is in the log.
    #[error("internal error")]
    Internal,
}

impl From<FieldError> for SecondFactorError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

impl From<SecondFactorError> for Effect<SecondFactorError> {
    fn from(e: SecondFactorError) -> Self {
        Self::Refused(e)
    }
}

impl From<CommandError<SecondFactorError>> for SecondFactorError {
    fn from(e: CommandError<SecondFactorError>) -> Self {
        e.refusal()
    }
}

fn internal(operation: &'static str, cause: impl std::fmt::Display) -> SecondFactorError {
    tracing::error!(operation, error = %cause, "internal failure");
    SecondFactorError::Internal
}

impl From<FactorError> for SecondFactorError {
    fn from(e: FactorError) -> Self {
        match e {
            FactorError::InvalidField { field, reason } => Self::InvalidField { field, reason },
            FactorError::AlreadyEnrolled => Self::AlreadyEnrolled,
            FactorError::NotEnrolled(what) => Self::NotEnrolled(what),
            FactorError::Expired(what) => Self::Expired(what),
            FactorError::AuthenticationFailed => Self::AuthenticationFailed,
            FactorError::CredentialNotFound(id) => Self::CredentialNotFound(id),
            FactorError::LastSignInMethod(id) => {
                Self::Identity(crate::identity::IdentityError::LastPrimary(id))
            }
            FactorError::Unavailable { what, cause } => Self::Unavailable { what, cause },
            FactorError::RecoveryCodesIssued(id) => Self::RecoveryCodesIssued(id),
            FactorError::Operation(e) => Self::Operation(e),
            FactorError::State(e) => Self::SignIn(SignInError::from(e)),
            FactorError::Store(e) => Self::Store(e),
            e @ (FactorError::Sealed(_) | FactorError::Corrupt(_)) => {
                internal("a second-factor credential", e)
            }
        }
    }
}

/// A shared second-factor step inside a keyed command's effect: a store
/// failure stays the store's, for the command to resolve against a
/// concurrent attempt.
fn factor_effect(e: FactorError) -> Effect<SecondFactorError> {
    match e {
        FactorError::Store(e) => Effect::Store(e),
        FactorError::Operation(e) => Effect::Operation(e),
        e => Effect::Refused(e.into()),
    }
}

/// A TOTP code is exactly six ASCII digits; anything else is a malformed
/// request, not a wrong code.
fn require_totp_code_format(code: &str) -> Result<(), SecondFactorError> {
    Ok(sid_authn::second_factor::require_totp_code_format(code)?)
}

/// The store of `sign_in`'s accounts' credentials.
fn credentials(sign_in: &SignIn) -> &dyn CredentialStore<Owner = ProfileId> {
    sign_in.storage().as_ref()
}

/// The namespace of committed step-ups, whose results are their rotated
/// tokens sealed for a lost response.
const STEP_UP_NAMESPACE: &str = "step-up";

/// The method a committed step-up records.
const STEP_UP_METHOD: &str = "complete_step_up";

/// The key of the step-up the token `claims` stand for: the token it
/// rotates, which stops once it commits.
fn step_up_completion_key(
    claims: &sid_authn::jwt::AccessTokenClaims,
) -> Result<sid_core::models::OperationKey, SecondFactorError> {
    sid_core::models::OperationKey::parse(&format!("step-up:{}", claims.jti))
        .map_err(|e| internal("name a step-up", e))
}

/// A spend whose credential changed before its commit lost to a concurrent
/// one: nothing was spent, and the client retries.
fn spent_concurrently(e: SecondFactorError) -> SecondFactorError {
    match e {
        SecondFactorError::Store(SidError::Fenced(_)) => SecondFactorError::ChangedConcurrently,
        other => other,
    }
}

/// The installation session a verified token stands for.
fn token_session(verified: &Verified) -> Result<SessionId, SecondFactorError> {
    SessionId::parse(&verified.claims.sid)
        .map_err(|e| internal("read session id of a verified token", e))
}

/// Who binds a second factor: an interactive session, or a sign-in's pending
/// context owing its first.
pub enum Enroller {
    Session(Caller),
    SignIn(Box<Session>),
}

impl Enroller {
    pub fn profile_id(&self) -> ProfileId {
        match self {
            Self::Session(caller) => caller.profile_id,
            Self::SignIn(pending) => pending.profile_id,
        }
    }
}

/// Who verifies a second factor.
pub enum FactorCaller {
    /// A sign-in's pending context, completed into its session for `client`.
    Pending(Session, CeremonyClient),
    /// A pending context its client proves that is no longer live: it may
    /// only receive again the sign-in its completion committed.
    Completed(CompletedContext),
    /// An installation session stepping up.
    StepUp(Session),
}

/// What a completed pending context receives again, through the shared
/// sign-in completion: its committed sign-in, or the context has ended.
async fn redelivered(
    sign_in: &SignIn,
    login_policy: &dyn LoginPolicySource,
    completed: &CompletedContext,
) -> Result<SignedIn, SecondFactorError> {
    sign_in
        .redeliver_second_factor(login_policy, completed)
        .await?
        .ok_or(SecondFactorError::SessionEnded)
}

/// A caller whose factor is judged now: a live pending context or an
/// installation session.
enum LiveCaller {
    Pending(Session, CeremonyClient),
    StepUp(Session),
}

impl LiveCaller {
    fn profile_id(&self) -> ProfileId {
        match self {
            Self::Pending(session, _) | Self::StepUp(session) => session.profile_id,
        }
    }
}

/// `caller` as it stands now: a pending context still live, read again
/// (a completed one, or one a host still holds after its completion
/// committed, is the context a retry of that completion proves), or the
/// session stepping up.
async fn live_caller(
    sign_in: &SignIn,
    caller: FactorCaller,
    native_key: Option<&str>,
) -> Result<Result<LiveCaller, CompletedContext>, SecondFactorError> {
    let (pending, client) = match caller {
        FactorCaller::Completed(completed) => return Ok(Err(completed)),
        FactorCaller::StepUp(session) => return Ok(Ok(LiveCaller::StepUp(session))),
        FactorCaller::Pending(pending, client) => (pending, client),
    };
    Ok(sign_in
        .live_pending(pending, client, native_key)
        .await?
        .map(|live| LiveCaller::Pending(live, client)))
}

/// A spent recovery code: the session it authenticated, the codes left
/// and, for a completed sign-in, its delivery.
pub struct RecoveryCodeSpent {
    pub session_id: SessionId,
    pub remaining: i32,
    pub signed_in: Option<SignedIn>,
}

/// How long a started step-up may be finished.
const CEREMONY_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// The second factors of one installation, with the ceremonies started and
/// not yet finished.
pub struct SecondFactors {
    webauthn: Arc<WebAuthnServer>,
    /// The issuer whose step-up deliveries are sealed to it.
    issuer: String,
    /// The ceremonies every authority shares: TOTP and recovery codes.
    ceremonies: FactorCeremonies<ProfileId>,
    /// The passkey ceremony of a pending step-up, keyed by session and
    /// step-up challenge: only a completion on the same session consumes it.
    step_ups: ChallengeStore<String>,
}

impl SecondFactors {
    pub fn new(
        webauthn: Arc<WebAuthnServer>,
        issuer: String,
        ceremonies: Arc<dyn sid_plugin::CeremonyStateStore>,
        keys: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            webauthn,
            step_ups: ChallengeStore::new(
                ceremonies.clone(),
                keys.clone(),
                "webauthn-step-up",
                CEREMONY_TTL,
            ),
            ceremonies: FactorCeremonies::new(issuer.clone(), "profile", ceremonies, keys),
            issuer,
        }
    }

    /// Accept `code` for `secret` once: a wrong code and a code already
    /// accepted on any path answer alike (RFC 6238 §5.2).
    async fn accept_totp(
        &self,
        profile_id: ProfileId,
        secret: &[u8],
        code: &str,
    ) -> Result<(), SecondFactorError> {
        Ok(self
            .ceremonies
            .accept_totp(profile_id, secret, code)
            .await?)
    }

    /// Refuse unless `enroller` may bind a new TOTP authenticator now.
    async fn totp_authority(
        &self,
        sign_in: &SignIn,
        enroller: &Enroller,
    ) -> Result<(), SecondFactorError> {
        let storage = sign_in.storage().as_ref();
        let passkey_satisfies_mfa = sign_in.policy().auth.passkey_satisfies_mfa;
        match enroller {
            Enroller::Session(caller) => Ok(sid_authn::credential_enrollment::authorize(
                storage,
                caller,
                CredentialType::Totp,
                passkey_satisfies_mfa,
            )
            .await?),
            Enroller::SignIn(pending) => {
                // A password replaced since the first factor binds nothing.
                sign_in.first_factor_fence(pending).await?;
                Ok(sid_authn::credential_enrollment::authorize_sign_in(
                    storage,
                    pending,
                    passkey_satisfies_mfa,
                )
                .await?)
            }
        }
    }

    /// The profile's active TOTP credential and its seed. A seed stored
    /// under an older key version is written back re-sealed under the
    /// current one.
    async fn active_totp_seed(
        &self,
        sign_in: &SignIn,
        profile_id: ProfileId,
    ) -> Result<Option<(Credential, sid_authn::sealed_secret::Opened)>, SecondFactorError> {
        Ok(self
            .ceremonies
            .active_totp_seed(credentials(sign_in), sign_in.keys(), profile_id)
            .await?)
    }

    /// Record an authentication on the active session `id`: `authenticate`
    /// changes it and the result is stored with a compare-and-swap on the
    /// session's authentication, so an ended session is never recreated and
    /// a concurrent authentication is not undone. Returns the stored session.
    async fn authenticate_session(
        &self,
        sign_in: &SignIn,
        id: SessionId,
        ctx: MutationContext,
        authenticate: impl FnOnce(&mut sid_core::models::session::ActiveSession<'_>),
    ) -> Result<Session, SecondFactorError> {
        let (expected, session) = self.authenticated(sign_in, id, authenticate).await?;
        self.record_authentication(sign_in, &expected, session, ctx)
            .await
    }

    /// The active session `id` as `authenticate` changes it, with the
    /// authentication it was read with; nothing is stored.
    async fn authenticated(
        &self,
        sign_in: &SignIn,
        id: SessionId,
        authenticate: impl FnOnce(&mut sid_core::models::session::ActiveSession<'_>),
    ) -> Result<(sid_core::models::SessionAuthentication, Session), SecondFactorError> {
        let mut session = sign_in
            .storage()
            .get_session(id)
            .await?
            .ok_or(SecondFactorError::SessionEnded)?;
        let expected = session.authentication();
        if session.is_provisional {
            return Err(SecondFactorError::SessionProvisional(id));
        }
        let mut active = session.as_active().ok_or(SecondFactorError::SessionEnded)?;
        authenticate(&mut active);
        Ok((expected, session))
    }

    /// Store `session`'s authentication over `expected` with a
    /// compare-and-swap, committing `ctx` with it.
    async fn record_authentication(
        &self,
        sign_in: &SignIn,
        expected: &sid_core::models::SessionAuthentication,
        session: Session,
        ctx: MutationContext,
    ) -> Result<Session, SecondFactorError> {
        let storage = sign_in.storage();
        if storage
            .record_session_authentication(session.id, expected, &session.authentication(), ctx)
            .await?
        {
            return Ok(session);
        }
        match storage.get_session(session.id).await? {
            Some(now) if !now.is_expired() => Err(SecondFactorError::ChangedConcurrently),
            _ => Err(SecondFactorError::SessionEnded),
        }
    }

    /// The spend of one recovery code of the profile's active set and how
    /// many remain after it. Nothing is spent here: the spend commits with
    /// the effect it pays for, as a compare-and-swap on the set as read, so
    /// concurrent uses spend a code once and only by an effect that
    /// committed; every stored hash is compared, in constant time.
    async fn recovery_spend(
        &self,
        sign_in: &SignIn,
        profile_id: ProfileId,
        code: &str,
    ) -> Result<(FactorSpend, i32), SecondFactorError> {
        Ok(self
            .ceremonies
            .recovery_spend(credentials(sign_in), profile_id, code)
            .await?)
    }

    /// Start enrolling a TOTP authenticator for `enroller`: a new seed and
    /// the parameters its codes are checked with. A new start replaces the
    /// caller's earlier pending one.
    pub async fn totp_enrollment_start(
        &self,
        sign_in: &SignIn,
        enroller: &Enroller,
    ) -> Result<TotpEnrollmentChallenge, SecondFactorError> {
        let profile_id = enroller.profile_id();
        self.totp_authority(sign_in, enroller).await?;
        let storage = sign_in.storage();
        // The account name of the otpauth URI: email, else username.
        let profile = storage
            .get_profile(profile_id)
            .await?
            .ok_or(SecondFactorError::ProfileNotFound(profile_id))?;
        let primary_email = storage.get_primary_profile_email(profile.id).await?;
        let account_name = primary_email
            .as_ref()
            .map(|e| e.email.clone())
            .or_else(|| profile.username.clone())
            .unwrap_or_else(|| profile.id.to_string());
        Ok(self
            .ceremonies
            .totp_enrollment_start(credentials(sign_in), profile_id, account_name)
            .await?)
    }

    /// Finish the enrollment with a code from the new authenticator, spent
    /// like any accepted one: the seed is stored sealed and, when it is the
    /// account's first second factor, with recovery codes in one write.
    pub async fn totp_enrollment_finish(
        &self,
        sign_in: &SignIn,
        enroller: &Enroller,
        code: &str,
    ) -> Result<FinishTotpEnrollmentResponse, SecondFactorError> {
        let profile_id = enroller.profile_id();
        require_totp_code_format(code)?;
        let secret = self.ceremonies.take_totp_enrollment(profile_id).await?;
        // The account may have changed since the start.
        self.totp_authority(sign_in, enroller).await?;
        let enrolled = self
            .ceremonies
            .enroll_totp(
                credentials(sign_in),
                sign_in.keys(),
                profile_id,
                &secret,
                code,
            )
            .await?;
        Ok(FinishTotpEnrollmentResponse {
            credential_id: crate::wire::stored_id::<sid_ids::CredentialId, _>(
                enrolled.credential_id.0,
            )
            .map_err(|e| internal("stored identifier", e))?,
            recovery_codes: enrolled.recovery_codes,
        })
    }

    /// Verify a TOTP code for `caller`: a sign-in's pending context is
    /// completed into its session under the requirements `login_policy`
    /// states (with the refresh generation of `native_key` when a native
    /// client proved one); an installation session is stepped up and gets
    /// its elevated token. A code guess spends the account's sign-in budget,
    /// shared by every context and replica, and is counted against
    /// `client_ip` when wrong.
    pub async fn verify_totp(
        &self,
        sign_in: &SignIn,
        login_policy: &dyn LoginPolicySource,
        caller: FactorCaller,
        client_ip: Option<std::net::IpAddr>,
        native_key: Option<&str>,
        code: &str,
    ) -> Result<SignedIn, SecondFactorError> {
        require_totp_code_format(code)?;
        // A context whose completion committed receives that sign-in again,
        // and the code is not judged a second time.
        let caller = match live_caller(sign_in, caller, native_key).await? {
            Ok(live) => live,
            Err(completed) => return redelivered(sign_in, login_policy, &completed).await,
        };
        let profile_id = caller.profile_id();
        let identity = profile_id.to_string();
        sign_in.refuse_if_locked(&identity).await?;

        // The active TOTP credential only, its use recorded only while it is
        // still active; a wrong code counts against the sign-in budget.
        match self
            .ceremonies
            .verify_totp(credentials(sign_in), sign_in.keys(), profile_id, code)
            .await
        {
            Ok(()) => {}
            Err(FactorError::AuthenticationFailed) => {
                sign_in.record_failed_login(&identity, client_ip).await?;
                return Err(SecondFactorError::AuthenticationFailed);
            }
            Err(e) => return Err(e.into()),
        }
        let storage = sign_in.storage();

        let session_id = match caller {
            LiveCaller::Pending(pending, client) => {
                let signed_in = sign_in
                    .complete_second_factor(
                        login_policy,
                        pending,
                        TOTP_AMR,
                        client,
                        native_key,
                        None,
                    )
                    .await?;
                info!("TOTP completed the sign-in of profile {}", profile_id);
                return Ok(signed_in);
            }
            LiveCaller::StepUp(session) => session.id,
        };

        // A token must not claim an elevation that was not stored.
        let session = self
            .authenticate_session(
                sign_in,
                session_id,
                AuditEntry::user(
                    profile_id.to_string(),
                    "session.step_up",
                    session_id.to_string(),
                )
                .into(),
                |active| {
                    active.elevate(AuthLevel::Standard);
                    active.add_amr(TOTP_AMR);
                },
            )
            .await?;
        let profile = storage
            .get_profile(profile_id)
            .await?
            .ok_or(SecondFactorError::SessionEnded)?;
        let sub = profile_id.to_string();
        let roles = sid_authn::account_roles::account_roles(storage.as_ref(), &profile).await?;
        let access_token = sign_in
            .jwt()
            .issue_access_token(
                &sub,
                Some(&sub),
                &roles,
                &session,
                &session.scopes,
                None,
                None,
            )
            .map_err(|e| internal("issue access token", e))?;
        info!("TOTP step-up verified for profile {}", profile_id);
        // The caller presented the session's token, so the elevated one goes
        // back the same way, whoever it is (a native client or a BFF).
        Ok(SignedIn {
            session_id,
            expires_in: sign_in.jwt().access_token_ttl_secs(),
            delivery: Delivery::bearer(access_token.into()),
        })
    }

    /// Issue `caller` a new set of recovery codes in place of the old one.
    /// New codes step up to Standard, so issuing them is an enrollment. SID
    /// keeps only their hashes: a retry of a completed generation names the
    /// set it issued and issues no other.
    pub async fn generate_recovery_codes(
        &self,
        sign_in: &SignIn,
        caller: &Caller,
        operation: Option<OperationContext>,
        request: &GenerateRecoveryCodesRequest,
    ) -> Result<GenerateRecoveryCodesResponse, SecondFactorError> {
        let profile_id = caller.profile_id;
        let storage = sign_in.storage();
        sid_authn::credential_enrollment::authorize(
            storage.as_ref(),
            caller,
            CredentialType::Recovery,
            sign_in.policy().auth.passkey_satisfies_mfa,
        )
        .await?;
        let operation = operation.ok_or(SecondFactorError::ContextRequired)?;
        let command = self
            .ceremonies
            .command::<sid_proto::keyed::authn::auth_service::GenerateRecoveryCodes>(
                profile_id, operation, request,
            );
        let codes = self
            .ceremonies
            .regenerate_recovery_codes(credentials(sign_in), &**storage, profile_id, command)
            .await?;
        Ok(GenerateRecoveryCodesResponse { codes })
    }

    /// Spend a recovery code for `caller`: a sign-in's pending context is
    /// completed into its session, as by a TOTP code, when the requirements
    /// `login_policy` states accept the code's method, checked before the
    /// code is spent (with the refresh generation of `native_key` when a
    /// native client proved one); an installation session has the method
    /// recorded (recovery grants it no elevation, so no new token). A wrong
    /// code completing a sign-in spends the account's sign-in budget.
    pub async fn verify_recovery_code(
        &self,
        sign_in: &SignIn,
        login_policy: &dyn LoginPolicySource,
        caller: FactorCaller,
        client_ip: Option<std::net::IpAddr>,
        native_key: Option<&str>,
        code: &str,
    ) -> Result<RecoveryCodeSpent, SecondFactorError> {
        if code.is_empty() {
            return Err(SecondFactorError::MissingField("code"));
        }
        let amr = RECOVERY_CODE_AMR;
        // A context whose completion committed receives that sign-in again;
        // the code presented is not judged and nothing more is spent.
        let caller = match live_caller(sign_in, caller, native_key).await? {
            Ok(live) => live,
            Err(completed) => {
                let signed_in = redelivered(sign_in, login_policy, &completed).await?;
                return Ok(RecoveryCodeSpent {
                    session_id: signed_in.session_id,
                    remaining: self.codes_left(sign_in, &signed_in).await?,
                    signed_in: Some(signed_in),
                });
            }
        };
        let profile_id = caller.profile_id();
        let (pending, client) = match caller {
            LiveCaller::Pending(pending, client) => (pending, client),
            LiveCaller::StepUp(session) => {
                let (spend, remaining) = self.recovery_spend(sign_in, profile_id, code).await?;
                // The code is spent in the commit recording it on the session.
                self.authenticate_session(
                    sign_in,
                    session.id,
                    spend.into_context(
                        AuditEntry::user(
                            profile_id.to_string(),
                            "session.recovery_code_used",
                            session.id.to_string(),
                        )
                        .into(),
                    ),
                    |active| active.add_amr(amr),
                )
                .await
                .map_err(spent_concurrently)?;
                return Ok(RecoveryCodeSpent {
                    session_id: session.id,
                    remaining,
                    signed_in: None,
                });
            }
        };
        let identity = profile_id.to_string();
        sign_in.refuse_if_locked(&identity).await?;
        // The code is spent only in the commit that completes the sign-in:
        // a completion refused (the pending context ended, the policy or the
        // first factor changed) or lost to a concurrent one spends nothing.
        // The checks here answer early; the commit makes them again.
        sign_in
            .second_factor_requirements(login_policy, &pending, amr)
            .await?;
        sign_in.first_factor_fence(&pending).await?;
        let (spend, remaining) = match self.recovery_spend(sign_in, profile_id, code).await {
            Ok(spend) => spend,
            Err(SecondFactorError::AuthenticationFailed) => {
                sign_in.record_failed_login(&identity, client_ip).await?;
                return Err(SecondFactorError::AuthenticationFailed);
            }
            Err(e) => return Err(e),
        };
        let signed_in = sign_in
            .complete_second_factor(login_policy, pending, amr, client, native_key, Some(spend))
            .await?;
        // A concurrent completion that committed first answers instead of
        // this one, and this code stays unspent: the count is the store's.
        let remaining = match self.codes_left(sign_in, &signed_in).await {
            Ok(left) => left,
            Err(_) => remaining,
        };
        info!(
            "A recovery code completed the sign-in of profile {} ({} remaining)",
            profile_id, remaining
        );
        Ok(RecoveryCodeSpent {
            session_id: signed_in.session_id,
            remaining,
            signed_in: Some(signed_in),
        })
    }

    /// How many recovery codes the account `signed_in` signed into has left.
    async fn codes_left(
        &self,
        sign_in: &SignIn,
        signed_in: &SignedIn,
    ) -> Result<i32, SecondFactorError> {
        let storage = sign_in.storage();
        let session = storage
            .get_session(signed_in.session_id)
            .await?
            .ok_or(SecondFactorError::SessionEnded)?;
        Ok(sid_authn::second_factor::codes_left(credentials(sign_in), session.profile_id).await?)
    }

    /// The step-up methods the installation session `verified` stands for
    /// may use, by the session's decay; with `method` a passkey, also its
    /// challenge, kept for a completion on the same session.
    pub async fn step_up_request(
        &self,
        sign_in: &SignIn,
        verified: &Verified,
        method: i32,
    ) -> Result<StepUpChallenge, SecondFactorError> {
        // Step-up elevates the IdP session, never an application's session.
        verified.require_installation()?;
        verified.caller.require_interactive()?;
        let requested = StepUpMethod::try_from(method).unwrap_or(StepUpMethod::Unspecified);
        let storage = sign_in.storage();
        let session = storage
            .get_session(token_session(verified)?)
            .await?
            .ok_or(SecondFactorError::SessionEnded)?;
        let decay = session.decay_level();
        // Past medium decay only a full sign-in renews the session. The
        // token itself still works for other calls: a state of the session,
        // not a failed authentication.
        if decay > SessionDecayLevel::Medium {
            return Err(SecondFactorError::SessionTooOld);
        }
        // Only credentials that may still authenticate offer a method.
        let enrolled: Vec<Credential> = storage
            .get_credentials_by_profile(session.profile_id, None)
            .await?
            .into_iter()
            .filter(|c| c.status.is_active())
            .collect();
        let has = |kind| enrolled.iter().any(|c| c.credential_type == kind);
        // Medium decay: phishing-resistant only (passkeys); fresher: every
        // enrolled method.
        let phishing_resistant_only = decay >= SessionDecayLevel::Medium;
        let mut allowed = Vec::new();
        if has(CredentialType::WebAuthn) {
            allowed.push(StepUpMethod::Webauthn as i32);
        }
        if !phishing_resistant_only {
            if has(CredentialType::Totp) {
                allowed.push(StepUpMethod::Totp as i32);
            }
            if has(CredentialType::Recovery) {
                allowed.push(StepUpMethod::RecoveryCode as i32);
            }
        }
        let decay_level = match decay {
            SessionDecayLevel::Full => "full",
            SessionDecayLevel::High => "high",
            SessionDecayLevel::Medium => "medium",
            SessionDecayLevel::Low => "low",
        };
        let answer = |challenge_id, challenge, allowed_methods| StepUpChallenge {
            method,
            challenge_id,
            challenge,
            allowed_methods,
            decay_level: decay_level.to_string(),
        };
        match requested {
            StepUpMethod::Unspecified => {
                // A query of the methods; none means no step-up is possible.
                if allowed.is_empty() {
                    return Err(SecondFactorError::NotEnrolled(
                        "second factor usable for a step-up",
                    ));
                }
                Ok(StepUpChallenge {
                    method: StepUpMethod::Unspecified as i32,
                    ..answer(None, None, allowed)
                })
            }
            StepUpMethod::Totp | StepUpMethod::RecoveryCode => {
                if !allowed.contains(&(requested as i32)) {
                    return Err(SecondFactorError::MethodUnavailable(requested, decay_level));
                }
                // One phase: the client completes the step-up directly.
                Ok(answer(None, None, allowed))
            }
            StepUpMethod::Webauthn => {
                let passkeys: Vec<&Credential> = enrolled
                    .iter()
                    .filter(|c| c.credential_type == CredentialType::WebAuthn)
                    .collect();
                if passkeys.is_empty() {
                    return Err(SecondFactorError::NotEnrolled("passkey"));
                }
                let started = self
                    .webauthn
                    .authentication_start(AssertionPurpose::StepUp, passkeys)
                    .await
                    .map_err(|e| internal("start passkey step-up", e))?;
                let challenge_id = sid_ids::StepUpChallengeId::generate();
                self.step_ups
                    .insert(
                        &step_up_key(&verified.claims.sid, &challenge_id.to_string()),
                        &started.state_key,
                    )
                    .await
                    .map_err(SignInError::from)?;
                Ok(answer(
                    Some(challenge_id.into()),
                    Some(step_up_challenge::Challenge::WebauthnOptions(
                        started.options,
                    )),
                    allowed,
                ))
            }
        }
    }

    /// Complete a step-up of the installation session `verified` stands for
    /// with the proof `request` carries: the elevation is stored, then the
    /// session gets a rotated token and the one this call came with stops.
    pub async fn step_up_complete(
        &self,
        sign_in: &SignIn,
        verified: &Verified,
        request: CompleteStepUpRequest,
    ) -> Result<CompleteStepUpResponse, SecondFactorError> {
        verified.require_installation()?;
        let claims = &verified.claims;
        let profile_id = verified.caller.profile_id;
        let session_id = token_session(verified)?;
        // A step-up of this token already committed: its rotated token is
        // delivered again and the proof is not judged a second time.
        if let Some(committed) = self.step_up_redeliver(sign_in, claims).await? {
            return Ok(committed);
        }
        let method = StepUpMethod::try_from(request.method).unwrap_or(StepUpMethod::Unspecified);
        let mut spend = None;
        let (amr_methods, target_level) = match method {
            StepUpMethod::Totp => {
                let Some(complete_step_up_request::Proof::TotpCode(code)) = request.proof else {
                    return Err(SecondFactorError::MissingField("totp_code"));
                };
                require_totp_code_format(&code)?;
                let (_, secret) = self
                    .active_totp_seed(sign_in, profile_id)
                    .await?
                    .ok_or(SecondFactorError::NotEnrolled("TOTP authenticator"))?;
                self.accept_totp(profile_id, &secret.secret, &code).await?;
                (vec![TOTP_AMR], AuthLevel::Standard)
            }
            StepUpMethod::RecoveryCode => {
                let Some(complete_step_up_request::Proof::RecoveryCode(code)) = request.proof
                else {
                    return Err(SecondFactorError::MissingField("recovery_code"));
                };
                // The code is spent in the commit storing the elevation: an
                // elevation not stored spends nothing, and a spent code
                // never stays reusable.
                spend = Some(self.recovery_spend(sign_in, profile_id, &code).await?.0);
                (vec![RECOVERY_CODE_AMR], AuthLevel::Standard)
            }
            StepUpMethod::Webauthn => {
                let Some(complete_step_up_request::Proof::WebauthnAssertion(assertion)) =
                    request.proof
                else {
                    return Err(SecondFactorError::MissingField("webauthn_assertion"));
                };
                let credential = AssertionResponse::parse(&assertion).map_err(|_| {
                    SecondFactorError::InvalidField {
                        field: "webauthn_assertion",
                        reason: "not a WebAuthn assertion".to_string(),
                    }
                })?;
                // The step-up this session requested, and the assertion must
                // answer that step-up's own challenge.
                let expired = || SecondFactorError::Expired("passkey step-up");
                let challenge_id = wire_id(request.challenge_id.as_ref(), "challenge_id")?;
                let state_key = self
                    .step_ups
                    .take(&step_up_key(&claims.sid, &challenge_id.to_string()))
                    .await
                    .map_err(SignInError::from)?
                    .ok_or_else(expired)?;
                if credential.state_key().ok() != Some(state_key) {
                    return Err(expired());
                }
                let storage = sign_in.storage();
                let passkeys = crate::passkey::active(storage.as_ref(), profile_id).await?;
                let asserted = self
                    .webauthn
                    .authentication_finish(AssertionPurpose::StepUp, &credential, &passkeys)
                    .await
                    .map_err(|e| match e {
                        SidError::AuthenticationFailed(why) => {
                            warn!("WebAuthn step-up verification failed: {why}");
                            SecondFactorError::AuthenticationFailed
                        }
                        other => internal("finish passkey step-up", other),
                    })?;
                let (key_amr, _) =
                    crate::passkey::record_use(storage.as_ref(), &passkeys, &asserted)
                        .await
                        .map_err(|e| match e {
                            crate::passkey::PasskeyError::Store(e) => SecondFactorError::Store(e),
                            _ => SecondFactorError::AuthenticationFailed,
                        })?;
                // A user-verifying passkey is phishing-resistant with two
                // factors (Elevated); possession alone is Standard.
                let target = if asserted.user_verified {
                    AuthLevel::Elevated
                } else {
                    AuthLevel::Standard
                };
                (
                    sid_authn::webauthn::passkey_amr(key_amr, asserted.user_verified),
                    target,
                )
            }
            StepUpMethod::Unspecified => return Err(SecondFactorError::MissingField("method")),
        };

        let (expected, elevated) = self
            .authenticated(sign_in, session_id, |active| {
                active.elevate(target_level);
                for method in &amr_methods {
                    active.add_amr(method);
                }
                // The step-up is an authentication now: it is what a later
                // sensitive operation counts as fresh.
                active.refresh_authentication();
            })
            .await?;
        // The rotated token exists before the elevation commits and is
        // sealed into that commit: the elevation, the factor's spend and
        // the answer to a lost response commit together, kept no longer
        // than the token they replace.
        let new_token = sign_in
            .jwt()
            .reissue_elevated_token(claims, &elevated)
            .map_err(|e| internal("reissue stepped-up token", e))?;
        // Kept while both the token it replaces and the replacement are
        // valid: a replacement past its own expiry is never delivered.
        let replacement_exp = sign_in
            .jwt()
            .validate_access_token(&new_token)
            .map_err(|e| internal("read the stepped-up token", e))?
            .exp;
        let deadline = chrono::DateTime::from_timestamp(claims.exp.min(replacement_exp), 0)
            .unwrap_or_else(chrono::Utc::now)
            .min(elevated.expires_at);
        let sealed = sid_authn::sign_in_delivery::retain_bearer(
            sign_in.keys(),
            &self.step_up_context(claims),
            &elevated,
            sid_authn::sign_in_delivery::BearerCredential {
                token: &new_token.clone().into(),
                token_expires_at: deadline,
                refresh: None,
            },
            deadline,
        )
        .await
        .map_err(|e| internal("seal the stepped-up token", e))?;
        let mut ctx = MutationContext::from(AuditEntry::user(
            profile_id.to_string(),
            "session.step_up",
            session_id.to_string(),
        ))
        .with_operation(
            sid_core::models::OperationCompletion::new(
                STEP_UP_NAMESPACE,
                step_up_completion_key(claims)?,
                STEP_UP_METHOD,
                claims.sid.as_bytes(),
                sealed,
            )
            .retained_until(deadline),
        );
        if let Some(spend) = spend {
            ctx = spend.into_context(ctx);
        }
        let session = match self
            .record_authentication(sign_in, &expected, elevated, ctx)
            .await
        {
            Ok(session) => session,
            // Another attempt of this step-up committed first: its token.
            Err(SecondFactorError::Store(SidError::OperationCompleted(_))) => {
                return self
                    .step_up_redeliver(sign_in, claims)
                    .await?
                    .ok_or(SecondFactorError::ChangedConcurrently);
            }
            Err(e) => return Err(spent_concurrently(e)),
        };
        let acr = session
            .assurance_at(chrono::Utc::now())
            .acr_value()
            .to_string();
        let amr = session.amr.clone();
        self.stop_token(sign_in, claims).await?;
        info!(
            profile = %profile_id,
            methods = ?amr_methods,
            acr = %acr,
            "Step-up completed via generic RPC"
        );
        Ok(CompleteStepUpResponse {
            new_session_token: new_token,
            acr,
            amr,
        })
    }

    /// Stop the token `claims` stand for, which a step-up replaced, for its
    /// remaining lifetime; repeating it changes nothing.
    async fn stop_token(
        &self,
        sign_in: &SignIn,
        claims: &sid_authn::jwt::AccessTokenClaims,
    ) -> Result<(), SecondFactorError> {
        // Both are Unix-second timestamps of this era: the difference cannot
        // overflow; a negative one is a token already expired.
        let remaining = u64::try_from(claims.exp - chrono::Utc::now().timestamp()).unwrap_or(0);
        sign_in
            .revocation()
            .revoke_jti(
                claims.jti.clone(),
                std::time::Duration::from_secs(remaining),
            )
            .await
            .map_err(|e| SecondFactorError::Unavailable {
                what: "token revocation",
                cause: e.to_string(),
            })
    }

    /// The sealing context of the step-up the token `claims` stand for.
    fn step_up_context(&self, claims: &sid_authn::jwt::AccessTokenClaims) -> String {
        format!("step-up:{}:{}:{}", self.issuer, claims.sid, claims.jti)
    }

    /// The step-up the token `claims` stand for, already committed,
    /// answered again after a lost response: the same rotated token, with
    /// the session's assurance and methods as they stand now. `None` when
    /// no step-up of that token committed, or it is no longer kept. The
    /// token's own signature is all `claims` must have passed: the step-up
    /// stopped it, and its record is the only authority it carries here. A
    /// session ended or expired, or an account that can no longer sign in,
    /// receives nothing.
    pub async fn step_up_redeliver(
        &self,
        sign_in: &SignIn,
        claims: &sid_authn::jwt::AccessTokenClaims,
    ) -> Result<Option<CompleteStepUpResponse>, SecondFactorError> {
        let storage = sign_in.storage();
        let Some(record) = storage
            .get_operation_result(STEP_UP_NAMESPACE, &step_up_completion_key(claims)?)
            .await?
        else {
            return Ok(None);
        };
        if !record.matches(STEP_UP_METHOD, claims.sid.as_bytes(), None) {
            return Err(SecondFactorError::AuthenticationFailed);
        }
        let delivery = sid_authn::sign_in_delivery::RetainedDelivery::open(
            sign_in.keys(),
            &self.step_up_context(claims),
            &record.completion.result,
        )
        .await
        .map_err(|e| internal("open the stepped-up token", e))?;
        let now = chrono::Utc::now();
        if delivery.deadline <= now {
            return Ok(None);
        }
        let session = storage
            .get_session(delivery.session_id)
            .await?
            .filter(|s| !s.is_expired() && s.id.to_string() == claims.sid)
            .ok_or(SecondFactorError::SessionEnded)?;
        storage
            .get_profile(session.profile_id)
            .await?
            .filter(|p| p.status.can_authenticate())
            .ok_or(SecondFactorError::SessionEnded)?;
        let token = delivery
            .into_bearer_token()
            .ok_or_else(|| internal("open the stepped-up token", "not a bearer delivery"))?;
        // A later step-up of the rotated token replaced and stopped it: that
        // token is no longer deliverable, and handing it out would replace
        // the client's current one with a revoked credential.
        let rotated = sign_in
            .jwt()
            .validate_access_token(secrecy::ExposeSecret::expose_secret(&token))
            .map_err(|e| internal("read the stepped-up token", e))?;
        let replaced = sign_in
            .revocation()
            .is_revoked(&rotated.jti, &rotated.sid)
            .await
            .map_err(|e| SecondFactorError::Unavailable {
                what: "token revocation",
                cause: e.to_string(),
            })?;
        if replaced {
            return Ok(None);
        }
        // The stopped token stops before the step-up is reported: a first
        // attempt that committed but failed to revoke it, or ended before,
        // has it revoked here.
        self.stop_token(sign_in, claims).await?;
        Ok(Some(CompleteStepUpResponse {
            new_session_token: secrecy::ExposeSecret::expose_secret(&token).to_owned(),
            acr: session.assurance_at(now).acr_value().to_string(),
            amr: session.amr.clone(),
        }))
    }

    /// Remove one of the caller's second factors (TOTP, passkey, recovery
    /// codes) from an elevated session: revoked, not deleted, and a passkey
    /// that is the account's last way to sign in stays. A retry of a
    /// completed removal answers as it did and owes no second event.
    pub async fn delete(
        &self,
        sign_in: &SignIn,
        verified: &Verified,
        operation: Option<OperationContext>,
        request: DeleteMfaCredentialRequest,
    ) -> Result<DeleteMfaCredentialResponse, SecondFactorError> {
        let acr = &verified.claims.acr;
        if !acr.contains("elevated") && !acr.contains("critical") {
            return Err(SecondFactorError::StepUpRequired(Unmet {
                acr: Some(AuthLevel::Elevated),
                ..Default::default()
            }));
        }
        let operation = operation.ok_or(SecondFactorError::ContextRequired)?;
        let profile_id = verified.caller.profile_id;
        let credential_id =
            CredentialId(wire_id(request.credential_id.as_ref(), "credential_id")?.into_uuid());
        let credentials = credentials(sign_in);
        let command = self
            .ceremonies
            .command::<sid_proto::keyed::authn::auth_service::DeleteMfaCredential>(
                profile_id, operation, &request,
            );
        Ok(command
            .execute::<_, SecondFactorError, _, _>(sign_in.storage().as_ref(), || async {
                let kind = sid_authn::second_factor::removable_factor(
                    credentials,
                    profile_id,
                    credential_id,
                )
                .await
                .map_err(factor_effect)?;
                self.ceremonies
                    .remove_factor(credentials, profile_id, credential_id, kind, |response| {
                        command.completion(prost::Message::encode_to_vec(response))
                    })
                    .await
                    .map_err(factor_effect)
            })
            .await?)
    }
}

/// The kept passkey ceremony of a step-up: bound to the session that
/// requested it, so a completion on another session cannot consume it.
fn step_up_key(session_id: &str, challenge_id: &str) -> String {
    format!("step-up:{session_id}:{challenge_id}")
}

#[cfg(test)]
mod tests;
