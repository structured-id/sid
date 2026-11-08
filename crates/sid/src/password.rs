// SPDX-License-Identifier: AGPL-3.0-only
//! Replacing a password: through the installation's password operations, the
//! caller's change of its own, proving the current password when its session
//! may no longer change it without, and the reset of a forgotten one under a
//! verified reset link, where the new password, its proof's evidence and the
//! owner's history are one write over the password read; and the upgrade of
//! a password imported as another system's hash to an OPAQUE password.

use std::sync::Arc;

use sid_authn::caller::Caller;
use sid_authn::challenge_store::ChallengeStore;
use sid_authn::credential_enrollment::{EnrollmentError, EnrollmentRefusal};
use sid_authn::login_policy::LoginPolicySource;
use sid_authn::opaque_zkpp::ZkppOpaqueServer;
use sid_authn::password_operation::{
    CurrentPasswordCheck, OperationOwner, PasswordOperationError, StepError, change_context,
};
use sid_authn::password_reset::PasswordResetService;
use sid_authn::sign_in_delivery::{CeremonyClient, SignedIn};
use sid_authn::sign_in_security::SignInRefusal;
use sid_core::Error as SidError;
use sid_core::models::principal::PrincipalType;
use sid_core::models::{
    AuditEntry, Credential, CredentialFence, CredentialId, CredentialType, HistoryCommit,
    MutationContext, PasswordResetSession, ProfileId, ResetSessionId, ResetSessionStatus,
    SessionEnd,
};
use sid_proto::sid::v1::{
    CompletePasswordResetRequest, ExecutePasswordResetRequest, ExecutePasswordResetResponse,
    LegacyMigrateFinishRequest, LegacyMigrateStartRequest, LegacyMigrateStartResponse,
    PasswordChangeChallengeRequest, PasswordChangeChallengeResponse, PasswordChangeExecuteRequest,
    PasswordChangeExecuteResponse, PasswordChangeFinishRequest, RequestPasswordResetResponse,
    VerifyPasswordResetRequest, VerifyPasswordResetResponse,
};
use tracing::{info, warn};

use crate::password_operation::{Finish, OperationPurpose, PasswordOperations, PendingOperation};
use crate::sign_in::{AttemptContext, FirstFactorSignedIn, LoginMethod, SignIn, SignInError};
use crate::wire::{FieldError, wire_id};

/// Why a password replacement is refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("{0} is required")]
    MissingField(&'static str),
    /// No password credential of the caller's has this id; also the answer
    /// for one the caller does not own, so a foreign id reveals nothing.
    #[error("credential not found")]
    CredentialNotFound(CredentialId),
    /// Another change replaced the password, or revoked it, in between.
    #[error("the password changed concurrently")]
    ChangedConcurrently,
    /// The current password did not prove, or the reset's account is gone.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The installation cannot serve this at all: `password_reset` without
    /// a page a link opens, `email_provider` without mail to send it.
    #[error("{0} is not configured")]
    NotConfigured(&'static str),
    /// The reset is unknown, expired or completed meanwhile; it starts again
    /// from the email.
    #[error("the password reset expired")]
    ResetExpired,
    /// The reset link `session` was already used.
    #[error("the reset link was already used")]
    ResetUsed(String),
    /// The reset `session` is not verified yet.
    #[error("the reset is not verified yet")]
    ResetUnverified(String),
    /// The reset link's token does not match its session.
    #[error("the reset link is not valid")]
    ResetTokenInvalid,
    /// The imported password's upgrade is unknown or expired; it starts
    /// again.
    #[error("the password upgrade expired")]
    UpgradeExpired,
    /// The caller's session may not change the password now.
    #[error(transparent)]
    Enrollment(#[from] EnrollmentError),
    /// The password operation refused the step.
    #[error(transparent)]
    Operation(#[from] PasswordOperationError),
    /// The lockout of the current password's guesses, or its counters.
    #[error(transparent)]
    SignIn(#[from] SignInError),
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation; its cause is in the log.
    #[error("internal error")]
    Internal,
}

impl From<FieldError> for PasswordError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

impl From<EnrollmentRefusal> for PasswordError {
    fn from(refusal: EnrollmentRefusal) -> Self {
        Self::Enrollment(refusal.into())
    }
}

fn internal(operation: &'static str, cause: impl std::fmt::Display) -> PasswordError {
    tracing::error!(operation, error = %cause, "internal failure");
    PasswordError::Internal
}

/// The OPAQUE password file `data` sealed for `profile_id` under `sign_in`'s
/// keys, as it is stored.
async fn seal(
    sign_in: &SignIn,
    profile_id: ProfileId,
    data: &[u8],
) -> Result<Vec<u8>, PasswordError> {
    sid_authn::sealed_secret::seal(
        sign_in.keys(),
        &sid_authn::sealed_secret::opaque_context(profile_id),
        data,
    )
    .await
    .map_err(|e| internal("seal OPAQUE envelope", e))
}

/// The attempt counter of the current-password sign-ins `profile`'s password
/// changes begin, apart from its sign-in counter.
fn current_password_guesses(profile: ProfileId) -> String {
    format!("current-password:{profile}")
}

/// Accept `op` as the caller's change of `credential` as it stands now; any
/// other operation reads as not pending, so a caller learns nothing about
/// others'. An operation begun on a password another change has since
/// replaced is refused: its authority (a sign-in with that password, or a
/// fresh session then) is over the replaced one and must not overwrite the
/// newer.
fn own_change(
    op: &PendingOperation,
    caller: ProfileId,
    credential: &Credential,
) -> Result<(), PasswordError> {
    match op.purpose {
        OperationPurpose::Change {
            profile_id,
            credential_id,
            password,
        } if profile_id == caller && credential_id == credential.id => {
            if password == credential.opaque_credential_identifier() {
                Ok(())
            } else {
                Err(PasswordError::ChangedConcurrently)
            }
        }
        _ => Err(PasswordOperationError::NotPending.into()),
    }
}

/// Password replacement over one installation's sign-ins and password
/// operations.
pub struct Passwords<'a> {
    sign_in: &'a SignIn,
    operations: &'a PasswordOperations,
}

impl<'a> Passwords<'a> {
    pub fn new(sign_in: &'a SignIn, operations: &'a PasswordOperations) -> Self {
        Self {
            sign_in,
            operations,
        }
    }

    /// Refuse unless `caller` may change its own password now; answer
    /// whether the change must prove the current password.
    async fn change_authority(&self, caller: &Caller) -> Result<bool, PasswordError> {
        let policy = self.sign_in.policy();
        Ok(sid_authn::credential_enrollment::password_change_authority(
            self.sign_in.storage().as_ref(),
            caller,
            policy.auth.passkey_satisfies_mfa,
            policy.password.change_current_password,
        )
        .await?)
    }

    /// The active password credential `credential_id` of `caller`.
    async fn own_password(
        &self,
        credential_id: Option<&sid_ids_proto::CredentialId>,
        caller: ProfileId,
    ) -> Result<Credential, PasswordError> {
        let id = CredentialId(wire_id(credential_id, "credential_id")?.into_uuid());
        let credential = self
            .sign_in
            .storage()
            .get_credential(id)
            .await?
            .ok_or(PasswordError::CredentialNotFound(id))?;
        if credential.profile_id != caller
            || credential.credential_type != CredentialType::Opaque
            || !credential.status.is_active()
        {
            return Err(PasswordError::CredentialNotFound(credential.id));
        }
        Ok(credential)
    }

    /// `history` with this installation's age retention: an accepted
    /// password's commit also drops the owner's entries older than the policy
    /// keeps, under the same revision fence.
    fn with_history_age(&self, history: Option<HistoryCommit>) -> Option<HistoryCommit> {
        history.map(|mut commit| {
            commit.max_age_days = self.sign_in.policy().password.history_max_age_days;
            commit
        })
    }

    /// Prepare a change of `caller`'s own password: the operation with the
    /// owner's history domains, which the client evaluates and proves over,
    /// and, when the request proves the current password, the KE2 of that
    /// sign-in, counted against the change's own budget.
    pub async fn change_challenge(
        &self,
        zkpp: &ZkppOpaqueServer,
        caller: &Caller,
        request: PasswordChangeChallengeRequest,
    ) -> Result<PasswordChangeChallengeResponse, PasswordError> {
        let required = self.change_authority(caller).await?;
        let caller = caller.profile_id;
        let credential = self
            .own_password(request.credential_id.as_ref(), caller)
            .await?;
        // The challenge fixes the new password's request: the current
        // password is confirmed for it, and execute starts no other.
        if request.registration_request.is_empty() {
            return Err(PasswordError::MissingField("registration_request"));
        }
        let proves = !request.credential_request.is_empty();
        if required && !proves {
            return Err(EnrollmentRefusal::CurrentPasswordRequired.into());
        }
        let guesses = current_password_guesses(caller);
        if proves {
            // As at sign-in: during a lockout the current password is not tried.
            self.sign_in.refuse_if_locked(&caller.to_string()).await?;
            self.sign_in.refuse_if_locked(&guesses).await?;
        }
        // The current password's sign-in starts first, under the operation it
        // confirms: a malformed one is refused before any history is
        // prepared for it, and charges nothing.
        let id = sid_ids::PasswordOperationId::generate();
        let started = if proves {
            let (stored, _) = self.sign_in.stored_password(&credential).await?;
            Some(
                self.sign_in
                    .opaque()
                    .login_start(
                        &stored,
                        &request.credential_request,
                        &credential.opaque_credential_identifier(),
                        &change_context(&id, &request.registration_request),
                    )
                    .map_err(|e| {
                        warn!("current-password sign-in start failed: {e}");
                        PasswordError::InvalidField {
                            field: "credential_request",
                            reason: "not an OPAQUE credential request".to_string(),
                        }
                    })?,
            )
        } else {
            None
        };
        let prepared = self
            .operations
            .prepare_as(
                id,
                zkpp,
                OperationPurpose::Change {
                    profile_id: caller,
                    credential_id: credential.id,
                    password: credential.opaque_credential_identifier(),
                },
                OperationOwner::Existing(caller),
                format!("profile:{caller}"),
                // Fixed now; its response is withheld until execute confirms.
                Some(request.registration_request),
            )
            .await?;

        let credential_response = if let Some((response, state)) = started {
            // A wrong guess fails on the client at KE2 and need never reach
            // execute, so each KE2 is counted just before it is issued,
            // against the change's own budget: a stolen session cannot guess
            // the password through changes, and the account's sign-in budget
            // is untouched. A challenge refused earlier taught nothing.
            let anomaly = self.sign_in.anomaly();
            if !anomaly
                .count_attempt(&guesses)
                .await
                .map_err(crate::sign_in::unavailable)?
            {
                return Err(SignInError::from(SignInRefusal::TooManyAttempts(
                    anomaly.lockout_duration(),
                ))
                .into());
            }
            self.operations
                .begin_current_password(&id, state, |op| own_change(op, caller, &credential))
                .await
                .map_err(StepError::refusal)?;
            response
        } else {
            Vec::new()
        };

        Ok(PasswordChangeChallengeResponse {
            history: Some(prepared.context),
            credential_response,
        })
    }

    /// The OPAQUE start of the new password, under the operation's own OPRF
    /// key, once the current password is proven when it must be: the
    /// request the proof is bound to. A wrong current password is counted
    /// against `client_ip`.
    pub async fn change_execute(
        &self,
        zkpp: &ZkppOpaqueServer,
        caller: &Caller,
        client_ip: Option<std::net::IpAddr>,
        request: PasswordChangeExecuteRequest,
    ) -> Result<PasswordChangeExecuteResponse, PasswordError> {
        let required = self.change_authority(caller).await?;
        let caller = caller.profile_id;
        let credential = self
            .own_password(request.credential_id.as_ref(), caller)
            .await?;
        let id = sid_authn::password_operation::operation_id(request.operation_id.as_ref())?;
        if !request.credential_finalization.is_empty() {
            // As at sign-in: during a lockout a right and a wrong password
            // get the same answer.
            self.sign_in.refuse_if_locked(&caller.to_string()).await?;
        }
        let opaque = self.sign_in.opaque();
        let check = self
            .operations
            .prove_current_password(
                &id,
                &request.credential_finalization,
                |op| own_change(op, caller, &credential),
                |state, finalization, context| {
                    opaque
                        .login_finish(state, finalization, context)
                        .inspect_err(|e| warn!("current-password sign-in failed: {e}"))
                        .is_ok()
                },
            )
            .await
            .map_err(StepError::refusal)?;
        match check {
            CurrentPasswordCheck::Failed => {
                // The guess was charged to the change's own budget when its
                // KE2 was issued; the account's sign-in budget stays apart.
                self.sign_in.record_failed_from(client_ip).await?;
                return Err(PasswordError::AuthenticationFailed);
            }
            CurrentPasswordCheck::NotBegun if required => {
                return Err(EnrollmentRefusal::CurrentPasswordRequired.into());
            }
            CurrentPasswordCheck::NotBegun => {}
            CurrentPasswordCheck::Proven => {
                // The budget limits guesses, not the owner: the right
                // password clears it, while abandoned and wrong guesses stay
                // charged until one is proven.
                self.sign_in
                    .anomaly()
                    .clear_lockout(&current_password_guesses(caller))
                    .await
                    .map_err(crate::sign_in::unavailable)?;
            }
        }
        let registration_response = self
            .operations
            .fixed_opaque_start(zkpp, &id, |op| own_change(op, caller, &credential))
            .await
            .map_err(StepError::refusal)?;
        Ok(PasswordChangeExecuteResponse {
            registration_response,
        })
    }

    /// Finish the change: verify the proof and the history over the final
    /// record, then replace the password, its evidence and the owner's
    /// history in one write over the password that was read. A repeat of a
    /// committed finish succeeds again.
    pub async fn change_finish(
        &self,
        zkpp: Arc<ZkppOpaqueServer>,
        caller: &Caller,
        request: PasswordChangeFinishRequest,
    ) -> Result<(), PasswordError> {
        // Rechecked at the commit: time may have run out since the challenge.
        let required = self.change_authority(caller).await?;
        let caller = caller.profile_id;
        let credential = self
            .own_password(request.credential_id.as_ref(), caller)
            .await?;
        let id = sid_authn::password_operation::operation_id(request.operation_id.as_ref())?;
        let done = match self
            .operations
            .finish(
                zkpp,
                &id,
                "change",
                &request.registration_record,
                request.proof,
                |op| {
                    own_change(op, caller, &credential)?;
                    if required && !op.current_password_proven() {
                        return Err(PasswordError::from(
                            EnrollmentRefusal::CurrentPasswordRequired,
                        ));
                    }
                    Ok(())
                },
            )
            .await
            .map_err(StepError::refusal)?
        {
            Finish::Completed(_) => return Ok(()),
            Finish::Ready(done) => *done,
        };

        // The new password, the evidence its proof gave it, its OPRF key and
        // the history entry are one write: none is ever the old password's.
        let current = credential.data.expose().to_vec();
        let sealed = seal(self.sign_in, caller, &done.password_file).await?;
        let mut new = done.credential(caller, sealed);
        new.id = credential.id;
        new.label = credential.label.clone();
        new.created_at = credential.created_at;
        let ctx = MutationContext::from(AuditEntry::user(
            caller.to_string(),
            "credential.password_change",
            credential.id.0.to_string(),
        ))
        // The change answers with nothing; its retry finds the same.
        .with_operation(done.completion(Vec::new()));

        // Applies only over the password just read, and only while it is
        // active: a revocation or another change in between is not undone.
        let history = self.with_history_age(done.history);
        let changed = self
            .sign_in
            .storage()
            .change_password(credential.id, &current, &new, history.as_ref(), ctx)
            .await
            .map_err(|e| {
                sid_authn::password_operation::commit_refusal(e, PasswordError::Store).refusal()
            })?;
        if !changed {
            return Err(PasswordError::ChangedConcurrently);
        }
        info!("Password changed for credential {}", credential.id.0);
        Ok(())
    }

    /// How long, by this server's clock, `caller`'s session may still change
    /// its password without the current password.
    pub async fn change_requirement(
        &self,
        caller: &Caller,
    ) -> Result<prost_types::Duration, PasswordError> {
        let left = sid_authn::credential_enrollment::password_change_requirement(
            self.sign_in.storage().as_ref(),
            caller,
            self.sign_in.policy().password.change_current_password,
        )
        .await?;
        // Never negative: the requirement clamps at zero.
        let left = left
            .to_std()
            .map_err(|e| internal("password change requirement", e))?;
        prost_types::Duration::try_from(left)
            .map_err(|e| internal("password change requirement", e))
    }
}

/// How many resets of one account may be pending at once.
const MAX_ACTIVE_RESETS: u32 = 3;

/// The answer to every reset request, whatever happened to it: whether an
/// account exists is never told.
fn reset_requested() -> RequestPasswordResetResponse {
    RequestPasswordResetResponse {
        message: "If an account exists, a reset email has been sent.".to_string(),
    }
}

/// The reset of a forgotten password: a link mailed to the account's login
/// mailbox, verified once, then a new password under the reset's own
/// operation, which ends every session and signs the account in when the
/// password alone protects it.
pub struct PasswordResets<'a> {
    passwords: Passwords<'a>,
    /// The organization's login requirements a reset's sign-in passes.
    login_policy: &'a dyn LoginPolicySource,
    /// The reset sessions and the mail delivering their links; `None` where
    /// no page opens a link.
    resets: Option<&'a PasswordResetService>,
}

impl<'a> PasswordResets<'a> {
    pub fn new(
        sign_in: &'a SignIn,
        operations: &'a PasswordOperations,
        login_policy: &'a dyn LoginPolicySource,
        resets: Option<&'a PasswordResetService>,
    ) -> Self {
        Self {
            passwords: Passwords::new(sign_in, operations),
            login_policy,
            resets,
        }
    }

    fn sign_in(&self) -> &'a SignIn {
        self.passwords.sign_in
    }

    /// Start a reset for the account `principal` names, mailing its link to
    /// the account's login mailbox. Refused alike for every address when the
    /// installation cannot reset at all; otherwise the answer is the same
    /// whether a reset started or not.
    pub async fn request(
        &self,
        principal: &str,
    ) -> Result<RequestPasswordResetResponse, PasswordError> {
        // Refused alike for every address, before any lookup: without the
        // page a link opens, or a provider to mail it, a reset could never
        // reach anyone.
        let resets = self
            .resets
            .ok_or(PasswordError::NotConfigured("password_reset"))?;
        let storage = self.sign_in().storage();
        if storage.get_email_provider_config().await?.is_none() {
            return Err(PasswordError::NotConfigured("email_provider"));
        }

        // A reset link goes to an email assignment's stored mailbox, so it is
        // requested by an email address, under its normalized key.
        let handle = sid_authn::normalize::normalize_principal(principal).map_err(|e| {
            PasswordError::InvalidField {
                field: "identifier",
                reason: e.to_string(),
            }
        })?;
        if handle.principal_type.to_principal_type() != PrincipalType::Email {
            return Ok(reset_requested());
        }
        let address = handle.normalized;
        let Some(profile) = self.sign_in().resolve_profile(&address).await? else {
            return Ok(reset_requested());
        };
        // The link goes to the mailbox the account bound the address with,
        // never the key or the caller's spelling of it.
        let Some(destination) = self
            .sign_in()
            .login_mail_destination(profile.id, &address)
            .await?
        else {
            info!("password reset requested for an account with no login mailbox: none started");
            return Ok(reset_requested());
        };

        // A count that cannot be read starts no reset (the limit would read
        // as zero); the answer keeps the same shape so it tells nothing about
        // the account.
        let active = match storage.count_active_reset_sessions(profile.id).await {
            Ok(count) => count,
            Err(e) => {
                tracing::error!(error = %e, "reset limit unreadable; no reset started");
                return Ok(reset_requested());
            }
        };
        if active >= MAX_ACTIVE_RESETS {
            return Ok(reset_requested());
        }

        // The session and the work mailing its link commit together; the
        // token leaves this service only inside that mail. A failure answers
        // like an unknown address: an error only for held addresses would
        // tell which accounts exist.
        match resets.request(profile.id, &address, &destination).await {
            Ok(session) => info!(reset_session = %session, "password reset requested"),
            Err(e) => tracing::error!(error = %e, "reset session not stored; no reset started"),
        }
        Ok(reset_requested())
    }

    /// Verify the reset link: its token is consumed once, and the
    /// replacement password's operation is prepared under the reset's
    /// authority, with the owner's retained history and no old password.
    pub async fn verify(
        &self,
        zkpp: &ZkppOpaqueServer,
        request: VerifyPasswordResetRequest,
    ) -> Result<VerifyPasswordResetResponse, PasswordError> {
        let session_id = wire_id(request.reset_session_id.as_ref(), "reset_session_id")?;
        let storage = self.sign_in().storage();
        // An unknown reset and an expired one answer alike: the reset starts
        // again from the email.
        let session = storage
            .get_reset_session(ResetSessionId(session_id.into_uuid()))
            .await?
            .filter(|s| !s.is_expired())
            .ok_or(PasswordError::ResetExpired)?;
        if session.status != ResetSessionStatus::Pending {
            return Err(PasswordError::ResetUsed(session_id.to_string()));
        }

        use subtle::ConstantTimeEq;
        let computed = sid_authn::password_reset::token_hash(&request.token);
        let matches: bool = computed
            .as_bytes()
            .ct_eq(session.token_hash.as_bytes())
            .into();
        if !matches {
            return Err(PasswordError::ResetTokenInvalid);
        }

        // Consume the token: of concurrent verifications one succeeds.
        let verified = storage
            .verify_reset_session(
                session.id,
                AuditEntry::user(
                    session.profile_id.to_string(),
                    "password_reset.verify",
                    session.id.to_string(),
                )
                .into(),
            )
            .await?;
        if !verified {
            return Err(PasswordError::ResetUsed(session_id.to_string()));
        }

        let prepared = self
            .passwords
            .operations
            .prepare(
                zkpp,
                OperationPurpose::Reset {
                    session: session.id,
                },
                OperationOwner::Existing(session.profile_id),
                format!("profile:{}", session.profile_id),
                None,
            )
            .await?;
        Ok(VerifyPasswordResetResponse {
            expires_in: sid_core::models::RESET_SESSION_TTL_SECS as i32,
            history: Some(prepared.context),
        })
    }

    /// The OPAQUE start of the replacement password, under the reset
    /// operation's own OPRF key, while its reset session is still verified.
    pub async fn execute(
        &self,
        zkpp: &ZkppOpaqueServer,
        request: ExecutePasswordResetRequest,
    ) -> Result<ExecutePasswordResetResponse, PasswordError> {
        let id = sid_authn::password_operation::operation_id(request.operation_id.as_ref())?;
        let mut reset = None;
        let registration_response = self
            .passwords
            .operations
            .opaque_start(zkpp, &id, request.registration_request, |op| {
                match op.purpose {
                    OperationPurpose::Reset { session } => {
                        reset = Some(session);
                        Ok(())
                    }
                    _ => Err(PasswordError::from(PasswordOperationError::NotPending)),
                }
            })
            .await
            .map_err(StepError::refusal)?;
        // The operation outlives nothing: a reset that expired or was
        // completed meanwhile does not go on.
        let session = reset.ok_or(PasswordOperationError::NotPending)?;
        self.verified_session(session).await?;
        Ok(ExecutePasswordResetResponse {
            registration_response,
        })
    }

    /// Complete the reset: the final record and its proof, checked against
    /// the reset's own operation; then, in one transaction, the reset
    /// completes, the new password replaces the old one and every session of
    /// the account ends. The account is signed in to `client` only when the
    /// password alone protects it and its login requirements admit the
    /// sign-in; `None` says the password is replaced and the client signs in.
    /// A retry of a completed reset gets no session either.
    pub async fn complete(
        &self,
        zkpp: Arc<ZkppOpaqueServer>,
        client: CeremonyClient,
        client_ip: Option<std::net::IpAddr>,
        user_agent: Option<&str>,
        request: CompletePasswordResetRequest,
    ) -> Result<Option<SignedIn>, PasswordError> {
        let id = sid_authn::password_operation::operation_id(request.operation_id.as_ref())?;
        let mut reset = None;
        let done = match self
            .passwords
            .operations
            .finish(
                zkpp,
                &id,
                "reset",
                &request.registration_record,
                request.proof,
                |op| match op.purpose {
                    OperationPurpose::Reset { session } => {
                        reset = Some(session);
                        Ok(())
                    }
                    _ => Err(PasswordError::from(PasswordOperationError::NotPending)),
                },
            )
            .await
            .map_err(StepError::refusal)?
        {
            Finish::Completed(_) => return Ok(None),
            Finish::Ready(done) => *done,
        };
        let reset = reset.ok_or(PasswordOperationError::NotPending)?;
        let session = self.verified_session(reset).await?;
        let profile_id = session.profile_id;

        // One transaction: the reset completes (only if still verified and
        // unexpired), the new password replaces the old one with its
        // evidence and history entry, and every session of the profile ends,
        // each owing its client's back-channel logout and its revoked event;
        // the completion owes its own event and records the operation's
        // result, the empty response. Of concurrent completions exactly one
        // gets here.
        let new_password = done.credential(
            profile_id,
            seal(self.sign_in(), profile_id, &done.password_file).await?,
        );
        let completed = sid_core::models::event::Event::new(
            format!("profile/{}", profile_id),
            sid_core::models::event::event_types::PASSWORD_RESET_COMPLETED,
        );
        let ctx = MutationContext::from(AuditEntry::user(
            profile_id.to_string(),
            "password_reset.complete",
            session.id.to_string(),
        ))
        .with_work(completed.relay())
        .with_operation(done.completion(Vec::new()));
        let end = SessionEnd::new(
            sid_core::models::RevocationReason::UserRequested,
            profile_id.to_string(),
        );
        let history = self.passwords.with_history_age(done.history);
        let storage = self.sign_in().storage();
        let ended = storage
            .complete_password_reset(session.id, &new_password, history.as_ref(), &end, ctx)
            .await
            .map_err(|e| {
                sid_authn::password_operation::commit_refusal(e, PasswordError::Store).refusal()
            })?
            // Completed, or expired, meanwhile: the reset starts again.
            .ok_or(PasswordError::ResetExpired)?;

        // The ended sessions' access tokens stop in every process. Their
        // sessions and refresh tokens are already gone; a failed propagation
        // leaves only access tokens until they expire.
        for ended in &ended {
            if let Err(e) = self
                .sign_in()
                .revocation()
                .revoke_session(ended.id.to_string())
                .await
            {
                warn!(
                    "Revocation of session {} after password reset not propagated: {}",
                    ended.id, e
                );
            }
        }

        // The reset proved only the mailbox. An account protected by more
        // than a password is not signed in by it: the new password still has
        // to pass the account's second factor at sign-in.
        let passkey_satisfies_mfa = self.sign_in().policy().auth.passkey_satisfies_mfa;
        let active: Vec<Credential> = storage
            .get_credentials_by_profile(profile_id, None)
            .await?
            .into_iter()
            .filter(|c| c.status.is_active())
            .collect();
        let established =
            sid_authn::credential_enrollment::established_assurance(&active, passkey_satisfies_mfa);
        if established > sid_core::models::session::AuthLevel::Basic {
            info!(
                "Password reset completed for profile {}; sign-in left to its second factor",
                profile_id
            );
            return Ok(None);
        }

        // The reset's sign-in is a sign-in like any other: its session
        // records the client's device and address, and the organization's
        // login requirements admit it. The password is already replaced: a
        // sign-in the requirements do not admit (or cannot state) leaves the
        // reset successful, with no session, as an account with a second
        // factor is left.
        let method = LoginMethod::Password;
        let Some(policy) = self
            .admitted(
                profile_id,
                method.auth_level(passkey_satisfies_mfa),
                &method.amr(),
            )
            .await
        else {
            return Ok(None);
        };
        let profile = storage
            .get_profile(profile_id)
            .await?
            // Deleted meanwhile: the password is replaced, no one signs in.
            .ok_or(PasswordError::AuthenticationFailed)?;
        let signed_in = self
            .sign_in()
            .sign_in_by(
                &profile,
                method,
                user_agent.map(sid_authn::sign_in_security::device_id),
                client_ip,
                client,
                None,
                // Another reset committed meanwhile signs this one in no more.
                Some(&CredentialFence {
                    id: new_password.id,
                    data: new_password.data.clone(),
                }),
                policy,
            )
            .await?;
        info!("Password reset completed for profile {}", profile_id);
        Ok(Some(signed_in))
    }

    /// The policy fence a reset's sign-in of `profile_id` at `assurance`
    /// with `amr` commits under, when the organization's login requirements
    /// admit it; `None` when they ask for more or cannot be read.
    async fn admitted(
        &self,
        profile_id: ProfileId,
        assurance: sid_core::models::session::AuthLevel,
        amr: &[String],
    ) -> Option<Option<sid_core::models::ActorFence>> {
        use sid_authn::login_policy::LoginDecision;
        let requirements = match self.login_policy.requirements(None).await {
            Ok(requirements) => requirements,
            Err(e) => {
                info!(
                    "Password reset completed for profile {}; sign-in not admitted: {}",
                    profile_id, e
                );
                return None;
            }
        };
        // A reset proves the mailbox, not an enabled second factor: an account
        // with established protection is not signed in by it.
        let requirements = match requirements
            .for_account(self.sign_in().storage().as_ref(), profile_id)
            .await
        {
            Ok(requirements) => requirements,
            Err(e) => {
                info!(
                    "Password reset completed for profile {}; sign-in not admitted: {}",
                    profile_id, e
                );
                return None;
            }
        };
        let now = chrono::Utc::now();
        let probe = sid_authn::login_policy::local_authentication(profile_id, assurance, amr, now);
        match requirements.decide(&probe, now) {
            LoginDecision::Allow { .. } => Some(requirements.fence),
            LoginDecision::StepUp(unmet) => {
                info!(
                    "Password reset completed for profile {}; sign-in not admitted: step-up {:?}",
                    profile_id, unmet
                );
                None
            }
        }
    }

    /// The reset session `id` while it is verified and unexpired.
    async fn verified_session(
        &self,
        id: ResetSessionId,
    ) -> Result<PasswordResetSession, PasswordError> {
        // An unknown reset session and an expired one answer alike: either
        // way the reset starts again.
        let session = self
            .sign_in()
            .storage()
            .get_reset_session(id)
            .await?
            .filter(|s| !s.is_expired())
            .ok_or(PasswordError::ResetExpired)?;
        if session.status != ResetSessionStatus::Verified {
            return Err(PasswordError::ResetUnverified(id.0.to_string()));
        }
        Ok(session)
    }
}

/// What an imported password's upgrade keeps between its steps.
#[derive(serde::Serialize, serde::Deserialize)]
struct UpgradeState {
    profile_id: ProfileId,
    /// The OPRF credential identifier of the password being registered.
    credential_identifier: [u8; 16],
}

/// How long a started upgrade may be finished.
const UPGRADE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// The upgrade of a password imported as another system's hash: the
/// password, proven once against that hash like any sign-in, is registered
/// as an OPAQUE password that replaces the hash, and the account signs in.
pub struct ImportedPasswordUpgrades {
    upgrades: ChallengeStore<UpgradeState>,
}

impl ImportedPasswordUpgrades {
    /// Upgrades kept in `ceremonies`, sealed by `keys`.
    pub fn new(
        ceremonies: Arc<dyn sid_plugin::CeremonyStateStore>,
        keys: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            upgrades: ChallengeStore::new(ceremonies, keys, "legacy-migration", UPGRADE_TTL),
        }
    }

    /// Prove the password against the account's imported hash and answer the
    /// OPAQUE registration request of the password that replaces it. A
    /// guess like any sign-in: refused during a lockout and a wrong one
    /// counted against `client_ip`. An unknown principal and an account
    /// without an imported hash are answered like a wrong password, after
    /// about the same work, so the answer tells nothing about the account.
    pub async fn start(
        &self,
        sign_in: &SignIn,
        client_ip: Option<std::net::IpAddr>,
        request: LegacyMigrateStartRequest,
    ) -> Result<LegacyMigrateStartResponse, PasswordError> {
        use secrecy::ExposeSecret;
        use sid_authn::legacy_hash::BuiltinLegacyVerifier;
        let password = secrecy::SecretBox::new(Box::new(request.password));
        let profile = sign_in.resolve_profile(&request.principal).await?;
        let identity = profile
            .as_ref()
            .map_or_else(|| request.principal.clone(), |p| p.id.to_string());
        sign_in.refuse_if_locked(&identity).await?;

        let imported = match &profile {
            Some(profile) => sign_in
                .storage()
                .get_credentials_by_profile(profile.id, Some(CredentialType::LegacyHash))
                .await?
                .into_iter()
                .next(),
            None => None,
        };
        let verified = match (&profile, &imported) {
            (Some(profile), Some(imported)) => {
                // The imported hash is stored as UTF-8 text.
                let hash = std::str::from_utf8(imported.data.expose()).map_err(|e| {
                    internal(
                        "read legacy hash",
                        format!("credential {}: {e}", imported.id.0),
                    )
                })?;
                BuiltinLegacyVerifier::verify(password.expose_secret().as_bytes(), hash)
                    .map_err(|e| internal("verify legacy hash", e))?
                    .then_some((profile, imported))
            }
            _ => {
                BuiltinLegacyVerifier::verify_decoy(password.expose_secret().as_bytes());
                None
            }
        };
        let Some((profile, imported)) = verified else {
            sign_in.record_failed_login(&identity, client_ip).await?;
            return Err(PasswordError::AuthenticationFailed);
        };

        // The new password registers under its own OPRF credential
        // identifier.
        let credential_identifier: [u8; 16] = rand::random();
        let (response, _state) = sign_in
            .opaque()
            .registration_start(&request.opaque_registration_request, &credential_identifier)
            .map_err(|e| {
                warn!("OPAQUE registration start failed during migration: {}", e);
                PasswordError::InvalidField {
                    field: "opaque_registration_request",
                    reason: "not a valid OPAQUE registration request".to_string(),
                }
            })?;
        let upgrade = sid_ids::ImportedPasswordUpgradeId::generate();
        self.upgrades
            .insert(
                &upgrade.to_string(),
                &UpgradeState {
                    profile_id: profile.id,
                    credential_identifier,
                },
            )
            .await
            .map_err(SignInError::from)?;
        info!(
            "Legacy migration started for profile {} (algorithm: {})",
            profile.id,
            imported.legacy_algorithm.as_deref().unwrap_or("unknown")
        );
        Ok(LegacyMigrateStartResponse {
            upgrade_id: Some(upgrade.into()),
            opaque_registration_response: response,
        })
    }

    /// Finish the upgrade: the OPAQUE password replaces the imported hash in
    /// one transaction, then the account signs in to `client` as a password
    /// first factor under the login requirements `login_policy` states,
    /// pending its second factor when one is owed.
    pub async fn finish(
        &self,
        sign_in: &SignIn,
        login_policy: &dyn LoginPolicySource,
        client: CeremonyClient,
        client_ip: Option<std::net::IpAddr>,
        context: AttemptContext<'_>,
        request: LegacyMigrateFinishRequest,
    ) -> Result<FirstFactorSignedIn, PasswordError> {
        let upgrade = wire_id(request.upgrade_id.as_ref(), "upgrade_id")?;
        let upgrade = self
            .upgrades
            .take(&upgrade.to_string())
            .await
            .map_err(SignInError::from)?
            .ok_or(PasswordError::UpgradeExpired)?;
        let stored = sign_in
            .opaque()
            .registration_finish(&request.opaque_registration_record)
            .map_err(|e| {
                warn!("OPAQUE registration finish failed during migration: {}", e);
                PasswordError::InvalidField {
                    field: "opaque_registration_record",
                    reason: "not a valid OPAQUE registration record".to_string(),
                }
            })?;

        let mut credential = Credential::new(
            upgrade.profile_id,
            CredentialType::Opaque,
            seal(sign_in, upgrade.profile_id, &stored.data).await?,
            None,
        );
        credential.opaque_curve = Some(stored.curve as u8);
        credential.opaque_credential_identifier = Some(upgrade.credential_identifier);

        // The OPAQUE password replaces the imported hash in one transaction.
        let storage = sign_in.storage();
        storage
            .replace_credential(
                &credential,
                AuditEntry::user(
                    upgrade.profile_id.to_string(),
                    "credential.migrated",
                    credential.id.0.to_string(),
                )
                .into(),
            )
            .await?;

        // A profile deleted meanwhile signs nobody in.
        let mut profile = storage
            .get_profile(upgrade.profile_id)
            .await?
            .ok_or(PasswordError::AuthenticationFailed)?;
        if profile.migration_pending {
            profile.migration_pending = false;
            profile.migration_completed_at = Some(chrono::Utc::now());
            // A profile changed meanwhile keeps the flag; the next sign-in
            // clears it. The migrated credential is already stored.
            match storage
                .update_profile(
                    &profile,
                    AuditEntry::user(
                        upgrade.profile_id.to_string(),
                        "profile.migration_completed",
                        upgrade.profile_id.to_string(),
                    )
                    .into(),
                )
                .await
            {
                Ok(true) => profile.revision += 1,
                Ok(false) => {}
                Err(e) => {
                    warn!(profile_id = %profile.id, error = %e, "Failed to clear migration flag")
                }
            }
        }

        let method = LoginMethod::Password;
        let requirements = crate::sign_in::organization_requirements(login_policy).await?;
        let admission = sign_in
            .first_factor(
                profile.id,
                client_ip,
                (
                    "opaque",
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
                None,
                Some(&CredentialFence {
                    id: credential.id,
                    data: credential.data.clone(),
                }),
                admission,
            )
            .await?;
        info!(
            "Legacy migration completed for profile {}",
            upgrade.profile_id
        );
        Ok(signed_in)
    }
}

#[cfg(test)]
mod tests;
