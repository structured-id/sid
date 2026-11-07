// SPDX-License-Identifier: AGPL-3.0-only
//! Replacing a password: the caller's change of its own, proving the current
//! password when its session may no longer change it without, through the
//! installation's password operations; the new password, its proof's
//! evidence and the owner's history are one write over the password read.

use std::sync::Arc;

use sid_authn::caller::Caller;
use sid_authn::credential_enrollment::{EnrollmentError, EnrollmentRefusal};
use sid_authn::opaque_zkpp::ZkppOpaqueServer;
use sid_authn::password_operation::{
    CurrentPasswordCheck, OperationOwner, PasswordOperationError, StepError, change_context,
};
use sid_authn::sign_in_security::SignInRefusal;
use sid_core::Error as SidError;
use sid_core::models::{
    AuditEntry, Credential, CredentialId, CredentialType, HistoryCommit, MutationContext, ProfileId,
};
use sid_proto::sid::v1::{
    PasswordChangeChallengeRequest, PasswordChangeChallengeResponse, PasswordChangeExecuteRequest,
    PasswordChangeExecuteResponse, PasswordChangeFinishRequest,
};
use tracing::{info, warn};

use crate::password_operation::{Finish, OperationPurpose, PasswordOperations, PendingOperation};
use crate::sign_in::{SignIn, SignInError};
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
    /// The current password did not prove.
    #[error("authentication failed")]
    AuthenticationFailed,
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
        let sealed = sid_authn::sealed_secret::seal(
            self.sign_in.keys(),
            &sid_authn::sealed_secret::opaque_context(caller),
            &done.password_file,
        )
        .await
        .map_err(|e| internal("seal OPAQUE envelope", e))?;
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

#[cfg(test)]
mod tests;
