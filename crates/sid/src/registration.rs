// SPDX-License-Identifier: AGPL-3.0-only
//! Self-registration of a new account: what a started registration may
//! commit, decided before anything about its identifier is told (the
//! instance claim while the installation has no administrator, the
//! registration switch and the enrollment policy), and the atomic commit of
//! the account with its first credential and password history.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sid_authn::normalize::normalize_principal;
use sid_authn::opaque_zkpp::ZkppOpaqueServer;
use sid_authn::password_operation::{OperationOwner, PasswordOperationError, StepError};
use sid_proto::sid::v1::{
    OpaqueZkppRegistrationFinishRequest, OpaqueZkppRegistrationFinishResponse,
    OpaqueZkppRegistrationStartResponse,
};

use crate::password_operation::{Finish, OperationPurpose, PasswordOperations};
use sid_core::Error as SidError;
use sid_core::enrollment::{EnrollmentDecision, EnrollmentDenialReason, evaluate_enrollment};
use sid_core::models::event::{Event, event_types};
use sid_core::models::principal::PrincipalType;
use sid_core::models::{
    AuditEntry, Credential, CredentialData, CredentialId, CredentialType, EnrollmentMode,
    HistoryCommit, MutationContext, NewRegistration, OperationCompletion, Profile, ProfileId,
};
use sid_plugin::storage::StorageBackend;
use tracing::info;

/// What a pending registration may commit when it finishes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PendingRegistration {
    /// A new account for an identifier nobody holds. `profile_id` is reserved
    /// at start.
    NewAccount {
        profile_id: ProfileId,
        principal_type: PrincipalType,
        value: String,
        /// For an email, the handle as validated at start: the address in the
        /// registrant's spelling (the new contact stores it, while `value` is
        /// the resolution key) and the policy revision of the key.
        email: Option<sid_authn::email::EmailHandle>,
        /// The sealed instance claim the start verified: the account becomes
        /// the first administrator and consumes it when it is committed.
        instance_claim: Option<Vec<u8>>,
        /// The invite code presented, spent with the account when the
        /// enrollment mode is invite-only.
        #[serde(default)]
        invite_code: Option<String>,
    },
    /// The identifier already belongs to an account. Start still evaluates the
    /// OPRF under a key that exists nowhere, so the answer looks like any other;
    /// finishing commits nothing, so a registration never attaches to an
    /// existing account. It keeps what a new account's commit is admitted
    /// by, so its finish is refused alike before it tells the identifier is
    /// held.
    ExistingAccount {
        principal_type: PrincipalType,
        #[serde(default)]
        value: String,
        #[serde(default)]
        invite_code: Option<String>,
        /// The start presented the open instance claim, which a new
        /// account's commit is admitted by instead of the policy.
        #[serde(default)]
        by_claim: bool,
    },
}

/// Why a registration is refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    /// Self-registration is switched off on this installation.
    #[error("registration is not enabled")]
    NotEnabled,
    /// Self-registration needs `requirement` first (`instance_claim`,
    /// `admin_only`, `invite`, `email`, `email_domain`).
    #[error("registration needs {0}")]
    Restricted(&'static str),
    /// The identifier of this kind is already registered.
    #[error("identifier is already registered")]
    AlreadyRegistered(PrincipalType),
    /// The identifier is not a valid principal.
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    /// The identifier cannot start a new account.
    #[error(transparent)]
    Identity(#[from] crate::identity::IdentityError),
    /// The password operation the registration installs refused.
    #[error(transparent)]
    Operation(#[from] PasswordOperationError),
    /// The registration's context is spent or expired: its finish already
    /// committed, or it starts again.
    #[error("the registration's context ended")]
    ContextEnded,
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation; its cause is in the log.
    #[error("internal error")]
    Internal,
}

fn internal(operation: &'static str, cause: impl std::fmt::Display) -> RegistrationError {
    tracing::error!(operation, error = %cause, "internal failure");
    RegistrationError::Internal
}

/// The requirement a refusal names for `reason`; an invalid invite asks for a
/// (valid) invite, as a missing one does.
fn requirement(reason: &EnrollmentDenialReason) -> &'static str {
    match reason {
        EnrollmentDenialReason::AdminOnly => "admin_only",
        EnrollmentDenialReason::InviteRequired | EnrollmentDenialReason::InviteInvalid => "invite",
        EnrollmentDenialReason::EmailRequired => "email",
        EnrollmentDenialReason::DomainNotAllowed { .. } => "email_domain",
    }
}

/// What a registration's commit writes besides the account and its first
/// credential.
struct Commit {
    /// The first password's accepted history.
    history: Option<HistoryCommit>,
    /// The first passkey's user handle; the address was confirmed.
    first_passkey: Option<sid_core::models::NewUserHandle>,
    /// The result a retry of the installing operation gets.
    completion: Option<OperationCompletion>,
    /// The registration context the commit spends.
    consumption: Option<sid_core::models::CeremonyConsumption>,
}

/// A registration finish verified up to its write.
#[derive(Debug)]
pub enum PreparedFinish {
    /// A repeat of a finish that already committed: its recorded answer,
    /// with nothing to write.
    Answered(OpaqueZkppRegistrationFinishResponse),
    /// The account to write, and the answer once it is written. Boxed: the
    /// sealed registration is large and the answer variant is not.
    Ready {
        prepared: Box<PreparedRegistration>,
        response: OpaqueZkppRegistrationFinishResponse,
    },
}

/// A registration checked and sealed, ready to be written by the storage's
/// commit or in a host's own transaction, either way with the same records.
#[derive(Debug)]
pub struct PreparedRegistration {
    registration: NewRegistration,
    ctx: MutationContext,
    profile_id: ProfileId,
    credential_id: CredentialId,
    principal_type: PrincipalType,
    spends_context: bool,
}

impl PreparedRegistration {
    /// What is written: the account, its identifier and first credential.
    pub fn registration(&self) -> &NewRegistration {
        &self.registration
    }

    /// What commits with it: its audit, owed work and the operation
    /// completion a retry of the finish is answered from. A host running its
    /// attempt again writes it again under a fresh copy.
    pub fn context(&self) -> MutationContext {
        self.ctx.clone()
    }

    /// The new account's profile.
    pub fn profile_id(&self) -> ProfileId {
        self.profile_id
    }

    /// The new account's first credential.
    pub fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    /// The registration refusal a storage refusal of this write stands for,
    /// the same for the storage's commit and a host's transaction.
    pub fn refusal(&self, e: SidError) -> RegistrationError {
        match e {
            // The registration's context was spent by a concurrent finish or
            // ran out meanwhile.
            SidError::Expired(_) | SidError::OperationCompleted(_) if self.spends_context => {
                RegistrationError::ContextEnded
            }
            // Another registration took the identifier between start and finish.
            SidError::Conflict(_) => RegistrationError::AlreadyRegistered(self.principal_type),
            // The claim was taken between start and finish.
            SidError::InvalidState(_) => RegistrationError::Restricted("instance_claim"),
            // The policy in force at the commit refuses it, or its invite is
            // no longer usable.
            SidError::RegistrationRestricted(reason) => {
                RegistrationError::Restricted(requirement(&reason))
            }
            e => {
                sid_authn::password_operation::commit_refusal(e, RegistrationError::Store).refusal()
            }
        }
    }
}

/// Self-registration on one installation.
pub struct Registration {
    storage: Arc<dyn StorageBackend>,
    keys: Arc<dyn sid_keys::KeyManager>,
    /// The issuer whose events announce new accounts.
    issuer: String,
}

impl Registration {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        keys: Arc<dyn sid_keys::KeyManager>,
        issuer: String,
    ) -> Self {
        Self {
            storage,
            keys,
            issuer,
        }
    }

    /// Decide what a registration started for `principal` may commit, with
    /// self-registration switched on when `enabled`. Admission is decided
    /// before anything about the identifier is looked up, so a closed policy
    /// tells nobody which accounts exist; a held identifier's start is
    /// answered like a new one but can never be committed to.
    pub async fn begin(
        &self,
        principal: &str,
        claim_token: Option<&str>,
        invite_code: Option<&str>,
        enabled: bool,
    ) -> Result<PendingRegistration, RegistrationError> {
        let invite_code = invite_code.map(str::trim).filter(|c| !c.is_empty());
        let handle = normalize_principal(principal)
            .map_err(|e| RegistrationError::InvalidIdentifier(e.to_string()))?;
        let principal_type = handle.principal_type.to_principal_type();
        let instance_claim = self
            .admit(
                principal_type,
                &handle.normalized,
                claim_token,
                invite_code,
                enabled,
            )
            .await?;
        let existing = PendingRegistration::ExistingAccount {
            principal_type,
            value: handle.normalized.clone(),
            invite_code: invite_code.map(str::to_string),
            by_claim: instance_claim.is_some(),
        };
        if crate::sign_in::resolve_handle(self.storage.as_ref(), &handle)
            .await?
            .is_some()
            // Held but not resolvable (contested, closed): never registered over.
            || self
                .storage
                .get_principal_by_value(principal_type, &handle.normalized)
                .await?
                .is_some()
        {
            return Ok(existing);
        }
        Ok(PendingRegistration::NewAccount {
            profile_id: ProfileId::generate(),
            principal_type,
            value: handle.normalized,
            email: handle.email,
            instance_claim,
            invite_code: invite_code.map(str::to_string),
        })
    }

    /// Decide again whether `pending`, admitted when it started, may still
    /// go on, before any later step of it: the instance claim it presented
    /// is still open, else the registration switch and the enrollment policy
    /// in force now admit it. The commit decides once more in its own
    /// transaction.
    pub async fn readmit(
        &self,
        pending: &PendingRegistration,
        enabled: bool,
    ) -> Result<(), RegistrationError> {
        let PendingRegistration::NewAccount {
            principal_type,
            value,
            instance_claim,
            invite_code,
            ..
        } = pending
        else {
            return Err(self.refuse_held(pending, enabled).await);
        };
        if instance_claim.is_some() {
            let open = sid_authn::admin_claim::is_open(self.storage.as_ref())
                .await
                .map_err(|e| internal("check instance claim", e))?;
            return if open {
                Ok(())
            } else {
                Err(RegistrationError::Restricted("instance_claim"))
            };
        }
        self.admitted_by_enrollment(*principal_type, value, invite_code.as_deref(), enabled)
            .await
    }

    /// Commit `pending` with its confirmed email and `passkey`, its first
    /// credential, registered under `user_handle`, atomically with
    /// `completion`, the result a retry gets, and `consumption`, the
    /// registration's context, spent by this commit. A context already
    /// spent or expired is [`RegistrationError::ContextEnded`] and nothing
    /// is written.
    pub async fn commit_first_passkey(
        &self,
        pending: PendingRegistration,
        passkey: Credential,
        user_handle: sid_core::models::NewUserHandle,
        completion: OperationCompletion,
        consumption: sid_core::models::CeremonyConsumption,
        enabled: bool,
    ) -> Result<(ProfileId, CredentialId), RegistrationError> {
        self.commit_with(
            pending,
            passkey,
            Commit {
                history: None,
                first_passkey: Some(user_handle),
                completion: Some(completion),
                consumption: Some(consumption),
            },
            enabled,
        )
        .await
    }

    /// Commit `pending` with its first `credential`, atomically, with
    /// `history`, the first password's accepted history, and `completion`,
    /// the durable result of the operation that installs it. A taken
    /// identifier is refused and nothing is written: the holder is not
    /// contacted. Returns the new account's profile and credential.
    pub async fn commit(
        &self,
        pending: PendingRegistration,
        credential: Credential,
        history: Option<HistoryCommit>,
        completion: Option<OperationCompletion>,
        enabled: bool,
    ) -> Result<(ProfileId, CredentialId), RegistrationError> {
        self.commit_with(
            pending,
            credential,
            Commit {
                history,
                first_passkey: None,
                completion,
                consumption: None,
            },
            enabled,
        )
        .await
    }

    async fn commit_with(
        &self,
        pending: PendingRegistration,
        credential: Credential,
        commit: Commit,
        enabled: bool,
    ) -> Result<(ProfileId, CredentialId), RegistrationError> {
        let prepared = self
            .prepare_with(pending, credential, commit, enabled)
            .await?;
        self.commit_prepared(&prepared).await?;
        Ok((prepared.profile_id, prepared.credential_id))
    }

    /// Write `prepared` in the storage's own transaction.
    async fn commit_prepared(
        &self,
        prepared: &PreparedRegistration,
    ) -> Result<(), RegistrationError> {
        self.storage
            .register_profile(&prepared.registration, prepared.ctx.clone())
            .await
            .map_err(|e| prepared.refusal(e))?;
        info!(
            "Self-registration committed for profile {}",
            prepared.profile_id
        );
        Ok(())
    }

    async fn prepare_with(
        &self,
        pending: PendingRegistration,
        mut credential: Credential,
        commit: Commit,
        enabled: bool,
    ) -> Result<PreparedRegistration, RegistrationError> {
        let Commit {
            history,
            first_passkey,
            completion,
            consumption,
        } = commit;
        let PendingRegistration::NewAccount {
            profile_id,
            principal_type,
            value,
            email,
            instance_claim,
            invite_code,
        } = pending
        else {
            return Err(self.refuse_held(&pending, enabled).await);
        };
        if credential.credential_type == CredentialType::Opaque {
            credential.data = CredentialData::new(
                sid_authn::sealed_secret::seal(
                    self.keys.as_ref(),
                    &sid_authn::sealed_secret::opaque_context(profile_id),
                    credential.data.expose(),
                )
                .await
                .map_err(|e| internal("seal OPAQUE envelope", e))?,
            );
        }
        let credential_id = credential.id;
        // A gated registration's source is decided by the storage from the
        // policy that admits it; the claim registration follows the stored
        // tracking setting.
        let track_source = match instance_claim {
            Some(_) => {
                crate::enrollment::stored_or_default(self.storage.as_ref())
                    .await?
                    .track_source
            }
            None => false,
        };
        let identifier =
            crate::identity::signup_identifier(principal_type, &value, email.as_ref())?;
        let username = matches!(principal_type, PrincipalType::Username).then_some(value.as_str());
        let mut profile = Profile::new(username);
        profile.id = profile_id;
        let mut registration = NewRegistration::new(profile, identifier, Some(credential))
            .map_err(|e| RegistrationError::InvalidIdentifier(e.to_string()))?;
        if track_source {
            registration =
                registration.with_source(sid_core::models::RegistrationSource::self_signup(None));
        }
        // A passwordless registration confirmed its address before its
        // passkey: the account signs in with both from its first commit.
        if let Some(user_handle) = first_passkey {
            registration = registration
                .with_confirmed_email()
                .map_err(|e| RegistrationError::InvalidIdentifier(e.to_string()))?
                .with_webauthn_user_handle(user_handle.rp_id, user_handle.handle);
        }
        // The claim registration is admitted by its token whatever the mode;
        // any other one by the policy the storage reads in the account's own
        // transaction, so a policy changed since the start applies to it.
        if instance_claim.is_none() {
            if !enabled {
                return Err(RegistrationError::NotEnabled);
            }
            registration = registration.admitted_by(sid_core::models::EnrollmentGate {
                email: matches!(principal_type, PrincipalType::Email).then(|| value.clone()),
                invite_code,
            });
        }
        if let Some(history) = history {
            registration = registration
                .with_history(history)
                .map_err(|e| internal("attach password history", e))?;
        }
        let action = match instance_claim {
            Some(claim) => {
                registration = registration.claiming_instance(claim);
                "profile.admin_claimed"
            }
            None => "profile.self_register",
        };
        let created = Event::new(&self.issuer, event_types::USER_CREATED)
            .with_subject(format!("profile/{}", profile_id))
            .with_data(serde_json::json!({ "profile_id": profile_id.to_string() }));
        let mut ctx = MutationContext::from(AuditEntry::user(
            profile_id.to_string(),
            action,
            profile_id.to_string(),
        ))
        .with_work(created.relay());
        if let Some(completion) = completion {
            ctx = ctx.with_operation(completion);
        }
        let spends_context = consumption.is_some();
        if let Some(consumption) = consumption {
            ctx = ctx.consuming(consumption);
        }
        Ok(PreparedRegistration {
            registration,
            ctx,
            profile_id,
            credential_id,
            principal_type,
            spends_context,
        })
    }

    /// Start a registration of `principal` through `operations`: the
    /// operation is prepared for the new account (or as a decoy for a held
    /// identifier) and the client's OPAQUE request answered under the new
    /// password's own OPRF key. The proof arrives at the finish.
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        &self,
        operations: &PasswordOperations,
        zkpp: &ZkppOpaqueServer,
        principal: &str,
        claim_token: Option<&str>,
        invite_code: Option<&str>,
        registration_request: Vec<u8>,
        enabled: bool,
    ) -> Result<OpaqueZkppRegistrationStartResponse, RegistrationError> {
        let charged = normalize_principal(principal)
            .map_err(|e| RegistrationError::InvalidIdentifier(e.to_string()))?
            .normalized;
        let pending = self
            .begin(principal, claim_token, invite_code, enabled)
            .await?;
        let owner = match &pending {
            PendingRegistration::NewAccount { profile_id, .. } => OperationOwner::New(*profile_id),
            PendingRegistration::ExistingAccount { .. } => {
                OperationOwner::Decoy(ProfileId::generate())
            }
        };
        let prepared = operations
            .prepare(
                zkpp,
                OperationPurpose::Registration { pending },
                owner,
                format!("registration:{charged}"),
                Some(registration_request),
            )
            .await?;
        Ok(OpaqueZkppRegistrationStartResponse {
            registration_response: prepared.registration_response.unwrap_or_default(),
            history: Some(prepared.context),
        })
    }

    /// Finish a registration: verify the proof and the history over the
    /// final record, then commit the account, its first credential with the
    /// proof's evidence and its first history entry (dropping entries older
    /// than `history_max_age_days`) together. A held identifier's decoy is
    /// verified like any other and refused here; a repeat of a committed
    /// finish gets the answer it recorded.
    pub async fn finish(
        &self,
        operations: &PasswordOperations,
        zkpp: Arc<ZkppOpaqueServer>,
        request: OpaqueZkppRegistrationFinishRequest,
        history_max_age_days: u32,
        enabled: bool,
    ) -> Result<OpaqueZkppRegistrationFinishResponse, RegistrationError> {
        match self
            .prepare_finish(operations, zkpp, request, history_max_age_days, enabled)
            .await?
        {
            PreparedFinish::Answered(response) => Ok(response),
            PreparedFinish::Ready { prepared, response } => {
                self.commit_prepared(&prepared).await?;
                Ok(response)
            }
        }
    }

    /// Everything [`Self::finish`] does before it writes: the operation and
    /// its purpose read, the proof and the history verified, the credential
    /// sealed, the result a retry gets recorded in the completion. A host
    /// writing the account in its own transaction
    /// (`sid_storage::coordinode::HostTransaction`) calls this once, outside
    /// its runs again, writes [`PreparedRegistration::registration`] under
    /// [`PreparedRegistration::context`], answers the response on success
    /// and reports a refusal through [`PreparedRegistration::refusal`].
    pub async fn prepare_finish(
        &self,
        operations: &PasswordOperations,
        zkpp: Arc<ZkppOpaqueServer>,
        request: OpaqueZkppRegistrationFinishRequest,
        history_max_age_days: u32,
        enabled: bool,
    ) -> Result<PreparedFinish, RegistrationError> {
        let id = sid_authn::password_operation::operation_id(request.operation_id.as_ref())?;
        let done = match operations
            .finish(
                zkpp,
                &id,
                "registration",
                &request.registration_record,
                request.proof,
                |op| match op.purpose {
                    OperationPurpose::Registration { .. } => Ok(()),
                    _ => Err(RegistrationError::from(PasswordOperationError::NotPending)),
                },
            )
            .await
            .map_err(StepError::refusal)?
        {
            Finish::Completed(result) => {
                return prost::Message::decode(result.as_slice())
                    .map(PreparedFinish::Answered)
                    .map_err(|e| internal("decode recorded password operation result", e));
            }
            Finish::Ready(done) => *done,
        };
        let OperationPurpose::Registration { pending } = &done.operation.purpose else {
            return Err(PasswordOperationError::NotPending.into());
        };
        let pending = pending.clone();
        let PendingRegistration::NewAccount { profile_id, .. } = pending else {
            return Err(self.refuse_held(&pending, enabled).await);
        };
        let credential = done.credential(profile_id, done.password_file.clone());
        let response = OpaqueZkppRegistrationFinishResponse {
            credential_id: crate::wire::stored_id::<sid_ids::CredentialId, _>(credential.id.0)
                .map_err(|e| internal("encode the credential id", e))?,
        };
        let completion = done.completion(prost::Message::encode_to_vec(&response));
        let history = done.history.map(|mut commit| {
            commit.max_age_days = history_max_age_days;
            commit
        });
        let prepared = self
            .prepare_with(
                pending,
                credential,
                Commit {
                    history,
                    first_passkey: None,
                    completion: Some(completion),
                    consumption: None,
                },
                enabled,
            )
            .await?;
        Ok(PreparedFinish::Ready {
            prepared: Box::new(prepared),
            response,
        })
    }

    /// The refusal of a held identifier's registration finish: the one a new
    /// account's commit would get under the policy in force now, else
    /// already registered. A closed policy refuses a held and a free
    /// identifier alike, so the finish tells no more than the start.
    pub async fn refuse_held(
        &self,
        pending: &PendingRegistration,
        enabled: bool,
    ) -> RegistrationError {
        let PendingRegistration::ExistingAccount {
            principal_type,
            value,
            invite_code,
            by_claim,
        } = pending
        else {
            return internal("registration finish", "not a held identifier");
        };
        if !by_claim
            && let Err(refused) = self
                .admitted_by_enrollment(*principal_type, value, invite_code.as_deref(), enabled)
                .await
        {
            return refused;
        }
        RegistrationError::AlreadyRegistered(*principal_type)
    }

    /// Gate a new self-registration. While the installation has no
    /// administrator, the only registration accepted is one presenting the
    /// instance claim token, whatever the mode; it returns the sealed claim
    /// to consume with the account. Otherwise the registration switch and
    /// the enrollment policy decide.
    async fn admit(
        &self,
        principal_type: PrincipalType,
        value: &str,
        claim_token: Option<&str>,
        invite_code: Option<&str>,
        enabled: bool,
    ) -> Result<Option<Vec<u8>>, RegistrationError> {
        use sid_authn::admin_claim::{self, ClaimError};
        if admin_claim::is_open(self.storage.as_ref())
            .await
            .map_err(|e| internal("check instance claim", e))?
        {
            let Some(token) = claim_token.filter(|t| !t.is_empty()) else {
                return Err(RegistrationError::Restricted("instance_claim"));
            };
            let token = secrecy::SecretString::from(token.to_owned());
            match admin_claim::verify(self.storage.as_ref(), self.keys.as_ref(), &token).await {
                Ok(Some(sealed)) => return Ok(Some(sealed)),
                // Claimed meanwhile: an ordinary registration from here on.
                // Still open with no stored claim, nothing can be presented:
                // the claim is not open to anyone.
                Ok(None) => {
                    if admin_claim::is_open(self.storage.as_ref())
                        .await
                        .map_err(|e| internal("check instance claim", e))?
                    {
                        return Err(RegistrationError::Restricted("instance_claim"));
                    }
                }
                Err(ClaimError::Mismatch) => {
                    return Err(RegistrationError::Restricted("instance_claim"));
                }
                Err(e) => return Err(internal("verify instance claim", e)),
            }
        }
        self.admitted_by_enrollment(principal_type, value, invite_code, enabled)
            .await?;
        Ok(None)
    }

    /// Refuse a self-registration of `value` the enrollment policy in force
    /// does not admit, before the client spends work on its proof. The
    /// storage decides again when the account commits, under the policy then
    /// in force, and spends the invite there.
    async fn admitted_by_enrollment(
        &self,
        principal_type: PrincipalType,
        value: &str,
        invite_code: Option<&str>,
        enabled: bool,
    ) -> Result<(), RegistrationError> {
        if !enabled {
            return Err(RegistrationError::NotEnabled);
        }
        let policy = crate::enrollment::stored_or_default(self.storage.as_ref()).await?;
        let email = matches!(principal_type, PrincipalType::Email).then_some(value);
        if let EnrollmentDecision::Deny(reason) = evaluate_enrollment(&policy, email, invite_code) {
            return Err(RegistrationError::Restricted(requirement(&reason)));
        }
        if policy.mode == EnrollmentMode::InviteOnly
            && let Some(code) = invite_code
        {
            let usable = self
                .storage
                .get_invite_by_code(code)
                .await?
                .is_some_and(|invite| invite.is_usable());
            if !usable {
                return Err(RegistrationError::Restricted(requirement(
                    &EnrollmentDenialReason::InviteInvalid,
                )));
            }
        }
        Ok(())
    }

    /// Refuse to create an account for an upstream sign-in this installation
    /// does not admit, as it refuses a self-registration: the registration
    /// switch (`enabled`), then the effective enrollment policy, the
    /// provider's verified email as the address a domain policy checks. An
    /// upstream sign-in carries no invite.
    pub async fn admit_upstream(
        &self,
        claims: &sid_core::models::MappedClaims,
        enabled: bool,
    ) -> Result<(), RegistrationError> {
        if !enabled {
            return Err(RegistrationError::NotEnabled);
        }
        let policy = crate::enrollment::stored_or_default(self.storage.as_ref()).await?;
        let email = claims
            .has_verified_email()
            .then_some(claims.email.as_deref())
            .flatten();
        match evaluate_enrollment(&policy, email, None) {
            EnrollmentDecision::Allow => Ok(()),
            EnrollmentDecision::Deny(reason) => {
                Err(RegistrationError::Restricted(requirement(&reason)))
            }
        }
    }
}

#[cfg(test)]
mod tests;
