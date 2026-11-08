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

/// Self-registration on one installation.
pub struct Registration {
    storage: Arc<dyn StorageBackend>,
    keys: Arc<dyn sid_keys::KeyManager>,
    /// The issuer whose events announce new accounts.
    issuer: String,
    /// The enrollment mode the deployment pins over the stored one.
    pinned: Option<EnrollmentMode>,
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
            pinned: None,
        }
    }

    /// Apply `mode` whatever mode is stored.
    pub fn set_pinned(&mut self, mode: Option<EnrollmentMode>) {
        self.pinned = mode;
    }

    /// The enrollment mode the deployment pins, if any.
    pub fn pinned(&self) -> Option<EnrollmentMode> {
        self.pinned
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

    /// Commit `pending` with its first `credential`, atomically, with
    /// `history`, the first password's accepted history, and `completion`,
    /// the durable result of the operation that installs it. A taken
    /// identifier is refused and nothing is written: the holder is not
    /// contacted. Returns the new account's profile and credential.
    pub async fn commit(
        &self,
        pending: PendingRegistration,
        mut credential: Credential,
        history: Option<HistoryCommit>,
        completion: Option<OperationCompletion>,
        enabled: bool,
    ) -> Result<(ProfileId, CredentialId), RegistrationError> {
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
        // The claim registration is admitted by its token whatever the mode;
        // any other one by the policy the storage reads in the account's own
        // transaction, so a policy changed since the start applies to it.
        if instance_claim.is_none() {
            if !enabled {
                return Err(RegistrationError::NotEnabled);
            }
            registration = registration.admitted_by(sid_core::models::EnrollmentGate {
                pinned: self.pinned,
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
        match self.storage.register_profile(&registration, ctx).await {
            Ok(()) => {}
            // Another registration took the identifier between start and finish.
            Err(SidError::Conflict(_)) => {
                return Err(RegistrationError::AlreadyRegistered(principal_type));
            }
            // The claim was taken between start and finish.
            Err(SidError::InvalidState(_)) => {
                return Err(RegistrationError::Restricted("instance_claim"));
            }
            // The policy in force at the commit refuses it, or its invite is
            // no longer usable.
            Err(SidError::RegistrationRestricted(reason)) => {
                return Err(RegistrationError::Restricted(requirement(&reason)));
            }
            Err(e) => {
                return Err(sid_authn::password_operation::commit_refusal(
                    e,
                    RegistrationError::Store,
                )
                .refusal());
            }
        }
        info!("Self-registration committed for profile {}", profile_id);
        Ok((profile_id, credential_id))
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
        self.commit(pending, credential, history, Some(completion), enabled)
            .await?;
        Ok(response)
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
        let policy = crate::enrollment::effective(self.storage.as_ref(), self.pinned).await?;
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
        let policy = crate::enrollment::effective(self.storage.as_ref(), self.pinned).await?;
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
