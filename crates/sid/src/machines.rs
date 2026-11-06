// SPDX-License-Identifier: AGPL-3.0-only
//! Machine identity management: machine users, their credentials and their
//! impersonation grants, the same operations for the service and an
//! embedding application. Each operation takes a verified [`Caller`] and
//! checks its authority itself; a keyed one takes the caller's operation
//! context, commits its state, audit and completion together and answers a
//! retry with what the first attempt recorded.

use std::sync::Arc;

use prost::Message;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use sid_authn::caller::{Caller, CallerError};
use sid_authn::operation::{Effect, KeyedCommand, OperationError};
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::{
    AuditEntry, ImpersonationGrant, ImpersonationTargetType as DomainImpersonationTargetType,
    MachineCredentialType as DomainCredentialType, MachineOwner, MachineRestrictions, MachineUser,
    MachineUserCredential, MachineUserId, MachineUserStatus as DomainMachineUserStatus,
    MachineUserType as DomainMachineUserType, MutationContext, OperationContext, OrgId,
    machine_user::CredentialStatus as DomainCredentialStatus,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::machine::machine_user_service as keyed;
use sid_proto::sid::v1::{
    self, AddMachineCredentialRequest, AddMachineCredentialResponse, CreateMachineUserRequest,
    CreateMachineUserResponse, DeleteMachineUserRequest, DeleteMachineUserResponse,
    GetMachineUserRequest, GrantImpersonationRequest, GrantImpersonationResponse,
    ImpersonationGrantInfo, ListImpersonationGrantsRequest, ListImpersonationGrantsResponse,
    ListMachineCredentialsRequest, ListMachineCredentialsResponse, ListMachineUsersRequest,
    ListMachineUsersResponse, MachineCredentialInfo, MachineUserInfo, MachineUserResponse,
    ReactivateMachineUserRequest, RevokeImpersonationRequest, RevokeImpersonationResponse,
    RevokeMachineCredentialRequest, RevokeMachineCredentialResponse,
    RotateMachineCredentialRequest, RotateMachineCredentialResponse, SuspendMachineUserRequest,
    UpdateMachineUserRequest,
};
use tracing::info;

/// Why a machine operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum MachineError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The keyed command conflicts, is refused its period or its outcome is
    /// unknown.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] sid_core::Error),
    /// A required field is absent.
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// No machine user with this id.
    #[error("no machine user {0}")]
    NotFound(MachineUserId),
    /// No credential of this kid belongs to the machine user.
    #[error("no machine credential {0}")]
    CredentialNotFound(String),
    /// The machine user's state does not allow the change.
    #[error("a {state} machine user cannot be {change}")]
    MachineState {
        id: MachineUserId,
        state: &'static str,
        change: &'static str,
    },
    /// Only an active credential can be rotated.
    #[error("credential {kid} is {state}")]
    CredentialState { kid: String, state: &'static str },
    /// The machine user holds the most active credentials allowed.
    #[error("machine user {0} holds the most active credentials allowed")]
    CredentialLimit(MachineUserId),
    /// The record changed since it was read.
    #[error("changed concurrently")]
    ChangedConcurrently,
}

impl From<MachineError> for Effect<MachineError> {
    fn from(e: MachineError) -> Self {
        Self::Refused(e)
    }
}

/// The identifier `field` of a request names, validated before any lookup.
fn wire_id<W: sid_ids_proto::WireId>(
    value: Option<&W>,
    field: &'static str,
) -> Result<W::Domain, MachineError> {
    sid_ids_proto::required(value).map_err(|e| MachineError::InvalidField {
        field,
        reason: format!("{field}: {e}"),
    })
}

/// Machine identity management of one installation.
pub struct Machines {
    storage: Arc<dyn StorageBackend>,
    revocation: Arc<RevocationCache>,
    /// The installation's organization, which owns the machine users its
    /// administrators create.
    organization: OrgId,
}

impl Machines {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        revocation: Arc<RevocationCache>,
        organization: OrgId,
    ) -> Self {
        Self {
            storage,
            revocation,
            organization,
        }
    }

    /// Machine users, their credentials and their impersonation grants are
    /// instance administration. An agent owned by a Profile is managed by
    /// its owner through the application's consent flow, not here.
    fn admin(caller: &Caller) -> Result<(), MachineError> {
        Ok(caller.require_admin()?)
    }

    /// Stop the tokens issued for `kids` at every replica and resource: a
    /// machine token's `sid` is the credential it was issued for. The stored
    /// change has committed; a resource of this installation rechecks the
    /// stored state anyway, so a cache failure is logged, not refused.
    async fn stop_tokens(&self, kids: &[String]) {
        for kid in kids {
            if let Err(e) = self.revocation.revoke_session(kid.clone()).await {
                tracing::warn!(kid = %kid, error = %e, "machine credential revocation not propagated");
            }
        }
    }

    /// Stop the tokens of every credential of machine user `id`.
    async fn stop_all_tokens(&self, id: MachineUserId) -> Result<(), MachineError> {
        let kids: Vec<String> = self
            .storage
            .list_machine_credentials_by_user(id)
            .await?
            .into_iter()
            .map(|c| c.kid)
            .collect();
        self.stop_tokens(&kids).await;
        Ok(())
    }

    // ── Machine users ──

    pub async fn create_machine_user(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: CreateMachineUserRequest,
    ) -> Result<CreateMachineUserResponse, MachineError> {
        Self::admin(caller)?;
        if req.display_name.is_empty() {
            return Err(MachineError::MissingField("display_name"));
        }
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        // A retry of a completed creation answers with the machine user it
        // created and creates no second one.
        let command = KeyedCommand::by_profile::<keyed::CreateMachineUser>(
            caller.profile_id,
            operation,
            &req,
        );

        // An administrator acts for the installation's organization; a
        // system-owned machine is established only by installation
        // provisioning, never through this API.
        let mut mu = MachineUser::new(
            project_id,
            generate_client_id(),
            &req.display_name,
            MachineOwner::Organization(self.organization),
        );
        mu.machine_type = proto_to_machine_type(req.machine_type);
        if !req.description.is_empty() {
            mu.description = Some(req.description);
        }
        if !req.scopes.is_empty() {
            mu.scopes = req.scopes;
        }
        if !req.ip_allowlist.is_empty() || req.rate_limit_rpm > 0 {
            mu.restrictions = MachineRestrictions {
                ip_allowlist: req.ip_allowlist,
                rate_limit_rpm: req.rate_limit_rpm as u32,
            };
        }
        if req.max_token_lifetime > 0 {
            mu.max_token_lifetime = Some(req.max_token_lifetime as u32);
        }
        mu.expires_at = optional_timestamp(&req.expires_at)?;

        let response = command
            .execute::<_, MachineError, _, _>(&*self.storage, || async {
                let response = CreateMachineUserResponse {
                    machine_user: Some(machine_user_to_proto(&mu)),
                };
                let audit = MutationContext::from(AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "machine_user.create",
                    mu.id.to_string(),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                self.storage.create_machine_user(&mu, audit).await?;
                Ok(response)
            })
            .await?;
        info!(
            "Created machine user {} ({}) for project {}",
            mu.id, mu.display_name, mu.project_id
        );
        Ok(response)
    }

    pub async fn get_machine_user(
        &self,
        caller: &Caller,
        req: GetMachineUserRequest,
    ) -> Result<MachineUserResponse, MachineError> {
        Self::admin(caller)?;
        let id = wire_id(req.machine_user_id.as_ref(), "machine_user_id")?;
        let mu = self
            .storage
            .get_machine_user(id)
            .await?
            .ok_or(MachineError::NotFound(id))?;
        Ok(MachineUserResponse {
            machine_user: Some(machine_user_to_proto(&mu)),
        })
    }

    pub async fn update_machine_user(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: UpdateMachineUserRequest,
    ) -> Result<MachineUserResponse, MachineError> {
        Self::admin(caller)?;
        let id = wire_id(req.machine_user_id.as_ref(), "machine_user_id")?;
        // A retry of a completed edit answers with the machine user as that
        // edit left it and never writes its settings over a later edit.
        let command = KeyedCommand::by_profile::<keyed::UpdateMachineUser>(
            caller.profile_id,
            operation,
            &req,
        );
        let response = command
            .execute::<_, MachineError, _, _>(&*self.storage, || async {
                let mut mu = self
                    .storage
                    .get_machine_user(id)
                    .await?
                    .ok_or(MachineError::NotFound(id))?;
                let req = req.clone();
                // Only the fields given are changed.
                if !req.display_name.is_empty() {
                    mu.display_name = req.display_name;
                }
                if !req.description.is_empty() {
                    mu.description = Some(req.description);
                }
                if !req.scopes.is_empty() {
                    mu.scopes = req.scopes;
                }
                if !req.ip_allowlist.is_empty() {
                    mu.restrictions.ip_allowlist = req.ip_allowlist;
                }
                if req.rate_limit_rpm > 0 {
                    mu.restrictions.rate_limit_rpm = req.rate_limit_rpm as u32;
                }
                if req.max_token_lifetime > 0 {
                    mu.max_token_lifetime = Some(req.max_token_lifetime as u32);
                }
                if req.expires_at.is_some() {
                    mu.expires_at = optional_timestamp(&req.expires_at)?;
                }
                mu.updated_at = chrono::Utc::now();

                let response = MachineUserResponse {
                    machine_user: Some(machine_user_to_proto(&mu)),
                };
                let audit = MutationContext::from(AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "machine_user.update",
                    mu.id.to_string(),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                // Settings only: a suspension or deletion made meanwhile stays.
                if !self.storage.update_machine_user(&mu, audit).await? {
                    return Err(MachineError::NotFound(id).into());
                }
                Ok(response)
            })
            .await?;
        info!("Updated machine user {}", id);
        Ok(response)
    }

    pub async fn delete_machine_user(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: DeleteMachineUserRequest,
    ) -> Result<DeleteMachineUserResponse, MachineError> {
        Self::admin(caller)?;
        let id = wire_id(req.machine_user_id.as_ref(), "machine_user_id")?;
        // A retry of a completed deletion answers as it did.
        let command = KeyedCommand::by_profile::<keyed::DeleteMachineUser>(
            caller.profile_id,
            operation,
            &req,
        );
        let response = command
            .execute::<_, MachineError, _, _>(&*self.storage, || async {
                let response = DeleteMachineUserResponse {};
                let audit = MutationContext::from(AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "machine_user.delete",
                    id.to_string(),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                self.storage.delete_machine_user(id, audit).await?;
                Ok(response)
            })
            .await?;
        // Repeated on a retry too: the tokens stop wherever they still run.
        self.stop_all_tokens(id).await?;
        info!("Deleted machine user {}", id);
        Ok(response)
    }

    pub async fn list_machine_users(
        &self,
        caller: &Caller,
        req: ListMachineUsersRequest,
    ) -> Result<ListMachineUsersResponse, MachineError> {
        Self::admin(caller)?;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let users = self
            .storage
            .list_machine_users_by_project(project_id)
            .await?;
        Ok(ListMachineUsersResponse {
            machine_users: users.iter().map(machine_user_to_proto).collect(),
        })
    }

    pub async fn suspend_machine_user(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: SuspendMachineUserRequest,
    ) -> Result<MachineUserResponse, MachineError> {
        Self::admin(caller)?;
        let id = wire_id(req.machine_user_id.as_ref(), "machine_user_id")?;
        // A retry of a completed suspension answers as it did and never
        // suspends again a machine user reactivated since.
        let command = KeyedCommand::by_profile::<keyed::SuspendMachineUser>(
            caller.profile_id,
            operation,
            &req,
        );
        command
            .execute::<_, MachineError, _, _>(&*self.storage, || async {
                let mut mu = self
                    .storage
                    .get_machine_user(id)
                    .await?
                    .ok_or(MachineError::NotFound(id))?;
                let audit = |response: &MachineUserResponse| {
                    MutationContext::from(AuditEntry::admin(
                        caller.profile_id.to_string(),
                        "machine_user.suspend",
                        id.to_string(),
                    ))
                    .with_operation(command.completion(response.encode_to_vec()))
                };
                if mu.status == DomainMachineUserStatus::Deleted {
                    return Err(state(id, "deleted", "suspended").into());
                }
                if mu.status == DomainMachineUserStatus::Suspended {
                    // Already suspended: nothing changes, and the current
                    // state is the command's outcome for its retry.
                    let response = MachineUserResponse {
                        machine_user: Some(machine_user_to_proto(&mu)),
                    };
                    self.storage.record_outcome(audit(&response)).await?;
                    return Ok(response);
                }
                // Expired is the one state left here.
                let active = mu
                    .as_active()
                    .ok_or_else(|| state(id, "expired", "suspended"))?;
                active.suspend();
                let response = MachineUserResponse {
                    machine_user: Some(machine_user_to_proto(&mu)),
                };
                // Only from active: a deletion made meanwhile is not turned back.
                if !self
                    .storage
                    .transition_machine_user(
                        mu.id,
                        DomainMachineUserStatus::Active,
                        DomainMachineUserStatus::Suspended,
                        audit(&response),
                    )
                    .await?
                {
                    return Err(MachineError::ChangedConcurrently.into());
                }
                self.stop_all_tokens(mu.id).await?;
                info!("Suspended machine user {}", mu.id);
                Ok(response)
            })
            .await
    }

    pub async fn reactivate_machine_user(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: ReactivateMachineUserRequest,
    ) -> Result<MachineUserResponse, MachineError> {
        Self::admin(caller)?;
        let id = wire_id(req.machine_user_id.as_ref(), "machine_user_id")?;
        // A retry of a completed reactivation answers as it did and never
        // reactivates a machine user suspended since.
        let command = KeyedCommand::by_profile::<keyed::ReactivateMachineUser>(
            caller.profile_id,
            operation,
            &req,
        );
        command
            .execute::<_, MachineError, _, _>(&*self.storage, || async {
                let mut mu = self
                    .storage
                    .get_machine_user(id)
                    .await?
                    .ok_or(MachineError::NotFound(id))?;
                let audit = |response: &MachineUserResponse| {
                    MutationContext::from(AuditEntry::admin(
                        caller.profile_id.to_string(),
                        "machine_user.reactivate",
                        id.to_string(),
                    ))
                    .with_operation(command.completion(response.encode_to_vec()))
                };
                if mu.status == DomainMachineUserStatus::Deleted {
                    return Err(state(id, "deleted", "reactivated").into());
                }
                if mu.status == DomainMachineUserStatus::Active {
                    // Already active: nothing changes, and the current state
                    // is the command's outcome for its retry.
                    let response = MachineUserResponse {
                        machine_user: Some(machine_user_to_proto(&mu)),
                    };
                    self.storage.record_outcome(audit(&response)).await?;
                    return Ok(response);
                }
                let previous = mu.status;
                mu.status = DomainMachineUserStatus::Active;
                mu.updated_at = chrono::Utc::now();
                let response = MachineUserResponse {
                    machine_user: Some(machine_user_to_proto(&mu)),
                };
                // Only from the state just read: a deletion made meanwhile stays.
                if !self
                    .storage
                    .transition_machine_user(
                        mu.id,
                        previous,
                        DomainMachineUserStatus::Active,
                        audit(&response),
                    )
                    .await?
                {
                    return Err(MachineError::ChangedConcurrently.into());
                }
                info!("Reactivated machine user {}", mu.id);
                Ok(response)
            })
            .await
    }

    // ── Credentials ──

    pub async fn add_machine_credential(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: AddMachineCredentialRequest,
    ) -> Result<AddMachineCredentialResponse, MachineError> {
        Self::admin(caller)?;
        let mu_id = wire_id(req.machine_user_id.as_ref(), "machine_user_id")?;
        let cred_type = proto_to_credential_type(req.credential_type)?;
        // A secret is shown once and only its verifier is kept: a retry of a
        // completed addition answers with the credential it added, its secret
        // empty, and adds no second one.
        let command = KeyedCommand::by_profile::<keyed::AddMachineCredential>(
            caller.profile_id,
            operation,
            &req,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        // A refusal a concurrent attempt of this command caused (the slot its
        // credential took) is that attempt's answer.
        let answer = async {
            let mu = self
                .storage
                .get_machine_user(mu_id)
                .await?
                .ok_or(MachineError::NotFound(mu_id))?;
            if mu.status == DomainMachineUserStatus::Deleted {
                return Err(state(mu_id, "deleted", "given a credential"));
            }
            let kid = generate_kid();
            let (credential_data, secret) = credential_material(cred_type, &req.public_key_pem)?;
            let mut cred = MachineUserCredential::new(mu_id, &kid, cred_type, credential_data);
            if !req.algorithm.is_empty() {
                cred.algorithm = Some(req.algorithm.clone());
            }
            cred.expires_at = optional_timestamp(&req.expires_at)?;

            let mut response = AddMachineCredentialResponse {
                credential: Some(credential_to_proto(&cred)),
                client_secret: String::new(),
            };
            let audit = MutationContext::from(AuditEntry::admin(
                caller.profile_id.to_string(),
                "machine_user.credential.add",
                format!("{mu_id}:{kid}"),
            ))
            .with_operation(command.completion(response.encode_to_vec()));
            // The limit is checked with the insert, so concurrent adds cannot
            // exceed it.
            match self
                .storage
                .add_machine_credential(
                    &cred,
                    Some(sid_core::models::machine_user::MAX_ACTIVE_CREDENTIALS as u64),
                    audit,
                )
                .await
            {
                Ok(_) => {}
                Err(sid_core::Error::OperationCompleted(_)) => {
                    return Err(MachineError::ChangedConcurrently);
                }
                // The limit is counted before the key: the slot may be full
                // with the credential a concurrent attempt of this command
                // added.
                Err(sid_core::Error::ResourceExhausted(_)) => {
                    return Err(MachineError::CredentialLimit(mu_id));
                }
                Err(e) => return Err(e.into()),
            }
            info!("Added credential {} to machine user {}", kid, mu_id);
            response.client_secret = secret
                .as_ref()
                .map(|s| s.expose_secret().clone())
                .unwrap_or_default();
            Ok(response)
        }
        .await;
        command.settle(&*self.storage, answer).await
    }

    pub async fn revoke_machine_credential(
        &self,
        caller: &Caller,
        req: RevokeMachineCredentialRequest,
    ) -> Result<RevokeMachineCredentialResponse, MachineError> {
        Self::admin(caller)?;
        let mu_id = wire_id(req.machine_user_id.as_ref(), "machine_user_id")?;
        if req.kid.is_empty() {
            return Err(MachineError::MissingField("kid"));
        }
        let audit: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "machine_user.credential.revoke",
            format!("{mu_id}:{}", req.kid),
        )
        .into();
        if !self
            .storage
            .revoke_machine_credential(mu_id, &req.kid, audit)
            .await?
        {
            // Revoking a revoked credential is a no-op; a kid of another
            // machine user, or none, is not found.
            let already = self
                .storage
                .get_machine_credential_by_kid(&req.kid)
                .await?
                .is_some_and(|c| {
                    c.machine_user_id == mu_id && c.status == DomainCredentialStatus::Revoked
                });
            if !already {
                return Err(MachineError::CredentialNotFound(req.kid));
            }
        }
        self.stop_tokens(std::slice::from_ref(&req.kid)).await;
        info!("Revoked credential {} for machine user {mu_id}", req.kid);
        Ok(RevokeMachineCredentialResponse {})
    }

    pub async fn list_machine_credentials(
        &self,
        caller: &Caller,
        req: ListMachineCredentialsRequest,
    ) -> Result<ListMachineCredentialsResponse, MachineError> {
        Self::admin(caller)?;
        let mu_id = wire_id(req.machine_user_id.as_ref(), "machine_user_id")?;
        let creds = self.storage.list_machine_credentials_by_user(mu_id).await?;
        Ok(ListMachineCredentialsResponse {
            credentials: creds.iter().map(credential_to_proto).collect(),
        })
    }

    pub async fn rotate_machine_credential(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: RotateMachineCredentialRequest,
    ) -> Result<RotateMachineCredentialResponse, MachineError> {
        Self::admin(caller)?;
        let mu_id = wire_id(req.machine_user_id.as_ref(), "machine_user_id")?;
        if req.kid.is_empty() {
            return Err(MachineError::MissingField("kid"));
        }
        // A retry of a completed rotation answers with the credentials it left,
        // the new secret empty, and rotates nothing again: the old credential
        // is no longer active, so it would otherwise be refused.
        let command = KeyedCommand::by_profile::<keyed::RotateMachineCredential>(
            caller.profile_id,
            operation,
            &req,
        );
        if let Some(recorded) = command.replay(&*self.storage).await? {
            return Ok(recorded);
        }
        // A refusal a concurrent attempt of this command caused (the
        // credential it rotated is no longer active) is that attempt's answer.
        let answer = async {
            // A kid of another machine user is not found, as one that does not exist.
            let old_cred = self
                .storage
                .get_machine_credential_by_kid(&req.kid)
                .await?
                .filter(|c| c.machine_user_id == mu_id)
                .ok_or_else(|| MachineError::CredentialNotFound(req.kid.clone()))?;
            if old_cred.status != DomainCredentialStatus::Active {
                return Err(MachineError::CredentialState {
                    kid: req.kid.clone(),
                    state: old_cred.status.as_str(),
                });
            }
            let new_kid = generate_kid();
            let (credential_data, secret) =
                credential_material(old_cred.credential_type, &req.public_key_pem)?;
            let mut new_cred = MachineUserCredential::new(
                mu_id,
                &new_kid,
                old_cred.credential_type,
                credential_data,
            );
            new_cred.algorithm = if req.algorithm.is_empty() {
                old_cred.algorithm.clone()
            } else {
                Some(req.algorithm.clone())
            };
            new_cred.expires_at = optional_timestamp(&req.expires_at)?;

            // The old credential enters its grace period and the new one is
            // stored in one step, only if the old one is still active. The
            // grace ends, at the latest, ROTATION_GRACE_PERIOD_HOURS from now.
            let grace_until = chrono::Utc::now()
                + chrono::Duration::hours(i64::from(
                    sid_core::models::machine_user::ROTATION_GRACE_PERIOD_HOURS,
                ));
            let mut left = old_cred.clone();
            left.status = DomainCredentialStatus::GracePeriod;
            left.expires_at = Some(
                left.expires_at
                    .map_or(grace_until, |own| own.min(grace_until)),
            );
            let mut response = RotateMachineCredentialResponse {
                old_credential: Some(credential_to_proto(&left)),
                new_credential: Some(credential_to_proto(&new_cred)),
                client_secret: String::new(),
            };
            let audit = MutationContext::from(AuditEntry::admin(
                caller.profile_id.to_string(),
                "machine_user.credential.rotate",
                format!("{}:{}->{}", mu_id, old_cred.kid, new_kid),
            ))
            .with_operation(command.completion(response.encode_to_vec()));
            match self
                .storage
                .rotate_machine_credential(mu_id, &old_cred.kid, &new_cred, grace_until, audit)
                .await
            {
                Ok(true) => {}
                // Rotated since it was read, or the key completed: by a
                // concurrent attempt of this command or by another.
                Ok(false) | Err(sid_core::Error::OperationCompleted(_)) => {
                    return Err(MachineError::ChangedConcurrently);
                }
                Err(e) => return Err(e.into()),
            }
            info!(
                "Rotated credential {} -> {} for machine user {}",
                old_cred.kid, new_kid, mu_id
            );
            response.client_secret = secret
                .as_ref()
                .map(|s| s.expose_secret().clone())
                .unwrap_or_default();
            Ok(response)
        }
        .await;
        command.settle(&*self.storage, answer).await
    }

    // ── Impersonation ──

    pub async fn grant_impersonation(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: GrantImpersonationRequest,
    ) -> Result<GrantImpersonationResponse, MachineError> {
        Self::admin(caller)?;
        let mu_id = wire_id(req.machine_user_id.as_ref(), "machine_user_id")?;
        let target_type = proto_to_impersonation_target(req.target_type)?;
        if req.target.is_empty() {
            return Err(MachineError::MissingField("target"));
        }
        // A retry of a completed grant answers as it did and never grants
        // again what was revoked since.
        let command = KeyedCommand::by_profile::<keyed::GrantImpersonation>(
            caller.profile_id,
            operation,
            &req,
        );
        let response = command
            .execute::<_, MachineError, _, _>(&*self.storage, || async {
                let mu = self
                    .storage
                    .get_machine_user(mu_id)
                    .await?
                    .ok_or(MachineError::NotFound(mu_id))?;
                if mu.status == DomainMachineUserStatus::Deleted {
                    return Err(state(mu_id, "deleted", "granted impersonation").into());
                }
                let grant = ImpersonationGrant::new(
                    mu_id,
                    target_type,
                    &req.target,
                    req.allowed_scopes.clone(),
                );
                let response = GrantImpersonationResponse {
                    grant: Some(grant_to_proto(&grant)),
                };
                let audit = MutationContext::from(AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "machine_user.impersonation.grant",
                    format!("{}:{}:{}", mu_id, target_type.as_str(), req.target),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                self.storage.save_impersonation_grant(&grant, audit).await?;
                Ok(response)
            })
            .await?;
        info!(
            "Granted impersonation to machine user {} for {} {}",
            mu_id,
            target_type.as_str(),
            req.target
        );
        Ok(response)
    }

    pub async fn revoke_impersonation(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: RevokeImpersonationRequest,
    ) -> Result<RevokeImpersonationResponse, MachineError> {
        Self::admin(caller)?;
        let mu_id = wire_id(req.machine_user_id.as_ref(), "machine_user_id")?;
        if req.target_type.is_empty() {
            return Err(MachineError::MissingField("target_type"));
        }
        if req.target.is_empty() {
            return Err(MachineError::MissingField("target"));
        }
        // A retry of a completed revocation answers as it did and never
        // removes a grant made again since.
        let command = KeyedCommand::by_profile::<keyed::RevokeImpersonation>(
            caller.profile_id,
            operation,
            &req,
        );
        let response = command
            .execute::<_, MachineError, _, _>(&*self.storage, || async {
                let response = RevokeImpersonationResponse {};
                let audit = MutationContext::from(AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "machine_user.impersonation.revoke",
                    format!("{}:{}:{}", mu_id, req.target_type, req.target),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                self.storage
                    .delete_impersonation_grant(mu_id, &req.target_type, &req.target, audit)
                    .await?;
                Ok(response)
            })
            .await?;
        info!(
            "Revoked impersonation from machine user {} for {} {}",
            mu_id, req.target_type, req.target
        );
        Ok(response)
    }

    pub async fn list_impersonation_grants(
        &self,
        caller: &Caller,
        req: ListImpersonationGrantsRequest,
    ) -> Result<ListImpersonationGrantsResponse, MachineError> {
        Self::admin(caller)?;
        let mu_id = wire_id(req.machine_user_id.as_ref(), "machine_user_id")?;
        let grants = self.storage.list_impersonation_grants(mu_id).await?;
        Ok(ListImpersonationGrantsResponse {
            grants: grants.iter().map(grant_to_proto).collect(),
        })
    }
}

/// The refusal of `change` on a machine user in `state`.
fn state(id: MachineUserId, state: &'static str, change: &'static str) -> MachineError {
    MachineError::MachineState { id, state, change }
}

/// What a new credential of `kind` stores, and its secret when one is issued
/// (shown once; only its verifier is kept).
fn credential_material(
    kind: DomainCredentialType,
    public_key_pem: &str,
) -> Result<(String, Option<SecretBox<String>>), MachineError> {
    Ok(match kind {
        DomainCredentialType::ClientSecret => {
            let issued = sid_authn::bearer_secret::issue(MACHINE_SECRET_PREFIX);
            (issued.verifier, Some(issued.secret))
        }
        DomainCredentialType::PrivateKeyJwt => {
            if public_key_pem.is_empty() {
                return Err(MachineError::MissingField("public_key_pem"));
            }
            (public_key_pem.to_owned(), None)
        }
        DomainCredentialType::Mtls => {
            if public_key_pem.is_empty() {
                return Err(MachineError::MissingField("public_key_pem"));
            }
            // The certificate's fingerprint (SHA-256 of its PEM).
            (sha256_hex(public_key_pem.as_bytes()), None)
        }
        // A trust bundle reference.
        DomainCredentialType::WorkloadIdentity => (public_key_pem.to_owned(), None),
    })
}

/// A client_id for a machine user: `mu_{24 base62 chars}`.
fn generate_client_id() -> String {
    format!("mu_{}", base62::<24>())
}

/// Prefix of a machine user's client secret.
const MACHINE_SECRET_PREFIX: &str = "ms_";

/// A kid for a credential: `kid_{16 base62 chars}`.
fn generate_kid() -> String {
    format!("kid_{}", base62::<16>())
}

/// `N` random base62 characters.
fn base62<const N: usize>() -> String {
    use rand::TryRng;
    use rand::rngs::SysRng;
    const BASE62: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut bytes = [0u8; N];
    SysRng
        .try_fill_bytes(&mut bytes)
        .expect("the operating system random source is available");
    bytes
        .iter()
        .map(|b| BASE62[(*b as usize) % 62] as char)
        .collect()
}

/// SHA-256 hex digest.
fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn to_timestamp(dt: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

/// The time of an optional field.
fn optional_timestamp(
    ts: &Option<prost_types::Timestamp>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, MachineError> {
    ts.as_ref()
        .map(|t| {
            chrono::DateTime::from_timestamp(t.seconds, t.nanos as u32).ok_or_else(|| {
                MachineError::InvalidField {
                    field: "expires_at",
                    reason: "not a representable time".into(),
                }
            })
        })
        .transpose()
}

fn proto_to_machine_type(proto: i32) -> DomainMachineUserType {
    match v1::MachineUserType::try_from(proto) {
        Ok(v1::MachineUserType::Bot) => DomainMachineUserType::Bot,
        Ok(v1::MachineUserType::Agent) => DomainMachineUserType::Agent,
        _ => DomainMachineUserType::Service,
    }
}

fn machine_type_to_proto(t: DomainMachineUserType) -> v1::MachineUserType {
    match t {
        DomainMachineUserType::Service => v1::MachineUserType::Service,
        DomainMachineUserType::Bot => v1::MachineUserType::Bot,
        DomainMachineUserType::Agent => v1::MachineUserType::Agent,
    }
}

fn status_to_proto(s: DomainMachineUserStatus) -> v1::MachineUserStatus {
    match s {
        DomainMachineUserStatus::Active => v1::MachineUserStatus::Active,
        DomainMachineUserStatus::Suspended => v1::MachineUserStatus::Suspended,
        DomainMachineUserStatus::Expired => v1::MachineUserStatus::Expired,
        DomainMachineUserStatus::Deleted => v1::MachineUserStatus::Deleted,
    }
}

fn proto_to_credential_type(proto: i32) -> Result<DomainCredentialType, MachineError> {
    match v1::MachineCredentialType::try_from(proto) {
        Ok(v1::MachineCredentialType::ClientSecret) => Ok(DomainCredentialType::ClientSecret),
        Ok(v1::MachineCredentialType::PrivateKeyJwt) => Ok(DomainCredentialType::PrivateKeyJwt),
        Ok(v1::MachineCredentialType::Mtls) => Ok(DomainCredentialType::Mtls),
        Ok(v1::MachineCredentialType::WorkloadIdentity) => {
            Ok(DomainCredentialType::WorkloadIdentity)
        }
        _ => Err(MachineError::InvalidField {
            field: "credential_type",
            reason: "not a supported credential type".into(),
        }),
    }
}

fn credential_type_to_proto(t: DomainCredentialType) -> v1::MachineCredentialType {
    match t {
        DomainCredentialType::ClientSecret => v1::MachineCredentialType::ClientSecret,
        DomainCredentialType::PrivateKeyJwt => v1::MachineCredentialType::PrivateKeyJwt,
        DomainCredentialType::Mtls => v1::MachineCredentialType::Mtls,
        DomainCredentialType::WorkloadIdentity => v1::MachineCredentialType::WorkloadIdentity,
    }
}

fn credential_status_to_proto(s: DomainCredentialStatus) -> v1::MachineCredentialStatus {
    match s {
        DomainCredentialStatus::Active => v1::MachineCredentialStatus::Active,
        DomainCredentialStatus::GracePeriod => v1::MachineCredentialStatus::GracePeriod,
        DomainCredentialStatus::Expired => v1::MachineCredentialStatus::Expired,
        DomainCredentialStatus::Revoked => v1::MachineCredentialStatus::Revoked,
    }
}

fn proto_to_impersonation_target(
    proto: i32,
) -> Result<DomainImpersonationTargetType, MachineError> {
    match v1::ImpersonationTargetType::try_from(proto) {
        Ok(v1::ImpersonationTargetType::Role) => Ok(DomainImpersonationTargetType::Role),
        Ok(v1::ImpersonationTargetType::User) => Ok(DomainImpersonationTargetType::User),
        _ => Err(MachineError::InvalidField {
            field: "target_type",
            reason: "must be a role or a user".into(),
        }),
    }
}

fn impersonation_target_to_proto(t: DomainImpersonationTargetType) -> v1::ImpersonationTargetType {
    match t {
        DomainImpersonationTargetType::Role => v1::ImpersonationTargetType::Role,
        DomainImpersonationTargetType::User => v1::ImpersonationTargetType::User,
    }
}

/// Who a machine user acts for, as the API names it.
fn owner_to_proto(owner: MachineOwner) -> v1::MachineUserOwner {
    use v1::machine_user_owner::Owner;
    v1::MachineUserOwner {
        owner: Some(match owner {
            MachineOwner::Profile(id) => Owner::Profile(id.into()),
            MachineOwner::Organization(id) => Owner::Organization(id.into()),
            MachineOwner::System => Owner::System(()),
        }),
    }
}

/// A machine user as the API shows it.
pub fn machine_user_to_proto(mu: &MachineUser) -> MachineUserInfo {
    MachineUserInfo {
        id: Some(mu.id.into()),
        project_id: Some(mu.project_id.into()),
        client_id: mu.client_id.clone(),
        display_name: mu.display_name.clone(),
        description: mu.description.clone().unwrap_or_default(),
        machine_type: machine_type_to_proto(mu.machine_type).into(),
        status: status_to_proto(mu.status).into(),
        owner: Some(owner_to_proto(mu.owner)),
        scopes: mu.scopes.clone(),
        ip_allowlist: mu.restrictions.ip_allowlist.clone(),
        rate_limit_rpm: mu.restrictions.rate_limit_rpm as i32,
        max_token_lifetime: mu.max_token_lifetime.map(|v| v as i32).unwrap_or(0),
        expires_at: mu.expires_at.map(to_timestamp),
        last_used_at: None,
        created_at: Some(to_timestamp(mu.created_at)),
        updated_at: Some(to_timestamp(mu.updated_at)),
    }
}

fn credential_to_proto(cred: &MachineUserCredential) -> MachineCredentialInfo {
    MachineCredentialInfo {
        kid: cred.kid.clone(),
        credential_type: credential_type_to_proto(cred.credential_type).into(),
        status: credential_status_to_proto(cred.status).into(),
        algorithm: cred.algorithm.clone().unwrap_or_default(),
        expires_at: cred.expires_at.map(to_timestamp),
        created_at: Some(to_timestamp(cred.created_at)),
    }
}

fn grant_to_proto(grant: &ImpersonationGrant) -> ImpersonationGrantInfo {
    ImpersonationGrantInfo {
        id: format!(
            "{}:{}:{}",
            grant.machine_user_id,
            grant.target_type.as_str(),
            grant.target
        ),
        machine_user_id: Some(grant.machine_user_id.into()),
        target_type: impersonation_target_to_proto(grant.target_type).into(),
        target: grant.target.clone(),
        allowed_scopes: grant.allowed_scopes.clone(),
        created_at: Some(to_timestamp(grant.created_at)),
    }
}

#[cfg(test)]
mod tests;
