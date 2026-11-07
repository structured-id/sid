// SPDX-License-Identifier: AGPL-3.0-only
//! Privileged Profile administration: claiming the installation as its first
//! administrator, an administrator's change of a Profile's status and roles,
//! ending every session of a Profile, and Profile metadata. A keyed
//! operation commits its change, audit and completion together and answers
//! a retry with what the first attempt recorded.

use std::sync::Arc;

use prost::Message;
use secrecy::SecretString;
use sid_authn::account_roles::ADMIN_ROLE_CLAIM;
use sid_authn::admin_claim::{self, ClaimError};
use sid_authn::caller::{Caller, CallerError};
use sid_authn::operation::{CommandError, Effect, KeyedCommand, OperationError};
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_core::Error as SidError;
use sid_core::models::event::{Event, event_types};
use sid_core::models::{
    AuditEntry, MutationContext, OperationContext, ProfileId, ProfileMetadata, ProfileStatus,
    RevocationReason,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::admin::admin_service as keyed;
use sid_proto::sid::v1::{
    self, AdminUpdateProfileRequest, AdminUpdateProfileResponse, DeleteProfileMetadataRequest,
    GetProfileMetadataRequest, ListProfileMetadataRequest, ListProfileMetadataResponse,
    ProfileMetadataEntry, RevokeAllSessionsRequest, RevokeAllSessionsResponse,
    SetProfileMetadataRequest,
};
use tracing::info;

use crate::wire::{FieldError, json_to_value, to_timestamp, value_to_json, wire_id};

/// Why an administration operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The keyed command conflicts, is refused its period or its outcome is
    /// unknown.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A failure of this installation; its cause is in the log, not the
    /// refusal.
    #[error("internal error")]
    Internal,
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("profile {0} not found")]
    ProfileNotFound(ProfileId),
    /// The Profile's status is not one an administrator changes.
    #[error("the status of profile {0} cannot be changed by an administrator")]
    StatusNotChangeable(ProfileId),
    #[error("metadata {key} of profile {profile} not found")]
    MetadataNotFound { profile: ProfileId, key: String },
    /// The installation already has its first administrator.
    #[error("the installation is already claimed")]
    AlreadyClaimed,
    /// The claim token does not match.
    #[error("the claim token does not match")]
    ClaimMismatch,
    /// The record changed since it was read.
    #[error("changed concurrently")]
    ChangedConcurrently,
}

impl From<AdminError> for Effect<AdminError> {
    fn from(e: AdminError) -> Self {
        Self::Refused(e)
    }
}

impl From<CommandError<AdminError>> for AdminError {
    fn from(e: CommandError<AdminError>) -> Self {
        e.refusal()
    }
}

impl From<FieldError> for AdminError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

fn invalid(field: &'static str, reason: &str) -> AdminError {
    AdminError::InvalidField {
        field,
        reason: reason.into(),
    }
}

/// An administrator's command `M` with `req`'s inputs under `operation`.
fn admin_command<M: sid_proto::KeyedMethod>(
    caller: &Caller,
    operation: OperationContext,
    req: &M::Request,
) -> KeyedCommand {
    KeyedCommand::of::<M>(format!("profile:{}", caller.profile_id), operation, req)
}

/// The Profile administration of one installation.
pub struct Admin {
    storage: Arc<dyn StorageBackend>,
    cascade: Arc<RevocationCascadeService>,
    /// Opens the sealed instance claim.
    keys: Arc<dyn sid_keys::KeyManager>,
}

impl Admin {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        cascade: Arc<RevocationCascadeService>,
        keys: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            storage,
            cascade,
            keys,
        }
    }

    /// The signed-in caller becomes the first administrator with the claim
    /// token from the service log. Whether the installation is claimed is
    /// public (the enrollment policy shows it), so its refusals may differ.
    pub async fn claim_instance(
        &self,
        caller: &Caller,
        token: &SecretString,
    ) -> Result<(), AdminError> {
        caller.require_interactive()?;
        match admin_claim::claim(
            self.storage.as_ref(),
            self.keys.as_ref(),
            caller.profile_id,
            token,
        )
        .await
        {
            Ok(()) => {
                info!("Instance claimed by profile {}", caller.profile_id);
                Ok(())
            }
            Err(ClaimError::NotOpen) => Err(AdminError::AlreadyClaimed),
            Err(ClaimError::Mismatch) => Err(AdminError::ClaimMismatch),
            Err(ClaimError::UnknownProfile(id)) => Err(AdminError::ProfileNotFound(id)),
            Err(e) => {
                tracing::error!(operation = "claim instance", error = %e, "internal failure");
                Err(AdminError::Internal)
            }
        }
    }

    /// Change a Profile's status (active or suspended) and roles over the
    /// revision read. A retry of a completed update answers as it did and
    /// never writes its copy again over a later change. A suspended Profile
    /// loses every live sign-in (sessions, their tokens in every process,
    /// the relying parties' logouts, and personal access tokens); its
    /// credentials stay so reactivation works. The suspension is stored
    /// first, so a retry ends what a failure left, unless the Profile was
    /// reactivated meanwhile.
    pub async fn update_profile(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: AdminUpdateProfileRequest,
    ) -> Result<AdminUpdateProfileResponse, AdminError> {
        caller.require_admin()?;
        let profile_id = wire_id(req.profile_id.as_ref(), "profile_id")?;
        let actor = caller.profile_id.to_string();
        let command = admin_command::<keyed::AdminUpdateProfile>(caller, operation, &req);
        let suspends = req.profile_status == v1::ProfileStatus::Suspended as i32;
        let response = command
            .execute(&*self.storage, || {
                self.write_profile(&actor, &command, profile_id, req)
            })
            .await
            .map_err(CommandError::<AdminError>::refusal)?;
        if suspends
            && self
                .storage
                .get_profile(profile_id)
                .await?
                .is_some_and(|p| p.status == ProfileStatus::Suspended)
        {
            self.cascade
                .end_access(profile_id, RevocationReason::Admin, &actor)
                .await?;
        }
        info!("Admin: updated profile {}", profile_id);
        Ok(response)
    }

    async fn write_profile(
        &self,
        actor: &str,
        command: &KeyedCommand,
        profile_id: ProfileId,
        req: AdminUpdateProfileRequest,
    ) -> Result<AdminUpdateProfileResponse, Effect<AdminError>> {
        let mut profile = self
            .storage
            .get_profile(profile_id)
            .await?
            .ok_or(AdminError::ProfileNotFound(profile_id))?;
        let old_status = profile.status;
        // A value the enum does not define is refused, never read as "no
        // change" while the rest of the request applies.
        let not_settable = || {
            invalid(
                "profile_status",
                "an administrator sets ACTIVE or SUSPENDED only",
            )
        };
        let requested =
            v1::ProfileStatus::try_from(req.profile_status).map_err(|_| not_settable())?;
        if requested != v1::ProfileStatus::Unspecified {
            let target = match requested {
                v1::ProfileStatus::Active => ProfileStatus::Active,
                v1::ProfileStatus::Suspended => ProfileStatus::Suspended,
                _ => return Err(not_settable().into()),
            };
            // Activation and suspension move an account between its
            // ordinary states only: a closing, held, closed or purged
            // account is never reopened by setting a status.
            if !matches!(
                profile.status,
                ProfileStatus::Provisioned | ProfileStatus::Active | ProfileStatus::Suspended
            ) || profile.transition_status(target).is_err()
            {
                return Err(AdminError::StatusNotChangeable(profile_id).into());
            }
        }
        if !req.roles.is_empty() {
            // Administering the installation is a role assignment, never a
            // label on the Profile.
            if req.roles.iter().any(|r| r == ADMIN_ROLE_CLAIM) {
                return Err(invalid(
                    "roles",
                    "installation administration is granted by role assignment",
                )
                .into());
            }
            profile.roles = req.roles;
        }
        let response = AdminUpdateProfileResponse {
            profile_id: Some(profile.id.into()),
        };
        // A status change owes its event in the same commit.
        let mut ctx = MutationContext::from(AuditEntry::admin(
            actor.to_owned(),
            "profile.admin_update",
            profile.id.to_string(),
        ))
        .with_operation(command.completion(response.encode_to_vec()));
        let status_event = match (old_status == profile.status, profile.status) {
            (false, ProfileStatus::Suspended) => Some(event_types::USER_DEACTIVATED),
            (false, ProfileStatus::Active) => Some(event_types::USER_UNLOCKED),
            _ => None,
        };
        if let Some(event_type) = status_event {
            let event = Event::new("sid-admin", event_type)
                .with_subject(format!("profile/{}", profile.id))
                .with_data(serde_json::json!({
                    "profile_id": profile.id.to_string(),
                    "old_status": format!("{old_status:?}"),
                    "new_status": format!("{:?}", profile.status),
                }));
            ctx = ctx.with_work(event.relay());
        }
        // Over the revision read above: a concurrent change (a closure, the
        // owner's own edit) is never overwritten with this copy.
        if !self.storage.update_profile(&profile, ctx).await? {
            return Err(AdminError::ChangedConcurrently.into());
        }
        Ok(response)
    }

    /// End every session of a Profile through the cascade: their tokens stop
    /// in every process and each relying party is owed a back-channel
    /// logout. A retry of a completed revocation answers with the count it
    /// ended and never ends sessions signed in after it.
    pub async fn revoke_all_sessions(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: RevokeAllSessionsRequest,
    ) -> Result<RevokeAllSessionsResponse, AdminError> {
        caller.require_admin()?;
        let profile_id = wire_id(req.profile_id.as_ref(), "profile_id")?;
        let actor = caller.profile_id.to_string();
        let command = admin_command::<keyed::RevokeAllSessions>(caller, operation, &req);
        let ended: usize = command
            .execute_recorded(&*self.storage, || async {
                let ctx = MutationContext::from(AuditEntry::admin(
                    actor.clone(),
                    "session.revoke_all",
                    profile_id.to_string(),
                ))
                .with_operation(command.effect_completion());
                let revoked = self
                    .cascade
                    .revoke_sessions(profile_id, RevocationReason::Admin, &actor, ctx)
                    .await?;
                Ok(revoked.cascade_entries.len())
            })
            .await
            .map_err(CommandError::<AdminError>::refusal)?;
        // A count of sessions is far below u64::MAX.
        let revoked_count = ended as u64;
        info!(
            "Admin: revoked {} sessions for profile {}",
            revoked_count, profile_id
        );
        Ok(RevokeAllSessionsResponse { revoked_count })
    }

    pub async fn list_metadata(
        &self,
        caller: &Caller,
        req: ListProfileMetadataRequest,
    ) -> Result<ListProfileMetadataResponse, AdminError> {
        caller.require_admin()?;
        let profile_id = wire_id(req.profile_id.as_ref(), "profile_id")?;
        let entries = self.storage.list_profile_metadata(profile_id).await?;
        Ok(ListProfileMetadataResponse {
            entries: entries.into_iter().map(metadata_to_proto).collect(),
        })
    }

    pub async fn get_metadata(
        &self,
        caller: &Caller,
        req: GetProfileMetadataRequest,
    ) -> Result<ProfileMetadataEntry, AdminError> {
        caller.require_admin()?;
        let profile_id = wire_id(req.profile_id.as_ref(), "profile_id")?;
        let meta = self
            .storage
            .get_profile_metadata(profile_id, &req.key)
            .await?
            .ok_or_else(|| AdminError::MetadataNotFound {
                profile: profile_id,
                key: req.key.clone(),
            })?;
        Ok(metadata_to_proto(meta))
    }

    /// Write a metadata value. A retry of a completed write answers with the
    /// entry it wrote and never writes it again over a later value.
    pub async fn set_metadata(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: SetProfileMetadataRequest,
    ) -> Result<ProfileMetadataEntry, AdminError> {
        caller.require_admin()?;
        let profile_id = wire_id(req.profile_id.as_ref(), "profile_id")?;
        let actor = caller.profile_id.to_string();
        let command = admin_command::<keyed::SetProfileMetadata>(caller, operation, &req);
        command
            .execute(&*self.storage, || async {
                let value = req
                    .value
                    .clone()
                    .map(value_to_json)
                    .unwrap_or(serde_json::Value::Null);
                let metadata = ProfileMetadata::new(profile_id, req.key.clone(), value);
                let entry = metadata_to_proto(metadata.clone());
                let ctx = MutationContext::from(AuditEntry::admin(
                    actor.clone(),
                    "metadata.set",
                    format!("{}:{}", profile_id, metadata.key),
                ))
                .with_operation(command.completion(entry.encode_to_vec()));
                self.storage
                    .set_profile_metadata(&metadata, ctx)
                    .await
                    .map_err(|e| match e {
                        SidError::NotFound(_) => {
                            Effect::from(AdminError::ProfileNotFound(profile_id))
                        }
                        other => Effect::from(other),
                    })?;
                Ok(entry)
            })
            .await
            .map_err(CommandError::<AdminError>::refusal)
    }

    /// Delete a metadata value. A retry of a completed deletion answers as
    /// it did and never deletes a value written after it.
    pub async fn delete_metadata(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: DeleteProfileMetadataRequest,
    ) -> Result<(), AdminError> {
        caller.require_admin()?;
        let profile_id = wire_id(req.profile_id.as_ref(), "profile_id")?;
        let actor = caller.profile_id.to_string();
        let command = admin_command::<keyed::DeleteProfileMetadata>(caller, operation, &req);
        command
            .execute(&*self.storage, || async {
                let ctx = MutationContext::from(AuditEntry::admin(
                    actor.clone(),
                    "metadata.delete",
                    format!("{}:{}", profile_id, req.key),
                ))
                .with_operation(command.completion(().encode_to_vec()));
                self.storage
                    .delete_profile_metadata(profile_id, &req.key, ctx)
                    .await?;
                Ok(())
            })
            .await
            .map_err(CommandError::<AdminError>::refusal)?;
        info!(
            "Admin: deleted metadata key '{}' for profile {}",
            req.key, profile_id
        );
        Ok(())
    }
}

fn metadata_to_proto(m: ProfileMetadata) -> ProfileMetadataEntry {
    ProfileMetadataEntry {
        profile_id: Some(m.profile_id.into()),
        key: m.key,
        value: Some(json_to_value(m.value)),
        updated_at: Some(to_timestamp(m.updated_at)),
    }
}

#[cfg(test)]
mod tests;
