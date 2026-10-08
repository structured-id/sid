// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC AdminService implementation.
//!
//! Privileged operations: bootstrap, admin profile update,
//! bulk session revocation, profile metadata CRUD.

use sid_authn::caller::authenticate;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_core::grpc_error::refuse::{
    changed_concurrently, internal, invalid_field, not_found, storage_failure,
};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::event::{Event, event_types};
use sid_core::models::{
    AuditEntry, MutationContext, ProfileId, ProfileMetadata, ProfileStatus, RevocationReason,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::admin_service_server::AdminService;
use sid_proto::sid::v1::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, instrument};

/// The profile an administrator request names.
#[allow(clippy::result_large_err)]
fn parse_profile_id(id: &str) -> Result<ProfileId, Status> {
    ProfileId::parse(id).map_err(|_| invalid_field("profile_id", "not a profile identifier"))
}

fn profile_not_found(id: ProfileId) -> Status {
    not_found(ErrorReason::ProfileNotFound, "Profile", id.to_string())
}

/// A storage refusal of a profile write: a profile that does not exist is
/// not found, anything else is internal.
fn profile_write(id: ProfileId, e: sid_core::Error) -> Status {
    match e {
        sid_core::Error::NotFound(_) => profile_not_found(id),
        other => storage_failure(other),
    }
}

pub struct AdminServiceImpl {
    pub(crate) storage: Arc<dyn StorageBackend>,
    pub(crate) jwt: Arc<JwtService>,
    pub(crate) revocation: Arc<RevocationCache>,
    pub(crate) cascade: Arc<RevocationCascadeService>,
    /// Opens the sealed instance claim.
    pub(crate) key_manager: Arc<dyn sid_keys::KeyManager>,
}

impl AdminServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
        cascade: Arc<RevocationCascadeService>,
        key_manager: Arc<dyn sid_keys::KeyManager>,
    ) -> Self {
        Self {
            storage,
            jwt,
            revocation,
            cascade,
            key_manager,
        }
    }

    /// Authenticate the caller and require the administrator role; returns the
    /// caller's ProfileId as the audit actor.
    #[allow(clippy::result_large_err)]
    async fn require_admin<T>(&self, req: &Request<T>) -> Result<String, Status> {
        let caller = authenticate(req, self.jwt.verifier(), &self.revocation).await?;
        caller.require_admin()?;
        Ok(caller.profile_id.to_string())
    }
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    /// The signed-in caller becomes the first administrator with the claim
    /// token from the service log (enrollment-policy.md, First Administrator).
    #[instrument(skip_all, name = "admin.claim_instance")]
    async fn claim_instance(
        &self,
        request: Request<ClaimInstanceRequest>,
    ) -> Result<Response<()>, Status> {
        use sid_authn::admin_claim::{self, ClaimError};
        let caller = authenticate(&request, self.jwt.verifier(), &self.revocation).await?;
        caller.require_interactive()?;
        let token = secrecy::SecretString::from(request.into_inner().claim_token);
        match admin_claim::claim(
            self.storage.as_ref(),
            self.key_manager.as_ref(),
            caller.profile_id,
            &token,
        )
        .await
        {
            Ok(()) => {
                info!("Instance claimed by profile {}", caller.profile_id);
                Ok(Response::new(()))
            }
            // Whether the installation is claimed is public (enrollment
            // policy), so the two refusals may differ.
            Err(ClaimError::NotOpen) => Err(ApiError::new(
                ErrorReason::InvalidState,
                "the installation is already claimed",
            )
            .with_precondition("INSTANCE_CLAIM", "installation", "claimed")
            .into()),
            Err(ClaimError::Mismatch) => Err(ApiError::new(
                ErrorReason::InsufficientPermissions,
                "the claim token does not match",
            )
            .into()),
            Err(ClaimError::Changed) => Err(changed_concurrently()),
            Err(e) => Err(internal("claim instance", e)),
        }
    }

    #[instrument(skip_all, name = "admin.update_profile")]
    async fn admin_update_profile(
        &self,
        request: Request<AdminUpdateProfileRequest>,
    ) -> Result<Response<AdminUpdateProfileResponse>, Status> {
        let actor = self.require_admin(&request).await?;

        let req = request.into_inner();
        let profile_id = parse_profile_id(&req.profile_id)?;

        let mut profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| profile_not_found(profile_id))?;

        // Capture old status for event emission.
        let old_status = profile.status;

        // Apply admin-only fields
        // A value the enum does not define is refused, never read as "no
        // change" while the rest of the request applies.
        let not_settable = || {
            invalid_field(
                "profile_status",
                "an administrator sets ACTIVE or SUSPENDED only",
            )
        };
        let requested_status = sid_proto::sid::v1::ProfileStatus::try_from(req.profile_status)
            .map_err(|_| not_settable())?;
        if requested_status != sid_proto::sid::v1::ProfileStatus::Unspecified {
            let target = match requested_status {
                sid_proto::sid::v1::ProfileStatus::Active => ProfileStatus::Active,
                sid_proto::sid::v1::ProfileStatus::Suspended => ProfileStatus::Suspended,
                _ => return Err(not_settable()),
            };
            // Activation and suspension move an account between its ordinary
            // states only: a closing, held, closed or purged account is never
            // reopened by setting a status.
            if !matches!(
                profile.status,
                ProfileStatus::Provisioned | ProfileStatus::Active | ProfileStatus::Suspended
            ) || profile.transition_status(target).is_err()
            {
                return Err(ApiError::new(
                    ErrorReason::InvalidState,
                    "the profile's status cannot be changed by an administrator",
                )
                .with_precondition("PROFILE_STATUS", profile_id.to_string(), "not changeable")
                .into());
            }
        }
        if !req.roles.is_empty() {
            profile.roles = req.roles;
        }
        // email_verified now managed via profile_emails table

        // A status change owes its event in the same commit.
        let mut ctx = MutationContext::from(AuditEntry::admin(
            actor.clone(),
            "profile.admin_update",
            profile.id.to_string(),
        ));
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
                    "old_status": format!("{:?}", old_status),
                    "new_status": format!("{:?}", profile.status),
                }));
            ctx = ctx.with_work(event.relay());
        }
        // Over the revision read above: a concurrent change (a closure, the
        // owner's own edit) is never overwritten with this copy.
        if !self
            .storage
            .update_profile(&profile, ctx)
            .await
            .map_err(storage_failure)?
        {
            return Err(changed_concurrently());
        }

        // A suspended profile loses every live sign-in: sessions (their
        // tokens stop in every process, RPs are owed a logout) and PATs.
        // Credentials are kept so reactivation works. A failure fails the
        // request; the suspension is stored, so a retry ends the rest.
        if profile.status == ProfileStatus::Suspended {
            self.cascade
                .end_access(profile.id, RevocationReason::Admin, &actor)
                .await
                .map_err(storage_failure)?;
        }

        info!("Admin: updated profile {}", profile.id);
        Ok(Response::new(AdminUpdateProfileResponse {
            profile_id: profile.id.to_string(),
        }))
    }

    #[instrument(skip_all, name = "admin.revoke_all_sessions")]
    async fn revoke_all_sessions(
        &self,
        request: Request<RevokeAllSessionsRequest>,
    ) -> Result<Response<RevokeAllSessionsResponse>, Status> {
        let actor = self.require_admin(&request).await?;

        let req = request.into_inner();
        let profile_id = parse_profile_id(&req.profile_id)?;

        // Through the cascade: the sessions' tokens stop in every process and
        // each RP they signed in to is owed a back-channel logout.
        let revoked = self
            .cascade
            .revoke_sessions(
                profile_id,
                RevocationReason::Admin,
                &actor,
                AuditEntry::admin(actor.clone(), "session.revoke_all", profile_id.to_string()),
            )
            .await
            .map_err(storage_failure)?;
        // Each ended session's revoked event is committed with its deletion.
        let count =
            u64::try_from(revoked.cascade_entries.len()).expect("a session count fits in u64");

        info!(
            "Admin: revoked {} sessions for profile {}",
            count, profile_id
        );
        Ok(Response::new(RevokeAllSessionsResponse {
            revoked_count: count,
        }))
    }

    #[instrument(skip_all, name = "admin.list_profile_metadata")]
    async fn list_profile_metadata(
        &self,
        request: Request<ListProfileMetadataRequest>,
    ) -> Result<Response<ListProfileMetadataResponse>, Status> {
        self.require_admin(&request).await?;

        let req = request.into_inner();
        let profile_id = parse_profile_id(&req.profile_id)?;

        let entries = self
            .storage
            .list_profile_metadata(profile_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListProfileMetadataResponse {
            entries: entries.into_iter().map(to_proto_metadata).collect(),
        }))
    }

    #[instrument(skip_all, name = "admin.get_profile_metadata")]
    async fn get_profile_metadata(
        &self,
        request: Request<GetProfileMetadataRequest>,
    ) -> Result<Response<ProfileMetadataEntry>, Status> {
        self.require_admin(&request).await?;

        let req = request.into_inner();
        let profile_id = parse_profile_id(&req.profile_id)?;

        let meta = self
            .storage
            .get_profile_metadata(profile_id, &req.key)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                not_found(
                    ErrorReason::ProfileMetadataNotFound,
                    "ProfileMetadata",
                    format!("{profile_id}:{}", req.key),
                )
            })?;

        Ok(Response::new(to_proto_metadata(meta)))
    }

    #[instrument(skip_all, name = "admin.set_profile_metadata")]
    async fn set_profile_metadata(
        &self,
        request: Request<SetProfileMetadataRequest>,
    ) -> Result<Response<ProfileMetadataEntry>, Status> {
        let actor = self.require_admin(&request).await?;

        let req = request.into_inner();
        let profile_id = parse_profile_id(&req.profile_id)?;

        let json_value = req
            .value
            .map(pbjson_value_to_json)
            .unwrap_or(serde_json::Value::Null);

        let metadata = ProfileMetadata::new(profile_id, req.key, json_value);

        self.storage
            .set_profile_metadata(
                &metadata,
                AuditEntry::admin(
                    actor,
                    "metadata.set",
                    format!("{}:{}", profile_id, metadata.key),
                )
                .into(),
            )
            .await
            .map_err(|e| profile_write(profile_id, e))?;

        Ok(Response::new(to_proto_metadata(metadata)))
    }

    #[instrument(skip_all, name = "admin.delete_profile_metadata")]
    async fn delete_profile_metadata(
        &self,
        request: Request<DeleteProfileMetadataRequest>,
    ) -> Result<Response<()>, Status> {
        let actor = self.require_admin(&request).await?;

        let req = request.into_inner();
        let profile_id = parse_profile_id(&req.profile_id)?;

        self.storage
            .delete_profile_metadata(
                profile_id,
                &req.key,
                AuditEntry::admin(
                    actor,
                    "metadata.delete",
                    format!("{}:{}", profile_id, req.key),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;

        info!(
            "Admin: deleted metadata key '{}' for profile {}",
            req.key, profile_id
        );
        Ok(Response::new(()))
    }
}

// ── Conversion helpers ──

fn to_proto_metadata(m: ProfileMetadata) -> ProfileMetadataEntry {
    ProfileMetadataEntry {
        profile_id: m.profile_id.to_string(),
        key: m.key,
        value: Some(json_to_pbjson_value(m.value)),
        updated_at: Some(prost_types::Timestamp {
            seconds: m.updated_at.timestamp(),
            nanos: m.updated_at.timestamp_subsec_nanos() as i32,
        }),
    }
}

fn json_to_pbjson_value(v: serde_json::Value) -> prost_types::Value {
    match v {
        serde_json::Value::Null => prost_types::Value {
            kind: Some(prost_types::value::Kind::NullValue(0)),
        },
        serde_json::Value::Bool(b) => prost_types::Value {
            kind: Some(prost_types::value::Kind::BoolValue(b)),
        },
        serde_json::Value::Number(n) => prost_types::Value {
            kind: Some(prost_types::value::Kind::NumberValue(
                n.as_f64().unwrap_or(0.0),
            )),
        },
        serde_json::Value::String(s) => prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(s)),
        },
        serde_json::Value::Array(arr) => prost_types::Value {
            kind: Some(prost_types::value::Kind::ListValue(
                prost_types::ListValue {
                    values: arr.into_iter().map(json_to_pbjson_value).collect(),
                },
            )),
        },
        serde_json::Value::Object(map) => prost_types::Value {
            kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                fields: map
                    .into_iter()
                    .map(|(k, v)| (k, json_to_pbjson_value(v)))
                    .collect(),
            })),
        },
    }
}

fn pbjson_value_to_json(v: prost_types::Value) -> serde_json::Value {
    match v.kind {
        Some(prost_types::value::Kind::NullValue(_)) => serde_json::Value::Null,
        Some(prost_types::value::Kind::BoolValue(b)) => serde_json::Value::Bool(b),
        Some(prost_types::value::Kind::NumberValue(n)) => {
            serde_json::Value::Number(serde_json::Number::from_f64(n).unwrap_or_else(|| 0.into()))
        }
        Some(prost_types::value::Kind::StringValue(s)) => serde_json::Value::String(s),
        Some(prost_types::value::Kind::ListValue(list)) => {
            serde_json::Value::Array(list.values.into_iter().map(pbjson_value_to_json).collect())
        }
        Some(prost_types::value::Kind::StructValue(s)) => serde_json::Value::Object(
            s.fields
                .into_iter()
                .map(|(k, v)| (k, pbjson_value_to_json(v)))
                .collect(),
        ),
        None => serde_json::Value::Null,
    }
}
