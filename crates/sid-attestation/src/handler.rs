// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC AttestationService handler implementation. It is served only behind
//! its receiver (`crate::access`), which admits each call and asks the
//! issuer whether its token is current before it reaches a handler.
//!
//! CE: stores attestation data and device public keys without
//! cryptographic verification of attestation chains.

use sid_core::models::{
    AuditEntry, DeviceAttestation, DeviceAttestationFormat, DeviceId, KeyStorageType,
    MutationContext, ProfileId, SessionId,
};
use sid_infra::grpc_error::refuse::{invalid_field, missing_field, not_found, storage_failure};
use sid_infra::grpc_error::{ApiError, ErrorReason};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::attestation::attestation_service_server::AttestationService;
use sid_proto::sid::v1::attestation::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{info, instrument};

pub struct AttestationServiceImpl {
    storage: Arc<dyn StorageBackend>,
}

/// The verified caller of an admitted call.
struct Caller {
    /// The Profile whose sign-in the token stands for, read from that
    /// sign-in in the store, never from the token's subject.
    profile: Option<ProfileId>,
    /// The token's subject, what the audit names a caller without a Profile.
    subject: String,
    /// The Profile's own sign-in, not an impersonation: only such a session
    /// changes a device's keys.
    interactive: bool,
}

impl Caller {
    /// Mutation context whose audit entry names this caller.
    fn audit(&self, action: &str, resource: &str) -> MutationContext {
        let actor = self
            .profile
            .map(|p| p.to_string())
            .unwrap_or_else(|| self.subject.clone());
        AuditEntry::user(actor, action, resource).into()
    }
}

fn denied() -> Status {
    ApiError::new(
        ErrorReason::InsufficientPermissions,
        "the caller may not perform this operation",
    )
    .into()
}

impl AttestationServiceImpl {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    /// The caller of `request`: the Profile of the stored, live sign-in its
    /// token was issued from. A token of no sign-in (a client's own) has no
    /// Profile and owns no device.
    async fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let claims = sid_auth::receiver::owner_claims(request)?;
        let profile = match SessionId::parse(&claims.sid) {
            Ok(id) => self
                .storage
                .get_session(id)
                .await
                .map_err(storage_failure)?
                .filter(|s| !s.is_expired())
                .map(|s| s.profile_id),
            Err(_) => None,
        };
        Ok(Caller {
            profile,
            subject: claims.sub.clone(),
            interactive: profile.is_some() && claims.acr != sid_authn::caller::ACR_IMPERSONATION,
        })
    }

    /// Load `device_id` for its owner, or for a caller the issuer allows the
    /// call's action on that device (the installation's administrator); key
    /// changes also require the caller's own sign-in session. A device the
    /// caller may not reach is DEVICE_NOT_FOUND, as an unknown one: its
    /// existence is not disclosed.
    async fn authorized_device<T>(
        &self,
        request: &mut Request<T>,
        caller: &Caller,
        device_id: DeviceId,
        change: bool,
    ) -> Result<sid_core::models::Device, Status> {
        let unknown = || not_found(ErrorReason::DeviceNotFound, "Device", device_id.to_string());
        let device = self
            .storage
            .get_device(device_id)
            .await
            .map_err(storage_failure)?;
        match &device {
            Some(d) if caller.profile == Some(d.profile_id) => {
                sid_auth::receiver::allow_owner(request)?;
            }
            _ => {
                match sid_auth::receiver::authorize_object(request, &format!("device:{device_id}"))
                    .await
                {
                    Ok(()) => {}
                    Err(status) if status.code() == tonic::Code::PermissionDenied => {
                        return Err(unknown());
                    }
                    Err(status) => return Err(status),
                }
            }
        }
        let device = device.ok_or_else(unknown)?;
        if change && !caller.interactive {
            return Err(denied());
        }
        Ok(device)
    }
}

/// ATTESTATION_NOT_FOUND for `device_id`.
fn no_attestation(device_id: DeviceId) -> Status {
    not_found(
        ErrorReason::AttestationNotFound,
        "DeviceAttestation",
        device_id.to_string(),
    )
}

#[allow(clippy::result_large_err)]
fn parse_id<T: std::str::FromStr>(s: &str, field: &'static str) -> Result<T, Status> {
    s.parse()
        .map_err(|_| invalid_field(field, "not an identifier of its kind"))
}

fn proto_format(v: i32) -> DeviceAttestationFormat {
    match AttestationFormat::try_from(v) {
        Ok(AttestationFormat::Packed) => DeviceAttestationFormat::Packed,
        Ok(AttestationFormat::Tpm) => DeviceAttestationFormat::Tpm,
        Ok(AttestationFormat::AndroidKey) => DeviceAttestationFormat::AndroidKey,
        Ok(AttestationFormat::Apple) => DeviceAttestationFormat::Apple,
        Ok(AttestationFormat::FidoU2f) => DeviceAttestationFormat::FidoU2f,
        _ => DeviceAttestationFormat::None,
    }
}

fn proto_key_storage(v: i32) -> KeyStorageType {
    match KeyStorageType2::try_from(v) {
        Ok(KeyStorageType2::Tpm) => KeyStorageType::Tpm,
        Ok(KeyStorageType2::SecureEnclave) => KeyStorageType::SecureEnclave,
        Ok(KeyStorageType2::Strongbox) => KeyStorageType::StrongBox,
        Ok(KeyStorageType2::Tee) => KeyStorageType::Tee,
        _ => KeyStorageType::Software,
    }
}

// Map proto enum name (generated as KeyStorageType but we alias to avoid conflict with domain)
use sid_proto::sid::v1::attestation::KeyStorageType as KeyStorageType2;

fn domain_to_proto(att: &DeviceAttestation) -> super::handler::DeviceAttestationProto {
    use prost_types::Timestamp;

    fn to_ts(dt: chrono::DateTime<chrono::Utc>) -> Option<Timestamp> {
        Some(Timestamp {
            seconds: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos() as i32,
        })
    }

    DeviceAttestationProto {
        id: att.id.0.to_string(),
        device_id: att.device_id.to_string(),
        profile_id: att.profile_id.to_string(),
        format: match att.format {
            DeviceAttestationFormat::None => AttestationFormat::None as i32,
            DeviceAttestationFormat::Packed => AttestationFormat::Packed as i32,
            DeviceAttestationFormat::Tpm => AttestationFormat::Tpm as i32,
            DeviceAttestationFormat::AndroidKey => AttestationFormat::AndroidKey as i32,
            DeviceAttestationFormat::Apple => AttestationFormat::Apple as i32,
            DeviceAttestationFormat::FidoU2f => AttestationFormat::FidoU2f as i32,
        },
        key_storage: match att.key_storage {
            KeyStorageType::Software => KeyStorageType2::Software as i32,
            KeyStorageType::Tpm => KeyStorageType2::Tpm as i32,
            KeyStorageType::SecureEnclave => KeyStorageType2::SecureEnclave as i32,
            KeyStorageType::StrongBox => KeyStorageType2::Strongbox as i32,
            KeyStorageType::Tee => KeyStorageType2::Tee as i32,
        },
        status: match att.status {
            sid_core::models::AttestationStatus::Pending => AttestationStatus::Pending as i32,
            sid_core::models::AttestationStatus::Verified => AttestationStatus::Verified as i32,
            sid_core::models::AttestationStatus::Unverified => AttestationStatus::Unverified as i32,
            sid_core::models::AttestationStatus::Rejected => AttestationStatus::Rejected as i32,
            sid_core::models::AttestationStatus::Revoked => AttestationStatus::Revoked as i32,
        },
        device_public_key: att.device_public_key.clone(),
        attestation_object: att.attestation_object.clone(),
        attestation_certificate: att.attestation_certificate.clone(),
        aaguid: att.aaguid.clone(),
        credential_id: att.credential_id.clone(),
        created_at: to_ts(att.created_at),
        updated_at: to_ts(att.updated_at),
        revoked_at: att.revoked_at.and_then(to_ts),
    }
}

// Use proto-generated DeviceAttestation message name
use sid_proto::sid::v1::attestation::DeviceAttestation as DeviceAttestationProto;

#[tonic::async_trait]
impl AttestationService for AttestationServiceImpl {
    #[instrument(skip_all, fields(method = "register_device_key"))]
    async fn register_device_key(
        &self,
        mut request: Request<RegisterDeviceKeyRequest>,
    ) -> Result<Response<DeviceAttestationProto>, Status> {
        let caller = self.caller(&request).await?;
        let device_id = parse_id::<DeviceId>(&request.get_ref().device_id, "device_id")?;
        if request.get_ref().device_public_key.is_empty() {
            return Err(missing_field("device_public_key"));
        }
        let device = self
            .authorized_device(&mut request, &caller, device_id, true)
            .await?;
        let req = request.into_inner();

        let mut att = DeviceAttestation::new_ce(
            device_id,
            device.profile_id,
            proto_format(req.format),
            proto_key_storage(req.key_storage),
            req.device_public_key,
        );
        att.attestation_object = req.attestation_object;
        att.attestation_certificate = req.attestation_certificate;
        att.aaguid = req.aaguid;
        att.credential_id = req.credential_id;

        // The store refuses a device that already has a live attestation; a
        // revoked one is replaced by this new enrollment.
        self.storage
            .create_device_attestation(&att, caller.audit("register_device_key", &req.device_id))
            .await
            .map_err(|e| match e {
                sid_core::Error::Conflict(_) => ApiError::new(
                    ErrorReason::AttestationAlreadyExists,
                    "the device already has a key attestation; rotate its key instead",
                )
                .with_resource("DeviceAttestation", device_id.to_string())
                .into(),
                other => storage_failure(other),
            })?;

        // The attestation is stored unverified (the chain is not checked here),
        // so the device is not marked hardware-attested.

        info!(device_id = %req.device_id, "Device key registered");
        Ok(Response::new(domain_to_proto(&att)))
    }

    #[instrument(skip_all, fields(method = "get_device_attestation"))]
    async fn get_device_attestation(
        &self,
        mut request: Request<GetDeviceAttestationRequest>,
    ) -> Result<Response<DeviceAttestationProto>, Status> {
        let caller = self.caller(&request).await?;
        let device_id = parse_id::<DeviceId>(&request.get_ref().device_id, "device_id")?;
        self.authorized_device(&mut request, &caller, device_id, false)
            .await?;

        let att = self
            .storage
            .get_device_attestation_by_device_id(device_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| no_attestation(device_id))?;

        Ok(Response::new(domain_to_proto(&att)))
    }

    #[instrument(skip_all, fields(method = "rotate_device_key"))]
    async fn rotate_device_key(
        &self,
        mut request: Request<RotateDeviceKeyRequest>,
    ) -> Result<Response<DeviceAttestationProto>, Status> {
        let caller = self.caller(&request).await?;
        let device_id = parse_id::<DeviceId>(&request.get_ref().device_id, "device_id")?;
        if request.get_ref().new_device_public_key.is_empty() {
            return Err(missing_field("new_device_public_key"));
        }
        self.authorized_device(&mut request, &caller, device_id, true)
            .await?;
        let req = request.into_inner();

        // Applies only to a live attestation: a key revoked meanwhile is
        // never replaced and revived.
        let rotated = self
            .storage
            .rotate_device_attestation(
                device_id,
                &req.new_device_public_key,
                req.new_attestation_object.as_deref(),
                req.new_attestation_certificate.as_deref(),
                caller.audit("rotate_device_key", &req.device_id),
            )
            .await
            .map_err(storage_failure)?;
        if !rotated {
            return Err(no_attestation(device_id));
        }
        let att = self
            .storage
            .get_device_attestation_by_device_id(device_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| no_attestation(device_id))?;

        info!(device_id = %req.device_id, "Device key rotated");
        Ok(Response::new(domain_to_proto(&att)))
    }

    #[instrument(skip_all, fields(method = "revoke_device_key"))]
    async fn revoke_device_key(
        &self,
        mut request: Request<RevokeDeviceKeyRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        let device_id = parse_id::<DeviceId>(&request.get_ref().device_id, "device_id")?;
        self.authorized_device(&mut request, &caller, device_id, true)
            .await?;

        // The store also stops counting the device as hardware-attested, in
        // the same transaction.
        let revoked = self
            .storage
            .revoke_device_attestation(
                device_id,
                caller.audit("revoke_device_key", &device_id.to_string()),
            )
            .await
            .map_err(storage_failure)?;
        if !revoked {
            return Err(no_attestation(device_id));
        }

        info!(device_id = %device_id, "Device key revoked");
        Ok(Response::new(()))
    }

    #[instrument(skip_all, fields(method = "list_device_attestations"))]
    async fn list_device_attestations(
        &self,
        mut request: Request<ListDeviceAttestationsRequest>,
    ) -> Result<Response<ListDeviceAttestationsResponse>, Status> {
        let caller = self.caller(&request).await?;
        let profile_id = parse_id::<ProfileId>(&request.get_ref().profile_id, "profile_id")?;
        if caller.profile == Some(profile_id) {
            sid_auth::receiver::allow_owner(&mut request)?;
        } else {
            sid_auth::receiver::authorize_object(&mut request, &format!("profile:{profile_id}"))
                .await?;
        }

        let attestations = self
            .storage
            .list_device_attestations_by_profile(profile_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(ListDeviceAttestationsResponse {
            attestations: attestations.iter().map(domain_to_proto).collect(),
        }))
    }
}

#[cfg(test)]
mod tests;
