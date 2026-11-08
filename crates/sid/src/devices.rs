// SPDX-License-Identifier: AGPL-3.0-only
//! Device keys: registering a device's key, reading, rotating and revoking
//! it, and listing a Profile's device keys, the same operations for the
//! attestation service and an embedding application. Who may act is decided
//! here, once: a device's owner acts on its keys, any other caller only on
//! what its [`DeviceAccess`] allows, and only the owner's own sign-in changes
//! a key. A device the caller may not reach is not found, as an unknown one.
//!
//! CE stores attestation data and device public keys without verifying
//! attestation chains: a stored attestation is unverified evidence and never
//! marks the device hardware-attested.

use std::sync::Arc;

use sid_authn::caller::{Caller, CallerError, TokenKind};
use sid_core::models::{
    AuditEntry, Device, DeviceAttestation, DeviceAttestationFormat, DeviceId, KeyStorageType,
    MutationContext, ProfileId,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::attestation::{
    self as v1, GetDeviceAttestationRequest, ListDeviceAttestationsRequest,
    ListDeviceAttestationsResponse, RegisterDeviceKeyRequest, RevokeDeviceKeyRequest,
    RotateDeviceKeyRequest,
};
use tracing::info;

/// Why a device key operation was refused or failed. `E` is the refusal of
/// the caller's [`DeviceAccess`], passed through unchanged.
#[derive(Debug, thiserror::Error)]
pub enum DeviceKeyError<E> {
    /// The caller's access refused the call or could not decide it.
    #[error("access refused")]
    Access(E),
    /// Only the owner's own sign-in, not an impersonation, changes a key.
    #[error("the caller may not perform this operation")]
    Denied,
    /// No device the caller may reach has this id.
    #[error("no device {0}")]
    DeviceNotFound(DeviceId),
    /// The device has no live key attestation.
    #[error("no attestation for device {0}")]
    NoAttestation(DeviceId),
    /// The device already has a live key attestation; its key is rotated.
    #[error("device {0} already has a key attestation")]
    AlreadyEnrolled(DeviceId),
    /// A required field is absent.
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A field holds a value the operation does not take.
    #[error("{0}: not an identifier of its kind")]
    InvalidId(&'static str),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] sid_core::Error),
}

/// Who calls: the Profile whose sign-in the token stands for, if any, what
/// the audit names a caller without one, and whether it is that Profile's
/// own sign-in rather than an impersonation.
#[derive(Debug, Clone)]
pub struct KeyCaller {
    pub profile: Option<ProfileId>,
    pub subject: String,
    pub interactive: bool,
}

impl KeyCaller {
    fn audit(&self, action: &str, resource: &str) -> MutationContext {
        let actor = self
            .profile
            .map(|p| p.to_string())
            .unwrap_or_else(|| self.subject.clone());
        AuditEntry::user(actor, action, resource).into()
    }
}

impl From<&Caller> for KeyCaller {
    fn from(caller: &Caller) -> Self {
        Self {
            profile: Some(caller.profile_id),
            subject: caller.profile_id.to_string(),
            interactive: caller.kind() == TokenKind::Interactive,
        }
    }
}

/// What a caller may do beyond its own devices, as its authority decides.
#[async_trait::async_trait]
pub trait DeviceAccess: Send {
    type Error: Send;
    /// The call acts on the caller's own object.
    async fn owner(&mut self) -> Result<(), Self::Error>;
    /// Whether the caller may act on `object` it does not own; a denial is
    /// `false`, so the object's existence is not disclosed.
    async fn may(&mut self, object: &str) -> Result<bool, Self::Error>;
    /// The caller may act on `object` it does not own, or the call is
    /// refused with the authority's own answer.
    async fn require(&mut self, object: &str) -> Result<(), Self::Error>;
}

/// An embedding application's caller, authenticated in process: the
/// installation's administrator may act on any device.
pub struct LocalAccess<'a>(pub &'a Caller);

#[async_trait::async_trait]
impl DeviceAccess for LocalAccess<'_> {
    type Error = CallerError;

    async fn owner(&mut self) -> Result<(), CallerError> {
        Ok(())
    }

    async fn may(&mut self, _object: &str) -> Result<bool, CallerError> {
        Ok(self.0.is_admin())
    }

    async fn require(&mut self, _object: &str) -> Result<(), CallerError> {
        self.0.require_admin()
    }
}

fn parse_id<T: std::str::FromStr, E>(
    value: &str,
    field: &'static str,
) -> Result<T, DeviceKeyError<E>> {
    value.parse().map_err(|_| DeviceKeyError::InvalidId(field))
}

/// The device keys of one installation.
pub struct DeviceKeys {
    storage: Arc<dyn StorageBackend>,
}

impl DeviceKeys {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    /// Device `device_id` for its owner, or for a caller `access` allows the
    /// call's action on that device; a change also requires the caller's
    /// own sign-in.
    async fn authorized_device<A: DeviceAccess>(
        &self,
        access: &mut A,
        caller: &KeyCaller,
        device_id: DeviceId,
        change: bool,
    ) -> Result<Device, DeviceKeyError<A::Error>> {
        let device = self.storage.get_device(device_id).await?;
        match &device {
            Some(d) if caller.profile == Some(d.profile_id) => {
                access.owner().await.map_err(DeviceKeyError::Access)?;
            }
            _ => {
                if !access
                    .may(&format!("device:{device_id}"))
                    .await
                    .map_err(DeviceKeyError::Access)?
                {
                    return Err(DeviceKeyError::DeviceNotFound(device_id));
                }
            }
        }
        let device = device.ok_or(DeviceKeyError::DeviceNotFound(device_id))?;
        if change && !caller.interactive {
            return Err(DeviceKeyError::Denied);
        }
        Ok(device)
    }

    /// Register the device's key. The store refuses a device that already
    /// has a live attestation; a revoked one is replaced by this enrollment.
    pub async fn register_key<A: DeviceAccess>(
        &self,
        access: &mut A,
        caller: &KeyCaller,
        req: RegisterDeviceKeyRequest,
    ) -> Result<v1::DeviceAttestation, DeviceKeyError<A::Error>> {
        let device_id = parse_id::<DeviceId, _>(&req.device_id, "device_id")?;
        if req.device_public_key.is_empty() {
            return Err(DeviceKeyError::MissingField("device_public_key"));
        }
        let device = self
            .authorized_device(access, caller, device_id, true)
            .await?;

        let mut att = DeviceAttestation::new_ce(
            device_id,
            device.profile_id,
            format_from_proto(req.format),
            key_storage_from_proto(req.key_storage),
            req.device_public_key,
        );
        att.attestation_object = req.attestation_object;
        att.attestation_certificate = req.attestation_certificate;
        att.aaguid = req.aaguid;
        att.credential_id = req.credential_id;

        self.storage
            .create_device_attestation(&att, caller.audit("register_device_key", &req.device_id))
            .await
            .map_err(|e| match e {
                sid_core::Error::Conflict(_) => DeviceKeyError::AlreadyEnrolled(device_id),
                other => other.into(),
            })?;
        // The attestation is stored unverified (the chain is not checked
        // here), so the device is not marked hardware-attested.
        info!(device_id = %req.device_id, "Device key registered");
        Ok(attestation_to_proto(&att))
    }

    /// The device's live key attestation.
    pub async fn get_attestation<A: DeviceAccess>(
        &self,
        access: &mut A,
        caller: &KeyCaller,
        req: GetDeviceAttestationRequest,
    ) -> Result<v1::DeviceAttestation, DeviceKeyError<A::Error>> {
        let device_id = parse_id::<DeviceId, _>(&req.device_id, "device_id")?;
        self.authorized_device(access, caller, device_id, false)
            .await?;
        let att = self
            .storage
            .get_device_attestation_by_device_id(device_id)
            .await?
            .ok_or(DeviceKeyError::NoAttestation(device_id))?;
        Ok(attestation_to_proto(&att))
    }

    /// Replace the device's key. Applies only to a live attestation: a key
    /// revoked meanwhile is never replaced and revived.
    pub async fn rotate_key<A: DeviceAccess>(
        &self,
        access: &mut A,
        caller: &KeyCaller,
        req: RotateDeviceKeyRequest,
    ) -> Result<v1::DeviceAttestation, DeviceKeyError<A::Error>> {
        let device_id = parse_id::<DeviceId, _>(&req.device_id, "device_id")?;
        if req.new_device_public_key.is_empty() {
            return Err(DeviceKeyError::MissingField("new_device_public_key"));
        }
        self.authorized_device(access, caller, device_id, true)
            .await?;
        let rotated = self
            .storage
            .rotate_device_attestation(
                device_id,
                &req.new_device_public_key,
                req.new_attestation_object.as_deref(),
                req.new_attestation_certificate.as_deref(),
                caller.audit("rotate_device_key", &req.device_id),
            )
            .await?;
        if !rotated {
            return Err(DeviceKeyError::NoAttestation(device_id));
        }
        let att = self
            .storage
            .get_device_attestation_by_device_id(device_id)
            .await?
            .ok_or(DeviceKeyError::NoAttestation(device_id))?;
        info!(device_id = %req.device_id, "Device key rotated");
        Ok(attestation_to_proto(&att))
    }

    /// Revoke the device's key. The store also stops counting the device as
    /// hardware-attested, in the same transaction.
    pub async fn revoke_key<A: DeviceAccess>(
        &self,
        access: &mut A,
        caller: &KeyCaller,
        req: RevokeDeviceKeyRequest,
    ) -> Result<(), DeviceKeyError<A::Error>> {
        let device_id = parse_id::<DeviceId, _>(&req.device_id, "device_id")?;
        self.authorized_device(access, caller, device_id, true)
            .await?;
        let revoked = self
            .storage
            .revoke_device_attestation(
                device_id,
                caller.audit("revoke_device_key", &device_id.to_string()),
            )
            .await?;
        if !revoked {
            return Err(DeviceKeyError::NoAttestation(device_id));
        }
        info!(device_id = %device_id, "Device key revoked");
        Ok(())
    }

    /// A Profile's device key attestations, for the Profile itself or a
    /// caller `access` allows to read it.
    pub async fn list_attestations<A: DeviceAccess>(
        &self,
        access: &mut A,
        caller: &KeyCaller,
        req: ListDeviceAttestationsRequest,
    ) -> Result<ListDeviceAttestationsResponse, DeviceKeyError<A::Error>> {
        let profile_id = parse_id::<ProfileId, _>(&req.profile_id, "profile_id")?;
        if caller.profile == Some(profile_id) {
            access.owner().await
        } else {
            access.require(&format!("profile:{profile_id}")).await
        }
        .map_err(DeviceKeyError::Access)?;
        let attestations = self
            .storage
            .list_device_attestations_by_profile(profile_id)
            .await?;
        Ok(ListDeviceAttestationsResponse {
            attestations: attestations.iter().map(attestation_to_proto).collect(),
        })
    }
}

fn format_from_proto(v: i32) -> DeviceAttestationFormat {
    use v1::AttestationFormat as F;
    match F::try_from(v) {
        Ok(F::Packed) => DeviceAttestationFormat::Packed,
        Ok(F::Tpm) => DeviceAttestationFormat::Tpm,
        Ok(F::AndroidKey) => DeviceAttestationFormat::AndroidKey,
        Ok(F::Apple) => DeviceAttestationFormat::Apple,
        Ok(F::FidoU2f) => DeviceAttestationFormat::FidoU2f,
        _ => DeviceAttestationFormat::None,
    }
}

fn key_storage_from_proto(v: i32) -> KeyStorageType {
    use v1::KeyStorageType as K;
    match K::try_from(v) {
        Ok(K::Tpm) => KeyStorageType::Tpm,
        Ok(K::SecureEnclave) => KeyStorageType::SecureEnclave,
        Ok(K::Strongbox) => KeyStorageType::StrongBox,
        Ok(K::Tee) => KeyStorageType::Tee,
        _ => KeyStorageType::Software,
    }
}

fn attestation_to_proto(att: &DeviceAttestation) -> v1::DeviceAttestation {
    use sid_core::models::AttestationStatus as S;
    use v1::{AttestationFormat as F, AttestationStatus as P, KeyStorageType as K};
    fn to_ts(dt: chrono::DateTime<chrono::Utc>) -> Option<prost_types::Timestamp> {
        Some(prost_types::Timestamp {
            seconds: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos() as i32,
        })
    }
    v1::DeviceAttestation {
        id: att.id.0.to_string(),
        device_id: att.device_id.to_string(),
        profile_id: att.profile_id.to_string(),
        format: match att.format {
            DeviceAttestationFormat::None => F::None,
            DeviceAttestationFormat::Packed => F::Packed,
            DeviceAttestationFormat::Tpm => F::Tpm,
            DeviceAttestationFormat::AndroidKey => F::AndroidKey,
            DeviceAttestationFormat::Apple => F::Apple,
            DeviceAttestationFormat::FidoU2f => F::FidoU2f,
        } as i32,
        key_storage: match att.key_storage {
            KeyStorageType::Software => K::Software,
            KeyStorageType::Tpm => K::Tpm,
            KeyStorageType::SecureEnclave => K::SecureEnclave,
            KeyStorageType::StrongBox => K::Strongbox,
            KeyStorageType::Tee => K::Tee,
        } as i32,
        status: match att.status {
            S::Pending => P::Pending,
            S::Verified => P::Verified,
            S::Unverified => P::Unverified,
            S::Rejected => P::Rejected,
            S::Revoked => P::Revoked,
        } as i32,
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

#[cfg(test)]
mod tests;
