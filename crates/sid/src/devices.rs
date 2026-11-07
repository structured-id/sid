// SPDX-License-Identifier: AGPL-3.0-only
//! Device keys: one ceremony enrolls a device's key (a new device or an
//! existing one without a live key) or rotates an enrolled device's key, and
//! the key is read, revoked and listed, the same operations for the
//! attestation service and an embedding application.
//!
//! A ceremony starts under the owner's own sufficient sign-in (the
//! credential-enrollment rules, at a device key's own assurance, which
//! possession alone does not raise) and returns a single-use challenge bound
//! to its purpose, owner, session, issuer and device. Its finish proves
//! possession of the proposed key with a device-key proof over that
//! challenge (a rotation also with the current key's approval of the exact
//! replacement), rechecks the owner's authority and commits the device, its
//! binding, the consumed ceremony, the audit and the outcome as one
//! transaction. A retry of a committed finish answers with its recorded
//! outcome; a ceremony expired, finished or overtaken by a revocation or a
//! removal completes nothing.
//!
//! Who may act on an existing key is decided here, once: a device's owner,
//! any other caller only on what its [`DeviceAccess`] allows; only the
//! owner's own sign-in changes a key. A device the caller may not reach is
//! not found, as an unknown one. CE does not verify attestation chains: a
//! stored attestation is unverified evidence and never marks a device
//! hardware-attested.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use prost::Message;
use sid_authn::caller::{Caller, CallerError, TokenKind};
use sid_authn::challenge_store::{ChallengeStore, ChallengeStoreError};
use sid_authn::credential_enrollment::{EnrollmentError, EnrollmentRefusal, authorize_binding};
use sid_authn::device_key_proof::{
    Ceremony, DeviceKeyProofError, ProofPurpose, stored_key_thumbprint, verify_current_key,
    verify_proposed_key,
};
use sid_authn::operation::{CommandError, Effect, KeyedCommand, OperationError};
use sid_core::models::session::AuthLevel;
use sid_core::models::{
    AttestationStatus, AuditEntry, Device, DeviceAttestation, DeviceAttestationFormat,
    DeviceAttestationId, DeviceEnrollment, DeviceId, DeviceType, EnrollmentTarget, KeyStorageType,
    MutationContext, OperationContext, ProfileId, SessionId,
};
use sid_ids::DeviceEnrollmentId;
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::attestation::attestation_service as keyed;
use sid_proto::sid::v1::attestation::{
    self as v1, DeviceEnrollmentChallenge, DeviceEnrollmentPurpose, FinishDeviceEnrollmentRequest,
    GetDeviceAttestationRequest, ListDeviceAttestationsRequest, ListDeviceAttestationsResponse,
    RevokeDeviceKeyRequest, RotateDeviceKeyRequest, StartDeviceEnrollmentRequest,
};
use tracing::info;

use crate::wire::{FieldError, to_timestamp, wire_id};

/// How long a device-key ceremony waits for its finish.
const CEREMONY_TTL: Duration = Duration::from_secs(300);

/// Why a device key operation was refused or failed. `E` is the refusal of
/// the caller's [`DeviceAccess`], passed through unchanged.
#[derive(Debug, thiserror::Error)]
pub enum DeviceKeyError<E> {
    /// The caller's access refused the call or could not decide it.
    #[error("access refused")]
    Access(E),
    /// Only the owner's own sign-in, not an impersonation, a client's token
    /// or an administrator, starts, finishes or changes a key.
    #[error("the caller may not perform this operation")]
    Denied,
    /// The owner's session may not bind a key now.
    #[error("key binding refused: {0:?}")]
    Enrollment(EnrollmentRefusal),
    /// No device the caller may reach has this id.
    #[error("no device {0}")]
    DeviceNotFound(DeviceId),
    /// The device has no live key attestation.
    #[error("no attestation for device {0}")]
    NoAttestation(DeviceId),
    /// The device already has a live key attestation; its key is rotated.
    #[error("device {0} already has a key attestation")]
    AlreadyEnrolled(DeviceId),
    /// The ceremony expired, was finished, or is not this caller's.
    #[error("the device-key ceremony is not pending")]
    CeremonyExpired,
    /// The device's key changed since the ceremony started (revoked,
    /// rotated or enrolled meanwhile): it completes nothing.
    #[error("the device's key changed since the ceremony started")]
    Changed,
    /// A proof does not prove what the ceremony asks.
    #[error(transparent)]
    Proof(#[from] DeviceKeyProofError),
    /// A required field is absent.
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// A keyed finish needs the caller's operation context.
    #[error("the operation context is required")]
    ContextRequired,
    /// The keyed command conflicts, is refused its period or its outcome is
    /// unknown.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The store failed.
    #[error("store: {0}")]
    Store(sid_core::Error),
}

impl<E> From<FieldError> for DeviceKeyError<E> {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

impl<E> From<sid_core::Error> for DeviceKeyError<E> {
    fn from(e: sid_core::Error) -> Self {
        Self::Store(e)
    }
}

impl<E> From<ChallengeStoreError> for DeviceKeyError<E> {
    fn from(e: ChallengeStoreError) -> Self {
        Self::Store(e.into())
    }
}

impl<E> From<EnrollmentError> for DeviceKeyError<E> {
    fn from(e: EnrollmentError) -> Self {
        match e {
            EnrollmentError::Refused(refusal) => Self::Enrollment(refusal),
            EnrollmentError::Caller(_) | EnrollmentError::SessionInvalid => Self::Denied,
            EnrollmentError::Storage(e) => Self::Store(e),
        }
    }
}

impl<E> From<CommandError<DeviceKeyError<E>>> for DeviceKeyError<E> {
    fn from(e: CommandError<DeviceKeyError<E>>) -> Self {
        e.refusal()
    }
}

/// Who calls: the Profile whose sign-in the token stands for and that
/// session, if any, what the audit names a caller without one, and whether
/// it is that Profile's own sign-in rather than an impersonation.
#[derive(Debug, Clone)]
pub struct KeyCaller {
    pub profile: Option<ProfileId>,
    pub session: Option<SessionId>,
    pub subject: String,
    pub interactive: bool,
}

impl KeyCaller {
    fn audit(&self, action: &str, resource: &str) -> MutationContext {
        AuditEntry::user(self.actor(), action, resource).into()
    }

    fn actor(&self) -> String {
        self.profile
            .map(|p| p.to_string())
            .unwrap_or_else(|| self.subject.clone())
    }

    /// The owner's own interactive sign-in that may start or finish a
    /// ceremony.
    fn own_sign_in<E>(&self) -> Result<(ProfileId, SessionId), DeviceKeyError<E>> {
        match (self.profile, self.session, self.interactive) {
            (Some(profile), Some(session), true) => Ok((profile, session)),
            _ => Err(DeviceKeyError::Denied),
        }
    }
}

impl From<&Caller> for KeyCaller {
    fn from(caller: &Caller) -> Self {
        Self {
            profile: Some(caller.profile_id),
            session: SessionId::parse(&caller.session_id).ok(),
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
/// installation's administrator may read, revoke and list any device's key.
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

/// What a ceremony does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Purpose {
    Enroll,
    Rotate,
}

/// The device a ceremony binds a key to, as the ceremony found it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum PendingTarget {
    /// A device allocated by the ceremony.
    New {
        device_type: DeviceType,
        os_info: Option<String>,
        display_name: Option<String>,
    },
    /// The owner's device without a live key, with the revoked binding it
    /// had.
    Existing {
        revoked: Option<DeviceAttestationId>,
    },
    /// The owner's enrolled device and its live binding.
    Rotation {
        current: DeviceAttestationId,
        current_key: String,
    },
}

/// A started ceremony, kept sealed until its finish.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PendingEnrollment {
    purpose: Purpose,
    profile: ProfileId,
    session: SessionId,
    issuer: String,
    device: DeviceId,
    challenge: Vec<u8>,
    target: PendingTarget,
}

/// The device keys of one installation.
pub struct DeviceKeys {
    storage: Arc<dyn StorageBackend>,
    ceremonies: ChallengeStore<PendingEnrollment>,
}

impl DeviceKeys {
    /// The device keys over `storage`, their pending ceremonies sealed under
    /// `keys`.
    pub fn new(storage: Arc<dyn StorageBackend>, keys: Arc<dyn sid_keys::KeyManager>) -> Self {
        let ceremonies: Arc<dyn sid_plugin::CeremonyStateStore> = storage.clone();
        Self {
            ceremonies: ChallengeStore::new(ceremonies, keys, "device-enrollment", CEREMONY_TTL),
            storage,
        }
    }

    /// The owner's session may bind a device key now: a device key is used
    /// at basic assurance, which possession alone does not raise. At basic
    /// assurance whether a passkey counts as a second factor changes
    /// nothing, as the account's established assurance is never below it.
    async fn may_bind<E>(
        &self,
        profile: ProfileId,
        session: SessionId,
    ) -> Result<(), DeviceKeyError<E>> {
        authorize_binding(
            self.storage.as_ref(),
            profile,
            session,
            AuthLevel::Basic,
            false,
        )
        .await?;
        Ok(())
    }

    /// The owner's device `device_id`; another Profile's device is not
    /// found, as an unknown one.
    async fn own_device<A: DeviceAccess>(
        &self,
        access: &mut A,
        owner: ProfileId,
        device_id: DeviceId,
    ) -> Result<Device, DeviceKeyError<A::Error>> {
        let device = self
            .storage
            .get_device(device_id)
            .await?
            .filter(|d| d.profile_id == owner)
            .ok_or(DeviceKeyError::DeviceNotFound(device_id))?;
        access.owner().await.map_err(DeviceKeyError::Access)?;
        Ok(device)
    }

    /// The key binding of `device`, live or revoked.
    async fn binding<E>(
        &self,
        owner: ProfileId,
        device: DeviceId,
    ) -> Result<Option<DeviceAttestation>, DeviceKeyError<E>> {
        Ok(self
            .storage
            .list_device_attestations_by_profile(owner)
            .await?
            .into_iter()
            .find(|a| a.device_id == device))
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

    /// Start a device-key ceremony at `issuer`: the enrollment of a new
    /// device (its id allocated here) or of the owner's device without a live
    /// key, or the rotation of an enrolled device's key. Only the owner's own
    /// sufficient sign-in starts one; nothing is enrolled, trusted or
    /// authorized until it finishes.
    pub async fn start_enrollment<A: DeviceAccess>(
        &self,
        access: &mut A,
        caller: &KeyCaller,
        issuer: &str,
        req: StartDeviceEnrollmentRequest,
    ) -> Result<DeviceEnrollmentChallenge, DeviceKeyError<A::Error>> {
        let purpose = match DeviceEnrollmentPurpose::try_from(req.purpose) {
            Ok(DeviceEnrollmentPurpose::Enroll) => Purpose::Enroll,
            Ok(DeviceEnrollmentPurpose::Rotate) => Purpose::Rotate,
            _ => {
                return Err(DeviceKeyError::InvalidField {
                    field: "purpose",
                    reason: "an enrollment or a rotation".into(),
                });
            }
        };
        let named = req
            .device_id
            .as_ref()
            .map(|id| wire_id(Some(id), "device_id"))
            .transpose()?;
        let (profile, session) = caller.own_sign_in()?;
        self.may_bind(profile, session).await?;

        let (device, target) = match (purpose, named) {
            (Purpose::Enroll, None) => {
                access.owner().await.map_err(DeviceKeyError::Access)?;
                (
                    DeviceId::generate(),
                    PendingTarget::New {
                        device_type: device_type(req.device_type),
                        os_info: req.os_info,
                        display_name: req.display_name,
                    },
                )
            }
            (Purpose::Enroll, Some(device)) => {
                self.own_device(access, profile, device).await?;
                let revoked = match self.binding(profile, device).await? {
                    None => None,
                    Some(b) if b.status == AttestationStatus::Revoked => Some(b.id),
                    Some(_) => return Err(DeviceKeyError::AlreadyEnrolled(device)),
                };
                (device, PendingTarget::Existing { revoked })
            }
            (Purpose::Rotate, Some(device)) => {
                self.own_device(access, profile, device).await?;
                let current = self
                    .binding(profile, device)
                    .await?
                    .filter(|b| b.status != AttestationStatus::Revoked)
                    .ok_or(DeviceKeyError::NoAttestation(device))?;
                (
                    device,
                    PendingTarget::Rotation {
                        current: current.id,
                        current_key: current.public_jwk,
                    },
                )
            }
            (Purpose::Rotate, None) => return Err(DeviceKeyError::MissingField("device_id")),
        };

        let id = DeviceEnrollmentId::generate();
        let challenge: [u8; 32] = rand::random();
        let expires_at = Utc::now()
            + chrono::Duration::from_std(CEREMONY_TTL).expect("the ceremony lifetime fits");
        self.ceremonies
            .insert(
                &id.to_string(),
                &PendingEnrollment {
                    purpose,
                    profile,
                    session,
                    issuer: issuer.to_owned(),
                    device,
                    challenge: challenge.to_vec(),
                    target,
                },
            )
            .await?;
        Ok(DeviceEnrollmentChallenge {
            enrollment_id: Some(id.into()),
            device_id: Some(device.into()),
            challenge: challenge.to_vec(),
            expires_at: Some(to_timestamp(expires_at)),
        })
    }

    /// Finish an enrollment ceremony: the proposed key proves possession,
    /// the owner's authority is rechecked, and the device, its binding, the
    /// consumed ceremony, the audit and the outcome commit together. A retry
    /// of the committed finish answers with its recorded outcome.
    pub async fn finish_enrollment<A: DeviceAccess>(
        &self,
        access: &mut A,
        caller: &KeyCaller,
        operation: Option<OperationContext>,
        req: FinishDeviceEnrollmentRequest,
    ) -> Result<v1::DeviceAttestation, DeviceKeyError<A::Error>> {
        let id: DeviceEnrollmentId = wire_id(req.enrollment_id.as_ref(), "enrollment_id")?;
        if req.proof.is_empty() {
            return Err(DeviceKeyError::MissingField("proof"));
        }
        let (profile, session) = caller.own_sign_in()?;
        let command = KeyedCommand::by_profile::<keyed::FinishDeviceEnrollment>(
            profile,
            operation.ok_or(DeviceKeyError::ContextRequired)?,
            &req,
        );
        // The owner's authority as it stands, for a retry too: a recorded
        // outcome is answered only to a caller who may bind now.
        self.may_bind(profile, session).await?;
        access.owner().await.map_err(DeviceKeyError::Access)?;
        Ok(command
            .execute(self.storage.as_ref(), || async {
                let (pending, consumption) = self
                    .pending(&id, Purpose::Enroll, profile, session)
                    .await
                    .map_err(Effect::Refused)?;
                let key = verify_proposed_key(&req.proof, ceremony(&pending), ProofPurpose::Enroll)
                    .map_err(|e| Effect::Refused(e.into()))?;
                let target = match pending.target.clone() {
                    PendingTarget::New {
                        device_type,
                        os_info,
                        display_name,
                    } => {
                        let mut device = Device::new(profile, device_type);
                        device.id = pending.device;
                        device.os_info = os_info;
                        device.display_name = display_name;
                        EnrollmentTarget::NewDevice(device)
                    }
                    PendingTarget::Existing { revoked } => EnrollmentTarget::ExistingDevice {
                        device: pending.device,
                        revoked,
                    },
                    PendingTarget::Rotation { .. } => {
                        return Err(Effect::Refused(DeviceKeyError::CeremonyExpired));
                    }
                };
                let mut attestation = DeviceAttestation::new_ce(
                    pending.device,
                    profile,
                    format(req.format),
                    key_storage(req.key_storage),
                    key.public_jwk,
                );
                attestation.attestation_object = req.attestation_object.clone();
                attestation.attestation_certificate = req.attestation_certificate.clone();
                attestation.aaguid = req.aaguid.clone();
                let response = attestation_to_proto(&attestation);
                let ctx = caller
                    .audit("device_key.enroll", &pending.device.to_string())
                    .with_operation(command.completion(response.encode_to_vec()))
                    .consuming(consumption);
                self.commit(
                    &DeviceEnrollment {
                        profile_id: profile,
                        session: Some(session),
                        target,
                        attestation,
                    },
                    ctx,
                )
                .await?;
                info!(device_id = %pending.device, "Device key enrolled");
                Ok(response)
            })
            .await?)
    }

    /// Finish a rotation ceremony: the proposed key proves possession, the
    /// current key approves that exact replacement, the owner's authority is
    /// rechecked, and the old binding is retired and the new one committed
    /// with the consumed ceremony, the audit and the outcome.
    pub async fn rotate_key<A: DeviceAccess>(
        &self,
        access: &mut A,
        caller: &KeyCaller,
        operation: Option<OperationContext>,
        req: RotateDeviceKeyRequest,
    ) -> Result<v1::DeviceAttestation, DeviceKeyError<A::Error>> {
        let id: DeviceEnrollmentId = wire_id(req.enrollment_id.as_ref(), "enrollment_id")?;
        if req.new_key_proof.is_empty() {
            return Err(DeviceKeyError::MissingField("new_key_proof"));
        }
        if req.current_key_proof.is_empty() {
            return Err(DeviceKeyError::MissingField("current_key_proof"));
        }
        let (profile, session) = caller.own_sign_in()?;
        let command = KeyedCommand::by_profile::<keyed::RotateDeviceKey>(
            profile,
            operation.ok_or(DeviceKeyError::ContextRequired)?,
            &req,
        );
        self.may_bind(profile, session).await?;
        access.owner().await.map_err(DeviceKeyError::Access)?;
        Ok(command
            .execute(self.storage.as_ref(), || async {
                let (pending, consumption) = self
                    .pending(&id, Purpose::Rotate, profile, session)
                    .await
                    .map_err(Effect::Refused)?;
                let PendingTarget::Rotation {
                    current,
                    current_key,
                } = pending.target.clone()
                else {
                    return Err(Effect::Refused(DeviceKeyError::CeremonyExpired));
                };
                let proposed = verify_proposed_key(
                    &req.new_key_proof,
                    ceremony(&pending),
                    ProofPurpose::RotateNew,
                )
                .map_err(|e| Effect::Refused(e.into()))?;
                let current_thumbprint =
                    stored_key_thumbprint(&current_key).map_err(|e| Effect::Refused(e.into()))?;
                verify_current_key(
                    &req.current_key_proof,
                    ceremony(&pending),
                    &current_thumbprint,
                    &proposed.thumbprint,
                )
                .map_err(|e| Effect::Refused(e.into()))?;
                let mut attestation = DeviceAttestation::new_ce(
                    pending.device,
                    profile,
                    format(req.format),
                    key_storage(req.key_storage),
                    proposed.public_jwk,
                );
                attestation.attestation_object = req.attestation_object.clone();
                attestation.attestation_certificate = req.attestation_certificate.clone();
                attestation.aaguid = req.aaguid.clone();
                let response = attestation_to_proto(&attestation);
                let ctx = caller
                    .audit("device_key.rotate", &pending.device.to_string())
                    .with_operation(command.completion(response.encode_to_vec()))
                    .consuming(consumption);
                self.commit(
                    &DeviceEnrollment {
                        profile_id: profile,
                        session: Some(session),
                        target: EnrollmentTarget::Rotation {
                            device: pending.device,
                            current,
                            current_key,
                        },
                        attestation,
                    },
                    ctx,
                )
                .await?;
                info!(device_id = %pending.device, "Device key rotated");
                Ok(response)
            })
            .await?)
    }

    /// The pending ceremony `id` of `purpose`, started by `profile` under
    /// `session`, and what its finish consumes. Another caller's ceremony is
    /// answered as one that is not pending.
    async fn pending<E>(
        &self,
        id: &DeviceEnrollmentId,
        purpose: Purpose,
        profile: ProfileId,
        session: SessionId,
    ) -> Result<(PendingEnrollment, sid_core::models::CeremonyConsumption), DeviceKeyError<E>> {
        let key = id.to_string();
        let read = self
            .ceremonies
            .read_versioned(&key)
            .await?
            .filter(|read| {
                read.value.purpose == purpose
                    && read.value.profile == profile
                    && read.value.session == session
            })
            .ok_or(DeviceKeyError::CeremonyExpired)?;
        let consumption = self.ceremonies.consumption(&key, &read);
        Ok((read.value, consumption))
    }

    /// Commit a finished ceremony; the store's refusals in the ceremony's
    /// terms, an already completed command resolved to its recorded outcome.
    async fn commit<E>(
        &self,
        enrollment: &DeviceEnrollment,
        ctx: MutationContext,
    ) -> Result<(), Effect<DeviceKeyError<E>>> {
        use sid_core::Error as Store;
        self.storage
            .commit_device_enrollment(enrollment, ctx)
            .await
            .map_err(|e| match e {
                e @ Store::OperationCompleted(_) => Effect::Store(e),
                Store::Expired(_) => Effect::Refused(DeviceKeyError::CeremonyExpired),
                Store::Conflict(_) => Effect::Refused(DeviceKeyError::Changed),
                Store::NotFound(_) => {
                    Effect::Refused(DeviceKeyError::DeviceNotFound(enrollment.target.device()))
                }
                Store::Fenced(_) => Effect::Refused(DeviceKeyError::Denied),
                e => Effect::Store(e),
            })
    }

    /// The device's live key attestation.
    pub async fn get_attestation<A: DeviceAccess>(
        &self,
        access: &mut A,
        caller: &KeyCaller,
        req: GetDeviceAttestationRequest,
    ) -> Result<v1::DeviceAttestation, DeviceKeyError<A::Error>> {
        let device_id = wire_id(req.device_id.as_ref(), "device_id")?;
        self.authorized_device(access, caller, device_id, false)
            .await?;
        let att = self
            .storage
            .get_device_attestation_by_device_id(device_id)
            .await?
            .ok_or(DeviceKeyError::NoAttestation(device_id))?;
        Ok(attestation_to_proto(&att))
    }

    /// Revoke the device's key. The store also stops counting the device as
    /// hardware-attested, in the same transaction; a ceremony started before
    /// the revocation completes nothing afterwards. A retry of a committed
    /// revocation answers as it did, not as a device without a key.
    pub async fn revoke_key<A: DeviceAccess>(
        &self,
        access: &mut A,
        caller: &KeyCaller,
        operation: Option<OperationContext>,
        req: RevokeDeviceKeyRequest,
    ) -> Result<(), DeviceKeyError<A::Error>> {
        let device_id = wire_id(req.device_id.as_ref(), "device_id")?;
        self.authorized_device(access, caller, device_id, true)
            .await?;
        // A change is made only by a Profile's own sign-in.
        let profile = caller.profile.ok_or(DeviceKeyError::Denied)?;
        let command = KeyedCommand::by_profile::<keyed::RevokeDeviceKey>(
            profile,
            operation.ok_or(DeviceKeyError::ContextRequired)?,
            &req,
        );
        command
            .execute(self.storage.as_ref(), || async {
                let ctx = caller
                    .audit("device_key.revoke", &device_id.to_string())
                    .with_operation(command.completion(().encode_to_vec()));
                let revoked = self
                    .storage
                    .revoke_device_attestation(device_id, ctx)
                    .await
                    .map_err(Effect::Store)?;
                if !revoked {
                    return Err(Effect::Refused(DeviceKeyError::NoAttestation(device_id)));
                }
                Ok(())
            })
            .await?;
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
        let profile_id = wire_id(req.profile_id.as_ref(), "profile_id")?;
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

/// The ceremony `pending`'s proofs must bind.
fn ceremony(pending: &PendingEnrollment) -> Ceremony<'_> {
    Ceremony {
        challenge: &pending.challenge,
        issuer: &pending.issuer,
        device: pending.device,
    }
}

fn device_type(v: i32) -> DeviceType {
    use sid_proto::sid::v1::identity::DeviceType as P;
    match P::try_from(v) {
        Ok(P::Desktop) => DeviceType::Desktop,
        Ok(P::Browser) => DeviceType::Browser,
        Ok(P::Iot) => DeviceType::Iot,
        Ok(P::Embedded) => DeviceType::Embedded,
        _ => DeviceType::Mobile,
    }
}

fn format(v: i32) -> DeviceAttestationFormat {
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

fn key_storage(v: i32) -> KeyStorageType {
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
    v1::DeviceAttestation {
        id: Some(att.id.into()),
        device_id: Some(att.device_id.into()),
        profile_id: Some(att.profile_id.into()),
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
        public_jwk: att.public_jwk.clone(),
        attestation_object: att.attestation_object.clone(),
        attestation_certificate: att.attestation_certificate.clone(),
        aaguid: att.aaguid.clone(),
        created_at: Some(to_timestamp(att.created_at)),
        updated_at: Some(to_timestamp(att.updated_at)),
        revoked_at: att.revoked_at.map(to_timestamp),
    }
}

#[cfg(test)]
mod tests;
