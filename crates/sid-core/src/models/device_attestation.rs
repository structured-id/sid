// SPDX-License-Identifier: AGPL-3.0-only
//! Device attestation domain model.
//!
//! Tracks cryptographic identity of devices: hardware keys, platform
//! attestation blobs, and verification status. Split from device.rs
//! because attestation lives in sid-attestation (crypto boundary),
//! while device metadata lives in sid-identity (UX boundary).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{DeviceId, ProfileId};

pub use sid_ids::DeviceAttestationId;

/// Attestation format reported by the device.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAttestationFormat {
    /// No attestation provided.
    #[default]
    None,
    /// FIDO2 packed attestation.
    Packed,
    /// TPM 2.0 attestation.
    Tpm,
    /// Android Keystore attestation.
    AndroidKey,
    /// Apple App Attest / Secure Enclave.
    Apple,
    /// FIDO U2F attestation.
    FidoU2f,
}

impl DeviceAttestationFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Packed => "packed",
            Self::Tpm => "tpm",
            Self::AndroidKey => "android_key",
            Self::Apple => "apple",
            Self::FidoU2f => "fido_u2f",
        }
    }
}

impl std::str::FromStr for DeviceAttestationFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "packed" => Ok(Self::Packed),
            "tpm" => Ok(Self::Tpm),
            "android_key" => Ok(Self::AndroidKey),
            "apple" => Ok(Self::Apple),
            "fido_u2f" => Ok(Self::FidoU2f),
            other => Err(format!("unknown attestation format: {other}")),
        }
    }
}

impl std::fmt::Display for DeviceAttestationFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Type of hardware key storage on the device.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStorageType {
    /// Software-only key (no hardware backing).
    #[default]
    Software,
    /// Trusted Platform Module.
    Tpm,
    /// Apple Secure Enclave.
    SecureEnclave,
    /// Android StrongBox.
    StrongBox,
    /// ARM TrustZone or similar TEE.
    Tee,
}

impl KeyStorageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::Tpm => "tpm",
            Self::SecureEnclave => "secure_enclave",
            Self::StrongBox => "strongbox",
            Self::Tee => "tee",
        }
    }

    /// Whether this key storage type involves dedicated hardware.
    pub fn is_hardware_backed(&self) -> bool {
        !matches!(self, Self::Software)
    }
}

impl std::str::FromStr for KeyStorageType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "software" => Ok(Self::Software),
            "tpm" => Ok(Self::Tpm),
            "secure_enclave" => Ok(Self::SecureEnclave),
            "strongbox" => Ok(Self::StrongBox),
            "tee" => Ok(Self::Tee),
            other => Err(format!("unknown key storage type: {other}")),
        }
    }
}

impl std::fmt::Display for KeyStorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Attestation verification status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    /// Received, not yet verified.
    #[default]
    Pending,
    /// Attestation chain verified.
    Verified,
    /// Stored but not verified (default).
    Unverified,
    /// Verification failed.
    Rejected,
    /// Key has been revoked.
    Revoked,
}

impl AttestationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Unverified => "unverified",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
        }
    }

    /// Whether attestation is in a usable state.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Verified | Self::Unverified)
    }
}

impl std::str::FromStr for AttestationStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "verified" => Ok(Self::Verified),
            "unverified" => Ok(Self::Unverified),
            "rejected" => Ok(Self::Rejected),
            "revoked" => Ok(Self::Revoked),
            other => Err(format!("unknown attestation status: {other}")),
        }
    }
}

impl std::fmt::Display for AttestationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Device attestation record — cryptographic identity of a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAttestation {
    pub id: DeviceAttestationId,

    /// References Device in sid-identity.
    pub device_id: DeviceId,

    /// Owner profile.
    pub profile_id: ProfileId,

    /// Attestation format.
    pub format: DeviceAttestationFormat,

    /// Hardware key type.
    pub key_storage: KeyStorageType,

    /// Verification status.
    pub status: AttestationStatus,

    /// The device's public key as a JSON Web Key holding only its RFC 7638
    /// required members, in their canonical form: what its possession proof
    /// was signed with.
    pub public_jwk: String,

    /// Raw attestation blob (platform-specific, opaque to CE).
    pub attestation_object: Option<Vec<u8>>,

    /// Leaf certificate from attestation chain.
    pub attestation_certificate: Option<Vec<u8>>,

    /// Authenticator Attestation GUID (WebAuthn AAGUID).
    pub aaguid: Option<String>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl DeviceAttestation {
    /// Create a new attestation record.
    ///
    /// CE default: status = Unverified (stored but not cryptographically checked).
    pub fn new_ce(
        device_id: DeviceId,
        profile_id: ProfileId,
        format: DeviceAttestationFormat,
        key_storage: KeyStorageType,
        public_jwk: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: DeviceAttestationId::generate(),
            device_id,
            profile_id,
            format,
            key_storage,
            status: AttestationStatus::Unverified,
            public_jwk,
            attestation_object: None,
            attestation_certificate: None,
            aaguid: None,
            created_at: now,
            updated_at: now,
            revoked_at: None,
        }
    }

    /// Revoke this attestation (device removed or compromised).
    pub fn revoke(&mut self) {
        self.status = AttestationStatus::Revoked;
        self.revoked_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Whether the device key is backed by hardware.
    pub fn is_hardware_backed(&self) -> bool {
        self.key_storage.is_hardware_backed()
    }
}

/// What a finished device-key ceremony binds, committed as one transaction
/// with the ceremony it consumes, its audit, work and outcome
/// (`StorageBackend::commit_device_enrollment`). The authority it was
/// authorized under is the mutation's fence.
#[derive(Debug, Clone)]
pub struct DeviceEnrollment {
    /// The Profile that owns the device.
    pub profile_id: ProfileId,
    /// The device the key is bound to and how.
    pub target: EnrollmentTarget,
    /// The new key binding, of `target`'s device and `profile_id`.
    pub attestation: DeviceAttestation,
}

/// The device a ceremony binds its key to, as the ceremony found it.
#[derive(Debug, Clone)]
pub enum EnrollmentTarget {
    /// A device allocated by the ceremony, created with its first key.
    NewDevice(super::Device),
    /// The owner's existing device without a live key; `revoked` names the
    /// revoked binding it had when the ceremony started, if any, so a binding
    /// changed meanwhile completes nothing.
    ExistingDevice {
        device: DeviceId,
        revoked: Option<DeviceAttestationId>,
    },
    /// The owner's enrolled device whose live binding `current`, of key
    /// `current_key` (its public JWK), is retired by the new one.
    Rotation {
        device: DeviceId,
        current: DeviceAttestationId,
        current_key: String,
    },
}

impl EnrollmentTarget {
    /// The device the key is bound to.
    pub fn device(&self) -> DeviceId {
        match self {
            Self::NewDevice(device) => device.id,
            Self::ExistingDevice { device, .. } | Self::Rotation { device, .. } => *device,
        }
    }
}

#[cfg(test)]
mod tests;
