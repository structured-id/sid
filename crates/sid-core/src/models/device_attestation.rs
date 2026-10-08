// SPDX-License-Identifier: AGPL-3.0-only
//! Device attestation domain model.
//!
//! Tracks cryptographic identity of devices: hardware keys, platform
//! attestation blobs, and verification status. Split from device.rs
//! because attestation lives in sid-attestation (crypto boundary),
//! while device metadata lives in sid-identity (UX boundary).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{DeviceId, ProfileId};

/// Unique identifier for a device attestation record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceAttestationId(pub Uuid);

impl DeviceAttestationId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for DeviceAttestationId {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// Attestation chain verified (EE).
    Verified,
    /// Stored but not verified (CE default).
    Unverified,
    /// Verification failed (EE).
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Device public key (DER-encoded).
    pub device_public_key: Vec<u8>,

    /// Raw attestation blob (platform-specific, opaque to CE).
    pub attestation_object: Option<Vec<u8>>,

    /// Leaf certificate from attestation chain.
    pub attestation_certificate: Option<Vec<u8>>,

    /// Authenticator Attestation GUID (WebAuthn AAGUID).
    pub aaguid: Option<String>,

    /// Bound credential ID (links to WebAuthn/OPAQUE credential).
    pub credential_id: Option<String>,

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
        device_public_key: Vec<u8>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: DeviceAttestationId::new(),
            device_id,
            profile_id,
            format,
            key_storage,
            status: AttestationStatus::Unverified,
            device_public_key,
            attestation_object: None,
            attestation_certificate: None,
            aaguid: None,
            credential_id: None,
            created_at: now,
            updated_at: now,
            revoked_at: None,
        }
    }

    /// Rotate the device key. Resets status to Unverified (CE) or Pending (EE).
    pub fn rotate_key(&mut self, new_public_key: Vec<u8>) {
        self.device_public_key = new_public_key;
        self.attestation_object = None;
        self.attestation_certificate = None;
        self.status = AttestationStatus::Unverified;
        self.updated_at = Utc::now();
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

#[cfg(test)]
mod tests;
