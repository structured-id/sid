// SPDX-License-Identifier: AGPL-3.0-only
//! Credential domain model.
//!
//! Represents authentication factors (OPAQUE, WebAuthn, TOTP, etc.)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use super::ProfileId;

/// Opaque credential data — zeroized on drop, redacted in Debug.
///
/// Wraps raw credential bytes (OPAQUE password files, WebAuthn passkeys,
/// TOTP secrets, recovery code hashes). Memory is zeroed when dropped
/// to prevent extraction from core dumps.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialData(Vec<u8>);

impl CredentialData {
    /// Create from raw bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Access the underlying bytes. Analogous to `expose_secret()`.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Consume and return inner bytes (for storage layer).
    /// Caller takes ownership — data will NOT be zeroized automatically.
    pub fn into_inner(self) -> Vec<u8> {
        // Use ManuallyDrop to prevent Drop from zeroing before we return
        let mut md = std::mem::ManuallyDrop::new(self);
        std::mem::take(&mut md.0)
    }
}

impl Clone for CredentialData {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl std::fmt::Debug for CredentialData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED credential data]")
    }
}

impl Zeroize for CredentialData {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for CredentialData {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<Vec<u8>> for CredentialData {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl PartialEq for CredentialData {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison for credential data
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

/// Unique identifier for a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialId(pub Uuid);

impl CredentialId {
    /// Create a new random credential ID (UUIDv7, time-ordered).
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for CredentialId {
    fn default() -> Self {
        Self::new()
    }
}

/// Credential type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    /// OPAQUE password authentication
    Opaque,
    /// WebAuthn/Passkey
    WebAuthn,
    /// TOTP (Time-based One-Time Password)
    Totp,
    /// Recovery codes
    Recovery,
    /// Legacy password hash (temporary, used during migration from other IdPs).
    /// Stored encrypted. Deleted atomically when OPAQUE registration completes.
    #[serde(rename = "legacy_hash")]
    LegacyHash,
}

impl CredentialType {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Opaque => "opaque",
            Self::WebAuthn => "webauthn",
            Self::Totp => "totp",
            Self::Recovery => "recovery",
            Self::LegacyHash => "legacy_hash",
        }
    }

    /// Whether this method signs in on its own. A profile always keeps one
    /// active primary credential; second factors and recovery codes do not
    /// count.
    pub fn is_primary(&self) -> bool {
        Self::PRIMARY.contains(self)
    }

    /// The methods that sign in on their own.
    pub const PRIMARY: [Self; 3] = [Self::Opaque, Self::WebAuthn, Self::LegacyHash];

    /// The credentials a new one of this type takes the place of: a profile
    /// holds one password and one recovery-code set. Empty for types a
    /// profile may hold several of, which are added, never replaced.
    pub fn replaces(&self) -> &'static [Self] {
        match self {
            Self::Opaque => &[Self::Opaque, Self::LegacyHash],
            Self::Recovery => &[Self::Recovery],
            Self::WebAuthn | Self::Totp | Self::LegacyHash => &[],
        }
    }
}

/// Outcome of revoking a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRevocation {
    /// The credential is revoked now.
    Revoked,
    /// It was already revoked or does not exist; nothing changed.
    AlreadyGone,
    /// It is the profile's last active primary credential and stays.
    LastPrimary,
}

/// A Profile's WebAuthn user handle (`user.id`, WebAuthn Level 3 §5.4.3) at
/// one relying party: random and opaque, the same for every passkey of that
/// Profile there, and never a ProfileId or a BindingId.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WebAuthnUserHandle(pub [u8; 16]);

impl WebAuthnUserHandle {
    /// The handle stored as `bytes`; `None` unless they are exactly 16.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }
}

/// Credential lifecycle status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    /// Credential is active and can be used for authentication.
    #[default]
    Active,
    /// Credential has been revoked (admin action or security event).
    Revoked,
}

impl CredentialStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

impl std::str::FromStr for CredentialStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            other => Err(format!("unknown credential status: {other}")),
        }
    }
}

impl std::str::FromStr for CredentialType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "opaque" => Ok(Self::Opaque),
            "webauthn" => Ok(Self::WebAuthn),
            "totp" => Ok(Self::Totp),
            "recovery" => Ok(Self::Recovery),
            "legacy_hash" => Ok(Self::LegacyHash),
            other => Err(format!("unknown credential type: {other}")),
        }
    }
}

impl std::fmt::Display for CredentialStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Credential represents an authentication factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: CredentialId,
    pub profile_id: ProfileId,
    pub credential_type: CredentialType,
    pub status: CredentialStatus,

    /// Type-specific credential data (encrypted/encoded).
    /// Zeroized on drop, redacted in Debug.
    /// - OPAQUE: password file bytes
    /// - WebAuthn: public key + metadata
    /// - TOTP: secret key
    /// - Recovery: hashed codes
    pub data: CredentialData,

    /// Optional user-provided label (e.g., "iPhone 15 Pro", "Backup codes")
    pub label: Option<String>,

    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,

    // ─── OPAQUE-ZKPP fields (only for credential_type = Opaque) ───
    /// Policy version the ZKPP proof was verified against.
    pub policy_version: Option<u32>,

    /// Whether the server verified a policy proof bound to this registration.
    /// false = policy-unverified, for as long as this credential exists: a
    /// later proof never changes it, only a new registration with its proof.
    pub zkpp_verified: bool,

    /// OPAQUE curve discriminant (only for credential_type = Opaque).
    /// Maps to `CurveId`: 0=Pallas, 1=Ristretto255, 2=P256, 3=P384, 4=P521.
    /// Used for multi-curve login dispatch.
    pub opaque_curve: Option<u8>,

    /// The OPAQUE credential identifier this password's OPRF key is derived
    /// from (RFC 9807 §5, `credential_identifier`): drawn for the password
    /// operation that installed it, so the key never evaluated anything but
    /// that operation's own request before the record was committed, and
    /// used by every login of this credential. `None` only for a password
    /// installed before identifiers were stored, whose key is its profile id.
    pub opaque_credential_identifier: Option<[u8; 16]>,

    /// Legacy hash algorithm identifier (e.g., "bcrypt", "argon2id", "pbkdf2-sha256").
    /// Only set for credential_type = LegacyHash.
    pub legacy_algorithm: Option<String>,
}

impl Credential {
    /// Create a new credential
    pub fn new(
        profile_id: ProfileId,
        credential_type: CredentialType,
        data: impl Into<CredentialData>,
        label: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: CredentialId::new(),
            profile_id,
            credential_type,
            status: CredentialStatus::Active,
            data: data.into(),
            label,
            created_at: now,
            last_used_at: None,
            policy_version: None,
            zkpp_verified: false,
            opaque_curve: None,
            opaque_credential_identifier: None,
            legacy_algorithm: None,
        }
    }

    /// The OPAQUE credential identifier logins of this password evaluate
    /// under: the stored one, else the profile id of a password installed
    /// before identifiers were stored.
    pub fn opaque_credential_identifier(&self) -> [u8; 16] {
        self.opaque_credential_identifier
            .unwrap_or_else(|| *self.profile_id.as_bytes())
    }

    /// Update last used timestamp
    pub fn mark_used(&mut self) {
        self.last_used_at = Some(Utc::now());
    }

    /// Gateway: obtain a typed wrapper if credential is active.
    pub fn as_active(&mut self) -> Option<ActiveCredential<'_>> {
        if self.status.is_active() {
            Some(ActiveCredential(self))
        } else {
            None
        }
    }
}

/// Gateway wrapper for an active credential. Consume-self transitions
/// prevent double-transition within a single scope.
pub struct ActiveCredential<'a>(&'a mut Credential);

impl<'a> ActiveCredential<'a> {
    /// Revoke this credential (admin action or security event).
    /// Consumes the wrapper — cannot use credential as active after revocation.
    pub fn revoke(self) {
        self.0.status = CredentialStatus::Revoked;
    }

    /// Access the underlying credential immutably.
    pub fn inner(&self) -> &Credential {
        self.0
    }
}

#[cfg(test)]
mod tests;
