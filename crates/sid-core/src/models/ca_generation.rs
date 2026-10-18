// SPDX-License-Identifier: AGPL-3.0-only
//! A CA key generation and its lifecycle: prepared, recovery confirmed,
//! activated, retired or revoked. Issuance obeys it: only the current
//! generation of a scope issues, and only after both recovery confirmations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::OrgId;

/// One CA key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CaGenerationId(pub Uuid);

impl CaGenerationId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for CaGenerationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for CaGenerationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Whose issuing authority a generation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CaScope {
    /// The installation's own issuing CA.
    Deployment,
    /// An organization's CA.
    Organization(OrgId),
}

/// Where the key of a generation is held. Never the key itself in the clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyCustody {
    /// The private key sealed by the installation's key custody.
    Sealed(Vec<u8>),
    /// A key held by an external signer, named by its handle.
    External(String),
}

/// A generation's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CaState {
    /// Keys exist; the generation does not issue.
    Prepared,
    /// The one generation of its scope that issues.
    Current,
    /// Replaced by a newer current generation; issues nothing.
    Retired,
    /// Withdrawn; issues nothing, whatever it was before.
    Revoked,
}

impl CaState {
    /// Stable storage name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Current => "current",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }

    /// The state of a storage name.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "prepared" => Some(Self::Prepared),
            "current" => Some(Self::Current),
            "retired" => Some(Self::Retired),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// A confirmation that the generation can be recovered: the reference of
/// the recovery point or preserved key copy, who confirmed it and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryConfirmation {
    /// The recovery point or key-preservation reference; never a secret or
    /// an access-bearing URL.
    pub reference: String,
    /// The operator or automation that confirmed it.
    pub confirmed_by: String,
    pub confirmed_at: DateTime<Utc>,
}

/// A generation to prepare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCaGeneration {
    pub id: CaGenerationId,
    pub scope: CaScope,
    pub key: KeyCustody,
}

/// A stored generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaGeneration {
    pub id: CaGenerationId,
    pub scope: CaScope,
    /// Monotonic within the scope, from 1.
    pub generation: u32,
    pub key: KeyCustody,
    /// The certificate its parent issued (or the root's own).
    pub certificate: Option<Vec<u8>>,
    /// That the database recovery point holds this prepared generation.
    pub database_recovery: Option<RecoveryConfirmation>,
    /// That its key and the key's custody dependencies are preserved.
    pub key_recovery: Option<RecoveryConfirmation>,
    pub state: CaState,
    /// Advances on every transition; transitions name the revision they
    /// expect.
    pub revision: u64,
    /// The last serial number allocated; 0 before the first.
    pub last_serial: u64,
    pub prepared_at: DateTime<Utc>,
}

impl CaGeneration {
    /// Whether activation would be admitted: prepared, certified and
    /// recovery-confirmed both ways.
    pub fn activatable(&self) -> bool {
        self.state == CaState::Prepared
            && self.certificate.is_some()
            && self.database_recovery.is_some()
            && self.key_recovery.is_some()
    }

    /// SHA-256 of the certificate DER, the fingerprint records bind to;
    /// derived from the stored certificate, so it cannot disagree with it.
    pub fn certificate_sha256(&self) -> Option<[u8; 32]> {
        use sha2::Digest;
        self.certificate
            .as_deref()
            .map(|der| sha2::Sha256::digest(der).into())
    }
}

/// A serial number allocated to an issuance, with the generation revision it
/// was allocated under: the issuance commit rechecks that revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialAllocation {
    pub generation: CaGenerationId,
    pub revision: u64,
    pub serial: u64,
}

#[cfg(test)]
mod tests;
