// SPDX-License-Identifier: AGPL-3.0-only
//! Private password history: the owner's
//! history epochs (one VOPRF key and KSF configuration each) and the retained
//! KSF outputs of accepted passwords.
//!
//! The records are split along the authority boundary. [`HistoryEpoch`] and
//! [`HistoryEntry`] are what the history checker reads; they carry no key
//! material. [`WrappedHistoryKey`] is the evaluator's alone: the checker may
//! see its bytes but cannot unwrap them without the evaluator's key access.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::ProfileId;
use crate::{Error, Result};

/// Depth of retained history when the policy sets none: the last verified password.
pub const DEFAULT_HISTORY_DEPTH: u32 = 1;
/// The deepest retained history any policy may set.
pub const MAX_HISTORY_DEPTH: u32 = 24;

/// One history epoch of one owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HistoryEpochId(pub Uuid);

impl HistoryEpochId {
    /// A fresh, time-ordered epoch id.
    pub fn generate() -> Self {
        Self(Uuid::now_v7())
    }
}

/// History KSF parameters of an epoch (Argon2id v1.3, 32-byte output); fixed
/// for the epoch's life, since changing them makes its entries incomparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryKsf {
    /// Memory, KiB.
    pub memory_kib: u32,
    /// Passes.
    pub passes: u32,
    /// Lanes.
    pub lanes: u32,
}

impl HistoryKsf {
    /// Parameters of new epochs: Argon2id, 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        passes: 3,
        lanes: 1,
    };

    /// The memory one evaluation holds, bytes; what admission reserves.
    pub fn memory_bytes(&self) -> u64 {
        u64::from(self.memory_kib) * 1024
    }
}

/// The relation suite an epoch's tags follow; part of its manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistorySuite {
    /// Pallas VOPRF (DLEQ per RFC 9497 §2.2), Poseidon input and tag
    /// derivation, try-and-increment hash-to-group with minimal offset and
    /// even y, Argon2id KSF.
    PallasPoseidonV1,
}

impl HistorySuite {
    /// Stable identifier, stored and bound into the comparison domain.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PallasPoseidonV1 => "pallas-poseidon-v1",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "pallas-poseidon-v1" => Ok(Self::PallasPoseidonV1),
            other => Err(Error::Validation(format!(
                "unknown password history suite: {other}"
            ))),
        }
    }
}

/// What an epoch may still be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryEpochUse {
    /// New entries are written under it and required comparisons use it.
    Active,
    /// Retained entries are still compared, no new entry is written. A
    /// rotated epoch stays here until retention removes its last entry.
    CompareOnly,
    /// Neither; kept only for provenance until its entries are gone.
    Retired,
}

impl HistoryEpochUse {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::CompareOnly => "compare_only",
            Self::Retired => "retired",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "active" => Ok(Self::Active),
            "compare_only" => Ok(Self::CompareOnly),
            "retired" => Ok(Self::Retired),
            other => Err(Error::Validation(format!(
                "unknown password history epoch use: {other}"
            ))),
        }
    }
}

/// The public manifest of one epoch: everything a checker needs to compare
/// a proved tag, and nothing that evaluates one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEpoch {
    pub id: HistoryEpochId,
    pub owner: ProfileId,
    pub suite: HistorySuite,
    /// The evaluator's public key `k·G`: a compressed Pallas point.
    pub public_key: [u8; 32],
    pub ksf: HistoryKsf,
    /// The KSF salt of every entry under this epoch.
    pub ksf_salt: [u8; 32],
    pub status: HistoryEpochUse,
    pub created_at: DateTime<Utc>,
}

/// An epoch's VOPRF key, sealed by the evaluator's key manager. Persisted
/// with its epoch before its first use; never regenerated.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedHistoryKey(pub Vec<u8>);

impl std::fmt::Debug for WrappedHistoryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WrappedHistoryKey([REDACTED])")
    }
}

/// One retained entry: the history KSF output `s` of an accepted password
/// under one epoch. Only accepted outputs are ever stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub epoch: HistoryEpochId,
    /// Position in the owner's history; larger is newer. Entries written by
    /// one operation (one per required epoch) share it.
    pub seq: i64,
    pub entry: [u8; 32],
    pub evidence: HistoryEvidence,
    pub created_at: DateTime<Utc>,
}

/// Where a retained entry came from: the accepted operation and the policy
/// and suite its proof was verified under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEvidence {
    /// The password operation whose proof was accepted (16 UUIDv7 bytes).
    pub operation: Uuid,
    pub policy_version: u32,
}

/// An owner's history as the checker reads it: the revision it was read at,
/// every epoch not retired, and every retained entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PasswordHistory {
    /// Moves on every write to this owner's history; a commit names the
    /// revision its comparison was made against and fails if it moved.
    pub revision: i64,
    pub epochs: Vec<HistoryEpoch>,
    pub entries: Vec<HistoryEntry>,
}

impl PasswordHistory {
    /// The epoch new entries go under, if the owner has one.
    pub fn active_epoch(&self) -> Option<&HistoryEpoch> {
        self.epochs
            .iter()
            .find(|e| e.status == HistoryEpochUse::Active)
    }

    /// The epochs a new password must be compared in, in the order the
    /// operation lists them: the active one first, then each compare-only
    /// epoch that still retains an entry. The client cannot choose these.
    pub fn required_epochs(&self) -> Vec<&HistoryEpoch> {
        let mut required: Vec<&HistoryEpoch> = self.active_epoch().into_iter().collect();
        required.extend(self.epochs.iter().filter(|e| {
            e.status == HistoryEpochUse::CompareOnly
                && self.entries.iter().any(|entry| entry.epoch == e.id)
        }));
        required
    }

    /// The retained entries of `epoch`.
    pub fn entries_of(&self, epoch: HistoryEpochId) -> impl Iterator<Item = &HistoryEntry> {
        self.entries.iter().filter(move |e| e.epoch == epoch)
    }
}

/// A new epoch with its sealed key, written before its first use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewHistoryEpoch {
    pub epoch: HistoryEpoch,
    pub key: WrappedHistoryKey,
}

/// What an accepted password installation writes to its owner's history in
/// the same transaction as the credential: the new entries (one per active
/// epoch), and the retention that follows. A commit whose `expected_revision`
/// is not the stored one writes nothing, credential included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryCommit {
    pub owner: ProfileId,
    /// The revision the comparison was made against; `0` for an owner with
    /// no history row yet.
    pub expected_revision: i64,
    /// An epoch created by this operation (first registration), written with
    /// the entries.
    pub new_epoch: Option<NewHistoryEpoch>,
    /// Entries of the accepted password, one per epoch it is written under.
    pub entries: Vec<(HistoryEpochId, [u8; 32])>,
    pub evidence: HistoryEvidence,
    /// How many accepted passwords to retain, newest first, 1..=24.
    pub depth: u32,
}

impl HistoryCommit {
    /// Refuse a commit that could not be stored as stated.
    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_HISTORY_DEPTH).contains(&self.depth) {
            return Err(Error::Validation(format!(
                "password history depth must be 1..={MAX_HISTORY_DEPTH}"
            )));
        }
        if self.entries.is_empty() {
            return Err(Error::Validation(
                "a history commit writes at least one entry".to_string(),
            ));
        }
        if let Some(new) = &self.new_epoch
            && new.epoch.owner != self.owner
        {
            return Err(Error::Validation(
                "a new history epoch belongs to the committing owner".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
