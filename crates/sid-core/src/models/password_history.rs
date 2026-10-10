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
/// The most comparison domains one operation may require: the active epoch
/// and the rotated ones that still hold entries. Each is a proof slot and a
/// KSF run, so the bound caps both.
pub const MAX_HISTORY_DOMAINS: usize = 3;
/// The most Argon2 passes a history epoch may ask for, so a check's KSF time
/// is bounded before it runs, as its memory is. RFC 9106 §4 recommends one
/// or three passes; new epochs use three.
pub const MAX_HISTORY_KSF_PASSES: u32 = 10;

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

/// The immutable public description of one epoch, as the evaluator issues it
/// and the credential service keeps it: everything a checker needs to
/// recompute the comparison domain and stretch a tag, and nothing that
/// evaluates one. None of it changes for the epoch's life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEpochDescriptor {
    pub id: HistoryEpochId,
    pub suite: HistorySuite,
    /// The evaluator's public key `k·G`: a compressed Pallas point.
    pub public_key: [u8; 32],
    pub ksf: HistoryKsf,
    /// The KSF salt of every entry under this epoch.
    pub ksf_salt: [u8; 32],
    /// When the evaluator created the epoch's key, before sealing or first
    /// use: what a history write cutoff is compared with.
    pub created_at: DateTime<Utc>,
}

/// One epoch of one owner as the credential service keeps it: the public
/// descriptor, and its use as of the owner's history revision. The status is
/// the credential service's snapshot of the selection it committed, never a
/// second retirement authority: the evaluator alone retires an epoch.
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
    /// When the evaluator created the epoch's key (its descriptor's).
    pub created_at: DateTime<Utc>,
}

impl HistoryEpoch {
    /// The epoch's immutable public description.
    pub fn descriptor(&self) -> HistoryEpochDescriptor {
        HistoryEpochDescriptor {
            id: self.id,
            suite: self.suite,
            public_key: self.public_key,
            ksf: self.ksf,
            ksf_salt: self.ksf_salt,
            created_at: self.created_at,
        }
    }
}

/// One epoch of one owner as the evaluator keeps it, keyed by the owner's
/// history input domain: the evaluator never learns the owner's account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEpoch {
    pub id: HistoryEpochId,
    /// The owner's history input domain (32 bytes).
    pub owner_domain: [u8; 32],
    pub suite: HistorySuite,
    /// The evaluator's public key `k·G`: a compressed Pallas point.
    pub public_key: [u8; 32],
    pub ksf: HistoryKsf,
    /// The KSF salt of every entry under this epoch.
    pub ksf_salt: [u8; 32],
    pub status: HistoryEpochUse,
    pub created_at: DateTime<Utc>,
}

impl KeyEpoch {
    /// The epoch's immutable public description.
    pub fn descriptor(&self) -> HistoryEpochDescriptor {
        HistoryEpochDescriptor {
            id: self.id,
            suite: self.suite,
            public_key: self.public_key,
            ksf: self.ksf,
            ksf_salt: self.ksf_salt,
            created_at: self.created_at,
        }
    }
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

/// An owner's epochs as the evaluator reads them: every epoch not retired,
/// without any retained entry. Which compare-only epochs still retain an
/// entry is not here: the credential service says so in its
/// [`HistoryLiveSet`], and the checker confirms the selection against the
/// entries before it accepts a password.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyEpochs {
    pub epochs: Vec<KeyEpoch>,
}

impl KeyEpochs {
    /// The epoch new entries go under, if the owner has one.
    pub fn active_epoch(&self) -> Option<&KeyEpoch> {
        self.epochs
            .iter()
            .find(|e| e.status == HistoryEpochUse::Active)
    }
}

/// What the credential service, which holds the entries, tells the evaluator
/// about an owner's history when an operation is prepared: the revision, the
/// epochs that hold at least one retained entry at that revision, and the
/// owner's operations whose commit that revision records. The evaluator never
/// reads an entry to learn this.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HistoryLiveSet {
    pub revision: i64,
    /// Sorted, without duplicates.
    pub live: Vec<HistoryEpochId>,
    /// Committed operations (16 UUIDv7 bytes each), sorted, without duplicates.
    pub settled: Vec<Uuid>,
}

impl HistoryLiveSet {
    /// The live set of `history`, as read in one snapshot.
    pub fn of(history: &PasswordHistory) -> Self {
        let live: std::collections::BTreeSet<HistoryEpochId> =
            history.entries.iter().map(|e| e.epoch).collect();
        let settled: std::collections::BTreeSet<Uuid> = history
            .entries
            .iter()
            .map(|e| e.evidence.operation)
            .collect();
        Self {
            revision: history.revision,
            live: live.into_iter().collect(),
            settled: settled.into_iter().collect(),
        }
    }
}

/// One operation's preparation as the evaluator records it: the owner's live
/// set the credential service sent, and the operation that will use the
/// selected epochs until it settles or `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryPreparation {
    /// The owner's history input domain.
    pub owner_domain: [u8; 32],
    pub live: HistoryLiveSet,
    pub operation: Uuid,
    /// When the operation can no longer use its epochs: past it nothing of the
    /// operation is evaluated again.
    pub expires_at: DateTime<Utc>,
    pub now: DateTime<Utc>,
}

/// A new epoch with its sealed key, written by the evaluator before its
/// first use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewKeyEpoch {
    pub epoch: KeyEpoch,
    pub key: WrappedHistoryKey,
}

/// The sealing context of an epoch's key: the epoch and its owner's history
/// input domain, so a key moved to another epoch or owner is refused.
pub fn history_key_context(epoch: HistoryEpochId, owner_domain: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for b in owner_domain {
        use std::fmt::Write;
        write!(hex, "{b:02x}").expect("writing to a String cannot fail");
    }
    format!("password-history-key:{}:{hex}", epoch.0)
}

/// Whether `ksf` is storable and usable: positive, within the stored range
/// and the pass bound, with the Argon2 minimum memory per lane (RFC 9106 §3.1).
fn valid_ksf(ksf: &HistoryKsf) -> bool {
    ksf.memory_kib != 0
        && ksf.memory_kib <= i32::MAX as u32
        && ksf.passes != 0
        && ksf.passes <= MAX_HISTORY_KSF_PASSES
        && ksf.lanes != 0
        && ksf.lanes <= i32::MAX as u32
        && u64::from(ksf.memory_kib) >= 8 * u64::from(ksf.lanes)
}

/// The credential service's durable history of one owner for an offline,
/// same-authority transfer: every epoch descriptor, retired ones included,
/// and every retained entry. It carries no key; the evaluator's keys travel
/// separately ([`KeyArchive`]), and external wrapping keys are restored
/// apart from both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryArchive {
    pub owner: ProfileId,
    pub revision: i64,
    pub epochs: Vec<HistoryEpoch>,
    pub entries: Vec<HistoryEntry>,
}

impl HistoryArchive {
    /// Check reference and lifecycle integrity before any import mutation.
    pub fn validate(&self) -> Result<()> {
        use std::collections::{BTreeMap, BTreeSet};
        // Every later write advances the revision by one.
        if self.revision <= 0 || self.revision == i64::MAX {
            return Err(Error::Validation(
                "history archive revision must be positive and able to advance".into(),
            ));
        }
        // Both backends export the same order. Refuse reordered archives
        // before import so exact retries cannot conflict with a sorted read.
        if self
            .epochs
            .windows(2)
            .any(|pair| (pair[0].created_at, pair[0].id) >= (pair[1].created_at, pair[1].id))
            || self.entries.windows(2).any(|pair| {
                (std::cmp::Reverse(pair[0].seq), pair[0].epoch)
                    >= (std::cmp::Reverse(pair[1].seq), pair[1].epoch)
            })
        {
            return Err(Error::Validation(
                "history archive is not in canonical order".into(),
            ));
        }
        let mut ids = BTreeMap::new();
        let mut active = 0;
        for e in &self.epochs {
            if e.owner != self.owner
                || e.created_at.timestamp_subsec_nanos() % 1000 != 0
                || ids.insert(e.id, e.status).is_some()
                || !valid_ksf(&e.ksf)
            {
                return Err(Error::Validation("invalid history archive epoch".into()));
            }
            if e.status == HistoryEpochUse::Active {
                active += 1;
            }
        }
        if active > 1 {
            return Err(Error::Validation(
                "history archive has multiple active epochs".into(),
            ));
        }
        let mut entries = BTreeSet::new();
        for entry in &self.entries {
            if entry.seq <= 0
                || entry.created_at.timestamp_subsec_nanos() % 1000 != 0
                || entry.evidence.policy_version > i32::MAX as u32
                || !entries.insert((entry.epoch, entry.seq))
                || !matches!(
                    ids.get(&entry.epoch),
                    Some(HistoryEpochUse::Active | HistoryEpochUse::CompareOnly)
                )
            {
                return Err(Error::Validation("invalid history archive entry".into()));
            }
        }
        // A compare-only epoch without entries is valid: it is never selected,
        // and the evaluator retires it at the owner's next preparation, from
        // the credential service's live set. Every required epoch (the active
        // one and each compare-only one holding an entry) is a domain each
        // proved operation evaluates; past the limit no operation succeeds,
        // so nothing could age entries out.
        let live = ids
            .iter()
            .filter(|(id, status)| match status {
                HistoryEpochUse::Active => true,
                HistoryEpochUse::CompareOnly => entries.iter().any(|(e, _)| e == *id),
                HistoryEpochUse::Retired => false,
            })
            .count();
        if live > MAX_HISTORY_DOMAINS {
            return Err(Error::Validation(
                "history archive needs more history domains than a proof holds".into(),
            ));
        }
        Ok(())
    }
}

/// The evaluator's durable keys of one owner for an offline, same-authority
/// transfer: every epoch with its sealed key, and the history revision at
/// which each replaced epoch stopped being active. The sealed keys open only
/// under the evaluator's external wrapping key, restored separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyArchive {
    /// The owner's history input domain.
    pub owner_domain: [u8; 32],
    pub epochs: Vec<NewKeyEpoch>,
    /// `(epoch, revision)`: the revision at which a replaced epoch stopped
    /// being active; one per epoch that is no longer active.
    pub replaced: Vec<(HistoryEpochId, i64)>,
}

impl KeyArchive {
    /// Check that every key is sealed for its epoch and owner, and the
    /// lifecycle references, before any import mutation.
    pub fn validate(&self) -> Result<()> {
        use std::collections::BTreeMap;
        if self.epochs.windows(2).any(|pair| {
            (pair[0].epoch.created_at, pair[0].epoch.id)
                >= (pair[1].epoch.created_at, pair[1].epoch.id)
        }) || self.replaced.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(Error::Validation(
                "key archive is not in canonical order".into(),
            ));
        }
        let mut ids = BTreeMap::new();
        let mut active = 0;
        for new in &self.epochs {
            let e = &new.epoch;
            let context = history_key_context(e.id, &self.owner_domain);
            // The stored scalar is 32 bytes plus the 16-byte GCM tag. Bound
            // the encoded field before decoding any attacker-supplied lengths.
            if new.key.0.len() != 20 + context.len() + 48 {
                return Err(Error::Validation("invalid sealed history key size".into()));
            }
            let encoded_length =
                u32::from_le_bytes(new.key.0[16..20].try_into().expect("length checked"));
            if encoded_length as usize != context.len() {
                return Err(Error::Validation(
                    "invalid sealed history key context length".into(),
                ));
            }
            let sealed = sid_keys::EncryptedField::from_bytes(&new.key.0)
                .map_err(|_| Error::Validation("invalid sealed history key".into()))?;
            if sealed.context != context || sealed.key_version == 0 || sealed.ciphertext.len() != 48
            {
                return Err(Error::Validation(
                    "history key is not bound to its owner and epoch".into(),
                ));
            }
            if e.owner_domain != self.owner_domain
                || e.created_at.timestamp_subsec_nanos() % 1000 != 0
                || ids.insert(e.id, e.status).is_some()
                || !valid_ksf(&e.ksf)
            {
                return Err(Error::Validation("invalid key archive epoch".into()));
            }
            if e.status == HistoryEpochUse::Active {
                active += 1;
            }
        }
        if active > 1 {
            return Err(Error::Validation(
                "key archive has multiple active epochs".into(),
            ));
        }
        for (epoch, revision) in &self.replaced {
            if *revision <= 0
                || !matches!(
                    ids.get(epoch),
                    Some(HistoryEpochUse::CompareOnly | HistoryEpochUse::Retired)
                )
            {
                return Err(Error::Validation("invalid key archive replacement".into()));
            }
        }
        Ok(())
    }
}

/// A history write cutoff as stores keep it, to the microsecond: rounded up,
/// so storing it never lets an epoch created just before it through.
pub fn write_cutoff_instant(not_before: DateTime<Utc>) -> DateTime<Utc> {
    match not_before.timestamp_subsec_nanos() % 1000 {
        0 => not_before,
        nanos => not_before + chrono::Duration::nanoseconds(i64::from(1000 - nanos)),
    }
}

/// What an accepted password installation writes to its owner's history in
/// the same transaction as the credential: the operation's epochs as the
/// evaluator described them (the first active, the rest compare-only), the
/// new entries (one per active epoch), and the retention that follows. A
/// commit whose `expected_revision` is not the stored one writes nothing,
/// credential included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryCommit {
    pub owner: ProfileId,
    /// The revision the comparison was made against; `0` for an owner with
    /// no history row yet.
    pub expected_revision: i64,
    /// The operation's selected epochs in its domain order. Each is recorded
    /// if new; one already recorded with another descriptor fails the commit.
    pub epochs: Vec<HistoryEpochDescriptor>,
    /// Entries of the accepted password, one per epoch it is written under.
    pub entries: Vec<(HistoryEpochId, [u8; 32])>,
    pub evidence: HistoryEvidence,
    /// How many accepted passwords to retain, newest first, 1..=24.
    pub depth: u32,
    /// Accepted passwords older than this many days, counted from their
    /// acceptance, are dropped too; the one this commit accepts, the newest,
    /// always stays. 0 keeps every entry `depth` keeps.
    #[serde(default)]
    pub max_age_days: u32,
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
        if self.epochs.is_empty() || self.epochs.len() > MAX_HISTORY_DOMAINS {
            return Err(Error::Validation(
                "a history commit names its operation's epochs".to_string(),
            ));
        }
        // Creation instants are stored to the microsecond: a finer one could
        // not be recorded as stated.
        if self.epochs.iter().enumerate().any(|(i, e)| {
            self.epochs[..i].iter().any(|o| o.id == e.id)
                || !valid_ksf(&e.ksf)
                || e.created_at.timestamp_subsec_nanos() % 1000 != 0
        }) {
            return Err(Error::Validation(
                "a history commit names each valid epoch once".to_string(),
            ));
        }
        if self
            .entries
            .iter()
            .any(|(epoch, _)| *epoch != self.epochs[0].id)
        {
            return Err(Error::Validation(
                "a history commit writes entries under its active epoch only".to_string(),
            ));
        }
        Ok(())
    }

    /// The acceptance time before which an older entry is dropped by this
    /// commit made at `now`; `None` when age drops nothing.
    pub fn expires_before(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        (self.max_age_days > 0).then(|| now - chrono::Duration::days(i64::from(self.max_age_days)))
    }

    /// Refuse a commit that writes under an epoch created before the history
    /// write cutoff `not_before` (none when no cutoff was ever set). Only the
    /// epoch taking the new entry counts: older epochs named for comparison
    /// are not written to.
    pub fn check_write_cutoff(&self, not_before: Option<DateTime<Utc>>) -> Result<()> {
        match (not_before, self.epochs.first()) {
            (Some(cutoff), Some(written)) if written.created_at < cutoff => {
                Err(Error::Fenced(format!(
                    "history epoch {} was created before the write cutoff",
                    written.id.0
                )))
            }
            _ => Ok(()),
        }
    }
}

/// Work kind of a first enrollment's admission: owed from before the
/// evaluator is asked for the new owner's key until the registration has
/// either committed or been aborted and its key reclaimed.
pub const ENROLLMENT_ADMISSION_KIND: &str = "password_history.enrollment";

/// Attempts at an enrollment's terminal step before it is recorded failed:
/// with an hourly retry this outlasts an evaluator outage of more than a day.
pub const ENROLLMENT_ADMISSION_ATTEMPTS: u32 = 40;

/// A first enrollment as the credential authority admits it, before the
/// evaluator creates the new owner's key: the operation, the owner's
/// history input domain and the expiry after which it can no longer
/// commit. It carries no password, proof or secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentAdmission {
    /// The password operation (16 UUIDv7 bytes).
    pub operation: Uuid,
    pub owner_domain: [u8; 32],
    pub expires_at: DateTime<Utc>,
}

impl EnrollmentAdmission {
    /// The durable work recording this admission: one per operation, due at
    /// its expiry, when the registration is either committed or aborted.
    pub fn work(&self) -> crate::models::NewWork {
        let kind = crate::models::WorkKind::new(ENROLLMENT_ADMISSION_KIND)
            .expect("the enrollment kind is valid");
        let payload = serde_json::to_vec(self).expect("an admission serializes");
        let mut work = crate::models::NewWork::new(kind, payload);
        work.id = crate::models::WorkId(self.operation);
        work.not_before = Some(self.expires_at);
        work.max_attempts = ENROLLMENT_ADMISSION_ATTEMPTS;
        work
    }

    /// The admission a work payload records.
    pub fn from_work(payload: &[u8]) -> Result<Self> {
        serde_json::from_slice(payload)
            .map_err(|e| Error::Validation(format!("enrollment admission: {e}")))
    }
}

/// Work kind of a deleted owner's purge from the evaluator: owed in the
/// transaction that deletes the profile, until the evaluator has destroyed
/// the owner's history keys and lifecycle.
pub const OWNER_PURGE_KIND: &str = "password_history.owner_purge";

/// Namespace of the purge work ids, one per owner domain.
const OWNER_PURGE_NAMESPACE: Uuid = Uuid::from_u128(0x2c5d_8f17_a3e4_4b90_9d61_7e0f_c4a8_5b23);

/// A deleted owner whose history keys the evaluator destroys: only the
/// owner's history input domain, nothing that names the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerPurge {
    pub owner_domain: [u8; 32],
}

impl OwnerPurge {
    /// The durable work recording this purge: one per owner domain, so a
    /// repeated deletion owes the same purge.
    pub fn work(&self) -> crate::models::NewWork {
        let kind =
            crate::models::WorkKind::new(OWNER_PURGE_KIND).expect("the owner purge kind is valid");
        let payload = serde_json::to_vec(self).expect("a purge serializes");
        let mut work = crate::models::NewWork::new(kind, payload);
        work.id = crate::models::WorkId(Uuid::new_v5(&OWNER_PURGE_NAMESPACE, &self.owner_domain));
        work.max_attempts = ENROLLMENT_ADMISSION_ATTEMPTS;
        work
    }

    /// The purge a work payload records.
    pub fn from_work(payload: &[u8]) -> Result<Self> {
        serde_json::from_slice(payload).map_err(|e| Error::Validation(format!("owner purge: {e}")))
    }
}

/// What the evaluator did with an aborted first enrollment's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentCleanup {
    /// The key the operation created was destroyed.
    Reclaimed,
    /// The operation created no key (its preparation never ran, or ran
    /// after this cleanup and was refused); it can no longer create one.
    NothingCreated,
    /// The key is kept: the owner's lifecycle or another operation still
    /// needs it, which an aborted first enrollment should not allow.
    Retained(String),
}

#[cfg(test)]
mod tests;
