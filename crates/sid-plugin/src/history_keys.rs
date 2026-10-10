// SPDX-License-Identifier: AGPL-3.0-only
//! The password-history evaluator's own store: per-owner VOPRF keys, sealed,
//! and the lifecycle that decides which replaced keys stay in use. Keyed by
//! the owner's history input domain; it holds no account, entry or credential
//! state, and is deployed with its own database credentials where the
//! evaluator runs as its own service. Every mutation records its audit entry
//! in the same store, in the same transaction.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sid_core::Result;
use sid_core::models::{
    AuditEntry, EnrollmentCleanup, HistoryEpochId, HistoryPreparation, KeyArchive, KeyEpoch,
    KeyEpochs, NewKeyEpoch, WrappedHistoryKey,
};
use uuid::Uuid;

#[async_trait]
pub trait HistoryKeyStore: Send + Sync {
    /// Every epoch not retired of the owner of `owner_domain`; empty when it
    /// has none.
    async fn get_key_epochs(&self, owner_domain: &[u8; 32]) -> Result<KeyEpochs>;

    /// Store `new` as a new owner's first epoch with its sealed key, before
    /// the key's first use, recording that `operation` created it. An owner
    /// that already has any epoch is a `Conflict`, unless it is this very
    /// epoch (an exact retry): a new owner never resets an existing history
    /// or gets a parallel first epoch. An operation already cleaned up
    /// ([`Self::abandon_enrollment`]) creates nothing: `Fenced`.
    async fn create_first_epoch(
        &self,
        new: &NewKeyEpoch,
        operation: Uuid,
        audit: AuditEntry,
    ) -> Result<KeyEpoch>;

    /// The aborted first enrollment `operation` of the owner of
    /// `owner_domain`, in one transaction serialized with the owner's other
    /// writes: from now on the operation creates no key and is evaluated no
    /// more, and the key it created is destroyed when nothing else can need
    /// it (the owner has no recorded lifecycle and no other operation uses
    /// it). Never touches a key another operation created. Repeating it is
    /// harmless and returns what the first one did, as seen now.
    async fn abandon_enrollment(
        &self,
        owner_domain: &[u8; 32],
        operation: Uuid,
        audit: AuditEntry,
    ) -> Result<EnrollmentCleanup>;

    /// Whether `operation` was cleaned up as an aborted first enrollment.
    async fn enrollment_abandoned(&self, operation: Uuid) -> Result<bool>;

    /// Destroy every key, replacement, use and lifecycle of the deleted owner
    /// of `owner_domain`, in one transaction serialized with the owner's
    /// other writes, and fence the domain: from now on no epoch is created,
    /// imported or selected for it (`Fenced`). Repeating it is harmless.
    /// Returns how many keys it destroyed.
    async fn purge_owner(&self, owner_domain: &[u8; 32], audit: AuditEntry) -> Result<u64>;

    /// Drop the fences of first enrollments abandoned, and of owners purged,
    /// before `before`. A fence matters only while a delayed preparation of
    /// an operation it refuses could still be within that operation's
    /// expiry; past it the preparation is refused as expired, so `before`
    /// must lie at least the operation lifetime and the tolerated clock skew
    /// in the past. Returns how many were dropped.
    async fn compact_abandoned(&self, before: DateTime<Utc>, audit: AuditEntry) -> Result<u64>;

    /// Store `new` as the owner's active epoch when it has none. When it
    /// already has an active epoch nothing is written and that epoch is
    /// returned, so concurrent preparations agree on one key.
    async fn ensure_epoch(&self, new: &NewKeyEpoch, audit: AuditEntry) -> Result<KeyEpoch>;

    /// Replace the owner's active epoch `replaces` with `new`, before the new
    /// key's first use. The replaced epoch stops taking entries and becomes
    /// compare-only, recorded as replaced at `replaced_at_revision`: a live
    /// set older than it may still have been read while the epoch took
    /// entries, so it never retires the epoch. When `replaces` is no longer
    /// the active epoch nothing is written and the current active epoch is
    /// returned, so concurrent rotations agree on one key.
    async fn rotate_epoch(
        &self,
        new: &NewKeyEpoch,
        replaces: HistoryEpochId,
        replaced_at_revision: i64,
        audit: AuditEntry,
    ) -> Result<KeyEpoch>;

    /// Prepare operation `prep.operation`, in one transaction per owner,
    /// durable and shared by every replica:
    ///
    /// - record `prep.live` as the owner's lifecycle when its revision is newer
    ///   than the one recorded; the same revision with another live set is a
    ///   `Conflict`; an older one changes nothing and retires nothing;
    /// - release the uses of the operations `prep.live.settled` names and of
    ///   every operation past its expiry;
    /// - retire each compare-only epoch absent from the recorded live set,
    ///   replaced at or before its revision and used by no operation: it is no
    ///   longer selected, and its sealed key is kept;
    /// - select the active epoch, then each compare-only epoch of `prep.live`
    ///   not retired, and record that `prep.operation` uses them until it
    ///   settles or `prep.expires_at`.
    ///
    /// Each epoch of `prep.live.live` must be the owner's (`Validation`
    /// otherwise). Returns the selection, active epoch first.
    async fn prepare_epochs(
        &self,
        prep: &HistoryPreparation,
        audit: AuditEntry,
    ) -> Result<Vec<KeyEpoch>>;

    /// The sealed key of an epoch; `None` when no such epoch is stored.
    async fn get_epoch_key(&self, epoch: HistoryEpochId) -> Result<Option<WrappedHistoryKey>>;

    /// The history write cutoff this store records: no epoch created before
    /// it is selected to take entries or evaluated; `None` when none was set.
    async fn write_cutoff(&self) -> Result<Option<DateTime<Utc>>>;

    /// Raise the write cutoff to `not_before`, shared by every replica.
    /// Monotonic: an equal or earlier value changes nothing. Returns the
    /// cutoff in force.
    async fn raise_write_cutoff(
        &self,
        not_before: DateTime<Utc>,
        audit: AuditEntry,
    ) -> Result<DateTime<Utc>>;

    /// The non-secret derivation parameters of the key versions sealing this
    /// store's history keys: the evaluator's own key custody, apart from any
    /// other service's field keys. With the evaluator's master secret, held
    /// outside the database, they reconstruct every version.
    async fn list_key_versions(&self) -> Result<Vec<sid_keys::KeyVersionParams>>;

    /// Record a key version's parameters. Returns `false`, writing nothing,
    /// when the version is already recorded; versions are never replaced.
    async fn insert_key_version(
        &self,
        params: &sid_keys::KeyVersionParams,
        audit: AuditEntry,
    ) -> Result<bool>;

    /// Every epoch with its key and every replacement of one owner, for an
    /// offline same-authority transfer; `None` when the owner has no epoch.
    async fn export_keys(&self, owner_domain: &[u8; 32]) -> Result<Option<KeyArchive>>;

    /// Install an owner's keys only when it has none. Exact existing content
    /// is an idempotent no-op; any difference is a `Conflict`, never a
    /// rollback or merge. Callers quiesce writers for an instance transfer.
    async fn import_keys(&self, archive: &KeyArchive, audit: AuditEntry) -> Result<bool>;
}
