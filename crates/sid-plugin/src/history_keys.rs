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
    AuditEntry, HistoryEpochId, HistoryPreparation, KeyArchive, KeyEpoch, KeyEpochs, NewKeyEpoch,
    WrappedHistoryKey,
};

#[async_trait]
pub trait HistoryKeyStore: Send + Sync {
    /// Every epoch not retired of the owner of `owner_domain`; empty when it
    /// has none.
    async fn get_key_epochs(&self, owner_domain: &[u8; 32]) -> Result<KeyEpochs>;

    /// Store `new` as a new owner's first epoch with its sealed key, before
    /// the key's first use. An owner that already has any epoch is a
    /// `Conflict`, unless it is this very epoch (an exact retry): a new owner
    /// never resets an existing history or gets a parallel first epoch.
    async fn create_first_epoch(&self, new: &NewKeyEpoch, audit: AuditEntry) -> Result<KeyEpoch>;

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

    /// Every epoch with its key and every replacement of one owner, for an
    /// offline same-authority transfer; `None` when the owner has no epoch.
    async fn export_keys(&self, owner_domain: &[u8; 32]) -> Result<Option<KeyArchive>>;

    /// Install an owner's keys only when it has none. Exact existing content
    /// is an idempotent no-op; any difference is a `Conflict`, never a
    /// rollback or merge. Callers quiesce writers for an instance transfer.
    async fn import_keys(&self, archive: &KeyArchive, audit: AuditEntry) -> Result<bool>;
}
