// SPDX-License-Identifier: AGPL-3.0-only
//! Durable work capability: required work stored, claimed by one worker at a
//! time under a fenced lease, retried, and ended in a recorded outcome.
//!
//! A state owner that owes work adds it inside its own transaction through its
//! backend; the methods here cover work accepted on its own (an inbound event,
//! a fan-out) and the worker side. Attempts, errors and outcomes are recorded
//! on the work itself.

use async_trait::async_trait;
use sid_core::Result;
use sid_core::models::{
    ClaimedWork, NewWork, WorkFailure, WorkId, WorkKind, WorkRecord, WorkSnapshot,
};

#[async_trait]
pub trait WorkStore: Send + Sync {
    /// Store `work`. Returns `false`, writing nothing, when work with its id
    /// already exists (the same obligation again), whatever the load. When
    /// `capacity` pending or claimed items of its kind are stored the work is
    /// refused with `Error::ResourceExhausted`, never dropped after acceptance;
    /// the bound is per kind so one backlog cannot starve others, and it holds
    /// exactly however many replicas enqueue at once. (Work a mutation owes in
    /// its own transaction is bounded only as a safety net.)
    async fn enqueue_work(&self, work: &NewWork, capacity: u64) -> Result<bool>;

    /// Claim up to `limit` due work of `kinds` for `worker`, leased for
    /// `lease`. Work whose lease ran out is claimable again, with a new
    /// generation; work past its expiry is recorded expired and not returned;
    /// abandoned work with no attempts left is recorded failed.
    async fn claim_work(
        &self,
        kinds: &[WorkKind],
        worker: &str,
        limit: u32,
        lease: std::time::Duration,
    ) -> Result<Vec<ClaimedWork>>;

    /// Record that claimed work was done, with what it produced. Returns
    /// `false`, writing nothing, when `generation` is no longer the current claim.
    async fn complete_work(
        &self,
        id: WorkId,
        generation: i64,
        result: Option<&str>,
    ) -> Result<bool>;

    /// Record a failed attempt: the work is due again at `failure.retry_at`,
    /// or failed (dead-letter) when that is `None` or no attempts remain, in
    /// which case `failure.on_dead` is enqueued in the same transaction.
    /// Returns `false`, writing nothing, when `generation` is no longer the
    /// current claim.
    async fn fail_work(&self, id: WorkId, generation: i64, failure: &WorkFailure) -> Result<bool>;

    /// The stored record of a piece of work.
    async fn get_work(&self, id: WorkId) -> Result<Option<WorkRecord>>;

    /// Drop work of `kind` that ended (completed, failed, expired or
    /// cancelled) before `before`; open work is never touched. Its kind's
    /// owner decides when an ended item is no longer needed. Returns how
    /// many were dropped.
    async fn purge_ended_work(
        &self,
        kind: &WorkKind,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64>;

    /// Every stored piece of work with its payload, to carry to another store.
    async fn export_work(&self) -> Result<Vec<WorkSnapshot>>;

    /// Store exported work as [`WorkSnapshot::at_rest`] gives it, outside any
    /// capacity (it was accepted where it came from). Returns `false`, writing
    /// nothing, when work with its id already exists.
    async fn import_work(&self, work: &WorkSnapshot) -> Result<bool>;
}
