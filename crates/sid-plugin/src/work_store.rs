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
    ClaimedWork, NewWork, WorkCompletion, WorkFailure, WorkId, WorkKind, WorkRecord, WorkSnapshot,
};

#[async_trait]
pub trait WorkStore: Send + Sync {
    /// Store `work`. Returns `false`, writing nothing, when work with its id
    /// already exists (the same obligation again). The backlog is not
    /// counted or bounded here: requests are limited where they enter, and a
    /// failure to store the work fails the call, never drops it.
    async fn enqueue_work(&self, work: &NewWork) -> Result<bool>;

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

    /// Record claimed work done, as [`Self::complete_work`] does, with the
    /// follow-up work `owed` in the same commit: both are stored or neither.
    /// Returns `false`, writing nothing, when `generation` is no longer the
    /// current claim. A child already stored is accepted again, as by
    /// [`Self::enqueue_work`].
    async fn complete_work_owing(
        &self,
        id: WorkId,
        generation: i64,
        result: Option<&str>,
        owed: &[NewWork],
    ) -> Result<bool>;

    /// Record several done attempts, each as [`Self::complete_work_owing`]
    /// does, fenced by its own claim: an item whose generation is no longer
    /// the current claim is refused alone (`false` at its position) and
    /// stores none of its owed work, even beside the current claim of the
    /// same work. A backend commits them in one transaction, so a batch is
    /// never recorded in part; an error still leaves the outcome unknown (a
    /// commit whose reply was lost recorded them all). The default, for
    /// stores without a transaction over several items, records them one by
    /// one: on an error the items before it may already be recorded.
    async fn complete_works(&self, works: &[WorkCompletion]) -> Result<Vec<bool>> {
        let mut done = Vec::with_capacity(works.len());
        for work in works {
            done.push(
                self.complete_work_owing(
                    work.id,
                    work.generation,
                    work.result.as_deref(),
                    &work.owed,
                )
                .await?,
            );
        }
        Ok(done)
    }

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

    /// Whether any work of `kind` is stored, in any state, until it is purged.
    /// The default reads every item; a backend that can ask for one answers
    /// with a query instead.
    async fn has_work_of_kind(&self, kind: &WorkKind) -> Result<bool> {
        Ok(self
            .export_work()
            .await?
            .iter()
            .any(|work| &work.record.kind == kind))
    }

    /// Every stored piece of work with its payload, to carry to another store.
    async fn export_work(&self) -> Result<Vec<WorkSnapshot>>;

    /// Store exported work as [`WorkSnapshot::at_rest`] gives it. Returns
    /// `false`, writing nothing, when work with its id already exists.
    async fn import_work(&self, work: &WorkSnapshot) -> Result<bool>;
}
