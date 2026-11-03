// SPDX-License-Identifier: AGPL-3.0-only
//! Operation result capability: the committed completions of keyed
//! commands, so a retried command resolves to its original outcome.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sid_core::Result;
use sid_core::models::{
    IssuedOperationPeriod, MutationContext, OperationKey, OperationPeriodRecord, OperationRecord,
};

/// A keyed command's completion is admitted only under a period this store
/// issued and has not retired; a commit under any other refuses with
/// `Error::OperationPeriodRefused` and writes nothing.
#[async_trait]
pub trait OperationResultStore: Send + Sync {
    /// The period new keyed commands are named with: the latest issued one
    /// still accepting at `now`, else a new one, later than every period
    /// ever issued, accepting until `now + acceptance`. Every replica gets
    /// the same answer from the shared state.
    async fn current_operation_period(
        &self,
        now: DateTime<Utc>,
        acceptance: Duration,
    ) -> Result<IssuedOperationPeriod>;

    /// Retire every period whose acceptance ended before `before`, dropping
    /// the completions named with it in the same commit: from then on a
    /// command of that period is refused, never executed as new. A commit
    /// admitted under the period either finishes before the retirement or is
    /// refused. Returns how many periods were retired.
    async fn retire_operation_periods(&self, before: DateTime<Utc>) -> Result<u64>;

    /// Every period this store issued, to carry to another store with the
    /// completions named with them.
    async fn export_operation_periods(&self) -> Result<Vec<OperationPeriodRecord>>;

    /// Store an exported period. One already known keeps its state, except
    /// that a period retired at the source is retired here too; a retired
    /// period never becomes admitted again.
    async fn import_operation_period(&self, record: &OperationPeriodRecord) -> Result<()>;

    /// Commit `ctx` alone: its keyed command's completion, its audit entry
    /// and the work it owes, with no other state. A command that ends
    /// without changing anything else (a terminal abort) is recorded this
    /// way; when its key is already completed nothing is written and
    /// `Error::OperationCompleted` is returned.
    async fn record_outcome(&self, ctx: MutationContext) -> Result<()>;

    /// Drop the completions of `method` in `namespace` recorded before
    /// `before`, once their commands can no longer be retried or raced; the
    /// command's owner decides when. Returns how many were dropped.
    async fn purge_operation_results(
        &self,
        namespace: &str,
        method: &str,
        before: DateTime<Utc>,
    ) -> Result<u64>;

    /// Drop every completion whose retention ended by `now`
    /// ([`OperationCompletion::retain_until`]). Returns how many were dropped.
    ///
    /// [`OperationCompletion::retain_until`]: sid_core::models::OperationCompletion::retain_until
    async fn purge_expired_operation_results(&self, now: DateTime<Utc>) -> Result<u64>;

    /// The committed completion of the keyed command `key` in `namespace`
    /// (recorded through [`MutationContext::operation`]), if any; one past
    /// its retention is none, and its key takes a new outcome.
    async fn get_operation_result(
        &self,
        namespace: &str,
        key: &OperationKey,
    ) -> Result<Option<OperationRecord>>;

    /// Every committed completion, to carry to another store: a retry that
    /// arrives after a migration must still find its result.
    async fn export_operation_results(&self) -> Result<Vec<OperationRecord>>;

    /// Store an exported completion with its original completion time.
    /// Returns `false`, writing nothing, when its key is already completed in
    /// its namespace.
    async fn import_operation_result(&self, record: &OperationRecord) -> Result<bool>;
}
