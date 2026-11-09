// SPDX-License-Identifier: AGPL-3.0-only
//! Operation result capability: the committed completions of keyed
//! commands, so a retried command resolves to its original outcome.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sid_core::Result;
use sid_core::models::{
    IssuedOperationPeriod, MutationContext, OperationKey, OperationPeriod, OperationPeriodPolicy,
    OperationPeriodState, OperationRecord, OperationResourceBinding,
};
use uuid::Uuid;

/// A keyed command's completion is admitted only under a period this store
/// issued and has not retired; a commit under any other refuses with
/// `Error::OperationPeriodRefused` and writes nothing.
#[async_trait]
pub trait OperationResultStore: Send + Sync {
    /// The persisted policy every replica issues and retires periods under.
    async fn operation_period_policy(&self) -> Result<OperationPeriodPolicy>;

    /// The period new keyed commands are named with: the latest issued one
    /// still accepting at `now`, else a new one, later than every period
    /// ever issued (retired ones included), accepting until
    /// `now + acceptance`. Every replica gets the same answer from the shared
    /// state.
    async fn current_operation_period(
        &self,
        now: DateTime<Utc>,
        acceptance: Duration,
    ) -> Result<IssuedOperationPeriod>;

    /// Whether the store admits a command named with `period`, asked before
    /// a command's first effect: `Error::OperationPeriodRefused` when it is
    /// retired or never issued. The commit decides again in its own
    /// transaction.
    async fn admit_operation_period(&self, period: OperationPeriod) -> Result<()>;

    /// Retire every period whose acceptance ended before `before`, dropping
    /// the completions named with it in the same commit: from then on a
    /// command of that period is refused, never executed as new. A commit
    /// admitted under the period either finishes before the retirement or is
    /// refused. Returns how many periods were retired.
    async fn retire_operation_periods(&self, before: DateTime<Utc>) -> Result<u64>;

    /// The last period issued and the periods still admitted, to carry to
    /// another store with the completions named with them.
    async fn export_operation_periods(&self) -> Result<OperationPeriodState>;

    /// Take an exported period state: a period either store retired stays
    /// retired here, with its local completions dropped; an exported period
    /// still admitted at the source and not retired here is admitted; the
    /// last issued period moves to the later of the two.
    async fn import_operation_periods(&self, state: &OperationPeriodState) -> Result<()>;

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

    /// The resource identifier of the keyed creation `proposal` names:
    /// `proposal.resource` when this call binds the key first, else the one an
    /// earlier attempt of the same command bound. Concurrent attempts resolve
    /// one binding. The key bound or completed for another method, other
    /// inputs or another period is `Error::OperationKeyReused`, binding
    /// nothing; a key whose completion's retention ended takes a new binding.
    /// A keyed command's period is admitted first, like its commit. The
    /// binding is durable when this returns, before the creation's first
    /// effect outside this store.
    async fn bind_operation_resource(&self, proposal: &OperationResourceBinding) -> Result<Uuid>;

    /// Drop the bindings of `method` made under periods since retired and
    /// holding no completion: commands of that method can no longer run
    /// again, and their owner keeps nothing to reconcile from them (a message
    /// a provider was asked to send). A creation's unfinished binding is kept
    /// unless its owner asks. Returns how many were dropped.
    async fn drop_unfinished_bindings(&self, method: &str) -> Result<u64>;

    /// Every binding still held, to carry to another store with the
    /// completions: a creation resumed after a migration must find its
    /// identifier.
    async fn export_operation_resources(&self) -> Result<Vec<OperationResourceBinding>>;

    /// Store an exported binding. Returns `false`, writing nothing, when its
    /// key is already bound in its namespace or its period is not admitted
    /// here.
    async fn import_operation_resource(&self, binding: &OperationResourceBinding) -> Result<bool>;
}
