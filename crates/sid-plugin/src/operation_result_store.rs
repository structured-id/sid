// SPDX-License-Identifier: AGPL-3.0-only
//! Operation result capability: the committed completions of keyed
//! commands, so a retried command resolves to its original outcome.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sid_core::Result;
use sid_core::models::{MutationContext, OperationKey, OperationRecord};

#[async_trait]
pub trait OperationResultStore: Send + Sync {
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

    /// The committed completion of the keyed command `key` in `namespace`
    /// (recorded through [`MutationContext::operation`]), if any.
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
