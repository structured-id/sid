// SPDX-License-Identifier: AGPL-3.0-only
//! The CE engine's decisions over SQLite, in memory and in process.

mod decisions;

use std::sync::Arc;

use sid_plugin::StorageBackend;
use sid_storage::sqlite::SqliteBackend;

async fn store() -> Arc<SqliteBackend> {
    Arc::new(
        SqliteBackend::new_in_memory()
            .await
            .expect("in-memory SQLite"),
    )
}

async fn run<F, Fut>(scenario: F)
where
    F: FnOnce(Arc<dyn StorageBackend>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    scenario(store().await).await;
}

decision_scenarios!(run);

#[tokio::test]
async fn an_unreachable_store_never_allows() {
    let storage = store().await;
    let pool = storage.pool().clone();
    decisions::an_unreachable_store_never_allows(storage, async move { pool.close().await }).await;
}
