// SPDX-License-Identifier: AGPL-3.0-only
//! The CE engine's decisions over PostgreSQL (port 54399), in process. Each
//! scenario runs in an installation of its own, a copy of the database the
//! run migrated once: installation-wide policies would otherwise reach the
//! tests sharing the database.

mod decisions;

use std::sync::Arc;

use sid_plugin::StorageBackend;
use sid_storage::testing::{drop_isolated_postgres, isolated_postgres};

async fn run<F, Fut>(scenario: F)
where
    F: FnOnce(Arc<dyn StorageBackend>) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let backend = isolated_postgres().await;
    let outcome = tokio::spawn(scenario(Arc::new(backend.clone()))).await;
    drop_isolated_postgres(&backend).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}

decision_scenarios!(run);

#[tokio::test]
async fn an_unreachable_store_never_allows() {
    let backend = isolated_postgres().await;
    let pool = backend.pool().clone();
    let outcome = tokio::spawn(decisions::an_unreachable_store_never_allows(
        Arc::new(backend.clone()),
        async move { pool.close().await },
    ))
    .await;
    drop_isolated_postgres(&backend).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}
