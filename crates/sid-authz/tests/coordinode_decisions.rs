// SPDX-License-Identifier: AGPL-3.0-only
//! The CE engine's decisions over SID's CoordiNode backend, a CoordiNode
//! database in memory, in process.

mod decisions;

use std::sync::Arc;

use sid_plugin::StorageBackend;
use sid_storage::coordinode::CoordinodeBackend;

async fn run<F, Fut>(scenario: F)
where
    F: FnOnce(Arc<dyn StorageBackend>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let db = Arc::new(coordinode_embed::Database::open_in_memory().expect("CoordiNode in memory"));
    let backend = CoordinodeBackend::new(db)
        .await
        .expect("SID's schema in CoordiNode");
    scenario(Arc::new(backend)).await;
}

decision_scenarios!(run);
