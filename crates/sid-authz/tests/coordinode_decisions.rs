// SPDX-License-Identifier: AGPL-3.0-only
//! The CE engine's decisions over SID's CoordiNode backend, each over a copy
//! of the store with SID's schema the run prepared once, in process.

mod decisions;

use std::sync::Arc;

use sid_plugin::StorageBackend;

async fn run<F, Fut>(scenario: F)
where
    F: FnOnce(Arc<dyn StorageBackend>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let copy = sid_storage::testing::isolated_coordinode().await;
    scenario(Arc::new(copy.backend.clone())).await;
}

decision_scenarios!(run);
