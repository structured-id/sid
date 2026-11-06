// SPDX-License-Identifier: AGPL-3.0-only
//! The storage conformance scenarios against SID's CoordiNode backend, over
//! a CoordiNode database in memory.
//!
//! Run with: cargo nextest run -p sid-storage --features storage-coordinode --test coordinode_integration
#![cfg(feature = "storage-coordinode")]

use std::sync::Arc;

use sid_storage::coordinode::CoordinodeBackend;

async fn setup() -> CoordinodeBackend {
    let db = coordinode_embed::Database::open_in_memory().expect("CoordiNode in memory");
    CoordinodeBackend::new(Arc::new(db))
        .await
        .expect("SID's schema in CoordiNode")
}

/// Run work store conformance `scenario` against this backend.
macro_rules! work_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test(flavor = "multi_thread")]
        async fn $scenario() {
            sid_plugin::conformance::work_store::$scenario(&setup().await).await;
        }
    )*};
}

mod work_store {
    use super::*;

    work_store!(
        enqueue_is_idempotent,
        concurrent_enqueue_stores_once,
        capacity_is_enforced_per_kind,
        capacity_holds_under_concurrency,
        ended_work_is_purged,
        work_of_a_kind_is_reported,
        live_lease_is_exclusive,
        lease_fences_stale_worker,
        retries_then_fails,
        dead_letter_alert_commits_with_failure,
        expired_and_future_are_not_claimed,
        abandoned_last_attempt_fails,
        concurrent_claims_do_not_overlap,
        export_import_round_trip,
    );
}
