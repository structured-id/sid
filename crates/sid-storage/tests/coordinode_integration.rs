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

/// Run operation result conformance `scenario`; each one uses namespaces of
/// its own.
macro_rules! operation_result_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test(flavor = "multi_thread")]
        async fn $scenario() {
            sid_plugin::conformance::operation_result_store::$scenario(&setup().await).await;
        }
    )*};
}

mod operation_result_store {
    use super::*;

    operation_result_store!(
        recorded_outcome_resolves,
        completed_key_records_nothing,
        concurrent_outcomes_record_once,
        results_travel_between_stores,
        results_are_purged_by_method,
        a_result_is_kept_no_longer_than_its_retention,
        operation_periods_bound_admission,
        a_keyed_creation_binds_one_identifier,
        a_bound_key_completes_only_its_own_command,
        a_binding_lives_with_its_completion,
        bindings_travel_between_stores,
    );
}

/// The race `operation_periods_bound_admission` runs once, many times over:
/// commits under a period racing its retirement are each refused or dropped
/// with it, never left behind. CoordiNode checks only writes and pinned reads
/// at commit, so this is the race its snapshot isolation could lose.
#[tokio::test(flavor = "multi_thread")]
async fn commits_racing_retirement_are_never_left_behind() {
    use chrono::{Duration, Utc};
    use sid_core::models::{
        AuditEntry, MutationContext, OperationCompletion, OperationKey, OperationPeriodRefusal,
    };
    use sid_plugin::OperationResultStore;

    let store = setup().await;
    let t0 = Utc::now() - Duration::days(30);
    for round in 0..16 {
        let at = t0 + Duration::hours(2 * round);
        let period = store
            .current_operation_period(at, Duration::hours(1))
            .await
            .unwrap();
        let ns = format!("race:{round}");
        let keys: Vec<OperationKey> = (0..4)
            .map(|_| OperationKey::parse(&uuid::Uuid::new_v4().to_string()).unwrap())
            .collect();
        let commit = |key: &OperationKey| {
            store.record_outcome(
                MutationContext::from(AuditEntry::system("race", "operation_result"))
                    .with_operation(
                        OperationCompletion::new(&ns, key.clone(), "keyed", b"in", vec![])
                            .in_period(period.period),
                    ),
            )
        };
        let (commits, retired) = tokio::join!(
            futures::future::join_all(keys.iter().map(commit)),
            store.retire_operation_periods(period.accepted_until + Duration::milliseconds(1)),
        );
        assert!(retired.unwrap() >= 1);
        for result in commits {
            if let Err(e) = result {
                assert!(
                    matches!(
                        e,
                        sid_core::Error::OperationPeriodRefused(OperationPeriodRefusal::Retired)
                    ),
                    "{e:?}"
                );
            }
        }
        for key in &keys {
            assert!(
                store
                    .get_operation_result(&ns, key)
                    .await
                    .unwrap()
                    .is_none(),
                "round {round}: a completion outlived its retired period"
            );
        }
        assert!(
            !store
                .export_operation_results()
                .await
                .unwrap()
                .iter()
                .any(|r| r.completion.namespace == ns),
            "round {round}: exported under a retired period"
        );
    }
}

mod audit_chain {
    use super::*;
    use sid_plugin::conformance::backend;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_audit_chain_links_records() {
        backend::audit_chain::test_audit_chain_links_records(&setup().await).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_audit_chains_are_independent() {
        backend::audit_chain::test_audit_chains_are_independent(&setup().await).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_audit_chain_concurrent_appends() {
        backend::test_audit_chain_concurrent_appends(Arc::new(setup().await)).await;
    }
}
