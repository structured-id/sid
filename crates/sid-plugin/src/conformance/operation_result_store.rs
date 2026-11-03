// SPDX-License-Identifier: AGPL-3.0-only
//! [`OperationResultStore`] scenarios: a keyed command completes once per key
//! within its namespace, its completion resolves later, survives a move to
//! another store, and is dropped only when its owner asks.

use sid_core::Error;
use sid_core::models::{AuditEntry, MutationContext, OperationCompletion, OperationKey};
use uuid::Uuid;

use crate::OperationResultStore;

fn key() -> OperationKey {
    OperationKey::parse(&Uuid::new_v4().to_string()).unwrap()
}

fn namespace() -> String {
    format!("conformance:{}", Uuid::now_v7())
}

/// An outcome of `method` for `key` in `namespace`, answering with `result`.
fn outcome(namespace: &str, key: &OperationKey, method: &str, result: &[u8]) -> MutationContext {
    MutationContext::from(AuditEntry::system("conformance", "operation_result")).with_operation(
        OperationCompletion::new(namespace, key.clone(), method, b"inputs", result.to_vec()),
    )
}

/// A recorded outcome resolves its key with its method, inputs and result;
/// another key and the same key in another namespace resolve to nothing.
pub async fn recorded_outcome_resolves(store: &dyn OperationResultStore) {
    let (ns, key) = (namespace(), key());
    store
        .record_outcome(outcome(&ns, &key, "abort", b"done"))
        .await
        .unwrap();
    let record = store
        .get_operation_result(&ns, &key)
        .await
        .unwrap()
        .expect("recorded");
    assert!(record.matches("abort", b"inputs", None));
    assert!(!record.matches("abort", b"other", None));
    assert_eq!(record.completion.result, b"done");
    assert!(
        store
            .get_operation_result(&ns, &self::key())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_operation_result(&namespace(), &key)
            .await
            .unwrap()
            .is_none()
    );
}

/// A second outcome for a completed key writes nothing and says so; the
/// first one stands.
pub async fn completed_key_records_nothing(store: &dyn OperationResultStore) {
    let (ns, key) = (namespace(), key());
    store
        .record_outcome(outcome(&ns, &key, "abort", b"first"))
        .await
        .unwrap();
    let err = store
        .record_outcome(outcome(&ns, &key, "commit", b"second"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::OperationCompleted(_)), "{err:?}");
    let record = store
        .get_operation_result(&ns, &key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.completion.method, "abort");
    assert_eq!(record.completion.result, b"first");
}

/// Two outcomes for one key at once: exactly one is recorded, the other is
/// refused as completed.
pub async fn concurrent_outcomes_record_once(store: &dyn OperationResultStore) {
    let (ns, key) = (namespace(), key());
    let (a, b) = tokio::join!(
        store.record_outcome(outcome(&ns, &key, "abort", b"a")),
        store.record_outcome(outcome(&ns, &key, "commit", b"b")),
    );
    assert_eq!(
        usize::from(a.is_ok()) + usize::from(b.is_ok()),
        1,
        "{a:?} {b:?}"
    );
    let loser = if a.is_ok() { b } else { a }.unwrap_err();
    assert!(matches!(loser, Error::OperationCompleted(_)), "{loser:?}");
    let record = store
        .get_operation_result(&ns, &key)
        .await
        .unwrap()
        .unwrap();
    let winner: &[u8] = if record.completion.method == "abort" {
        b"a"
    } else {
        b"b"
    };
    assert_eq!(record.completion.result, winner);
}

/// A completion leaves in the export and comes back through import with its
/// original time; importing it again writes nothing, and the imported key
/// refuses another outcome like any completed key.
pub async fn results_travel_between_stores(store: &dyn OperationResultStore) {
    let (ns, key) = (namespace(), key());
    store
        .record_outcome(outcome(&ns, &key, "commit", b"done"))
        .await
        .unwrap();
    let mine = store
        .export_operation_results()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.completion.namespace == ns && r.completion.key == key)
        .expect("exported");
    assert!(
        !store.import_operation_result(&mine).await.unwrap(),
        "an existing completion is kept"
    );

    let mut moved = mine.clone();
    moved.completion.namespace = namespace();
    moved.completed_at -= chrono::Duration::days(1);
    assert!(store.import_operation_result(&moved).await.unwrap());
    let restored = store
        .get_operation_result(&moved.completion.namespace, &key)
        .await
        .unwrap()
        .expect("imported");
    assert_eq!(restored.completion, moved.completion);
    assert_eq!(
        restored.completed_at.timestamp_millis(),
        moved.completed_at.timestamp_millis()
    );
    let err = store
        .record_outcome(outcome(&moved.completion.namespace, &key, "abort", b""))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::OperationCompleted(_)), "{err:?}");
}

/// A completion recorded with a retention end is kept no longer: past it the
/// key resolves to nothing, a new outcome for it is recorded, and the expired
/// purge drops it. A completion without one, or still within it, stays.
pub async fn a_result_is_kept_no_longer_than_its_retention(store: &dyn OperationResultStore) {
    let ns = namespace();
    let (expired, kept, unbounded) = (key(), key(), key());
    let now = chrono::Utc::now();
    let retained = |key: &OperationKey, until: chrono::DateTime<chrono::Utc>, result: &[u8]| {
        MutationContext::from(AuditEntry::system("conformance", "operation_result")).with_operation(
            OperationCompletion::new(&ns, key.clone(), "deliver", b"inputs", result.to_vec())
                .retained_until(until),
        )
    };
    store
        .record_outcome(retained(
            &expired,
            now - chrono::Duration::seconds(1),
            b"old",
        ))
        .await
        .unwrap();
    store
        .record_outcome(retained(&kept, now + chrono::Duration::hours(1), b"kept"))
        .await
        .unwrap();
    store
        .record_outcome(outcome(&ns, &unbounded, "deliver", b"unbounded"))
        .await
        .unwrap();

    assert!(
        store
            .get_operation_result(&ns, &expired)
            .await
            .unwrap()
            .is_none(),
        "an expired completion resolves to nothing"
    );
    let record = store
        .get_operation_result(&ns, &kept)
        .await
        .unwrap()
        .expect("within its retention");
    assert_eq!(
        record.completion.retain_until.map(|t| t.timestamp_millis()),
        Some((now + chrono::Duration::hours(1)).timestamp_millis())
    );
    assert!(
        store
            .get_operation_result(&ns, &unbounded)
            .await
            .unwrap()
            .is_some()
    );

    // The expired key is free again: its new outcome is recorded.
    store
        .record_outcome(retained(&expired, now + chrono::Duration::hours(1), b"new"))
        .await
        .unwrap();
    let renewed = store
        .get_operation_result(&ns, &expired)
        .await
        .unwrap()
        .expect("recorded again");
    assert_eq!(renewed.completion.result, b"new");

    let dropped = key();
    store
        .record_outcome(retained(&dropped, now - chrono::Duration::seconds(1), b""))
        .await
        .unwrap();
    assert!(
        store
            .purge_expired_operation_results(chrono::Utc::now())
            .await
            .unwrap()
            >= 1
    );
    let left: Vec<_> = store
        .export_operation_results()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.completion.namespace == ns)
        .map(|r| r.completion.key)
        .collect();
    assert!(!left.contains(&dropped), "the expired purge dropped it");
    assert!(left.contains(&kept) && left.contains(&unbounded) && left.contains(&expired));
}

/// The life of the periods keyed commands are admitted under, in one
/// scenario because periods are shared by the whole store: it works in a
/// window a month back that no other caller names.
///
/// - Concurrent callers get one period; it stays current while accepting,
///   and a later instant gets a newer one while the first still admits.
/// - A commit names an issued period or is refused, writing nothing.
/// - Retiring a period races a commit under it: the commit is either refused
///   or dropped with the period, never left behind; a retired period refuses
///   every later commit and is never issued again.
/// - Periods leave in the export; an import never un-retires a period, and
///   a period its source retired is retired here with its completions.
pub async fn operation_periods_bound_admission(store: &dyn OperationResultStore) {
    use chrono::{Duration, Utc};
    use sid_core::models::{
        IssuedOperationPeriod, OperationPeriod, OperationPeriodRecord, OperationPeriodRefusal,
        OperationPeriodState,
    };

    let policy = store.operation_period_policy().await.unwrap();
    assert!(policy.acceptance > Duration::zero() && policy.retention >= Duration::zero());
    let acceptance = Duration::hours(1);
    // After every period an earlier run of this scenario left, and well
    // before any period a caller with a real clock is issued.
    let horizon = Utc::now() - Duration::days(2);
    let t0 = store
        .export_operation_periods()
        .await
        .unwrap()
        .active
        .iter()
        .map(|p| p.issued.accepted_until)
        .filter(|until| *until < horizon)
        .max()
        .map_or(horizon - Duration::days(28), |until| {
            until + Duration::hours(1)
        });
    assert!(t0 + Duration::hours(4) < horizon, "the scenario's window");
    let (a, b) = tokio::join!(
        store.current_operation_period(t0, acceptance),
        store.current_operation_period(t0, acceptance),
    );
    let first = a.unwrap();
    assert_eq!(first, b.unwrap(), "concurrent callers share one period");
    assert_eq!(
        first.accepted_until.timestamp_millis(),
        (t0 + acceptance).timestamp_millis()
    );
    let still = store
        .current_operation_period(t0 + Duration::minutes(30), acceptance)
        .await
        .unwrap();
    assert_eq!(still.period, first.period, "current while accepting");
    let next = store
        .current_operation_period(t0 + Duration::hours(2), acceptance)
        .await
        .unwrap();
    assert!(next.period > first.period);

    let ns = namespace();
    let keyed = |key: &OperationKey, period: OperationPeriod| {
        MutationContext::from(AuditEntry::system("conformance", "operation_result")).with_operation(
            OperationCompletion::new(&ns, key.clone(), "keyed", b"inputs", b"done".to_vec())
                .in_period(period),
        )
    };
    let refused = |result: sid_core::Result<()>| match result {
        Err(Error::OperationPeriodRefused(refusal)) => refusal,
        other => panic!("expected a refused period, got {other:?}"),
    };

    // The earlier period still admits while the next one is current.
    let kept = key();
    store
        .record_outcome(keyed(&kept, first.period))
        .await
        .unwrap();
    let record = store
        .get_operation_result(&ns, &kept)
        .await
        .unwrap()
        .expect("recorded");
    assert_eq!(record.completion.period, Some(first.period));
    assert!(record.matches("keyed", b"inputs", Some(first.period)));
    assert!(!record.matches("keyed", b"inputs", Some(next.period)));

    let unissued = OperationPeriod::new(i64::MAX as u64);
    let stray = key();
    assert_eq!(
        refused(store.record_outcome(keyed(&stray, unissued)).await),
        OperationPeriodRefusal::NotIssued
    );
    assert!(
        store
            .get_operation_result(&ns, &stray)
            .await
            .unwrap()
            .is_none()
    );

    // A commit racing the retirement of its period.
    let racing = key();
    let (committed, retired) = tokio::join!(
        store.record_outcome(keyed(&racing, first.period)),
        store.retire_operation_periods(first.accepted_until + Duration::milliseconds(1)),
    );
    assert!(retired.unwrap() >= 1);
    if let Err(e) = committed {
        assert_eq!(refused(Err(e)), OperationPeriodRefusal::Retired);
    }
    for key in [&kept, &racing] {
        assert!(
            store
                .get_operation_result(&ns, key)
                .await
                .unwrap()
                .is_none(),
            "a retired period's completions go with it"
        );
    }
    assert_eq!(
        refused(store.record_outcome(keyed(&key(), first.period)).await),
        OperationPeriodRefusal::Retired
    );
    // A completion carried from another store under a period retired here
    // is not taken: its command is refused here anyway.
    let carried = sid_core::models::OperationRecord {
        completion: OperationCompletion::new(&ns, key(), "keyed", b"inputs", b"done".to_vec())
            .in_period(first.period),
        completed_at: Utc::now(),
    };
    assert!(!store.import_operation_result(&carried).await.unwrap());
    // Asked before a command's first effect, the store answers the same.
    store.admit_operation_period(next.period).await.unwrap();
    assert_eq!(
        refused(store.admit_operation_period(first.period).await),
        OperationPeriodRefusal::Retired
    );
    assert_eq!(
        refused(store.admit_operation_period(unissued).await),
        OperationPeriodRefusal::NotIssued
    );
    let reissued = store
        .current_operation_period(t0 + Duration::minutes(30), acceptance)
        .await
        .unwrap();
    assert!(
        reissued.period > next.period,
        "a retired period is never current again"
    );

    // Periods travel with their state. The export holds the admitted ones
    // and the last issued; a retired one is neither.
    let exported = store.export_operation_periods().await.unwrap();
    let held = |state: &OperationPeriodState, period: OperationPeriod| {
        state.active.iter().any(|p| p.issued.period == period)
    };
    assert!(exported.issued_through >= reissued.period);
    assert!(!held(&exported, first.period));
    assert!(held(&exported, next.period) && held(&exported, reissued.period));

    // An import that names a period this store retired as admitted leaves
    // it retired; one whose source retired `next` retires it here, with its
    // completions; a period issued only at the source is admitted.
    let pending = key();
    store
        .record_outcome(keyed(&pending, next.period))
        .await
        .unwrap();
    let source_record =
        |period: OperationPeriod, until: chrono::DateTime<Utc>| OperationPeriodRecord {
            issued: IssuedOperationPeriod {
                period,
                accepted_until: until,
            },
            issued_at: t0,
        };
    // The number right after the last issued: a caller that takes it here
    // meanwhile keeps it, as the import names it admitted.
    let foreign = OperationPeriod::new(exported.issued_through.get() + 1);
    let mut active: Vec<OperationPeriodRecord> = exported
        .active
        .iter()
        .filter(|p| p.issued.period != next.period)
        .copied()
        .collect();
    active.push(source_record(first.period, first.accepted_until));
    active.push(source_record(foreign, t0 + Duration::minutes(10)));
    store
        .import_operation_periods(&OperationPeriodState {
            issued_through: foreign,
            active,
        })
        .await
        .unwrap();
    let after = store.export_operation_periods().await.unwrap();
    assert!(
        !held(&after, first.period),
        "a retired period stays retired"
    );
    assert!(!held(&after, next.period), "retired with the source");
    assert!(
        store
            .get_operation_result(&ns, &pending)
            .await
            .unwrap()
            .is_none(),
        "with its completions"
    );
    assert_eq!(
        refused(store.record_outcome(keyed(&key(), next.period)).await),
        OperationPeriodRefusal::Retired
    );
    assert!(held(&after, foreign) && held(&after, reissued.period));
    assert!(after.issued_through >= foreign);
    store.record_outcome(keyed(&key(), foreign)).await.unwrap();
}

/// Completions of one method in one namespace are dropped once older than
/// asked; another method's and another namespace's stay.
pub async fn results_are_purged_by_method(store: &dyn OperationResultStore) {
    let ns = namespace();
    let (aborted, committed, theirs) = (key(), key(), key());
    let elsewhere = namespace();
    store
        .record_outcome(outcome(&ns, &aborted, "abort", b""))
        .await
        .unwrap();
    store
        .record_outcome(outcome(&ns, &committed, "commit", b""))
        .await
        .unwrap();
    store
        .record_outcome(outcome(&elsewhere, &theirs, "abort", b""))
        .await
        .unwrap();

    let earlier = chrono::Utc::now() - chrono::Duration::hours(1);
    assert_eq!(
        store
            .purge_operation_results(&ns, "abort", earlier)
            .await
            .unwrap(),
        0
    );
    let later = chrono::Utc::now() + chrono::Duration::seconds(5);
    assert_eq!(
        store
            .purge_operation_results(&ns, "abort", later)
            .await
            .unwrap(),
        1
    );
    let found = async |ns: &str, key: &OperationKey| {
        store.get_operation_result(ns, key).await.unwrap().is_some()
    };
    assert!(!found(&ns, &aborted).await);
    assert!(found(&ns, &committed).await, "another method's");
    assert!(found(&elsewhere, &theirs).await, "another namespace's");
}
