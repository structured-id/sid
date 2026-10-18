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
    assert!(record.matches("abort", b"inputs"));
    assert!(!record.matches("abort", b"other"));
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
