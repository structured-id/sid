// SPDX-License-Identifier: AGPL-3.0-only
//! [`CeremonyStateStore`] scenarios: state is taken once across concurrent
//! callers, expires on the store's clock at use, is replaced only from what
//! was read, and a key is admitted once while its admission lives.

use std::time::Duration;

use uuid::Uuid;

use crate::CeremonyStateStore;

const LONG: Duration = Duration::from_secs(300);
const SHORT: Duration = Duration::from_millis(1500);

fn namespace() -> String {
    format!("conformance:{}", Uuid::now_v7())
}

fn key() -> String {
    Uuid::new_v4().to_string()
}

/// Stored state reads back, is taken once, and is gone after the take; the
/// same key in another namespace holds nothing.
pub async fn state_is_taken_once(store: &dyn CeremonyStateStore) {
    let (ns, key) = (namespace(), key());
    store
        .put_ceremony_state(&ns, &key, b"server state", LONG)
        .await
        .unwrap();
    assert_eq!(
        store
            .read_ceremony_state(&ns, &key)
            .await
            .unwrap()
            .as_deref(),
        Some(&b"server state"[..])
    );
    assert!(
        store
            .read_ceremony_state(&namespace(), &key)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .take_ceremony_state(&ns, &key)
            .await
            .unwrap()
            .as_deref(),
        Some(&b"server state"[..])
    );
    assert!(
        store
            .take_ceremony_state(&ns, &key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .read_ceremony_state(&ns, &key)
            .await
            .unwrap()
            .is_none()
    );
}

/// Of many concurrent takers of one state exactly one gets it: a challenge
/// finishes one ceremony, however many replicas race for it.
pub async fn concurrent_takers_get_it_once(store: &dyn CeremonyStateStore) {
    let (ns, key) = (namespace(), key());
    store
        .put_ceremony_state(&ns, &key, b"challenge", LONG)
        .await
        .unwrap();
    let takes =
        futures::future::join_all((0..16).map(|_| store.take_ceremony_state(&ns, &key))).await;
    let won = takes
        .into_iter()
        .map(|t| t.unwrap())
        .filter(Option::is_some)
        .count();
    assert_eq!(won, 1);
}

/// Expired state is refused at use, before any cleanup removed it, and a
/// purge then drops it.
pub async fn expired_state_is_refused_at_use(store: &dyn CeremonyStateStore) {
    let (ns, key) = (namespace(), key());
    store
        .put_ceremony_state(&ns, &key, b"stale", SHORT)
        .await
        .unwrap();
    tokio::time::sleep(SHORT + Duration::from_millis(500)).await;
    assert!(
        store
            .read_ceremony_state(&ns, &key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !store
            .replace_ceremony_state(&ns, &key, b"stale", b"revived", LONG)
            .await
            .unwrap()
    );
    assert!(
        store
            .take_ceremony_state(&ns, &key)
            .await
            .unwrap()
            .is_none()
    );
    store.purge_expired_ceremony_state().await.unwrap();
}

/// Storing again replaces the value and its lifetime.
pub async fn put_replaces(store: &dyn CeremonyStateStore) {
    let (ns, key) = (namespace(), key());
    store
        .put_ceremony_state(&ns, &key, b"first", SHORT)
        .await
        .unwrap();
    store
        .put_ceremony_state(&ns, &key, b"second", LONG)
        .await
        .unwrap();
    tokio::time::sleep(SHORT + Duration::from_millis(500)).await;
    assert_eq!(
        store
            .take_ceremony_state(&ns, &key)
            .await
            .unwrap()
            .as_deref(),
        Some(&b"second"[..])
    );
}

/// A replacement applies only to exactly what was read: a writer that read
/// an older value, or one another writer removed, changes nothing.
pub async fn replace_applies_only_to_what_was_read(store: &dyn CeremonyStateStore) {
    let (ns, key) = (namespace(), key());
    store
        .put_ceremony_state(&ns, &key, b"step 1", LONG)
        .await
        .unwrap();
    assert!(
        store
            .replace_ceremony_state(&ns, &key, b"step 1", b"step 2", LONG)
            .await
            .unwrap()
    );
    assert!(
        !store
            .replace_ceremony_state(&ns, &key, b"step 1", b"step 2 again", LONG)
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .read_ceremony_state(&ns, &key)
            .await
            .unwrap()
            .as_deref(),
        Some(&b"step 2"[..])
    );
    store.take_ceremony_state(&ns, &key).await.unwrap();
    assert!(
        !store
            .replace_ceremony_state(&ns, &key, b"step 2", b"resurrected", LONG)
            .await
            .unwrap()
    );
    assert!(
        store
            .read_ceremony_state(&ns, &key)
            .await
            .unwrap()
            .is_none()
    );
}

/// Of many concurrent replacements from one read exactly one applies.
pub async fn concurrent_replacements_apply_once(store: &dyn CeremonyStateStore) {
    let (ns, key) = (namespace(), key());
    store
        .put_ceremony_state(&ns, &key, b"read", LONG)
        .await
        .unwrap();
    let values: Vec<Vec<u8>> = (0..16u8).map(|i| vec![i]).collect();
    let applied = futures::future::join_all(
        values
            .iter()
            .map(|v| store.replace_ceremony_state(&ns, &key, b"read", v, LONG)),
    )
    .await
    .into_iter()
    .map(|r| r.unwrap())
    .filter(|applied| *applied)
    .count();
    assert_eq!(applied, 1);
}

/// A key is admitted once while its admission lives, in its namespace only;
/// once expired it is admitted again.
pub async fn key_is_admitted_once(store: &dyn CeremonyStateStore) {
    let (ns, key) = (namespace(), key());
    assert!(store.admit_once(&ns, &key, SHORT).await.unwrap());
    assert!(!store.admit_once(&ns, &key, SHORT).await.unwrap());
    assert!(store.admit_once(&namespace(), &key, SHORT).await.unwrap());
    tokio::time::sleep(SHORT + Duration::from_millis(500)).await;
    assert!(store.admit_once(&ns, &key, LONG).await.unwrap());
    assert!(!store.admit_once(&ns, &key, LONG).await.unwrap());
}

/// A key admitted for a holder is confirmed to that holder and refused to
/// any other while it lives; a confirmation does not extend it, and once it
/// expires another holder takes it.
pub async fn admission_is_confirmed_only_to_its_holder(store: &dyn CeremonyStateStore) {
    let (ns, key) = (namespace(), key());
    assert!(
        store
            .admit_for(&ns, &key, b"request-1", SHORT)
            .await
            .unwrap()
    );
    assert!(
        store
            .admit_for(&ns, &key, b"request-1", LONG)
            .await
            .unwrap()
    );
    assert!(
        !store
            .admit_for(&ns, &key, b"request-2", LONG)
            .await
            .unwrap()
    );
    assert!(
        store
            .admit_for(&namespace(), &key, b"request-2", LONG)
            .await
            .unwrap()
    );
    // The confirmation asked for LONG, yet the first deadline stands.
    tokio::time::sleep(SHORT + Duration::from_millis(500)).await;
    assert!(
        store
            .admit_for(&ns, &key, b"request-2", LONG)
            .await
            .unwrap()
    );
    assert!(
        !store
            .admit_for(&ns, &key, b"request-1", LONG)
            .await
            .unwrap()
    );
}

/// Of many concurrent holders admitting one key exactly one holds it, and it
/// is confirmed to that one alone.
pub async fn concurrent_holders_admit_once(store: &dyn CeremonyStateStore) {
    let (ns, key) = (namespace(), key());
    let holders: Vec<Vec<u8>> = (0..16u8).map(|i| vec![i]).collect();
    let held: Vec<bool> = futures::future::join_all(
        holders
            .iter()
            .map(|holder| store.admit_for(&ns, &key, holder, LONG)),
    )
    .await
    .into_iter()
    .map(|r| r.unwrap())
    .collect();
    assert_eq!(held.iter().filter(|held| **held).count(), 1);
    let winner = &holders[held.iter().position(|held| *held).unwrap()];
    assert!(store.admit_for(&ns, &key, winner, LONG).await.unwrap());
}

/// Events in one window add up, per key and namespace; the first event after
/// the window ends starts a new count at 1.
pub async fn events_count_within_their_window(store: &dyn CeremonyStateStore) {
    let (ns, key) = (namespace(), key());
    assert_eq!(store.count_in_window(&ns, &key, SHORT).await.unwrap(), 1);
    assert_eq!(store.count_in_window(&ns, &key, SHORT).await.unwrap(), 2);
    assert_eq!(store.count_in_window(&ns, &key, SHORT).await.unwrap(), 3);
    assert_eq!(
        store
            .count_in_window(&namespace(), &key, SHORT)
            .await
            .unwrap(),
        1
    );
    tokio::time::sleep(SHORT + Duration::from_millis(500)).await;
    assert_eq!(store.count_in_window(&ns, &key, LONG).await.unwrap(), 1);
}

/// Concurrent events are each counted once: the counts handed out are
/// exactly 1..=n, so a limit of n admits n events across every replica.
pub async fn concurrent_events_are_counted_once(store: &dyn CeremonyStateStore) {
    let (ns, key) = (namespace(), key());
    let mut counts: Vec<u64> =
        futures::future::join_all((0..16).map(|_| store.count_in_window(&ns, &key, LONG)))
            .await
            .into_iter()
            .map(|c| c.unwrap())
            .collect();
    counts.sort_unstable();
    assert_eq!(counts, (1..=16).collect::<Vec<u64>>());
}

/// Of many concurrent admissions of one key exactly one succeeds: a replayed
/// token is refused on every replica but one.
pub async fn concurrent_admissions_succeed_once(store: &dyn CeremonyStateStore) {
    let (ns, key) = (namespace(), key());
    let admitted = futures::future::join_all((0..16).map(|_| store.admit_once(&ns, &key, LONG)))
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .filter(|admitted| *admitted)
        .count();
    assert_eq!(admitted, 1);
}
