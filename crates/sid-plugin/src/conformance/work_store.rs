// SPDX-License-Identifier: AGPL-3.0-only
//! [`WorkStore`] scenarios: durable work admission, leases, retries, failure
//! and export. Each scenario uses its own work kind, so scenarios sharing one
//! database never see each other's work.

use chrono::{DateTime, Duration, Utc};
use sid_core::Error;
use sid_core::models::{NewWork, WorkFailure, WorkId, WorkKind, WorkState};
use std::collections::HashSet;
use std::slice::from_ref;
use std::time::Duration as StdDuration;
use uuid::Uuid;

use crate::WorkStore;

const LEASE: StdDuration = StdDuration::from_secs(60);
const SHORT_LEASE: StdDuration = StdDuration::from_millis(300);
const PAST_SHORT_LEASE: StdDuration = StdDuration::from_millis(450);

fn unique_kind(scenario: &str) -> WorkKind {
    WorkKind::new(&format!("test.{scenario}.{}", Uuid::now_v7().simple()))
        .expect("a valid work kind")
}

fn work(kind: &WorkKind) -> NewWork {
    NewWork::new(kind.clone(), b"payload".to_vec())
}

fn retry(error: &str, at: DateTime<Utc>) -> WorkFailure {
    WorkFailure {
        error: error.to_string(),
        ambiguous: false,
        retry_at: Some(at),
        on_dead: None,
    }
}

/// The same work enqueued twice is stored once, and a repeat is accepted even
/// when the kind is at capacity: a retried command owes nothing new.
pub async fn enqueue_is_idempotent(store: &dyn WorkStore) {
    let kind = unique_kind("dedup");
    let item = work(&kind);
    assert!(store.enqueue_work(&item, 1).await.unwrap());
    assert!(
        !store.enqueue_work(&item, 1).await.unwrap(),
        "the same obligation was stored twice or refused at capacity"
    );

    let record = store.get_work(item.id).await.unwrap().unwrap();
    assert_eq!(record.state, WorkState::Pending);
    assert_eq!(record.attempts, 0);
    assert_eq!(record.kind, kind);
    assert!(!record.ambiguous);
    assert!(record.result.is_none());
    assert_eq!(
        store
            .claim_work(&[kind], "w", 10, LEASE)
            .await
            .unwrap()
            .len(),
        1
    );
}

/// The same obligation enqueued concurrently is stored exactly once.
pub async fn concurrent_enqueue_stores_once(store: &dyn WorkStore) {
    let kind = unique_kind("concurrent_enqueue");
    let item = work(&kind);
    let enqueue = || store.enqueue_work(&item, 10);
    let (a, b, c) = tokio::join!(enqueue(), enqueue(), enqueue());
    let stored = [a, b, c]
        .into_iter()
        .map(|r| r.unwrap())
        .filter(|inserted| *inserted)
        .count();
    assert_eq!(stored, 1);
    assert_eq!(
        store
            .claim_work(&[kind], "w", 10, LEASE)
            .await
            .unwrap()
            .len(),
        1
    );
}

/// A kind holding `capacity` open items refuses more work explicitly; once an
/// item is done, there is room again. Other kinds are not affected.
pub async fn capacity_is_enforced_per_kind(store: &dyn WorkStore) {
    let kind = unique_kind("capacity");
    for _ in 0..2 {
        assert!(store.enqueue_work(&work(&kind), 2).await.unwrap());
    }
    let refused = store.enqueue_work(&work(&kind), 2).await;
    assert!(
        matches!(refused, Err(Error::ResourceExhausted(_))),
        "a full queue accepted work: {refused:?}"
    );
    let other = unique_kind("capacity_other");
    assert!(store.enqueue_work(&work(&other), 2).await.unwrap());

    let claimed = store
        .claim_work(from_ref(&kind), "w", 1, LEASE)
        .await
        .unwrap();
    assert!(
        store
            .complete_work(claimed[0].id, claimed[0].generation, None)
            .await
            .unwrap()
    );
    assert!(store.enqueue_work(&work(&kind), 2).await.unwrap());
}

/// Work enqueued on its own at once (replicas admitting it together) never
/// exceeds its kind's capacity: exactly the capacity is accepted.
pub async fn capacity_holds_under_concurrency(store: &dyn WorkStore) {
    for _ in 0..10 {
        let kind = unique_kind("capacity_race");
        let items: Vec<NewWork> = (0..64).map(|_| work(&kind)).collect();
        let results =
            futures::future::join_all(items.iter().map(|item| store.enqueue_work(item, 5))).await;
        let accepted = results.iter().filter(|r| matches!(r, Ok(true))).count();
        assert_eq!(accepted, 5, "{results:?}");
        assert!(
            results
                .iter()
                .filter(|r| !matches!(r, Ok(true)))
                .all(|r| matches!(r, Err(Error::ResourceExhausted(_)))),
            "{results:?}"
        );
    }
}

/// Ended work of a kind is dropped once older than asked; open work, newer
/// ended work and other kinds stay.
pub async fn ended_work_is_purged(store: &dyn WorkStore) {
    let kind = unique_kind("purge");
    let (done, open) = (work(&kind), work(&kind));
    store.enqueue_work(&done, 10).await.unwrap();
    let claimed = store
        .claim_work(from_ref(&kind), "w", 1, LEASE)
        .await
        .unwrap();
    assert!(
        store
            .complete_work(claimed[0].id, claimed[0].generation, None)
            .await
            .unwrap()
    );
    store.enqueue_work(&open, 10).await.unwrap();
    let other = unique_kind("purge_other");
    let theirs = work(&other);
    store.enqueue_work(&theirs, 10).await.unwrap();

    let earlier = Utc::now() - Duration::hours(1);
    assert_eq!(store.purge_ended_work(&kind, earlier).await.unwrap(), 0);
    let later = Utc::now() + Duration::seconds(5);
    assert_eq!(store.purge_ended_work(&kind, later).await.unwrap(), 1);
    assert!(store.get_work(claimed[0].id).await.unwrap().is_none());
    assert!(
        store.get_work(open.id).await.unwrap().is_some(),
        "open work"
    );
    assert!(store.get_work(theirs.id).await.unwrap().is_some());
}

/// Work under a live lease is not handed to another worker, however many
/// times it asks.
pub async fn live_lease_is_exclusive(store: &dyn WorkStore) {
    let kind = unique_kind("live_lease");
    store.enqueue_work(&work(&kind), 10).await.unwrap();
    let first = store
        .claim_work(from_ref(&kind), "w1", 10, LEASE)
        .await
        .unwrap();
    assert_eq!(first.len(), 1);
    for worker in ["w2", "w3", "w1"] {
        assert!(
            store
                .claim_work(from_ref(&kind), worker, 10, LEASE)
                .await
                .unwrap()
                .is_empty(),
            "claimed work was handed out twice under a live lease ({worker})"
        );
    }
}

/// A claim is held for its lease; once the lease runs out another worker
/// claims the work under a new generation, and the first holder's outcome
/// is refused.
pub async fn lease_fences_stale_worker(store: &dyn WorkStore) {
    let kind = unique_kind("lease");
    let item = work(&kind);
    store.enqueue_work(&item, 10).await.unwrap();

    let claimed_at = std::time::Instant::now();
    let first = store
        .claim_work(from_ref(&kind), "w1", 10, SHORT_LEASE)
        .await
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].attempt, 1);
    assert_eq!(first[0].payload, b"payload");
    let early = store
        .claim_work(from_ref(&kind), "w2", 10, LEASE)
        .await
        .unwrap();
    // On a loaded host the short lease may already have run out here, and
    // then a second claim is correct; only one made inside the lease is not.
    // A long lease's exclusivity is `live_lease_is_exclusive`.
    if !early.is_empty() {
        assert!(
            claimed_at.elapsed() >= SHORT_LEASE,
            "claimed work was handed out twice under a live lease"
        );
        return;
    }

    tokio::time::sleep(PAST_SHORT_LEASE).await;
    let second = store
        .claim_work(from_ref(&kind), "w2", 10, LEASE)
        .await
        .unwrap();
    assert_eq!(second.len(), 1, "abandoned work was not reclaimed");
    assert_eq!(second[0].attempt, 2);
    assert!(second[0].generation > first[0].generation);

    assert!(
        !store
            .complete_work(item.id, first[0].generation, Some("stale"))
            .await
            .unwrap()
    );
    assert!(
        !store
            .fail_work(item.id, first[0].generation, &retry("stale", Utc::now()))
            .await
            .unwrap()
    );
    let record = store.get_work(item.id).await.unwrap().unwrap();
    assert_eq!(
        record.state,
        WorkState::Claimed,
        "a stale worker changed the work"
    );
    assert!(record.result.is_none());

    assert!(
        store
            .complete_work(item.id, second[0].generation, Some("receipt-2"))
            .await
            .unwrap()
    );
    assert!(
        !store
            .complete_work(item.id, second[0].generation, None)
            .await
            .unwrap()
    );
    let record = store.get_work(item.id).await.unwrap().unwrap();
    assert_eq!(record.state, WorkState::Completed);
    assert_eq!(record.result.as_deref(), Some("receipt-2"));
    assert!(
        store
            .claim_work(&[kind], "w3", 10, LEASE)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A failed attempt makes the work due again at its retry time; the last
/// failed attempt ends it as failed, with its error kept.
pub async fn retries_then_fails(store: &dyn WorkStore) {
    let kind = unique_kind("retry");
    let mut item = work(&kind);
    item.max_attempts = 2;
    store.enqueue_work(&item, 10).await.unwrap();

    let first = store
        .claim_work(from_ref(&kind), "w", 10, LEASE)
        .await
        .unwrap();
    let later = Utc::now() + Duration::hours(1);
    assert!(
        store
            .fail_work(item.id, first[0].generation, &retry("smtp 451", later))
            .await
            .unwrap()
    );
    let record = store.get_work(item.id).await.unwrap().unwrap();
    assert_eq!(record.state, WorkState::Pending);
    assert_eq!(record.last_error.as_deref(), Some("smtp 451"));
    assert!(
        store
            .claim_work(from_ref(&kind), "w", 10, LEASE)
            .await
            .unwrap()
            .is_empty(),
        "work was retried before its retry time"
    );

    // A retry already due is handed out again, and the last attempt ends it.
    // The retry time comes from this process's clock, so "due" is set in the
    // past rather than at a now the store's clock may not have reached.
    let now = Utc::now() - Duration::seconds(5);
    let mut next = work(&kind);
    next.max_attempts = 2;
    store.enqueue_work(&next, 10).await.unwrap();
    let a = store
        .claim_work(from_ref(&kind), "w", 10, LEASE)
        .await
        .unwrap();
    assert!(
        store
            .fail_work(next.id, a[0].generation, &retry("timeout", now))
            .await
            .unwrap()
    );
    let b = store
        .claim_work(from_ref(&kind), "w", 10, LEASE)
        .await
        .unwrap();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].attempt, 2);
    assert!(
        store
            .fail_work(next.id, b[0].generation, &retry("timeout", now))
            .await
            .unwrap()
    );

    let record = store.get_work(next.id).await.unwrap().unwrap();
    assert_eq!(
        record.state,
        WorkState::Failed,
        "attempts ran out but work stayed open"
    );
    assert_eq!(record.attempts, 2);
    assert!(
        store
            .claim_work(&[kind], "w", 10, LEASE)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A permanent failure ends the work at once, and its dead-letter alert is
/// stored with it; a failure that leaves the work alive stores no alert, and
/// an ambiguous attempt is kept distinguishable.
pub async fn dead_letter_alert_commits_with_failure(store: &dyn WorkStore) {
    let kind = unique_kind("dead");
    let alert_kind = unique_kind("dead_alert");
    let item = work(&kind);
    store.enqueue_work(&item, 10).await.unwrap();
    let alert = work(&alert_kind);

    // Alive after this failure: the offered alert is not stored.
    let first = store
        .claim_work(from_ref(&kind), "w", 10, LEASE)
        .await
        .unwrap();
    let failure = WorkFailure {
        error: "reply lost".into(),
        ambiguous: true,
        // Already due, whatever the store's clock says.
        retry_at: Some(Utc::now() - Duration::seconds(5)),
        on_dead: Some(alert.clone()),
    };
    assert!(
        store
            .fail_work(item.id, first[0].generation, &failure)
            .await
            .unwrap()
    );
    let record = store.get_work(item.id).await.unwrap().unwrap();
    assert_eq!(record.state, WorkState::Pending);
    assert!(
        record.ambiguous,
        "an ambiguous attempt was recorded as a clean failure"
    );
    assert!(
        store.get_work(alert.id).await.unwrap().is_none(),
        "an alert was raised for work that is still alive"
    );

    // Permanent: failed now, whatever attempts remain, with its alert.
    let second = store
        .claim_work(from_ref(&kind), "w", 10, LEASE)
        .await
        .unwrap();
    let failure = WorkFailure {
        error: "mailbox does not exist".into(),
        ambiguous: false,
        retry_at: None,
        on_dead: Some(alert.clone()),
    };
    assert!(
        store
            .fail_work(item.id, second[0].generation, &failure)
            .await
            .unwrap()
    );
    let record = store.get_work(item.id).await.unwrap().unwrap();
    assert_eq!(record.state, WorkState::Failed);
    assert_eq!(record.attempts, 2);
    assert!(!record.ambiguous);
    let stored = store
        .get_work(alert.id)
        .await
        .unwrap()
        .expect("dead work lost its alert");
    assert_eq!(stored.state, WorkState::Pending);
    assert_eq!(stored.kind, alert_kind);
}

/// Work past its expiry is recorded expired and never handed out; work not
/// yet due is not handed out either.
pub async fn expired_and_future_are_not_claimed(store: &dyn WorkStore) {
    let kind = unique_kind("expiry");
    let mut expired = work(&kind);
    expired.expires_at = Some(Utc::now() - Duration::seconds(1));
    store.enqueue_work(&expired, 10).await.unwrap();
    let mut future = work(&kind);
    future.not_before = Some(Utc::now() + Duration::hours(1));
    store.enqueue_work(&future, 10).await.unwrap();

    assert!(
        store
            .claim_work(&[kind], "w", 10, LEASE)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.get_work(expired.id).await.unwrap().unwrap().state,
        WorkState::Expired
    );
    assert_eq!(
        store.get_work(future.id).await.unwrap().unwrap().state,
        WorkState::Pending
    );
}

/// Work abandoned on its last attempt is recorded failed, not claimed again.
pub async fn abandoned_last_attempt_fails(store: &dyn WorkStore) {
    let kind = unique_kind("abandoned");
    let mut item = work(&kind);
    item.max_attempts = 1;
    store.enqueue_work(&item, 10).await.unwrap();
    assert_eq!(
        store
            .claim_work(from_ref(&kind), "w1", 10, SHORT_LEASE)
            .await
            .unwrap()
            .len(),
        1
    );

    tokio::time::sleep(PAST_SHORT_LEASE).await;
    assert!(
        store
            .claim_work(&[kind], "w2", 10, LEASE)
            .await
            .unwrap()
            .is_empty()
    );
    let record = store.get_work(item.id).await.unwrap().unwrap();
    assert_eq!(record.state, WorkState::Failed);
    assert!(record.last_error.is_some());
}

/// Concurrent workers never receive the same work: every item goes to
/// exactly one of them.
pub async fn concurrent_claims_do_not_overlap(store: &dyn WorkStore) {
    let kind = unique_kind("concurrent");
    let mut ids: HashSet<WorkId> = HashSet::new();
    for _ in 0..12 {
        let item = work(&kind);
        ids.insert(item.id);
        store.enqueue_work(&item, 100).await.unwrap();
    }
    let kinds = [kind.clone()];
    let claim = |worker: &'static str| store.claim_work(&kinds, worker, 5, LEASE);
    let (a, b, c, d) = tokio::join!(claim("w1"), claim("w2"), claim("w3"), claim("w4"));

    let mut seen = HashSet::new();
    for batch in [a, b, c, d] {
        for claimed in batch.unwrap() {
            assert!(seen.insert(claimed.id), "work {} claimed twice", claimed.id);
        }
    }
    assert_eq!(seen, ids, "some work was not claimed by anyone");
}

/// Export carries every piece of work with its payload and outcome; import
/// stores it as it was, except that a claim does not travel (claimed work is
/// due again, or failed if that claim was its last attempt), and importing
/// the same work twice stores it once.
pub async fn export_import_round_trip(store: &dyn WorkStore) {
    let kind = unique_kind("export");
    let mut items = Vec::new();
    for max_attempts in [3, 3, 3, 3, 1] {
        let mut item = work(&kind);
        item.max_attempts = max_attempts;
        store.enqueue_work(&item, 10).await.unwrap();
        items.push(item);
    }
    let claimed = store
        .claim_work(from_ref(&kind), "w", 10, LEASE)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 5);
    let generation = |id: WorkId| claimed.iter().find(|c| c.id == id).unwrap().generation;
    // items[0] completed, items[1] failed, items[2] pending again, items[3]
    // and items[4] (its last attempt) still claimed.
    store
        .complete_work(items[0].id, generation(items[0].id), Some("receipt"))
        .await
        .unwrap();
    let permanent = WorkFailure {
        error: "refused".into(),
        ambiguous: true,
        retry_at: None,
        on_dead: None,
    };
    store
        .fail_work(items[1].id, generation(items[1].id), &permanent)
        .await
        .unwrap();
    let later = Utc::now() + Duration::hours(1);
    store
        .fail_work(items[2].id, generation(items[2].id), &retry("busy", later))
        .await
        .unwrap();

    let exported: Vec<_> = store
        .export_work()
        .await
        .unwrap()
        .into_iter()
        .filter(|w| w.record.kind == kind)
        .collect();
    assert_eq!(exported.len(), 5, "export missed work");
    assert!(exported.iter().all(|w| w.payload == b"payload"));
    for snapshot in &exported {
        assert!(
            !store.import_work(snapshot).await.unwrap(),
            "importing existing work stored it again"
        );
    }

    // Carried to fresh ids, as into another store.
    let mut expected = Vec::new();
    for snapshot in &exported {
        let mut moved = snapshot.clone();
        moved.record.id = WorkId::new();
        assert!(store.import_work(&moved).await.unwrap());
        assert!(!store.import_work(&moved).await.unwrap());
        expected.push((moved.record.id, moved.at_rest()));
    }
    for (id, want) in expected {
        let got = store.get_work(id).await.unwrap().unwrap();
        assert_eq!(got.state, want.state);
        assert_eq!(got.attempts, want.attempts);
        assert_eq!(got.max_attempts, want.max_attempts);
        assert_eq!(got.last_error, want.last_error);
        assert_eq!(got.ambiguous, want.ambiguous);
        assert_eq!(got.result, want.result);
        assert_eq!(
            got.not_before.timestamp_millis(),
            want.not_before.timestamp_millis()
        );
    }
    let states: Vec<_> = exported.iter().map(|w| w.at_rest().state).collect();
    assert!(!states.contains(&WorkState::Claimed), "a claim travelled");
    assert!(states.contains(&WorkState::Completed) && states.contains(&WorkState::Failed));
}
