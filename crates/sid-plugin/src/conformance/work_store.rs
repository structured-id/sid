// SPDX-License-Identifier: AGPL-3.0-only
//! [`WorkStore`] scenarios: durable work admission, leases, retries, failure
//! and export. Each scenario uses its own work kind, so scenarios sharing one
//! database never see each other's work.

use chrono::{DateTime, Duration, Utc};
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

/// The same work enqueued twice is stored once: a retried command owes
/// nothing new.
pub async fn enqueue_is_idempotent(store: &dyn WorkStore) {
    let kind = unique_kind("dedup");
    let item = work(&kind);
    assert!(store.enqueue_work(&item).await.unwrap());
    assert!(
        !store.enqueue_work(&item).await.unwrap(),
        "the same obligation was stored twice"
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
    let enqueue = || store.enqueue_work(&item);
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

/// Distinct work of one kind enqueued at once (replicas accepting it
/// together) is all stored and all claimable: the store neither refuses work
/// for its backlog nor makes writers of a kind wait on each other.
pub async fn concurrent_enqueues_of_a_kind_are_all_stored(store: &dyn WorkStore) {
    let kind = unique_kind("concurrent_kind");
    let items: Vec<NewWork> = (0..64).map(|_| work(&kind)).collect();
    let results =
        futures::future::join_all(items.iter().map(|item| store.enqueue_work(item))).await;
    assert!(results.iter().all(|r| matches!(r, Ok(true))), "{results:?}");
    let claimed = store
        .claim_work(from_ref(&kind), "w", 100, LEASE)
        .await
        .unwrap();
    let claimed: HashSet<WorkId> = claimed.iter().map(|c| c.id).collect();
    let stored: HashSet<WorkId> = items.iter().map(|i| i.id).collect();
    assert_eq!(claimed, stored);
}

/// A claim carries when the work was stored and when the claimed attempt was
/// due: the stored due time first, the retry time a failed attempt set after.
pub async fn claim_carries_creation_and_due_times(store: &dyn WorkStore) {
    let kind = unique_kind("claim_times");
    let item = work(&kind);
    store.enqueue_work(&item).await.unwrap();
    let record = store.get_work(item.id).await.unwrap().unwrap();
    let first = store
        .claim_work(from_ref(&kind), "w", 1, LEASE)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(first.created_at, record.created_at);
    assert_eq!(first.due_at, record.not_before);

    // The store keeps its own time precision; the retry time is read back
    // from the record rather than compared with the value passed in.
    let retry_at = Utc::now() + Duration::milliseconds(200);
    assert!(
        store
            .fail_work(first.id, first.generation, &retry("down", retry_at))
            .await
            .unwrap()
    );
    let retried = store.get_work(item.id).await.unwrap().unwrap();
    assert!(retried.not_before > record.not_before);
    tokio::time::sleep(StdDuration::from_millis(300)).await;
    let second = store
        .claim_work(from_ref(&kind), "w", 1, LEASE)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(second.attempt, 2);
    assert_eq!(second.created_at, record.created_at);
    assert_eq!(second.due_at, retried.not_before);
}

/// Ended work of a kind is dropped once older than asked; open work, newer
/// ended work and other kinds stay.
pub async fn ended_work_is_purged(store: &dyn WorkStore) {
    let kind = unique_kind("purge");
    let (done, open) = (work(&kind), work(&kind));
    store.enqueue_work(&done).await.unwrap();
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
    store.enqueue_work(&open).await.unwrap();
    let other = unique_kind("purge_other");
    let theirs = work(&other);
    store.enqueue_work(&theirs).await.unwrap();

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

/// A kind is reported as having work once any of it is stored, whatever its
/// state (open or ended), until it is purged; another kind's work does not
/// count for it.
pub async fn work_of_a_kind_is_reported(store: &dyn WorkStore) {
    let kind = unique_kind("has_kind");
    assert!(
        !store.has_work_of_kind(&kind).await.unwrap(),
        "nothing stored yet"
    );
    store
        .enqueue_work(&work(&unique_kind("has_kind_other")))
        .await
        .unwrap();
    assert!(
        !store.has_work_of_kind(&kind).await.unwrap(),
        "another kind's work"
    );

    store.enqueue_work(&work(&kind)).await.unwrap();
    assert!(store.has_work_of_kind(&kind).await.unwrap(), "pending work");
    let claimed = store
        .claim_work(from_ref(&kind), "w", 1, LEASE)
        .await
        .unwrap();
    assert!(store.has_work_of_kind(&kind).await.unwrap(), "claimed work");
    assert!(
        store
            .complete_work(claimed[0].id, claimed[0].generation, None)
            .await
            .unwrap()
    );
    assert!(store.has_work_of_kind(&kind).await.unwrap(), "ended work");

    let later = Utc::now() + Duration::seconds(5);
    store.purge_ended_work(&kind, later).await.unwrap();
    assert!(!store.has_work_of_kind(&kind).await.unwrap(), "purged");
}

/// Work under a live lease is not handed to another worker, however many
/// times it asks.
pub async fn live_lease_is_exclusive(store: &dyn WorkStore) {
    let kind = unique_kind("live_lease");
    store.enqueue_work(&work(&kind)).await.unwrap();
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
    store.enqueue_work(&item).await.unwrap();

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
    store.enqueue_work(&item).await.unwrap();

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
    store.enqueue_work(&next).await.unwrap();
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
    store.enqueue_work(&item).await.unwrap();
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
    store.enqueue_work(&expired).await.unwrap();
    let mut future = work(&kind);
    future.not_before = Some(Utc::now() + Duration::hours(1));
    store.enqueue_work(&future).await.unwrap();

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
    store.enqueue_work(&item).await.unwrap();
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
        store.enqueue_work(&item).await.unwrap();
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

/// The kinds a claim names are a set: a kind named twice yields each of its
/// items once. Read twice, one item was claimed twice in one call, its
/// first claim already stale and its attempts counted twice.
pub async fn a_kind_named_twice_claims_each_item_once(store: &dyn WorkStore) {
    let kind = unique_kind("twice");
    let item = work(&kind);
    store.enqueue_work(&item).await.unwrap();
    let claimed = store
        .claim_work(&[kind.clone(), kind], "w", 2, LEASE)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1, "{claimed:?}");
    assert_eq!(claimed[0].id, item.id);
    assert_eq!(claimed[0].attempt, 1);
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
        store.enqueue_work(&item).await.unwrap();
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

/// A claimed parent and its `kind`.
async fn claimed_parent(store: &dyn WorkStore, scenario: &str) -> sid_core::models::ClaimedWork {
    let kind = unique_kind(scenario);
    store.enqueue_work(&work(&kind)).await.unwrap();
    store
        .claim_work(&[kind], "w", 1, LEASE)
        .await
        .unwrap()
        .pop()
        .expect("the parent is claimed")
}

/// A completion owing follow-up work commits both: the parent completed with
/// its result, every child pending.
pub async fn completion_commits_with_follow_up_work(store: &dyn WorkStore) {
    let parent = claimed_parent(store, "owing_parent").await;
    let children = unique_kind("owing_child");
    let owed = [work(&children), work(&children)];

    assert!(
        store
            .complete_work_owing(parent.id, parent.generation, Some("planned"), &owed)
            .await
            .unwrap()
    );

    let record = store.get_work(parent.id).await.unwrap().unwrap();
    assert_eq!(record.state, WorkState::Completed);
    assert_eq!(record.result.as_deref(), Some("planned"));
    for child in &owed {
        let record = store.get_work(child.id).await.unwrap().unwrap();
        assert_eq!(record.state, WorkState::Pending);
    }
}

/// A completion by a stale claim writes neither the completion nor the
/// children: the current holder still owns the parent.
pub async fn stale_completion_owes_nothing(store: &dyn WorkStore) {
    let parent = claimed_parent(store, "owing_stale").await;
    let child = work(&unique_kind("owing_stale_child"));

    assert!(
        !store
            .complete_work_owing(parent.id, parent.generation + 1, None, from_ref(&child))
            .await
            .unwrap()
    );

    let record = store.get_work(parent.id).await.unwrap().unwrap();
    assert_eq!(record.state, WorkState::Claimed);
    assert!(store.get_work(child.id).await.unwrap().is_none());
}

/// A completion owing a child already stored (the same obligation again,
/// from a retried handler) and a fresh one commits: the stored child is kept
/// as it was, the fresh one is pending.
pub async fn completion_owing_a_stored_child_keeps_it(store: &dyn WorkStore) {
    let parent = claimed_parent(store, "owing_stored").await;
    let children = unique_kind("owing_stored_child");
    let stored = work(&children);
    store.enqueue_work(&stored).await.unwrap();
    let claimed = store
        .claim_work(from_ref(&children), "w", 1, LEASE)
        .await
        .unwrap();
    let fresh = work(&children);

    assert!(
        store
            .complete_work_owing(
                parent.id,
                parent.generation,
                None,
                &[stored.clone(), fresh.clone()],
            )
            .await
            .unwrap()
    );
    let record = store.get_work(parent.id).await.unwrap().unwrap();
    assert_eq!(record.state, WorkState::Completed);
    let kept = store.get_work(stored.id).await.unwrap().unwrap();
    assert_eq!(kept.state, WorkState::Claimed, "the stored child was reset");
    assert_eq!(kept.generation, claimed[0].generation);
    assert_eq!(
        store.get_work(fresh.id).await.unwrap().unwrap().state,
        WorkState::Pending
    );
}

/// Parents of one kind completing at once, each owing a child of another
/// kind and some owing a child of their own kind, all commit: completions do
/// not wait on each other in a cycle, and none is refused for the backlog.
pub async fn concurrent_completions_owing_work_all_commit(store: &dyn WorkStore) {
    let parents_kind = unique_kind("owing_race");
    for _ in 0..8 {
        store.enqueue_work(&work(&parents_kind)).await.unwrap();
    }
    let parents = store
        .claim_work(from_ref(&parents_kind), "w", 8, LEASE)
        .await
        .unwrap();
    assert_eq!(parents.len(), 8);
    let children = unique_kind("owing_race_child");
    let owed: Vec<Vec<NewWork>> = parents
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let mut owed = vec![work(&children)];
            if i % 2 == 0 {
                owed.push(work(&parents_kind));
            }
            owed
        })
        .collect();

    let results =
        futures::future::join_all(parents.iter().zip(&owed).map(|(parent, owed)| {
            store.complete_work_owing(parent.id, parent.generation, None, owed)
        }))
        .await;

    assert!(results.iter().all(|r| matches!(r, Ok(true))), "{results:?}");
    for parent in &parents {
        let record = store.get_work(parent.id).await.unwrap().unwrap();
        assert_eq!(record.state, WorkState::Completed);
    }
    for child in owed.iter().flatten() {
        let record = store.get_work(child.id).await.unwrap().unwrap();
        assert_eq!(record.state, WorkState::Pending);
    }
}
