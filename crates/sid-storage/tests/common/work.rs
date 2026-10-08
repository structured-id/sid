// SPDX-License-Identifier: AGPL-3.0-only
//! Durable work contract, run against every work store. Each scenario uses
//! its own work kind, so scenarios sharing one database never see each
//! other's work.

use chrono::{DateTime, Duration, Utc};
use sid_core::Error;
use sid_core::models::{
    Event, LOGOUT_DELIVERY_ATTEMPTS, LogoutDelivery, NewWork, RevocationReason, Session,
    SessionEnd, WorkFailure, WorkId, WorkKind, WorkState,
};
use sid_plugin::WorkStore;
use sid_plugin::storage::StorageBackend;
use std::collections::HashSet;
use std::slice::from_ref;
use std::time::Duration as StdDuration;
use uuid::Uuid;

const LEASE: StdDuration = StdDuration::from_secs(60);
const SHORT_LEASE: StdDuration = StdDuration::from_millis(300);
const PAST_SHORT_LEASE: StdDuration = StdDuration::from_millis(450);

fn unique_kind(scenario: &str) -> WorkKind {
    WorkKind::new(&format!("test.{scenario}.{}", Uuid::now_v7().simple())).unwrap()
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
pub async fn test_work_enqueue_is_idempotent(store: &dyn WorkStore) {
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

/// A kind holding `capacity` open items refuses more work explicitly; once an
/// item is done, there is room again. Other kinds are not affected.
pub async fn test_work_capacity_is_enforced_per_kind(store: &dyn WorkStore) {
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

/// Work under a live lease is not handed to another worker, however many
/// times it asks.
pub async fn test_work_live_lease_is_exclusive(store: &dyn WorkStore) {
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
pub async fn test_work_lease_fences_stale_worker(store: &dyn WorkStore) {
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
    // A long lease's exclusivity is `test_work_live_lease_is_exclusive`.
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
pub async fn test_work_retries_then_fails(store: &dyn WorkStore) {
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
pub async fn test_work_dead_letter_alert_commits_with_failure(store: &dyn WorkStore) {
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
pub async fn test_work_expired_and_future_are_not_claimed(store: &dyn WorkStore) {
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
pub async fn test_work_abandoned_last_attempt_fails(store: &dyn WorkStore) {
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
pub async fn test_work_concurrent_claims_do_not_overlap(store: &dyn WorkStore) {
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

/// A magic link is consumed at most once: the first consumption returns it,
/// every later one (and one of an expired link) returns nothing, and of
/// concurrent consumptions exactly one wins.
pub async fn test_magic_link_consumed_once(backend: &dyn StorageBackend) {
    use sid_core::models::MagicLinkSession;

    let link = MagicLinkSession::new("once@sid.example.com", "hash-once".into());
    backend
        .create_magic_link_session(&link, super::test_audit())
        .await
        .unwrap();
    let first = backend
        .try_consume_magic_link_session(link.id, super::test_audit())
        .await
        .unwrap();
    assert_eq!(first.map(|s| s.id), Some(link.id));
    assert!(
        backend
            .try_consume_magic_link_session(link.id, super::test_audit())
            .await
            .unwrap()
            .is_none(),
        "a consumed magic link was consumed again"
    );

    let mut expired = MagicLinkSession::new("late@sid.example.com", "hash-late".into());
    expired.expires_at = Utc::now() - Duration::minutes(1);
    backend
        .create_magic_link_session(&expired, super::test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .try_consume_magic_link_session(expired.id, super::test_audit())
            .await
            .unwrap()
            .is_none(),
        "an expired magic link was consumed"
    );

    let raced = MagicLinkSession::new("race@sid.example.com", "hash-race".into());
    backend
        .create_magic_link_session(&raced, super::test_audit())
        .await
        .unwrap();
    let take = || backend.try_consume_magic_link_session(raced.id, super::test_audit());
    let (a, b, c, d) = tokio::join!(take(), take(), take(), take());
    let winners = [a, b, c, d]
        .into_iter()
        .filter(|r| r.as_ref().unwrap().is_some())
        .count();
    assert_eq!(winners, 1, "concurrent consumptions of one link");
}

/// Creating a session at the profile's limit evicts the oldest: the evicted
/// session ends like any other (its client is owed a logout, committed with
/// the eviction), a limit of 0 is unlimited, and concurrent sign-ins never
/// leave more sessions than the limit.
pub async fn test_session_limit_evicts_oldest(backend: &dyn StorageBackend) {
    let client = super::create_test_oauth2_client(&format!("limit_{}", Uuid::now_v7().simple()));
    super::application::store_client(backend, &client, super::test_audit())
        .await
        .unwrap();
    let profile = super::create_test_profile("session_limit");
    backend
        .create_profile(&profile, super::test_audit())
        .await
        .unwrap();

    let mut oldest = super::create_test_session(profile.id);
    oldest.client_id = Some(client.client_id.clone());
    oldest.created_at = Utc::now() - Duration::minutes(2);
    let mut middle = super::create_test_session(profile.id);
    middle.created_at = Utc::now() - Duration::minutes(1);
    for s in [&oldest, &middle] {
        let evicted = backend
            .create_session_atomic(s, 0, super::test_audit())
            .await
            .unwrap();
        assert!(evicted.is_empty(), "a limit of 0 evicted a session");
    }

    let newest = super::create_test_session(profile.id);
    let evicted = backend
        .create_session_atomic(&newest, 2, super::test_audit())
        .await
        .unwrap();
    assert_eq!(
        evicted,
        vec![oldest.id],
        "the oldest session was not evicted"
    );
    assert!(backend.get_session(oldest.id).await.unwrap().is_none());
    for kept in [&middle, &newest] {
        assert!(backend.get_session(kept.id).await.unwrap().is_some());
    }
    let owed = LogoutDelivery::for_ended_session(&oldest).unwrap().work();
    assert_eq!(
        backend.get_work(owed.id).await.unwrap().map(|r| r.state),
        Some(WorkState::Pending),
        "the evicted session's client was not owed a logout"
    );

    // Under the limit: nothing is evicted.
    let other = super::create_test_profile("session_limit_under");
    backend
        .create_profile(&other, super::test_audit())
        .await
        .unwrap();
    let evicted = backend
        .create_session_atomic(
            &super::create_test_session(other.id),
            5,
            super::test_audit(),
        )
        .await
        .unwrap();
    assert!(evicted.is_empty());

    // Concurrent sign-ins at a limit of 2.
    let racing = super::create_test_profile("session_limit_race");
    backend
        .create_profile(&racing, super::test_audit())
        .await
        .unwrap();
    let s: Vec<_> = (0..6)
        .map(|_| super::create_test_session(racing.id))
        .collect();
    let create = |i: usize| backend.create_session_atomic(&s[i], 2, super::test_audit());
    let (a, b, c, d, e, f) = tokio::join!(
        create(0),
        create(1),
        create(2),
        create(3),
        create(4),
        create(5)
    );
    for result in [a, b, c, d, e, f] {
        result.unwrap();
    }
    assert_eq!(
        backend
            .list_sessions_by_profile(racing.id)
            .await
            .unwrap()
            .len(),
        2,
        "concurrent sign-ins exceeded the session limit"
    );
}

/// Export carries every piece of work with its payload and outcome; import
/// stores it as it was, except that a claim does not travel (claimed work is
/// due again, or failed if that claim was its last attempt), and importing
/// the same work twice stores it once.
pub async fn test_work_export_import_round_trip(store: &dyn WorkStore) {
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

/// Every ended session owes what `SessionEnd` names, stored with the
/// deletion: its client's back-channel logout (a first-party session owes
/// none) and the `sid.session.revoked.v1` event with the reason and actor.
/// Ending the same session again owes nothing new; work the caller owes
/// commits with the deletion too, and deleting a missing session owes nothing.
pub async fn test_session_end_owes_client_logout(backend: &dyn StorageBackend) {
    let client = super::create_test_oauth2_client(&format!("logout_{}", Uuid::now_v7().simple()));
    super::application::store_client(backend, &client, super::test_audit())
        .await
        .unwrap();
    let profile = super::create_test_profile("logout_owed");
    backend
        .create_profile(&profile, super::test_audit())
        .await
        .unwrap();
    let end = SessionEnd::new(RevocationReason::Admin, "admin-actor");
    let logout = |s: &Session| LogoutDelivery::for_ended_session(s).map(|l| l.work().id);
    let revoked = |s: &Session| end.revoked_event(s.id, s.profile_id).relay().id;

    let mut single = super::create_test_session(profile.id);
    single.client_id = Some(client.client_id.clone());
    backend
        .create_session(&single, super::test_audit())
        .await
        .unwrap();
    let caller_owed = work(&unique_kind("session_end"));
    backend
        .delete_session(
            single.id,
            &end,
            super::test_audit().with_work(caller_owed.clone()),
        )
        .await
        .unwrap();
    for id in [logout(&single).unwrap(), revoked(&single), caller_owed.id] {
        let record = backend.get_work(id).await.unwrap();
        assert_eq!(
            record.map(|r| r.state),
            Some(WorkState::Pending),
            "work owed by the session's end was not stored with it"
        );
    }
    let owed_event = backend
        .export_work()
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.record.id == revoked(&single))
        .expect("the revoked event is exported with its payload");
    let event: Event = serde_json::from_slice(&owed_event.payload).unwrap();
    assert_eq!(event.data["reason"], "admin");
    assert_eq!(event.data["by"], "admin-actor");

    // A session that is already gone ends nothing and owes nothing.
    let missing = super::create_test_session(profile.id);
    backend
        .delete_session(missing.id, &end, super::test_audit())
        .await
        .unwrap();
    assert!(backend.get_work(revoked(&missing)).await.unwrap().is_none());

    let mut bulk = super::create_test_session(profile.id);
    bulk.client_id = Some(client.client_id.clone());
    let first_party = super::create_test_session(profile.id);
    for s in [&bulk, &first_party] {
        backend
            .create_session(s, super::test_audit())
            .await
            .unwrap();
    }
    let ended = backend
        .delete_sessions_by_profile(profile.id, &end, super::test_audit())
        .await
        .unwrap();
    assert_eq!(ended.len(), 2);
    let record = backend
        .get_work(logout(&bulk).unwrap())
        .await
        .unwrap()
        .expect("the client's logout was not stored with the deletion");
    assert_eq!(record.state, WorkState::Pending);
    assert_eq!(record.max_attempts, LOGOUT_DELIVERY_ATTEMPTS);
    assert!(logout(&first_party).is_none());
    for s in [&bulk, &first_party] {
        assert!(
            backend.get_work(revoked(s)).await.unwrap().is_some(),
            "an ended session's revoked event was not stored with the deletion"
        );
    }

    // The session is ended again (a retried revocation): nothing new is owed.
    backend
        .create_session(&bulk, super::test_audit())
        .await
        .unwrap();
    backend
        .delete_sessions_by_profile(profile.id, &end, super::test_audit())
        .await
        .unwrap();
    for id in [logout(&bulk).unwrap(), revoked(&bulk)] {
        assert_eq!(
            backend.get_work(id).await.unwrap().map(|r| r.attempts),
            Some(0)
        );
    }
}

/// Removing expired role assignments returns them and stores, with the
/// deletion, the `role_expired` event each owes; active and permanent
/// assignments stay. A second run finds them gone and owes nothing new.
/// (Other scenarios may share the database, so only this one's assignments
/// are looked at.)
pub async fn test_expired_role_assignments_owe_event(backend: &dyn StorageBackend) {
    use sid_core::models::{ProjectId, Role, RoleAssignment, RoleAssignmentPrincipal};

    let profile = super::create_test_profile("role_expiry");
    backend
        .create_profile(&profile, super::test_audit())
        .await
        .unwrap();
    let key = format!("temp_{}", Uuid::now_v7().simple());
    let role = Role::new(ProjectId::system(), &key, &key);
    backend
        .create_role(&role, super::test_audit())
        .await
        .unwrap();
    let principal = RoleAssignmentPrincipal::Profile(profile.id);
    let expired = RoleAssignment::new(principal.clone(), role.id)
        .with_expiry(Utc::now() - Duration::hours(1));
    let active = RoleAssignment::new(principal.clone(), role.id)
        .with_expiry(Utc::now() + Duration::hours(24));
    let permanent = RoleAssignment::new(principal, role.id);
    for a in [&expired, &active, &permanent] {
        backend
            .create_role_assignment(a, super::test_audit())
            .await
            .unwrap();
    }

    let removed = backend
        .cleanup_expired_role_assignments(super::test_audit())
        .await
        .unwrap();
    let mine: Vec<_> = removed
        .iter()
        .filter(|a| [expired.id, active.id, permanent.id].contains(&a.id))
        .map(|a| a.id)
        .collect();
    assert_eq!(mine, [expired.id], "only the expired assignment is removed");
    let owed = expired.expired_event().relay().id;
    assert_eq!(
        backend.get_work(owed).await.unwrap().map(|r| r.state),
        Some(WorkState::Pending),
        "the expired event was not stored with the deletion"
    );
    for kept in [&active, &permanent] {
        assert!(
            backend
                .get_work(kept.expired_event().relay().id)
                .await
                .unwrap()
                .is_none()
        );
    }
    let left: Vec<_> = backend
        .list_role_assignments_for_profile(profile.id)
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.id)
        .collect();
    assert!(left.contains(&active.id) && left.contains(&permanent.id));
    assert!(!left.contains(&expired.id));

    let again = backend
        .cleanup_expired_role_assignments(super::test_audit())
        .await
        .unwrap();
    assert!(again.iter().all(|a| a.id != expired.id));
}

/// Work a mutation owes is stored in the mutation's own transaction: it
/// exists once the mutation returns, and a mutation that is refused (here a
/// client id that already exists) leaves no work behind.
pub async fn test_mutation_commits_owed_work(backend: &dyn StorageBackend) {
    let kind = unique_kind("owed");
    let profile = super::create_test_profile("owed_work");
    let owed_by_profile = work(&kind);
    backend
        .create_profile(
            &profile,
            super::test_audit().with_work(owed_by_profile.clone()),
        )
        .await
        .unwrap();
    let session = super::create_test_session(profile.id);
    let owed_by_session = work(&kind);
    backend
        .create_session(
            &session,
            super::test_audit().with_work(owed_by_session.clone()),
        )
        .await
        .unwrap();
    for owed in [&owed_by_profile, &owed_by_session] {
        let record = backend
            .get_work(owed.id)
            .await
            .unwrap()
            .expect("owed work was not stored with its mutation");
        assert_eq!(record.state, WorkState::Pending);
    }

    let client = super::create_test_oauth2_client(&format!("owed_{}", Uuid::now_v7().simple()));
    super::application::store_client(backend, &client, super::test_audit())
        .await
        .unwrap();
    let orphan = work(&kind);
    let refused = super::application::store_client(
        backend,
        &client,
        super::test_audit().with_work(orphan.clone()),
    )
    .await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    assert!(
        backend.get_work(orphan.id).await.unwrap().is_none(),
        "a refused mutation stored the work it owed"
    );
}

/// The same obligation enqueued concurrently is stored exactly once.
pub async fn test_work_concurrent_enqueue_stores_once(store: &dyn WorkStore) {
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
