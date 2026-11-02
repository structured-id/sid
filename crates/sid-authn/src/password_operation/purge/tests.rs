// SPDX-License-Identifier: AGPL-3.0-only
use super::super::tests::{Operations, change, manager, split, sqlite, zkpp_without_proofs};
use super::super::*;
use super::*;
use sid_core::models::{Organization, Profile, ProfileId, WorkId};
use sid_plugin::StorageBackend;
use sid_plugin::history_keys::HistoryKeyStore;

/// The work as the runner hands it over.
async fn claimed(storage: &dyn StorageBackend, id: WorkId) -> ClaimedWork {
    let record = storage
        .get_work(id)
        .await
        .unwrap()
        .expect("the purge is owed");
    let payload = storage
        .export_work()
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.record.id == id)
        .unwrap()
        .payload;
    ClaimedWork {
        id: record.id,
        kind: record.kind,
        payload,
        attempt: 1,
        max_attempts: record.max_attempts,
        generation: 1,
        expires_at: None,
    }
}

/// An installation of its own authority with one owner whose first
/// enrollment made it a history key: the store, the authority, the owner
/// and both sides.
async fn owner_with_a_key() -> (
    Arc<sid_storage::sqlite::SqliteBackend>,
    Organization,
    ProfileId,
    Operations,
    Arc<HistoryEvaluation>,
) {
    let storage = sqlite().await;
    let org = Organization::implicit_community("sid.example.com");
    storage
        .insert_instance_organization(&org, AuditEntry::system("test", "org").into())
        .await
        .unwrap();
    let (ops, evaluation) = split(storage.clone(), org.id, manager(3), manager(3));
    let profile = Profile::new(Some("purged-owner"));
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    ops.prepare(
        &zkpp_without_proofs(),
        change(),
        OperationOwner::New(profile.id),
        profile.id.to_string(),
        None,
    )
    .await
    .unwrap();
    (storage, org, profile.id, ops, evaluation)
}

/// The purge a deletion of `owner` owes, as its host commits it.
fn purge_of(org: &Organization, owner: ProfileId) -> NewWork {
    OwnerPurge {
        owner_domain: crate::password_history::owner_domain(org.id.as_bytes(), owner),
    }
    .work()
}

/// The purge destroys an owner's keys, and a preparation of the owner still
/// in flight makes no key afterwards. A repeated purge is harmless.
#[tokio::test]
async fn a_deleted_owners_keys_are_destroyed() {
    let (storage, org, profile, ops, evaluation) = owner_with_a_key().await;
    let domain = crate::password_history::owner_domain(org.id.as_bytes(), profile);
    let keys = || async {
        storage
            .history_keys()
            .get_key_epochs(&domain)
            .await
            .unwrap()
            .epochs
            .len()
    };
    assert_eq!(keys().await, 1);

    let purge = purge_of(&org, profile);
    storage.enqueue_work(&purge, 10).await.unwrap();

    let handler = OwnerPurgeHandler::new(
        storage.clone(),
        EvaluatorDelivery::InProcess(evaluation.clone()),
    );
    let work = claimed(storage.as_ref(), purge.id).await;
    assert_eq!(
        handler.handle(&work).await,
        WorkOutcome::Done(Some("1 keys destroyed".into()))
    );
    assert_eq!(keys().await, 0);

    let delayed = ops
        .prepare(
            &zkpp_without_proofs(),
            change(),
            OperationOwner::New(profile),
            profile.to_string(),
            None,
        )
        .await;
    assert!(delayed.is_err(), "a key was made for a deleted owner");
    assert_eq!(keys().await, 0);
    assert_eq!(
        handler.handle(&work).await,
        WorkOutcome::Done(Some("0 keys destroyed".into())),
        "a repeated purge"
    );
}

/// The handoff to the evaluator of `source` of the purge event `id`.
fn handoff(source: &str, id: uuid::Uuid) -> WorkId {
    let mut event = Event::new(source, event_types::PASSWORD_HISTORY_OWNER_PURGED);
    event.id = id.to_string();
    event.delivery_id(&super::super::relayed::cleanup_consumer(source))
}

/// Handoffs of events to receivers the store holds, done or not.
async fn deliveries(storage: &dyn StorageBackend) -> usize {
    storage
        .export_work()
        .await
        .unwrap()
        .iter()
        .filter(|w| w.record.kind.as_str() == sid_core::models::EVENT_DELIVERY_KIND)
        .count()
}

/// With a separate evaluator, the purge owes the event that tells it,
/// addressed to the evaluator, until the evaluator's settlement is recorded.
/// The attempts of one work share one handoff: while the evaluator is away
/// the first stays in its queue, and another would only pile up beside it.
/// A successor (the attempts ran out) relays anew, in case that one ended
/// without effect. Only the settlement ends the work.
#[tokio::test]
async fn a_separate_evaluator_is_told_of_the_purge_until_it_settles() {
    const SOURCE: &str = "https://sid.example.com";
    let (storage, org, profile, _, _) = owner_with_a_key().await;
    let purge = purge_of(&org, profile);
    storage.enqueue_work(&purge, 10).await.unwrap();
    let handler = OwnerPurgeHandler::new(
        storage.clone(),
        EvaluatorDelivery::Relay {
            source: SOURCE.into(),
        },
    );
    let mut work = claimed(storage.as_ref(), purge.id).await;
    assert!(matches!(handler.handle(&work).await, WorkOutcome::Retry(_)));
    let domain = crate::password_history::owner_domain(org.id.as_bytes(), profile);
    let event = handoff(SOURCE, purge_event_id(&domain, work.id));
    let relay = storage.get_work(event).await.unwrap().expect("relay owed");
    assert_eq!(relay.kind.as_str(), sid_core::models::EVENT_DELIVERY_KIND);

    for attempt in 2..=3 {
        work.attempt = attempt;
        assert!(matches!(handler.handle(&work).await, WorkOutcome::Retry(_)));
    }
    assert_eq!(
        deliveries(storage.as_ref()).await,
        1,
        "each attempt handed the purge over anew"
    );

    // Its attempts run out unsettled (an evaluator outage): the purge goes on
    // in a successor, which relays anew and ends on the settlement.
    assert!(
        handler.on_dead(&work, "awaiting").is_none(),
        "attempts remain"
    );
    work.attempt = work.max_attempts;
    let successor = handler
        .on_dead(&work, "awaiting")
        .expect("the purge goes on");
    assert_ne!(successor.id, work.id);
    storage.enqueue_work(&successor, 10).await.unwrap();
    let mut work = claimed(storage.as_ref(), successor.id).await;
    assert!(matches!(handler.handle(&work).await, WorkOutcome::Retry(_)));
    assert!(
        storage
            .get_work(handoff(SOURCE, purge_event_id(&domain, work.id)))
            .await
            .unwrap()
            .is_some(),
        "the successor relays anew"
    );
    assert_eq!(deliveries(storage.as_ref()).await, 2);

    super::super::relayed::record_settlement(
        storage.as_ref(),
        &sid_core::models::RelayedCleanup::OwnerPurge {
            owner_domain: domain,
        },
    )
    .await
    .unwrap();
    work.attempt = 3;
    assert_eq!(
        handler.handle(&work).await,
        WorkOutcome::Done(Some("settled by the evaluator".into()))
    );
}
