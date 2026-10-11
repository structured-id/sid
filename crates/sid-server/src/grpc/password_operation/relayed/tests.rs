// SPDX-License-Identifier: AGPL-3.0-only
use super::super::tests::{change, manager, split, sqlite, zkpp_without_proofs};
use super::super::*;
use super::*;
use sid_core::models::event::EventFilter;
use sid_plugin::event_bus::{Delivery, EventBusError};
use tokio::sync::mpsc;

/// The credential authority whose cleanup the evaluator serves.
const AUTHORITY: &str = "sid-credentials.sid.example.com";

/// A bus handing the consumer the deliveries a test feeds it and keeping
/// what is addressed to the credential authority, or refusing every handoff.
struct Feed {
    deliveries: std::sync::Mutex<Option<mpsc::Receiver<Delivery>>>,
    published: Arc<std::sync::Mutex<Vec<Event>>>,
    publishes: bool,
    /// The durable consumer the consumer under test must open.
    consumer: WorkRecipient,
}

#[tonic::async_trait]
impl EventBus for Feed {
    async fn publish(&self, event: Event) -> EventBusResult<()> {
        panic!(
            "{} went to history instead of its receiver",
            event.event_type
        )
    }
    async fn deliver(
        &self,
        recipient: &WorkRecipient,
        delivery: sid_core::models::WorkId,
        event: &Event,
    ) -> EventBusResult<()> {
        if !self.publishes {
            return Err(EventBusError::NotConnected);
        }
        assert_eq!(*recipient, settlement_consumer(AUTHORITY));
        assert_eq!(delivery, event.delivery_id(recipient));
        self.published.lock().unwrap().push(event.clone());
        Ok(())
    }
    async fn subscribe(&self, _: EventFilter) -> EventBusResult<mpsc::Receiver<Event>> {
        Err(EventBusError::NotConnected)
    }
    async fn consume(&self, consumer: DurableConsumer) -> EventBusResult<mpsc::Receiver<Delivery>> {
        assert_eq!(consumer.recipient, self.consumer);
        Ok(self
            .deliveries
            .lock()
            .unwrap()
            .take()
            .expect("consumed once"))
    }
    async fn health_check(&self) -> EventBusResult<()> {
        Ok(())
    }
}

/// Deliver `events` one at a time to a consumer run on a [`Feed`] under the
/// durable consumer `name`, as the bus does; how each was settled, and what
/// the consumer published.
async fn feed<F, Fut>(
    name: WorkRecipient,
    events: Vec<Event>,
    publishes: bool,
    run: F,
) -> (Vec<Settlement>, Vec<Event>)
where
    F: FnOnce(Feed) -> Fut,
    Fut: std::future::Future<Output = EventBusResult<()>> + Send + 'static,
{
    let (tx, rx) = mpsc::channel(1);
    let published = Arc::new(std::sync::Mutex::new(Vec::new()));
    let consumer = tokio::spawn(run(Feed {
        deliveries: std::sync::Mutex::new(Some(rx)),
        published: published.clone(),
        publishes,
        consumer: name,
    }));
    let mut settled = Vec::new();
    for event in events {
        let (delivery, outcome) = Delivery::new(event);
        tx.send(delivery).await.unwrap();
        settled.push(outcome.await.expect("settled"));
    }
    drop(tx);
    consumer.await.unwrap().unwrap();
    let published = published.lock().unwrap().clone();
    (settled, published)
}

/// Deliver `events` to the evaluator's cleanup consumer.
async fn relay(evaluation: Arc<HistoryEvaluation>, events: Vec<Event>) -> Vec<Settlement> {
    relay_reporting(evaluation, events, true).await.0
}

/// [`relay`], with a bus that takes the settlement reports or refuses them,
/// and what was reported.
async fn relay_reporting(
    evaluation: Arc<HistoryEvaluation>,
    events: Vec<Event>,
    publishes: bool,
) -> (Vec<Settlement>, Vec<Event>) {
    feed(
        cleanup_consumer(AUTHORITY),
        events,
        publishes,
        |bus| async move { consume_relayed_cleanup(&bus, evaluation, AUTHORITY).await },
    )
    .await
}

/// A first enrollment prepared for a new owner: its admission.
async fn enrolled(
    ops: &PasswordOperations,
    installation: sid_core::models::OrgId,
) -> EnrollmentAdmission {
    let owner = ProfileId::generate();
    let prepared = ops
        .prepare(
            &zkpp_without_proofs(),
            change(),
            OperationOwner::New(owner),
            owner.to_string(),
            None,
        )
        .await
        .unwrap();
    EnrollmentAdmission {
        operation: operation_id(prepared.context.operation_id.as_ref())
            .unwrap()
            .into_uuid(),
        owner_domain: owner_domain(installation.as_bytes(), owner),
        expires_at: chrono::Utc::now(),
    }
}

fn event(source: &str, kind: &str, data: serde_json::Value) -> Event {
    Event::new(source, kind).with_data(data)
}

async fn keys(storage: &sid_storage::sqlite::SqliteBackend, domain: &[u8; 32]) -> usize {
    storage
        .history_keys()
        .get_key_epochs(domain)
        .await
        .unwrap()
        .epochs
        .len()
}

/// In a split deployment the evaluator acts on the cleanup the credential
/// authority relays: an aborted enrollment's key is reclaimed and a deleted
/// owner's keys destroyed, each acknowledged only once done; a repeated
/// delivery (a lost acknowledgement) is done again harmlessly.
#[tokio::test]
async fn a_separate_evaluator_acts_on_relayed_cleanup() {
    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let (ops, evaluation) = split(storage.clone(), installation, manager(3), manager(3));
    let aborted = enrolled(&ops, installation).await;
    let deleted = enrolled(&ops, installation).await;
    assert_eq!(keys(&storage, &aborted.owner_domain).await, 1);
    assert_eq!(keys(&storage, &deleted.owner_domain).await, 1);

    let abort = event(
        AUTHORITY,
        event_types::PASSWORD_HISTORY_ENROLLMENT_ABORTED,
        serde_json::to_value(aborted).unwrap(),
    );
    let purge = event(
        AUTHORITY,
        event_types::PASSWORD_HISTORY_OWNER_PURGED,
        serde_json::to_value(OwnerPurge {
            owner_domain: deleted.owner_domain,
        })
        .unwrap(),
    );
    let (settled, reported) =
        relay_reporting(evaluation, vec![abort.clone(), purge, abort], true).await;
    assert_eq!(
        settled,
        vec![Settlement::Done, Settlement::Done, Settlement::Done]
    );
    assert_eq!(keys(&storage, &aborted.owner_domain).await, 0, "reclaimed");
    assert_eq!(keys(&storage, &deleted.owner_domain).await, 0, "destroyed");
    // Each settlement is reported to the authority, once per cleanup.
    let cleanups: Vec<RelayedCleanup> = reported
        .iter()
        .map(|e| {
            assert_eq!(e.event_type, event_types::PASSWORD_HISTORY_CLEANUP_SETTLED);
            let settled: CleanupSettled = serde_json::from_value(e.data.clone()).unwrap();
            assert_eq!(settled.authority, AUTHORITY);
            settled.cleanup
        })
        .collect();
    assert_eq!(
        cleanups,
        vec![
            RelayedCleanup::Enrollment {
                operation: aborted.operation
            },
            RelayedCleanup::OwnerPurge {
                owner_domain: deleted.owner_domain
            },
            RelayedCleanup::Enrollment {
                operation: aborted.operation
            },
        ]
    );
    assert_eq!(reported[0].id, reported[2].id, "the same report again");
}

/// A settlement that cannot be reported leaves its event unacknowledged: it
/// is delivered again, acted on again (harmlessly) and reported then.
#[tokio::test]
async fn an_unreported_settlement_is_retried() {
    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let (ops, evaluation) = split(storage.clone(), installation, manager(3), manager(3));
    let aborted = enrolled(&ops, installation).await;
    let abort = event(
        AUTHORITY,
        event_types::PASSWORD_HISTORY_ENROLLMENT_ABORTED,
        serde_json::to_value(aborted).unwrap(),
    );
    let (settled, _) = relay_reporting(evaluation, vec![abort], false).await;
    assert!(matches!(settled[0], Settlement::Retry(_)), "{settled:?}");
}

/// The credential authority records the settlements reported for it, once
/// however often they arrive, and rejects one for another authority.
#[tokio::test]
async fn the_authority_records_its_own_settlements() {
    let storage = sqlite().await;
    let cleanup = RelayedCleanup::Enrollment {
        operation: uuid::Uuid::now_v7(),
    };
    let report = |authority: &str| {
        event(
            "sid-password-history-evaluator",
            event_types::PASSWORD_HISTORY_CLEANUP_SETTLED,
            serde_json::to_value(CleanupSettled {
                authority: authority.into(),
                cleanup,
            })
            .unwrap(),
        )
    };
    let backend: Arc<dyn StorageBackend> = storage.clone();
    let (settled, _) = feed(
        settlement_consumer(AUTHORITY),
        vec![
            report("sid-credentials.other.example.com"),
            report(AUTHORITY),
            report(AUTHORITY),
        ],
        true,
        |bus| async move { consume_cleanup_settlements(&bus, backend, AUTHORITY).await },
    )
    .await;
    assert!(matches!(settled[0], Settlement::Reject(_)), "{settled:?}");
    assert_eq!(settled[1..], [Settlement::Done, Settlement::Done]);
    assert!(settled_in(storage.as_ref(), &cleanup).await);
}

/// Each authority's receivers are its own: authorities sharing a bus each
/// get their own work, instead of splitting one receiver's events and
/// rejecting the other's.
#[test]
fn durable_consumers_are_scoped_by_authority() {
    let other = "sid-credentials.other.example.com";
    for name in [cleanup_consumer, settlement_consumer] {
        assert_eq!(name(AUTHORITY), name(AUTHORITY));
        assert_ne!(name(AUTHORITY), name(other));
    }
    assert_ne!(cleanup_consumer(AUTHORITY), settlement_consumer(AUTHORITY));
}

async fn settled_in(storage: &dyn StorageBackend, cleanup: &RelayedCleanup) -> bool {
    super::settled(storage, cleanup).await.unwrap()
}

/// Only the served authority's cleanup events are acted on: one from another
/// source, one that is no cleanup event and one whose payload is not the
/// event's are rejected, and nothing is destroyed.
#[tokio::test]
async fn foreign_or_malformed_cleanup_is_rejected() {
    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let (ops, evaluation) = split(storage.clone(), installation, manager(3), manager(3));
    let admission = enrolled(&ops, installation).await;
    let data = serde_json::to_value(admission).unwrap();
    let settled = relay(
        evaluation,
        vec![
            event(
                "sid-credentials.other.example.com",
                event_types::PASSWORD_HISTORY_ENROLLMENT_ABORTED,
                data.clone(),
            ),
            event(AUTHORITY, event_types::USER_CREATED, data),
            event(
                AUTHORITY,
                event_types::PASSWORD_HISTORY_OWNER_PURGED,
                serde_json::json!({"owner": "nobody"}),
            ),
        ],
    )
    .await;
    assert!(
        settled.iter().all(|s| matches!(s, Settlement::Reject(_))),
        "{settled:?}"
    );
    assert_eq!(keys(&storage, &admission.owner_domain).await, 1, "kept");
}
