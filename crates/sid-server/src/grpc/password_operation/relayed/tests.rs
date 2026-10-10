// SPDX-License-Identifier: AGPL-3.0-only
use super::super::tests::{change, manager, split, sqlite, zkpp_without_proofs};
use super::super::*;
use super::*;
use sid_core::models::event::EventFilter;
use sid_plugin::event_bus::{Delivery, EventBusError};
use tokio::sync::mpsc;

/// The credential authority whose cleanup the evaluator serves.
const AUTHORITY: &str = "sid-credentials.sid.example.com";

/// A bus handing the consumer the deliveries a test feeds it.
struct Feed(std::sync::Mutex<Option<mpsc::Receiver<Delivery>>>);

#[tonic::async_trait]
impl EventBus for Feed {
    async fn publish(&self, _: Event) -> EventBusResult<()> {
        Ok(())
    }
    async fn subscribe(&self, _: EventFilter) -> EventBusResult<mpsc::Receiver<Event>> {
        Err(EventBusError::NotConnected)
    }
    async fn consume(&self, consumer: DurableConsumer) -> EventBusResult<mpsc::Receiver<Delivery>> {
        assert_eq!(consumer.name, CLEANUP_CONSUMER);
        Ok(self.0.lock().unwrap().take().expect("consumed once"))
    }
    async fn health_check(&self) -> EventBusResult<()> {
        Ok(())
    }
}

/// Deliver `events` one at a time to the evaluator's cleanup consumer, as the
/// bus does, and return how each was settled.
async fn relay(evaluation: Arc<HistoryEvaluation>, events: Vec<Event>) -> Vec<Settlement> {
    let (tx, rx) = mpsc::channel(1);
    let bus = Feed(std::sync::Mutex::new(Some(rx)));
    let consumer =
        tokio::spawn(async move { consume_relayed_cleanup(&bus, evaluation, AUTHORITY).await });
    let mut settled = Vec::new();
    for event in events {
        let (delivery, outcome) = Delivery::new(event);
        tx.send(delivery).await.unwrap();
        settled.push(outcome.await.expect("settled"));
    }
    drop(tx);
    consumer.await.unwrap().unwrap();
    settled
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
    let settled = relay(evaluation, vec![abort.clone(), purge, abort]).await;
    assert_eq!(
        settled,
        vec![Settlement::Done, Settlement::Done, Settlement::Done]
    );
    assert_eq!(keys(&storage, &aborted.owner_domain).await, 0, "reclaimed");
    assert_eq!(keys(&storage, &deleted.owner_domain).await, 0, "destroyed");
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
