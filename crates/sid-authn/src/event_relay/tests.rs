// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::event::event_types;
use sid_core::models::{EventFilter, WorkId, WorkRecipient};
use sid_plugin::event_bus::EventBusResult;
use std::sync::Mutex;
use tokio::sync::mpsc;

fn claimed(work: NewWork) -> ClaimedWork {
    ClaimedWork {
        id: work.id,
        kind: work.kind,
        payload: work.payload,
        attempt: 1,
        max_attempts: work.max_attempts,
        generation: 1,
        expires_at: None,
    }
}

fn recipient(name: &str) -> WorkRecipient {
    WorkRecipient::new(name).unwrap()
}

/// What a bus was asked to carry, refusing with `refusal` when set.
#[derive(Default)]
struct RecordingBus {
    published: Mutex<Vec<Event>>,
    delivered: Mutex<Vec<(WorkRecipient, WorkId, Event)>>,
    refusal: Option<fn() -> EventBusError>,
}

impl RecordingBus {
    fn refusing(refusal: fn() -> EventBusError) -> Self {
        Self {
            refusal: Some(refusal),
            ..Self::default()
        }
    }

    fn refused(&self) -> EventBusResult<()> {
        self.refusal.map_or(Ok(()), |refusal| Err(refusal()))
    }
}

#[async_trait]
impl EventBus for RecordingBus {
    async fn publish(&self, event: Event) -> EventBusResult<()> {
        self.refused()?;
        self.published.lock().unwrap().push(event);
        Ok(())
    }
    async fn deliver(
        &self,
        recipient: &WorkRecipient,
        delivery: WorkId,
        event: &Event,
    ) -> EventBusResult<()> {
        self.refused()?;
        self.delivered
            .lock()
            .unwrap()
            .push((recipient.clone(), delivery, event.clone()));
        Ok(())
    }
    async fn subscribe(&self, _: EventFilter) -> EventBusResult<mpsc::Receiver<Event>> {
        Err(EventBusError::SubscribeFailed("not observed".into()))
    }
    async fn health_check(&self) -> EventBusResult<()> {
        Ok(())
    }
}

fn down() -> EventBusError {
    EventBusError::PublishFailed("broker unreachable".into())
}

/// Records what is enqueued and under which capacity, refusing everything
/// once `full`.
#[derive(Default)]
struct RecordingStore {
    enqueued: Mutex<Vec<(NewWork, u64)>>,
    full: bool,
}

impl RecordingStore {
    fn ids(&self) -> Vec<WorkId> {
        self.enqueued
            .lock()
            .unwrap()
            .iter()
            .map(|(w, _)| w.id)
            .collect()
    }
}

#[async_trait]
impl WorkStore for RecordingStore {
    async fn enqueue_work(&self, work: &NewWork, capacity: u64) -> sid_core::Result<bool> {
        if self.full {
            return Err(sid_core::Error::ResourceExhausted("full".into()));
        }
        self.enqueued.lock().unwrap().push((work.clone(), capacity));
        Ok(true)
    }
    async fn claim_work(
        &self,
        _: &[WorkKind],
        _: &str,
        _: u32,
        _: Duration,
    ) -> sid_core::Result<Vec<ClaimedWork>> {
        unimplemented!()
    }
    async fn complete_work(&self, _: WorkId, _: i64, _: Option<&str>) -> sid_core::Result<bool> {
        unimplemented!()
    }
    async fn fail_work(
        &self,
        _: WorkId,
        _: i64,
        _: &sid_core::models::WorkFailure,
    ) -> sid_core::Result<bool> {
        unimplemented!()
    }
    async fn get_work(&self, _: WorkId) -> sid_core::Result<Option<sid_core::models::WorkRecord>> {
        unimplemented!()
    }
    async fn export_work(&self) -> sid_core::Result<Vec<sid_core::models::WorkSnapshot>> {
        unimplemented!()
    }
    async fn import_work(&self, _: &sid_core::models::WorkSnapshot) -> sid_core::Result<bool> {
        unimplemented!()
    }
    async fn purge_ended_work(
        &self,
        _: &WorkKind,
        _: chrono::DateTime<chrono::Utc>,
    ) -> sid_core::Result<u64> {
        unimplemented!()
    }
}

const CAPACITY: u64 = 77;

fn receivers() -> Vec<RequiredReceiver> {
    vec![
        RequiredReceiver {
            recipient: recipient("sid-notify"),
            event_types: Vec::new(),
        },
        RequiredReceiver {
            recipient: recipient("scim"),
            event_types: vec!["sid.scim.*".into()],
        },
    ]
}

fn relay(bus: Arc<RecordingBus>, store: Arc<RecordingStore>) -> EventRelayHandler {
    EventRelayHandler::new(bus, store, receivers(), CAPACITY)
}

/// A relayed fact is owed to every receiver that requires its type, each
/// under its own stable delivery id and the given capacity, and is then
/// published to history unchanged.
#[tokio::test]
async fn test_relay_owes_required_receivers_then_publishes() {
    let bus = Arc::new(RecordingBus::default());
    let store = Arc::new(RecordingStore::default());
    let event = Event::new("src", event_types::SCIM_USER_PROVISIONED).with_subject("profile/p");

    let outcome = relay(bus.clone(), store.clone())
        .handle(&claimed(event.relay()))
        .await;
    assert!(matches!(outcome, WorkOutcome::Done(_)), "{outcome:?}");
    assert_eq!(
        store.ids(),
        [
            event.delivery_id(&recipient("sid-notify")),
            event.delivery_id(&recipient("scim"))
        ]
    );
    for (work, capacity) in store.enqueued.lock().unwrap().iter() {
        assert_eq!(work.kind.as_str(), EVENT_DELIVERY_KIND);
        assert_eq!(*capacity, CAPACITY);
    }
    let published = bus.published.lock().unwrap().clone();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].id, event.id);
    assert_eq!(published[0].subject.as_deref(), Some("profile/p"));
}

/// A receiver whose patterns do not take the type is owed nothing; a retried
/// relay owes the same deliveries again under the same ids, so the store
/// keeps one each.
#[tokio::test]
async fn test_relay_owes_only_matching_receivers_with_stable_ids() {
    let bus = Arc::new(RecordingBus::default());
    let store = Arc::new(RecordingStore::default());
    let event = Event::new("src", event_types::SESSION_REVOKED);
    let handler = relay(bus, store.clone());
    handler.handle(&claimed(event.relay())).await;
    handler.handle(&claimed(event.relay())).await;
    let notify = event.delivery_id(&recipient("sid-notify"));
    assert_eq!(store.ids(), [notify, notify]);
}

/// A delivery owed before the deployment's receivers change stays owed:
/// the relay retried under the new set (`SID_EVENT_RECEIVERS` changed, SCIM
/// targets removed) adds the new receivers and erases none of the earlier
/// obligations, which the store keeps as their own pending work.
#[tokio::test]
async fn test_owed_deliveries_survive_a_receiver_change() {
    let store = Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    );
    let event = Event::new("src", event_types::SCIM_USER_PROVISIONED);
    let work = claimed(event.relay());
    let before = EventRelayHandler::new(
        Arc::new(RecordingBus::refusing(down)),
        store.clone(),
        receivers(),
        CAPACITY,
    );
    let outcome = before.handle(&work).await;
    assert!(matches!(outcome, WorkOutcome::Retry(_)), "{outcome:?}");

    let after = EventRelayHandler::new(
        Arc::new(RecordingBus::default()),
        store.clone(),
        vec![RequiredReceiver {
            recipient: recipient("audit-sink"),
            event_types: Vec::new(),
        }],
        CAPACITY,
    );
    let outcome = after.handle(&work).await;
    assert!(matches!(outcome, WorkOutcome::Done(_)), "{outcome:?}");

    for name in ["sid-notify", "scim", "audit-sink"] {
        let owed = store
            .get_work(event.delivery_id(&recipient(name)))
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("the delivery to {name} was not kept"));
        assert_eq!(owed.state, sid_core::models::WorkState::Pending, "{name}");
    }
}

/// While the bus refuses, the relay stays owed, and the deliveries it
/// already stored stay owed as their own work.
#[tokio::test]
async fn test_relay_retries_while_bus_is_down() {
    let store = Arc::new(RecordingStore::default());
    let event = Event::new("src", event_types::USER_CREATED);
    let outcome = relay(Arc::new(RecordingBus::refusing(down)), store.clone())
        .handle(&claimed(event.relay()))
        .await;
    assert!(matches!(outcome, WorkOutcome::Retry(_)), "{outcome:?}");
    assert_eq!(store.ids().len(), 1);
}

/// A delivery that cannot be stored (the store full) leaves the relay owed
/// and publishes nothing yet.
#[tokio::test]
async fn test_relay_retries_when_a_delivery_cannot_be_owed() {
    let bus = Arc::new(RecordingBus::default());
    let store = Arc::new(RecordingStore {
        full: true,
        ..RecordingStore::default()
    });
    let event = Event::new("src", event_types::USER_CREATED);
    let outcome = relay(bus.clone(), store)
        .handle(&claimed(event.relay()))
        .await;
    assert!(matches!(outcome, WorkOutcome::Retry(_)), "{outcome:?}");
    assert!(bus.published.lock().unwrap().is_empty());
}

/// Only registered identity facts are relayed: addressed work, a platform
/// fact and an unknown type fail visibly, owing and publishing nothing.
#[tokio::test]
async fn test_relay_refuses_what_is_not_an_identity_fact() {
    for event_type in [
        event_types::PASSWORD_HISTORY_OWNER_PURGED,
        event_types::ORG_TRIAL_ACTIVATED,
        "sid.unknown.v1",
    ] {
        let bus = Arc::new(RecordingBus::default());
        let store = Arc::new(RecordingStore::default());
        let event = Event::new("src", event_type);
        let outcome = relay(bus.clone(), store.clone())
            .handle(&claimed(event.relay()))
            .await;
        assert!(
            matches!(outcome, WorkOutcome::Permanent(_)),
            "{event_type}: {outcome:?}"
        );
        assert!(store.ids().is_empty(), "{event_type} was owed");
        assert!(bus.published.lock().unwrap().is_empty());
    }
}

/// A payload that is not an event can never be relayed.
#[tokio::test]
async fn test_relay_malformed_payload_is_permanent() {
    let mut work = claimed(Event::new("src", event_types::USER_CREATED).relay());
    work.payload = b"not json".to_vec();
    let outcome = relay(
        Arc::new(RecordingBus::default()),
        Arc::new(RecordingStore::default()),
    )
    .handle(&work)
    .await;
    assert!(matches!(outcome, WorkOutcome::Permanent(_)), "{outcome:?}");
}

/// A delivery hands its event to its receiver under the work's id, which is
/// the delivery id, so a repeated attempt is held once by the bus.
#[tokio::test]
async fn test_delivery_hands_the_event_under_its_id() {
    let bus = Arc::new(RecordingBus::default());
    let event = Event::new("src", event_types::PASSWORD_HISTORY_OWNER_PURGED);
    let evaluator = recipient("evaluator");
    let outcome = EventDeliveryHandler::new(bus.clone())
        .handle(&claimed(event.deliver(&evaluator)))
        .await;
    assert!(matches!(outcome, WorkOutcome::Done(None)), "{outcome:?}");
    let delivered = bus.delivered.lock().unwrap().clone();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].0, evaluator);
    assert_eq!(delivered[0].1, event.delivery_id(&evaluator));
    assert_eq!(delivered[0].2.id, event.id);
}

/// A bus outage retries a delivery; a type the bus does not carry, or a
/// payload that is not a delivery, ends it visibly.
#[tokio::test]
async fn test_delivery_outcomes() {
    let event = Event::new("src", event_types::USER_CREATED);
    let work = claimed(event.deliver(&recipient("r")));
    let handle = |bus: RecordingBus, work: ClaimedWork| async move {
        EventDeliveryHandler::new(Arc::new(bus)).handle(&work).await
    };
    let outcome = handle(RecordingBus::refusing(down), work.clone()).await;
    assert!(matches!(outcome, WorkOutcome::Retry(_)), "{outcome:?}");
    let outcome = handle(
        RecordingBus::refusing(|| EventBusError::Unroutable("t".into())),
        work.clone(),
    )
    .await;
    assert!(matches!(outcome, WorkOutcome::Permanent(_)), "{outcome:?}");
    let mut malformed = work;
    malformed.payload = b"{}".to_vec();
    let outcome = handle(RecordingBus::default(), malformed).await;
    assert!(matches!(outcome, WorkOutcome::Permanent(_)), "{outcome:?}");
}

/// An observed event is stored as its own relay work, under the observation
/// capacity: below what mutations may owe, so a flood of observations cannot
/// refuse a mutation its event.
#[tokio::test]
async fn test_observed_event_uses_the_observation_capacity() {
    let store = RecordingStore::default();
    let event = Event::new("src", event_types::SECURITY_BRUTE_FORCE);

    relay_observed(&store, &event).await.unwrap();
    let stored: Vec<(WorkId, u64)> = store
        .enqueued
        .lock()
        .unwrap()
        .iter()
        .map(|(w, c)| (w.id, *c))
        .collect();
    assert_eq!(stored, [(event.relay().id, OBSERVED_EVENT_CAPACITY)]);
    const {
        assert!(
            OBSERVED_EVENT_CAPACITY < sid_storage::OWED_WORK_CAPACITY,
            "observations may crowd out owed events"
        )
    };
}

/// Hourly retries over the attempt budget outlast a day-long outage.
#[test]
fn test_relay_budget_outlasts_a_day() {
    let total: u64 = (1..sid_core::models::EVENT_RELAY_ATTEMPTS)
        .map(|a| RELAY_RETRY.after(a).as_secs())
        .sum();
    assert!(total > 86_400, "relay gives up after {total} s");
}
