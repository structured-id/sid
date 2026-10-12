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
/// As a store keeps work: the first item under an id stays, a repeated
/// enqueue keeps it unchanged, and an id in `refuse` is refused once (a
/// failure part way through owing several items).
#[derive(Default)]
struct RecordingStore {
    enqueued: Mutex<Vec<(NewWork, u64)>>,
    full: bool,
    refuse: Mutex<std::collections::HashSet<WorkId>>,
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

    fn get(&self, id: WorkId) -> Option<NewWork> {
        self.enqueued
            .lock()
            .unwrap()
            .iter()
            .find(|(w, _)| w.id == id)
            .map(|(w, _)| w.clone())
    }
}

#[async_trait]
impl WorkStore for RecordingStore {
    async fn enqueue_work(&self, work: &NewWork, capacity: u64) -> sid_core::Result<bool> {
        if self.full || self.refuse.lock().unwrap().remove(&work.id) {
            return Err(sid_core::Error::ResourceExhausted("full".into()));
        }
        let mut enqueued = self.enqueued.lock().unwrap();
        if enqueued.iter().any(|(w, _)| w.id == work.id) {
            return Ok(false);
        }
        enqueued.push((work.clone(), capacity));
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

fn relay(store: Arc<RecordingStore>) -> EventRelayHandler {
    EventRelayHandler::new(store, receivers(), CAPACITY)
}

fn fanout(bus: Arc<RecordingBus>, store: Arc<RecordingStore>) -> EventFanoutHandler {
    EventFanoutHandler::new(bus, store, CAPACITY)
}

/// The plan stored for `event`, as the runner would claim it.
fn plan_of(store: &RecordingStore, event: &Event) -> ClaimedWork {
    claimed(
        store
            .get(event.fanout(&[]).id)
            .expect("the plan was not stored"),
    )
}

/// A relayed fact gets one plan naming every receiver that requires its
/// type; carrying it out owes the fact to each, under its own stable
/// delivery id and the given capacity, then publishes it unchanged.
#[tokio::test]
async fn test_relay_owes_required_receivers_then_publishes() {
    let bus = Arc::new(RecordingBus::default());
    let store = Arc::new(RecordingStore::default());
    let event = Event::new("src", event_types::SCIM_USER_PROVISIONED).with_subject("profile/p");

    let outcome = relay(store.clone()).handle(&claimed(event.relay())).await;
    assert!(matches!(outcome, WorkOutcome::Done(_)), "{outcome:?}");
    let plan = plan_of(&store, &event);
    assert_eq!(plan.kind.as_str(), EVENT_FANOUT_KIND);
    let planned: EventFanout = serde_json::from_slice(&plan.payload).unwrap();
    assert_eq!(
        planned.receivers,
        [recipient("sid-notify"), recipient("scim")]
    );
    assert!(
        bus.published.lock().unwrap().is_empty(),
        "published before owed"
    );

    let outcome = fanout(bus.clone(), store.clone()).handle(&plan).await;
    assert!(matches!(outcome, WorkOutcome::Done(_)), "{outcome:?}");
    assert_eq!(
        store.ids()[1..],
        [
            event.delivery_id(&recipient("sid-notify")),
            event.delivery_id(&recipient("scim"))
        ]
    );
    for (work, capacity) in store.enqueued.lock().unwrap().iter() {
        assert_eq!(*capacity, CAPACITY);
        if work.id != plan.id {
            assert_eq!(work.kind.as_str(), EVENT_DELIVERY_KIND);
        }
    }
    let published = bus.published.lock().unwrap().clone();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].id, event.id);
    assert_eq!(published[0].subject.as_deref(), Some("profile/p"));
}

/// A receiver whose patterns do not take the type is owed nothing; a retried
/// relay and a repeated plan owe the same under the same ids, so the store
/// keeps one each.
#[tokio::test]
async fn test_relay_owes_only_matching_receivers_with_stable_ids() {
    let bus = Arc::new(RecordingBus::default());
    let store = Arc::new(RecordingStore::default());
    let event = Event::new("src", event_types::SESSION_REVOKED);
    let handler = relay(store.clone());
    handler.handle(&claimed(event.relay())).await;
    handler.handle(&claimed(event.relay())).await;
    let plan = plan_of(&store, &event);
    fanout(bus.clone(), store.clone()).handle(&plan).await;
    fanout(bus, store.clone()).handle(&plan).await;
    let notify = event.delivery_id(&recipient("sid-notify"));
    assert_eq!(store.ids(), [plan.id, notify]);
}

/// The receivers a fact is owed to are fixed once: when owing them failed
/// part way (one delivery stored, the next refused) and the deployment's
/// receivers changed before the retry, the retry still owes the original
/// ones, the refused one included, and owes the old fact to no receiver the
/// new configuration added.
#[tokio::test]
async fn test_a_retry_keeps_the_receivers_first_fixed() {
    let bus = Arc::new(RecordingBus::default());
    let store = Arc::new(RecordingStore::default());
    let event = Event::new("src", event_types::SCIM_USER_PROVISIONED);
    let scim = event.delivery_id(&recipient("scim"));
    store.refuse.lock().unwrap().insert(scim);

    relay(store.clone()).handle(&claimed(event.relay())).await;
    let plan = plan_of(&store, &event);
    let first = fanout(bus.clone(), store.clone()).handle(&plan).await;
    assert!(matches!(first, WorkOutcome::Retry(_)), "{first:?}");

    // The configuration changes; the relay is run again (a lost outcome).
    let changed = EventRelayHandler::new(
        store.clone(),
        vec![RequiredReceiver {
            recipient: recipient("audit-sink"),
            event_types: Vec::new(),
        }],
        CAPACITY,
    );
    let retried = changed.handle(&claimed(event.relay())).await;
    assert!(matches!(retried, WorkOutcome::Done(_)), "{retried:?}");
    let plan = plan_of(&store, &event);
    let done = fanout(bus.clone(), store.clone()).handle(&plan).await;
    assert!(matches!(done, WorkOutcome::Done(_)), "{done:?}");

    assert!(
        store.get(scim).is_some(),
        "the refused delivery was never owed"
    );
    assert!(
        store
            .get(event.delivery_id(&recipient("sid-notify")))
            .is_some()
    );
    assert!(
        store
            .get(event.delivery_id(&recipient("audit-sink")))
            .is_none(),
        "a receiver added later was owed an earlier fact"
    );
}

/// On a real store the plan first stored is the one carried out: a relay
/// committed under one configuration and retried after `SID_EVENT_RECEIVERS`
/// changed and SCIM targets were removed owes its fact to the receivers of
/// the first plan, each kept as pending work, and to none added later.
#[tokio::test]
async fn test_owed_deliveries_survive_a_receiver_change() {
    let store = Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    );
    let event = Event::new("src", event_types::SCIM_USER_PROVISIONED);
    let work = claimed(event.relay());
    let outcome = EventRelayHandler::new(store.clone(), receivers(), CAPACITY)
        .handle(&work)
        .await;
    assert!(matches!(outcome, WorkOutcome::Done(_)), "{outcome:?}");
    let outcome = EventRelayHandler::new(
        store.clone(),
        vec![RequiredReceiver {
            recipient: recipient("audit-sink"),
            event_types: Vec::new(),
        }],
        CAPACITY,
    )
    .handle(&work)
    .await;
    assert!(matches!(outcome, WorkOutcome::Done(_)), "{outcome:?}");

    let plan_id = event.fanout(&[]).id;
    let plan = store.get_work(plan_id).await.unwrap().expect("plan stored");
    assert_eq!(plan.state, sid_core::models::WorkState::Pending);
    let payload = store
        .export_work()
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.record.id == plan_id)
        .unwrap()
        .payload;
    let outcome =
        EventFanoutHandler::new(Arc::new(RecordingBus::default()), store.clone(), CAPACITY)
            .handle(&ClaimedWork {
                id: plan_id,
                kind: plan.kind,
                payload,
                attempt: 1,
                max_attempts: plan.max_attempts,
                generation: 1,
                expires_at: None,
            })
            .await;
    assert!(matches!(outcome, WorkOutcome::Done(_)), "{outcome:?}");

    for name in ["sid-notify", "scim"] {
        let owed = store
            .get_work(event.delivery_id(&recipient(name)))
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("the delivery to {name} was not owed"));
        assert_eq!(owed.state, sid_core::models::WorkState::Pending, "{name}");
    }
    assert!(
        store
            .get_work(event.delivery_id(&recipient("audit-sink")))
            .await
            .unwrap()
            .is_none(),
        "a receiver added later was owed an earlier fact"
    );
}

/// While the bus refuses, the plan stays owed, and the deliveries it
/// already stored stay owed as their own work.
#[tokio::test]
async fn test_fanout_retries_while_bus_is_down() {
    let store = Arc::new(RecordingStore::default());
    let event = Event::new("src", event_types::USER_CREATED);
    relay(store.clone()).handle(&claimed(event.relay())).await;
    let plan = plan_of(&store, &event);
    let outcome = fanout(Arc::new(RecordingBus::refusing(down)), store.clone())
        .handle(&plan)
        .await;
    assert!(matches!(outcome, WorkOutcome::Retry(_)), "{outcome:?}");
    assert_eq!(store.ids().len(), 2, "plan and its delivery");
}

/// A plan that cannot be stored (the store full) leaves the relay owed; a
/// delivery that cannot be stored leaves the plan owed and publishes nothing.
#[tokio::test]
async fn test_relay_retries_when_nothing_can_be_owed() {
    let event = Event::new("src", event_types::USER_CREATED);
    let full = Arc::new(RecordingStore {
        full: true,
        ..RecordingStore::default()
    });
    let outcome = relay(full).handle(&claimed(event.relay())).await;
    assert!(matches!(outcome, WorkOutcome::Retry(_)), "{outcome:?}");

    let bus = Arc::new(RecordingBus::default());
    let store = Arc::new(RecordingStore::default());
    relay(store.clone()).handle(&claimed(event.relay())).await;
    let plan = plan_of(&store, &event);
    store
        .refuse
        .lock()
        .unwrap()
        .insert(event.delivery_id(&recipient("sid-notify")));
    let outcome = fanout(bus.clone(), store).handle(&plan).await;
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
        let store = Arc::new(RecordingStore::default());
        let event = Event::new("src", event_type);
        let outcome = relay(store.clone()).handle(&claimed(event.relay())).await;
        assert!(
            matches!(outcome, WorkOutcome::Permanent(_)),
            "{event_type}: {outcome:?}"
        );
        assert!(store.ids().is_empty(), "{event_type} was planned");
    }
}

/// A plan that is not one can never be carried out.
#[tokio::test]
async fn test_fanout_malformed_plan_is_permanent() {
    let mut work = claimed(Event::new("src", event_types::USER_CREATED).fanout(&[]));
    work.payload = b"{}".to_vec();
    let outcome = fanout(
        Arc::new(RecordingBus::default()),
        Arc::new(RecordingStore::default()),
    )
    .handle(&work)
    .await;
    assert!(matches!(outcome, WorkOutcome::Permanent(_)), "{outcome:?}");
}

/// A payload that is not an event can never be relayed.
#[tokio::test]
async fn test_relay_malformed_payload_is_permanent() {
    let mut work = claimed(Event::new("src", event_types::USER_CREATED).relay());
    work.payload = b"not json".to_vec();
    let outcome = relay(Arc::new(RecordingStore::default()))
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

/// A broker that stays down, or a work stream that stays full, never ends a
/// required handoff: at the relay's slowest pace its attempts outlast a
/// century, so it is still pending when the broker returns.
#[test]
fn test_relay_budget_outlasts_any_outage() {
    let slowest = RELAY_RETRY.after(u32::MAX).as_secs();
    let lasts = u64::from(sid_core::models::EVENT_RELAY_ATTEMPTS) * slowest;
    assert!(
        lasts > 100 * 365 * 86_400,
        "a handoff gives up after {lasts} s"
    );
}
