// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::EventFilter;
use sid_plugin::event_bus::{EventBusError, EventBusResult, InProcessEventBus};
use tokio::sync::mpsc;

fn claimed(event: &Event) -> ClaimedWork {
    let work = event.relay();
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

/// A bus that refuses every publish, as while the broker is unreachable.
struct DownBus;

#[async_trait]
impl EventBus for DownBus {
    async fn publish(&self, _: Event) -> EventBusResult<()> {
        Err(EventBusError::PublishFailed("broker unreachable".into()))
    }
    async fn subscribe(&self, _: EventFilter) -> EventBusResult<mpsc::Receiver<Event>> {
        Err(EventBusError::SubscribeFailed("down".into()))
    }
    async fn health_check(&self) -> EventBusResult<()> {
        Err(EventBusError::PublishFailed("down".into()))
    }
}

/// A relayed event reaches the bus unchanged and the work is done.
#[tokio::test]
async fn test_relay_publishes_the_committed_event() {
    let bus = Arc::new(InProcessEventBus::new());
    let mut rx = bus.subscribe(EventFilter::default()).await.unwrap();
    let event = Event::new("src", "sid.user.created.v1").with_subject("profile/p");

    let outcome = EventRelayHandler::new(bus).handle(&claimed(&event)).await;
    assert!(matches!(outcome, WorkOutcome::Done(None)), "{outcome:?}");
    let published = rx.try_recv().expect("the event was not published");
    assert_eq!(published.id, event.id);
    assert_eq!(published.subject.as_deref(), Some("profile/p"));
}

/// While the bus refuses, the event stays owed.
#[tokio::test]
async fn test_relay_retries_while_bus_is_down() {
    let event = Event::new("src", "sid.user.created.v1");
    let outcome = EventRelayHandler::new(Arc::new(DownBus))
        .handle(&claimed(&event))
        .await;
    assert!(matches!(outcome, WorkOutcome::Retry(_)), "{outcome:?}");
}

/// A payload that is not an event can never be published.
#[tokio::test]
async fn test_relay_malformed_payload_is_permanent() {
    let mut work = claimed(&Event::new("src", "t.v1"));
    work.payload = b"not json".to_vec();
    let outcome = EventRelayHandler::new(Arc::new(InProcessEventBus::new()))
        .handle(&work)
        .await;
    assert!(matches!(outcome, WorkOutcome::Permanent(_)), "{outcome:?}");
}

/// Records what is enqueued and under which capacity.
#[derive(Default)]
struct RecordingStore(std::sync::Mutex<Vec<(sid_core::models::WorkId, u64)>>);

#[async_trait]
impl WorkStore for RecordingStore {
    async fn enqueue_work(&self, work: &NewWork, capacity: u64) -> sid_core::Result<bool> {
        self.0.lock().unwrap().push((work.id, capacity));
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
    async fn complete_work(
        &self,
        _: sid_core::models::WorkId,
        _: i64,
        _: Option<&str>,
    ) -> sid_core::Result<bool> {
        unimplemented!()
    }
    async fn fail_work(
        &self,
        _: sid_core::models::WorkId,
        _: i64,
        _: &sid_core::models::WorkFailure,
    ) -> sid_core::Result<bool> {
        unimplemented!()
    }
    async fn get_work(
        &self,
        _: sid_core::models::WorkId,
    ) -> sid_core::Result<Option<sid_core::models::WorkRecord>> {
        unimplemented!()
    }
    async fn export_work(&self) -> sid_core::Result<Vec<sid_core::models::WorkSnapshot>> {
        unimplemented!()
    }
    async fn import_work(&self, _: &sid_core::models::WorkSnapshot) -> sid_core::Result<bool> {
        unimplemented!()
    }
}

/// An observed event is stored as its own relay work, under the observation
/// capacity: below what mutations may owe, so a flood of observations cannot
/// refuse a mutation its event.
#[tokio::test]
async fn test_observed_event_uses_the_observation_capacity() {
    let store = RecordingStore::default();
    let event = Event::new("src", "sid.security.brute_force.v1");

    relay_observed(&store, &event).await.unwrap();
    let stored = store.0.lock().unwrap().clone();
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
