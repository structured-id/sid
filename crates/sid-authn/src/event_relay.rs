// SPDX-License-Identifier: AGPL-3.0-only
//! Relay of committed events to the event bus (transactional outbox).
//!
//! A mutation that produces a fact commits it as durable work
//! ([`Event::relay`]) in its own transaction. [`EventRelayHandler`] owes it to
//! each receiver the deployment requires for its type, as durable work of its
//! own ([`Event::deliver`]), and then publishes it to the retained history.
//! [`EventDeliveryHandler`] hands each delivery to the bus, which keeps it
//! until its receiver settles it. Every handoff is recorded on its own and
//! keeps its id across retries, so the bus stores a republication once.

use crate::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use async_trait::async_trait;
use sid_core::models::{
    ClaimedWork, EVENT_DELIVERY_KIND, EVENT_RELAY_KIND, Event, EventDelivery, EventFamily,
    EventRoute, NewWork, RequiredReceiver, WorkKind, event_route,
};
use sid_plugin::WorkStore;
use sid_plugin::event_bus::{EventBus, EventBusError};
use std::sync::Arc;
use std::time::Duration;

/// Delays between publish attempts: quick at first, then hourly while the
/// bus stays unavailable.
pub const RELAY_RETRY: RetrySchedule = RetrySchedule::new(&[
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(120),
    Duration::from_secs(600),
    Duration::from_secs(3600),
]);

/// Open relay work beyond which an observed event is refused. It stays below
/// the capacity of work a mutation owes, so a flood of observations (a
/// password-guessing run) never refuses a mutation for its event.
pub const OBSERVED_EVENT_CAPACITY: u64 = 10_000;

/// Relay an event that no state change carries (a refused sign-in) as
/// durable work of its own. `Error::ResourceExhausted` when the relay backlog
/// holds [`OBSERVED_EVENT_CAPACITY`] items.
pub async fn relay_observed<S: WorkStore + ?Sized>(
    store: &S,
    event: &Event,
) -> sid_core::Result<()> {
    store
        .enqueue_work(&event.relay(), OBSERVED_EVENT_CAPACITY)
        .await
        .map(|_| ())
}

/// The outcome of a bus refusal: a type the bus does not carry never will,
/// anything else may pass later.
fn refused(what: &str, e: EventBusError) -> WorkOutcome {
    match e {
        EventBusError::Unroutable(_) => WorkOutcome::Permanent(format!("{what}: {e}")),
        e => WorkOutcome::Retry(format!("{what}: {e}")),
    }
}

/// Owes each committed fact to its required receivers, then publishes it to
/// the history.
pub struct EventRelayHandler {
    kind: WorkKind,
    bus: Arc<dyn EventBus>,
    work: Arc<dyn WorkStore>,
    receivers: Vec<RequiredReceiver>,
    capacity: u64,
}

impl EventRelayHandler {
    /// A relay onto `bus` that owes facts to `receivers` as work in `work`,
    /// each kind holding at most `capacity` open items.
    pub fn new(
        bus: Arc<dyn EventBus>,
        work: Arc<dyn WorkStore>,
        receivers: Vec<RequiredReceiver>,
        capacity: u64,
    ) -> Self {
        Self {
            kind: WorkKind::new(EVENT_RELAY_KIND).expect("the relay kind is valid"),
            bus,
            work,
            receivers,
            capacity,
        }
    }
}

#[async_trait]
impl WorkHandler for EventRelayHandler {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RELAY_RETRY
    }

    /// The failed work is the durable record of an event the bus never
    /// accepted; no further event is raised through the bus that failed.
    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let event: Event = match serde_json::from_slice(&work.payload) {
            Ok(event) => event,
            Err(e) => return WorkOutcome::Permanent(format!("malformed relayed event: {e}")),
        };
        if event_route(&event.event_type) != Some(EventRoute::Fact(EventFamily::Identity)) {
            return WorkOutcome::Permanent(format!(
                "{} is not a registered identity fact",
                event.event_type
            ));
        }
        // The deliveries are owed before the history is published, each
        // under its stable id: a retried relay stores none twice, and one a
        // later configuration no longer requires stays owed.
        let mut owed = 0usize;
        for receiver in self
            .receivers
            .iter()
            .filter(|r| r.requires(&event.event_type))
        {
            if let Err(e) = self
                .work
                .enqueue_work(&event.deliver(&receiver.recipient), self.capacity)
                .await
            {
                return WorkOutcome::Retry(format!("owe to {}: {e}", receiver.recipient));
            }
            owed += 1;
        }
        match self.bus.publish(event).await {
            Ok(()) => WorkOutcome::Done(Some(format!("published; owed to {owed} receivers"))),
            Err(e) => refused("publish", e),
        }
    }
}

/// Hands each owed event to its receiver.
pub struct EventDeliveryHandler {
    kind: WorkKind,
    bus: Arc<dyn EventBus>,
}

impl EventDeliveryHandler {
    pub fn new(bus: Arc<dyn EventBus>) -> Self {
        Self {
            kind: WorkKind::new(EVENT_DELIVERY_KIND).expect("the delivery kind is valid"),
            bus,
        }
    }
}

#[async_trait]
impl WorkHandler for EventDeliveryHandler {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RELAY_RETRY
    }

    /// The failed work is the durable record of a handoff the bus never
    /// accepted.
    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let delivery: EventDelivery = match serde_json::from_slice(&work.payload) {
            Ok(delivery) => delivery,
            Err(e) => return WorkOutcome::Permanent(format!("malformed delivery: {e}")),
        };
        // The work id is the delivery's identity, so the bus keeps one copy
        // however often this attempt is repeated.
        match self
            .bus
            .deliver(&delivery.recipient, work.id, &delivery.event)
            .await
        {
            Ok(()) => WorkOutcome::Done(None),
            Err(e) => refused("deliver", e),
        }
    }
}

#[cfg(test)]
mod tests;
