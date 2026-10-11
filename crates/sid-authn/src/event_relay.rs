// SPDX-License-Identifier: AGPL-3.0-only
//! Relay of committed events to the event bus (transactional outbox).
//!
//! A mutation that produces a fact commits it as durable work
//! ([`Event::relay`]) in its own transaction. [`EventRelayHandler`] fixes the
//! receivers it is owed to: the ones the deployment requires for its type
//! when the plan is first stored ([`Event::fanout`]); a later configuration
//! never rewrites it. [`EventFanoutHandler`] owes the fact to each planned
//! receiver as durable work of its own ([`Event::deliver`]) and then
//! publishes it to the retained history. [`EventDeliveryHandler`] hands each
//! delivery to the bus, which keeps it until its receiver settles it. Every
//! handoff is recorded on its own and keeps its id across retries, so the bus
//! stores a republication once.

use crate::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use async_trait::async_trait;
use sid_core::models::{
    ClaimedWork, EVENT_DELIVERY_KIND, EVENT_FANOUT_KIND, EVENT_RELAY_KIND, Event, EventDelivery,
    EventFamily, EventFanout, EventRoute, NewWork, RequiredReceiver, WorkKind, WorkRecipient,
    event_route,
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

/// Fixes the receivers each committed fact is owed to.
pub struct EventRelayHandler {
    kind: WorkKind,
    work: Arc<dyn WorkStore>,
    receivers: Vec<RequiredReceiver>,
    capacity: u64,
}

impl EventRelayHandler {
    /// A relay owing facts to the `receivers` that require their types, as a
    /// plan stored in `work`, each kind holding at most `capacity` open items.
    pub fn new(work: Arc<dyn WorkStore>, receivers: Vec<RequiredReceiver>, capacity: u64) -> Self {
        Self {
            kind: WorkKind::new(EVENT_RELAY_KIND).expect("the relay kind is valid"),
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
        // The plan is stored whole, under an id of the event alone: the store
        // keeps the first one, so the receivers are fixed when this first
        // succeeds and a retry under another configuration owes the same.
        let receivers: Vec<WorkRecipient> = self
            .receivers
            .iter()
            .filter(|r| r.requires(&event.event_type))
            .map(|r| r.recipient.clone())
            .collect();
        match self
            .work
            .enqueue_work(&event.fanout(&receivers), self.capacity)
            .await
        {
            Ok(_) => WorkOutcome::Done(Some(format!("planned for {} receivers", receivers.len()))),
            Err(e) => WorkOutcome::Retry(format!("plan: {e}")),
        }
    }
}

/// Carries out a fact's fixed plan: owes it to each planned receiver, then
/// publishes it to the history.
pub struct EventFanoutHandler {
    kind: WorkKind,
    bus: Arc<dyn EventBus>,
    work: Arc<dyn WorkStore>,
    capacity: u64,
}

impl EventFanoutHandler {
    /// Fan-out onto `bus`, owing deliveries as work in `work`, each kind
    /// holding at most `capacity` open items.
    pub fn new(bus: Arc<dyn EventBus>, work: Arc<dyn WorkStore>, capacity: u64) -> Self {
        Self {
            kind: WorkKind::new(EVENT_FANOUT_KIND).expect("the fan-out kind is valid"),
            bus,
            work,
            capacity,
        }
    }
}

#[async_trait]
impl WorkHandler for EventFanoutHandler {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RELAY_RETRY
    }

    /// The failed plan is the durable record of a fact not fully handed on.
    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let plan: EventFanout = match serde_json::from_slice(&work.payload) {
            Ok(plan) => plan,
            Err(e) => return WorkOutcome::Permanent(format!("malformed plan: {e}")),
        };
        // The deliveries are owed before the history is published, each
        // under its stable id: a retried plan stores none twice.
        for recipient in &plan.receivers {
            if let Err(e) = self
                .work
                .enqueue_work(&plan.event.deliver(recipient), self.capacity)
                .await
            {
                return WorkOutcome::Retry(format!("owe to {recipient}: {e}"));
            }
        }
        let owed = plan.receivers.len();
        match self.bus.publish(plan.event).await {
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
