// SPDX-License-Identifier: AGPL-3.0-only
//! Relay of committed events to the event bus (transactional outbox).
//!
//! A mutation that produces an event commits it as durable work
//! ([`Event::relay`]) in its own transaction; this handler publishes it. The
//! bus acknowledgement (JetStream PubAck) completes the work. A republished
//! event keeps its id, which the bus deduplicates, so a retry after a lost
//! acknowledgement stores it once.

use crate::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use async_trait::async_trait;
use sid_core::models::{ClaimedWork, EVENT_RELAY_KIND, Event, NewWork, WorkKind};
use sid_plugin::WorkStore;
use sid_plugin::event_bus::EventBus;
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

/// Publishes relayed events.
pub struct EventRelayHandler {
    kind: WorkKind,
    bus: Arc<dyn EventBus>,
}

impl EventRelayHandler {
    pub fn new(bus: Arc<dyn EventBus>) -> Self {
        Self {
            kind: WorkKind::new(EVENT_RELAY_KIND).expect("the relay kind is valid"),
            bus,
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
        match self.bus.publish(event).await {
            Ok(()) => WorkOutcome::Done(None),
            Err(e) => WorkOutcome::Retry(format!("publish: {e}")),
        }
    }
}

#[cfg(test)]
mod tests;
