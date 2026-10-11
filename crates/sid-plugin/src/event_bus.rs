// SPDX-License-Identifier: AGPL-3.0-only
//! Event bus abstraction for internal event publishing and subscription.
//!
//! All SID binaries publish domain events through the EventBus.
//! Implementations:
//! - embedded: in-process channel (single binary)
//! - external: NATS JetStream client
//!
//! Events follow CloudEvents 1.0 format (CNCF standard).

use async_trait::async_trait;
use sid_core::models::WorkId;
use sid_core::models::event::{Event, EventFilter, WorkRecipient};
use thiserror::Error;
use tokio::sync::mpsc;

/// Events a subscription buffers before its producer waits (NATS) or the
/// subscriber is dropped as lagging (in-process).
pub const SUBSCRIPTION_CAPACITY: usize = 1024;

/// Errors from event bus operations.
#[derive(Debug, Error)]
pub enum EventBusError {
    #[error("publish failed: {0}")]
    PublishFailed(String),

    #[error("subscribe failed: {0}")]
    SubscribeFailed(String),

    #[error("event bus not connected")]
    NotConnected,

    /// This bus keeps no event history to replay.
    #[error("event replay is not supported by this event bus")]
    ReplayUnsupported,

    /// The replay window cannot be expressed to the bus.
    #[error("invalid replay window: {0}")]
    InvalidReplayWindow(String),

    /// This bus keeps no event until a consumer settles it.
    #[error("durable consumption is not supported by this event bus")]
    DurableUnsupported,

    /// The event's type has no route this bus carries the event on: it is
    /// not registered, belongs to another family, or travels another way
    /// (a fact is published, addressed work is delivered).
    #[error("event type {0} is not routable here")]
    Unroutable(String),

    #[error("event bus error: {0}")]
    Other(String),
}

pub type EventBusResult<T> = Result<T, EventBusError>;

/// The durable consumer of one receiver's addressed work: what is addressed
/// to it is kept until it is settled, whether or not the receiver runs, and
/// its replicas share it, each event going to one of them.
#[derive(Debug, Clone)]
pub struct DurableConsumer {
    /// The receiver whose work this is.
    pub recipient: WorkRecipient,
    /// The event types it consumes (exact types or bus wildcards); empty is
    /// everything addressed to it.
    pub event_types: Vec<String>,
    /// Hand events over in the order they were delivered, one at a time
    /// across all replicas: none goes to any replica before the last is
    /// settled done or rejected, and one being retried holds the rest back.
    /// For a receiver whose effects on an entity depend on the earlier ones.
    pub ordered: bool,
}

/// What a durable consumer did with a delivered event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settlement {
    /// The effect is recorded: the event is acknowledged and not delivered
    /// again.
    Done,
    /// Not done yet: the event stays the consumer's and is delivered again
    /// after `delay`.
    Retry(std::time::Duration),
    /// The event can never be processed (malformed, not this consumer's to
    /// act on): it is not delivered again.
    Reject(String),
}

/// One event handed to a durable consumer. The bus acknowledges it only on
/// [`Settlement::Done`]: until the consumer settles it, the event remains
/// the consumer's. A delivery dropped unsettled is delivered again.
#[derive(Debug)]
pub struct Delivery {
    pub event: Event,
    settled: tokio::sync::oneshot::Sender<Settlement>,
}

impl Delivery {
    /// A delivery of `event` and the receiver its settlement arrives on.
    pub fn new(event: Event) -> (Self, tokio::sync::oneshot::Receiver<Settlement>) {
        let (settled, outcome) = tokio::sync::oneshot::channel();
        (Self { event, settled }, outcome)
    }

    /// Settle the delivery. A bus that stopped waiting delivers it again.
    pub fn settle(self, settlement: Settlement) {
        if self.settled.send(settlement).is_err() {
            tracing::debug!("event settled after its bus stopped waiting; it is delivered again");
        }
    }
}

/// Internal event bus for publishing and subscribing to domain events.
///
/// All SID services publish events through this trait.
/// NATS JetStream is the production implementation; in-process channel
/// is used for single-binary CE deployments and testing.
#[async_trait]
pub trait EventBus: Send + Sync {
    /// Publish a fact to the retained history that observers and replay
    /// read. History is bounded and is never the last copy of work a
    /// receiver must not lose: that is [`EventBus::deliver`]ed.
    async fn publish(&self, event: Event) -> EventBusResult<()>;

    /// Hand `event` to `recipient` as addressed work under the stable
    /// `delivery` id: once this returns `Ok` the bus keeps it until the
    /// recipient's durable consumer settles it, whatever its age. A
    /// redelivery under the same id is not handed over twice.
    async fn deliver(
        &self,
        recipient: &WorkRecipient,
        delivery: WorkId,
        event: &Event,
    ) -> EventBusResult<()> {
        let _ = (recipient, delivery, event);
        Err(EventBusError::DurableUnsupported)
    }

    /// Subscribe to events matching the filter. The receiver holds at most
    /// [`SUBSCRIPTION_CAPACITY`] undelivered events.
    async fn subscribe(&self, filter: EventFilter) -> EventBusResult<mpsc::Receiver<Event>>;

    /// Replay historical events from `from` (inclusive) to `to` (exclusive,
    /// or now if None), filtered by event type patterns in `filter`.
    ///
    /// A bus without history refuses with [`EventBusError::ReplayUnsupported`]
    /// rather than answering an empty history.
    async fn replay(
        &self,
        from: chrono::DateTime<chrono::Utc>,
        to: Option<chrono::DateTime<chrono::Utc>>,
        filter: EventFilter,
    ) -> EventBusResult<mpsc::Receiver<Event>> {
        let _ = (from, to, filter);
        Err(EventBusError::ReplayUnsupported)
    }

    /// Consume as `consumer`, at least once: every matching event delivered
    /// to its recipient, before or after it first ran, is handed over, and
    /// each stays the consumer's (delivered again after a crash, a drop or a
    /// retry) until it is settled [`Settlement::Done`] or
    /// [`Settlement::Reject`]. Deliveries arrive one at a time; the next
    /// follows the settlement of the last.
    ///
    /// A bus that keeps no event until it is settled refuses with
    /// [`EventBusError::DurableUnsupported`] rather than consume lossily.
    async fn consume(&self, consumer: DurableConsumer) -> EventBusResult<mpsc::Receiver<Delivery>> {
        let _ = consumer;
        Err(EventBusError::DurableUnsupported)
    }

    /// Check if the event bus is connected and healthy.
    async fn health_check(&self) -> EventBusResult<()>;
}

/// In-process event bus for single-binary CE deployments and testing.
///
/// Events are dispatched synchronously to all matching subscribers. A
/// subscriber whose buffer is full is dropped (its receiver ends) instead of
/// slowing every publisher; it can subscribe again. No durability, no replay.
pub struct InProcessEventBus {
    subscribers: std::sync::Mutex<Vec<(EventFilter, mpsc::Sender<Event>)>>,
}

impl InProcessEventBus {
    pub fn new() -> Self {
        Self {
            subscribers: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Default for InProcessEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventBus for InProcessEventBus {
    async fn publish(&self, event: Event) -> EventBusResult<()> {
        let mut subs = self
            .subscribers
            .lock()
            .map_err(|_| EventBusError::Other("subscriber list poisoned".into()))?;
        subs.retain(|(filter, sender)| {
            if !filter.matches(&event) {
                return !sender.is_closed();
            }
            match sender.try_send(event.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!("in-process event subscriber lagging; dropped");
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        });
        Ok(())
    }

    async fn subscribe(&self, filter: EventFilter) -> EventBusResult<mpsc::Receiver<Event>> {
        let (tx, rx) = mpsc::channel(SUBSCRIPTION_CAPACITY);
        self.subscribers
            .lock()
            .map_err(|_| EventBusError::Other("subscriber list poisoned".into()))?
            .push((filter, tx));
        Ok(rx)
    }

    async fn health_check(&self) -> EventBusResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
