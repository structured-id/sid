// SPDX-License-Identifier: AGPL-3.0-only
//! Event bus abstraction for internal event publishing and subscription.
//!
//! All SID binaries publish domain events through the EventBus.
//! Implementations:
//! - CE embedded: in-process channel (single binary)
//! - CE/EE external: NATS JetStream client
//!
//! Events follow CloudEvents 1.0 format (CNCF standard).

use async_trait::async_trait;
use sid_core::models::event::{Event, EventFilter};
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

    #[error("event bus error: {0}")]
    Other(String),
}

pub type EventBusResult<T> = Result<T, EventBusError>;

/// Internal event bus for publishing and subscribing to domain events.
///
/// All SID services publish events through this trait.
/// NATS JetStream is the production implementation; in-process channel
/// is used for single-binary CE deployments and testing.
#[async_trait]
pub trait EventBus: Send + Sync {
    /// Publish an event to the bus.
    async fn publish(&self, event: Event) -> EventBusResult<()>;

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
