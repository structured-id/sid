// SPDX-License-Identifier: AGPL-3.0-only
//! Durable ownership of notification delivery.
//!
//! An inbound event is accepted by storing a routing job before the broker
//! message is acknowledged. The routing job resolves the recipient and stores
//! one delivery job per (template, channel), each with a stable id so a
//! repeated fan-out creates nothing twice. Delivery jobs record receipts,
//! ambiguous attempts and failures; work that ends failed commits its
//! dead-letter alert in the same transaction, and the alert job publishes
//! `sid.notify.dlq.v1`.

use crate::dispatcher::NotificationDispatcher;
use crate::recipient_resolver::{RecipientResolver, ResolveError};
use crate::routing::RoutingTable;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sid_authn::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use sid_core::models::event::{Event, event_types};
use sid_core::models::{ClaimedWork, NewWork, WorkId, WorkKind};
use sid_plugin::notification::{DeliveryError, NotificationPriority, Recipient};
use sid_plugin::{EventBus, WorkStore};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Namespace of the stable ids this service derives for its jobs.
const ID_NAMESPACE: Uuid = Uuid::from_u128(0x5f0d_2c8e_6a41_4b7c_9e13_7d2a_0c64_b1f9);

/// Routing job: the inbound event, owned until its deliveries are stored.
pub const ROUTE: &str = "notify.route";
/// One delivery: an event rendered through one template to one channel.
pub const DELIVER: &str = "notify.deliver";
/// Publishing the alert for a job that ended failed.
pub const DLQ_ALERT: &str = "notify.dlq_alert";

/// Attempts per job, the first immediate and then the delays below.
pub const MAX_ATTEMPTS: u32 = 7;

/// Delays between attempts: 1 s, 5 s, 30 s, 2 min, 10 min, 1 h.
pub const RETRY: RetrySchedule = RetrySchedule::new(&[
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(120),
    Duration::from_secs(600),
    Duration::from_secs(3600),
]);

fn kind(name: &str) -> WorkKind {
    WorkKind::new(name).expect("job kinds are valid")
}

fn stable_id(name: &str) -> WorkId {
    WorkId(Uuid::new_v5(&ID_NAMESPACE, name.as_bytes()))
}

/// The routing job an accepted `event` is stored under.
pub fn route_job_id(event: &Event) -> WorkId {
    stable_id(&format!("route:{}", event.id))
}

/// Accept an inbound event: store its routing job. Once this returns `Ok`
/// the broker message may be acknowledged; on `Err` it must not be.
pub async fn accept_event(
    store: &dyn WorkStore,
    payload: &[u8],
    capacity: u64,
) -> sid_core::Result<()> {
    // The event id names the job, so a redelivered event is stored once. A
    // payload without one is still owned (its routing job fails it visibly).
    let id = match serde_json::from_slice::<Event>(payload) {
        Ok(event) if !event.id.is_empty() => route_job_id(&event),
        _ => WorkId(Uuid::new_v5(&ID_NAMESPACE, payload)),
    };
    let mut work = NewWork::new(kind(ROUTE), payload.to_vec());
    work.id = id;
    work.max_attempts = MAX_ATTEMPTS;
    store.enqueue_work(&work, capacity).await.map(|_| ())
}

/// How long the broker waits before redelivering an event that could not be
/// accepted (the job store is down or full).
pub const REDELIVER_AFTER: Duration = Duration::from_secs(5);

/// Take ownership of one broker message: ACK once its routing job is stored,
/// otherwise NAK so the broker redelivers it later.
pub async fn accept_message(
    store: &dyn WorkStore,
    capacity: u64,
    msg: &async_nats::jetstream::Message,
) {
    let reply = match accept_event(store, &msg.payload, capacity).await {
        Ok(()) => msg.ack().await,
        Err(e) => {
            tracing::warn!(error = %e, "event not accepted; left with the broker");
            msg.ack_with(async_nats::jetstream::AckKind::Nak(Some(REDELIVER_AFTER)))
                .await
        }
    };
    if let Err(e) = reply {
        // Without the reply the broker redelivers after its ack wait; the
        // job id is stable, so a stored event is not stored twice.
        tracing::warn!(error = %e, "acknowledging a NATS message failed");
    }
}

/// A delivery job's input.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeliveryJob {
    event: Event,
    template: String,
    priority: NotificationPriority,
    channel: String,
    recipient: Recipient,
}

/// The dead-letter alert for `work`, one per failed job.
fn dead_letter(work: &ClaimedWork, error: &str) -> Option<NewWork> {
    let alert = serde_json::json!({
        "work_id": work.id.to_string(),
        "kind": work.kind.as_str(),
        "attempts": work.attempt,
        "error": error,
    });
    let mut job = NewWork::new(kind(DLQ_ALERT), alert.to_string().into_bytes());
    job.id = stable_id(&format!("dlq:{}", work.id));
    job.max_attempts = MAX_ATTEMPTS;
    Some(job)
}

/// Routes an accepted event into delivery jobs.
pub struct RouteHandler {
    kind: WorkKind,
    routing: RoutingTable,
    resolver: Arc<RecipientResolver>,
    store: Arc<dyn WorkStore>,
    capacity: u64,
}

impl RouteHandler {
    pub(crate) fn new(
        routing: RoutingTable,
        resolver: Arc<RecipientResolver>,
        store: Arc<dyn WorkStore>,
        capacity: u64,
    ) -> Self {
        Self {
            kind: kind(ROUTE),
            routing,
            resolver,
            store,
            capacity,
        }
    }
}

#[async_trait]
impl WorkHandler for RouteHandler {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RETRY
    }

    fn on_dead(&self, work: &ClaimedWork, error: &str) -> Option<NewWork> {
        dead_letter(work, error)
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let event = match serde_json::from_slice::<Event>(&work.payload) {
            Ok(event) => event,
            Err(e) => return WorkOutcome::Permanent(format!("malformed event: {e}")),
        };
        if let Err(e) = event.validate() {
            return WorkOutcome::Permanent(format!("invalid CloudEvents envelope: {e}"));
        }
        // Contact details changed: the cached recipient is stale.
        if [
            event_types::PROFILE_EMAIL_CHANGED,
            event_types::PROFILE_CLAIM_CHANGED,
            event_types::USER_DELETED,
        ]
        .contains(&event.event_type.as_str())
            && let Some(subject) = &event.subject
        {
            self.resolver
                .invalidate(subject.strip_prefix("profile/").unwrap_or(subject))
                .await;
        }
        let rules = self.routing.route_all(&event);
        if rules.is_empty() {
            return WorkOutcome::Done(Some("no routing rule".into()));
        }
        let recipient = match self.resolver.resolve(&event).await {
            Ok(recipient) => recipient,
            Err(e @ ResolveError::ProfileGone(_)) => return WorkOutcome::Permanent(e.to_string()),
            Err(e @ ResolveError::Unavailable(_)) => return WorkOutcome::Retry(e.to_string()),
        };

        let mut stored = 0usize;
        for rule in rules {
            for channel in &rule.channels {
                let job = DeliveryJob {
                    event: event.clone(),
                    template: rule.template.clone(),
                    priority: rule.priority,
                    channel: channel.clone(),
                    recipient: recipient.clone(),
                };
                let payload = match serde_json::to_vec(&job) {
                    Ok(payload) => payload,
                    Err(e) => return WorkOutcome::Permanent(format!("delivery job: {e}")),
                };
                let mut delivery = NewWork::new(kind(DELIVER), payload);
                delivery.id = stable_id(&format!(
                    "deliver:{}:{}:{}",
                    event.id, rule.template, channel
                ));
                delivery.max_attempts = MAX_ATTEMPTS;
                // A delivery stored by an earlier attempt is kept as it is.
                if let Err(e) = self.store.enqueue_work(&delivery, self.capacity).await {
                    return WorkOutcome::Retry(format!("storing delivery: {e}"));
                }
                stored += 1;
            }
        }
        WorkOutcome::Done(Some(format!("{stored} deliveries")))
    }
}

/// Delivers one rendered message through one channel.
pub struct DeliverHandler {
    kind: WorkKind,
    dispatcher: Arc<NotificationDispatcher>,
}

impl DeliverHandler {
    pub fn new(dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self {
            kind: kind(DELIVER),
            dispatcher,
        }
    }
}

#[async_trait]
impl WorkHandler for DeliverHandler {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RETRY
    }

    fn on_dead(&self, work: &ClaimedWork, error: &str) -> Option<NewWork> {
        dead_letter(work, error)
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let job = match serde_json::from_slice::<DeliveryJob>(&work.payload) {
            Ok(job) => job,
            Err(e) => return WorkOutcome::Permanent(format!("malformed delivery job: {e}")),
        };
        let message = match self
            .dispatcher
            .render(&job.template, &job.event, job.priority)
            .await
        {
            Ok(message) => message,
            Err(e) => return WorkOutcome::Permanent(format!("render: {e}")),
        };
        match self
            .dispatcher
            .deliver_to_channel(&job.channel, &job.recipient, &message)
            .await
        {
            Ok(receipt) => WorkOutcome::Done(Some(format!(
                "{}:{}:{}",
                receipt.provider, receipt.channel, receipt.message_id
            ))),
            Err(e) => outcome_of(&e),
        }
    }
}

/// How a channel's error decides the delivery.
fn outcome_of(error: &DeliveryError) -> WorkOutcome {
    let text = error.to_string();
    match error {
        DeliveryError::Failed(_) | DeliveryError::RateLimited | DeliveryError::Internal(_) => {
            WorkOutcome::Retry(text)
        }
        DeliveryError::Ambiguous(_) => WorkOutcome::Ambiguous(text),
        DeliveryError::NotReachable
        | DeliveryError::InvalidRecipient(_)
        | DeliveryError::Rejected(_)
        | DeliveryError::NotConfigured => WorkOutcome::Permanent(text),
    }
}

/// Publishes the alert for a job that ended failed.
pub struct DlqAlertHandler {
    kind: WorkKind,
    bus: Arc<dyn EventBus>,
}

impl DlqAlertHandler {
    pub fn new(bus: Arc<dyn EventBus>) -> Self {
        Self {
            kind: kind(DLQ_ALERT),
            bus,
        }
    }
}

#[async_trait]
impl WorkHandler for DlqAlertHandler {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RETRY
    }

    /// The failed job itself stays recorded; an alert about an alert would
    /// only repeat the same broker outage.
    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let data = match serde_json::from_slice::<serde_json::Value>(&work.payload) {
            Ok(data) => data,
            Err(e) => return WorkOutcome::Permanent(format!("malformed alert: {e}")),
        };
        let mut event = Event::new("sid-notify", event_types::NOTIFY_DLQ).with_data(data);
        // The alert job's id is the event id, so a republished alert is
        // dropped by the broker's duplicate window.
        event.id = work.id.to_string();
        match self.bus.publish(event).await {
            Ok(()) => WorkOutcome::Done(None),
            Err(e) => WorkOutcome::Retry(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests;
