// SPDX-License-Identifier: AGPL-3.0-only
//! Durable ownership of notification delivery.
//!
//! Every committed fact is owed to this service as addressed work; an
//! inbound event is accepted by storing a routing job before it is settled.
//! The routing job resolves the recipient and the matching rules once and
//! stores them whole as the event's plan, under an id of the event alone:
//! the store keeps the first plan, so a retried routing under changed rules
//! owes the same deliveries. The plan job then stores one delivery job per
//! planned (template, channel), each with a stable id so a repeated fan-out
//! creates nothing twice, and stays owed until every one is stored. Delivery
//! jobs record receipts, ambiguous attempts and failures; work that ends
//! failed commits, in the same transaction, the relay of its
//! `sid.notify.dlq.v1` fact, which is owed and published as every fact is.

use crate::dispatcher::NotificationDispatcher;
use crate::recipient_resolver::{RecipientResolver, ResolveError};
use crate::routing::RoutingTable;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sid_authn::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use sid_core::models::event::{Event, WorkRecipient, event_types};
use sid_core::models::{ClaimedWork, NewWork, WorkId, WorkKind};
use sid_plugin::event_bus::{Delivery, DurableConsumer, EventBusResult, Settlement};
use sid_plugin::notification::{DeliveryError, NotificationPriority, Recipient};
use sid_plugin::{EventBus, WorkStore};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Namespace of the stable ids this service derives for its jobs.
const ID_NAMESPACE: Uuid = Uuid::from_u128(0x5f0d_2c8e_6a41_4b7c_9e13_7d2a_0c64_b1f9);

/// Routing job: the inbound event, owned until its plan is stored.
pub const ROUTE: &str = "notify.route";
/// Plan job: the deliveries an event's routing fixed, owned until each is
/// stored.
pub const PLAN: &str = "notify.plan";
/// One delivery: an event rendered through one template to one channel.
pub const DELIVER: &str = "notify.deliver";

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

/// The routing job an accepted `event` is stored under: one per event
/// `(source, id)`.
pub fn route_job_id(event: &Event) -> WorkId {
    stable_id(&format!("route:{}", event.relay_id()))
}

/// The plan job of `event`: one per event `(source, id)`, whatever routing
/// attempt stored it.
pub fn plan_job_id(event: &Event) -> WorkId {
    stable_id(&format!("plan:{}", event.relay_id()))
}

/// The delivery job of `event` through `template` to `channel`: one per event
/// `(source, id)`, template and channel.
pub fn delivery_job_id(event: &Event, template: &str, channel: &str) -> WorkId {
    stable_id(&format!(
        "deliver:{}:{template}:{channel}",
        event.relay_id()
    ))
}

/// Accept an inbound event: store its routing job. Once this returns `Ok`
/// the event may be settled; on `Err` it must not be.
pub async fn accept_event(
    store: &dyn WorkStore,
    event: &Event,
    capacity: u64,
) -> sid_core::Result<()> {
    // The event's identity names the job, so a redelivered event is stored
    // once, also when it was stored just before a crash cut its settlement.
    let payload = serde_json::to_vec(event)
        .map_err(|e| sid_core::Error::Internal(format!("event payload: {e}")))?;
    let mut work = NewWork::new(kind(ROUTE), payload);
    work.id = route_job_id(event);
    work.max_attempts = MAX_ATTEMPTS;
    store.enqueue_work(&work, capacity).await.map(|_| ())
}

/// How long the broker waits before redelivering an event that could not be
/// accepted (the job store is down or full).
pub const REDELIVER_AFTER: Duration = Duration::from_secs(5);

/// Open the durable consumer of the work addressed to `recipient` on `bus`.
/// Replicas consuming as the same receiver share its work.
pub async fn open_work(
    bus: &dyn EventBus,
    recipient: WorkRecipient,
) -> EventBusResult<mpsc::Receiver<Delivery>> {
    bus.consume(DurableConsumer {
        recipient,
        event_types: Vec::new(),
        ordered: false,
    })
    .await
}

/// Accept `deliveries` until the bus ends the consumer or `stop` resolves.
/// Each event is settled only once its routing job is stored, and left with
/// the bus (delivered again later) otherwise; `accepted` runs after each
/// stored one.
pub async fn accept_work(
    mut deliveries: mpsc::Receiver<Delivery>,
    store: &dyn WorkStore,
    capacity: u64,
    accepted: impl Fn(),
    stop: impl std::future::Future<Output = ()>,
) {
    tokio::pin!(stop);
    loop {
        let delivery = tokio::select! {
            delivery = deliveries.recv() => match delivery {
                Some(delivery) => delivery,
                None => return,
            },
            () = &mut stop => return,
        };
        match accept_event(store, &delivery.event, capacity).await {
            Ok(()) => {
                delivery.settle(Settlement::Done);
                accepted();
            }
            Err(e) => {
                tracing::warn!(error = %e, "event not accepted; left with the bus");
                delivery.settle(Settlement::Retry(REDELIVER_AFTER));
            }
        }
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

/// An event's fixed plan: the recipient resolved and the deliveries the
/// rules matched when it was first stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RoutePlan {
    event: Event,
    recipient: Recipient,
    deliveries: Vec<PlannedDelivery>,
}

/// One planned delivery: a template rendered at a priority to a channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlannedDelivery {
    template: String,
    priority: NotificationPriority,
    channel: String,
}

/// The relay of the dead-letter fact for `work`, one per failed job: its
/// event id follows from the job, so a repeated failure owes nothing new.
fn dead_letter(work: &ClaimedWork, error: &str) -> Option<NewWork> {
    let mut event =
        Event::new("sid-notify", event_types::NOTIFY_DLQ).with_data(serde_json::json!({
            "work_id": work.id.to_string(),
            "kind": work.kind.as_str(),
            "attempts": work.attempt,
            "error": error,
        }));
    event.id = stable_id(&format!("dlq:{}", work.id)).to_string();
    Some(event.relay())
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
        let deliveries: Vec<PlannedDelivery> = rules
            .iter()
            .flat_map(|rule| {
                rule.channels.iter().map(|channel| PlannedDelivery {
                    template: rule.template.clone(),
                    priority: rule.priority,
                    channel: channel.clone(),
                })
            })
            .collect();
        let planned = deliveries.len();
        let plan = RoutePlan {
            event,
            recipient,
            deliveries,
        };
        let payload = match serde_json::to_vec(&plan) {
            Ok(payload) => payload,
            Err(e) => return WorkOutcome::Permanent(format!("route plan: {e}")),
        };
        // Stored whole, under an id of the event alone: the store keeps the
        // first plan, so this event's deliveries are fixed when this first
        // succeeds and a retry under other rules owes the same.
        let mut job = NewWork::new(kind(PLAN), payload);
        job.id = plan_job_id(&plan.event);
        job.max_attempts = MAX_ATTEMPTS;
        match self.store.enqueue_work(&job, self.capacity).await {
            Ok(_) => WorkOutcome::Done(Some(format!("{planned} deliveries planned"))),
            Err(e) => WorkOutcome::Retry(format!("storing the plan: {e}")),
        }
    }
}

/// Stores the delivery jobs of an event's fixed plan.
pub struct PlanHandler {
    kind: WorkKind,
    store: Arc<dyn WorkStore>,
    capacity: u64,
}

impl PlanHandler {
    pub(crate) fn new(store: Arc<dyn WorkStore>, capacity: u64) -> Self {
        Self {
            kind: kind(PLAN),
            store,
            capacity,
        }
    }
}

#[async_trait]
impl WorkHandler for PlanHandler {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RETRY
    }

    /// The failed plan is the durable record of an event whose deliveries
    /// were not all stored.
    fn on_dead(&self, work: &ClaimedWork, error: &str) -> Option<NewWork> {
        dead_letter(work, error)
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let plan: RoutePlan = match serde_json::from_slice(&work.payload) {
            Ok(plan) => plan,
            Err(e) => return WorkOutcome::Permanent(format!("malformed plan: {e}")),
        };
        for planned in &plan.deliveries {
            let job = DeliveryJob {
                event: plan.event.clone(),
                template: planned.template.clone(),
                priority: planned.priority,
                channel: planned.channel.clone(),
                recipient: plan.recipient.clone(),
            };
            let payload = match serde_json::to_vec(&job) {
                Ok(payload) => payload,
                Err(e) => return WorkOutcome::Permanent(format!("delivery job: {e}")),
            };
            let mut delivery = NewWork::new(kind(DELIVER), payload);
            delivery.id = delivery_job_id(&plan.event, &planned.template, &planned.channel);
            delivery.max_attempts = MAX_ATTEMPTS;
            // A delivery stored by an earlier attempt is kept as it is, with
            // its own outcome; the plan stays owed until the rest are stored.
            if let Err(e) = self.store.enqueue_work(&delivery, self.capacity).await {
                return WorkOutcome::Retry(format!("storing delivery: {e}"));
            }
        }
        WorkOutcome::Done(Some(format!("{} deliveries", plan.deliveries.len())))
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

#[cfg(test)]
mod tests;
