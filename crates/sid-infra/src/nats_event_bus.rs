// SPDX-License-Identifier: AGPL-3.0-only
//! NATS JetStream event bus implementation.
//!
//! Production EventBus for multi-binary deployments, on the identity
//! [`Topology`]: facts go to the retained history, addressed work to the
//! work stream, where it stays until its receiver settles it.
//!
//! Connects to an embedded or external NATS server.

use async_nats::jetstream::{self, Context as JsContext};
use async_trait::async_trait;
use sid_core::models::WorkId;
use sid_core::models::event::{
    Event, EventFamily, EventFilter, EventRoute, WorkRecipient, event_route,
};
use sid_plugin::event_bus::{
    Delivery, DurableConsumer, EventBus, EventBusError, EventBusResult, Hold,
    SUBSCRIPTION_CAPACITY, Settlement,
};
use tokio::sync::mpsc;

use crate::nats_topology::{HANDED_OVER_FROM, Topology, TopologyRole, earlier_stream};

/// When a delivery dropped unsettled is delivered again.
const DURABLE_REDELIVERY: std::time::Duration = std::time::Duration::from_secs(5);

/// Renewals of an unsettled delivery per acknowledgement wait: a missed one
/// still leaves most of the wait.
const RENEWALS_PER_ACK_WAIT: u32 = 4;

/// Renew `msg` for another `ack_wait`, the server confirming it. The hold
/// it gives ends at a tenth of the wait before the server's own deadline,
/// counted from before the renewal was sent; `None` when unconfirmed.
async fn renew(
    msg: &jetstream::Message,
    ack_wait: std::time::Duration,
) -> Option<tokio::time::Instant> {
    let sent = tokio::time::Instant::now();
    match msg.double_ack_with(jetstream::AckKind::Progress).await {
        Ok(()) => Some(sent + ack_wait - ack_wait / 10),
        Err(e) => {
            tracing::warn!("renew a delivery: {e}");
            None
        }
    }
}

/// Whether a delivery held until `deadline` may still be renewed at `now`.
/// Once the hold ran out, the server may have handed the event to another
/// replica and still accept a late renewal from this one
/// (nats-io/nats-server#4786): the hold stays out and nothing is renewed.
fn may_renew(deadline: tokio::time::Instant, now: tokio::time::Instant) -> bool {
    now < deadline
}

/// How often the server confirms a durable consumer's open pull; two missed
/// in a row reopen it.
const DURABLE_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long one pull request stays open on the server.
const DURABLE_PULL_EXPIRES: std::time::Duration = std::time::Duration::from_secs(30);

/// The pause before a failed durable consumer is opened again.
const DURABLE_REOPEN: std::time::Duration = std::time::Duration::from_secs(1);

/// NATS JetStream event bus for production deployments.
pub struct NatsEventBus {
    /// NATS client connection.
    client: async_nats::Client,
    /// JetStream context for stream operations.
    jetstream: JsContext,
    topology: Topology,
}

impl NatsEventBus {
    /// Connect to the NATS server at `nats_url` and prepare `topology` in
    /// `role`: the deployment's topology owner creates or updates the
    /// streams, every other process requires them as defined.
    pub async fn connect(
        nats_url: &str,
        topology: Topology,
        role: TopologyRole,
    ) -> EventBusResult<Self> {
        let client = async_nats::connect(nats_url)
            .await
            .map_err(|e| EventBusError::Other(format!("NATS connect failed: {e}")))?;
        let jetstream = jetstream::new(client.clone());
        topology
            .prepare(&jetstream, role)
            .await
            .map_err(|e| EventBusError::Other(format!("event topology: {e}")))?;
        Ok(Self {
            client,
            jetstream,
            topology,
        })
    }

    /// Publish `payload` on `subject` with message id `id`, accepted only by
    /// `stream`, and wait for the stream's acknowledgement.
    async fn send(
        &self,
        stream: &str,
        subject: String,
        id: WorkId,
        payload: Vec<u8>,
    ) -> EventBusResult<()> {
        // The id travels as the message id, so a republication (a retry
        // after a lost acknowledgement) within the duplicate window is
        // stored once; the expected stream keeps it from landing anywhere
        // else should the subjects ever be captured by another stream.
        let message = jetstream::message::PublishMessage::build()
            .payload(payload.into())
            .message_id(id.to_string())
            .expected_stream(stream);
        self.jetstream
            .send_publish(subject, message)
            .await
            .map_err(|e| EventBusError::PublishFailed(format!("publish: {e}")))?
            .await
            .map_err(|e| EventBusError::PublishFailed(format!("ack: {e}")))?;
        Ok(())
    }

    /// The history on `subjects` from `deliver`, read in order by an ordered
    /// consumer: nothing is acknowledged, so the server never sends an event
    /// again, however long the reader takes. It is pulled a batch at a time,
    /// the next batch only once the reader took the last, so a reader that
    /// is behind holds the server back; a consumer the server dropped meanwhile
    /// is recreated from the last event read.
    async fn read_history(
        &self,
        subjects: Vec<String>,
        deliver: jetstream::consumer::DeliverPolicy,
    ) -> EventBusResult<jetstream::consumer::pull::Ordered> {
        let stream = self
            .jetstream
            .get_stream(self.topology.history_stream())
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("get stream: {e}")))?;
        stream
            .create_consumer(jetstream::consumer::pull::OrderedConfig {
                filter_subjects: subjects,
                deliver_policy: deliver,
                ..Default::default()
            })
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("create consumer: {e}")))?
            .messages()
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("messages stream: {e}")))
    }

    /// What the earlier events stream still keeps from `start_time`, read in
    /// order, or `None` when there is no such stream or it keeps nothing
    /// from then.
    async fn read_archive(
        &self,
        start_time: time::OffsetDateTime,
    ) -> EventBusResult<Option<jetstream::consumer::pull::Ordered>> {
        let failed = |e: &dyn std::fmt::Display| EventBusError::SubscribeFailed(format!("{e}"));
        let Some(stream) = earlier_stream(&self.topology, &self.jetstream)
            .await
            .map_err(|e| failed(&e))?
        else {
            return Ok(None);
        };
        let mut consumer = stream
            .create_consumer(jetstream::consumer::pull::OrderedConfig {
                deliver_policy: jetstream::consumer::DeliverPolicy::ByStartTime { start_time },
                ..Default::default()
            })
            .await
            .map_err(|e| failed(&e))?;
        let pending = consumer.info().await.map_err(|e| failed(&e))?.num_pending;
        if pending == 0 {
            return Ok(None);
        }
        consumer.messages().await.map(Some).map_err(|e| failed(&e))
    }
}

/// Forward the earlier version's history `messages` matching `filter` into
/// `tx` until nothing is left to read or an event at or after `cutoff`
/// arrives, returning the relay ids forwarded; `None` once the reader is
/// gone. The stream takes no more events, so reading ends once the reader
/// reached what it held.
async fn forward_archive(
    mut messages: jetstream::consumer::pull::Ordered,
    filter: &EventFilter,
    tx: &mpsc::Sender<Event>,
    cutoff: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<std::collections::HashSet<WorkId>> {
    use futures::StreamExt;
    let mut seen = std::collections::HashSet::new();
    while let Some(read) = messages.next().await {
        let msg = match read {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!("earlier history read ended: {e}");
                break;
            }
        };
        let last = msg.info().map_or(true, |info| info.pending == 0);
        match serde_json::from_slice::<Event>(&msg.payload) {
            Ok(event) if cutoff.is_some_and(|cutoff| event.time >= cutoff) => break,
            // The earlier stream kept every event; history is the facts.
            Ok(event)
                if event.validate().is_ok()
                    && event_route(&event.event_type).is_some_and(identity_fact)
                    && filter.matches(&event) =>
            {
                seen.insert(event.relay_id());
                if tx.send(event).await.is_err() {
                    return None;
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("failed to deserialize an earlier event: {e}"),
        }
        if last {
            break;
        }
    }
    Some(seen)
}

/// Refuses `event` unless its route is one `accepts`.
fn routed(event: &Event, accepts: fn(EventRoute) -> bool) -> EventBusResult<()> {
    match event_route(&event.event_type) {
        Some(route) if accepts(route) => Ok(()),
        _ => Err(EventBusError::Unroutable(event.event_type.clone())),
    }
}

/// An identity fact: the only thing kept in this bus's history.
fn identity_fact(route: EventRoute) -> bool {
    route == EventRoute::Fact(EventFamily::Identity)
}

/// Anything of the identity family: a fact owed to a required receiver, or
/// work addressed to a named one.
fn identity_work(route: EventRoute) -> bool {
    route.family() == EventFamily::Identity
}

#[async_trait]
impl EventBus for NatsEventBus {
    async fn publish(&self, event: Event) -> EventBusResult<()> {
        routed(&event, identity_fact)?;
        let subject = self
            .topology
            .history_subject(&event.event_type)
            .ok_or_else(|| EventBusError::Unroutable(event.event_type.clone()))?;
        let payload = serde_json::to_vec(&event)
            .map_err(|e| EventBusError::PublishFailed(format!("serialize: {e}")))?;
        self.send(
            &self.topology.history_stream(),
            subject,
            event.relay_id(),
            payload,
        )
        .await
    }

    async fn deliver(
        &self,
        recipient: &WorkRecipient,
        delivery: WorkId,
        event: &Event,
    ) -> EventBusResult<()> {
        routed(event, identity_work)?;
        let subject = self
            .topology
            .work_subject(recipient, &event.event_type)
            .ok_or_else(|| EventBusError::Unroutable(event.event_type.clone()))?;
        let payload = serde_json::to_vec(event)
            .map_err(|e| EventBusError::PublishFailed(format!("serialize: {e}")))?;
        self.send(&self.topology.work_stream(), subject, delivery, payload)
            .await
    }

    async fn subscribe(&self, filter: EventFilter) -> EventBusResult<mpsc::Receiver<Event>> {
        let subjects = self
            .topology
            .history_filters(&filter.event_types)
            .map_err(EventBusError::SubscribeFailed)?;
        // An observer: sees what is published while it exists and keeps
        // nothing for it.
        let messages = self
            .read_history(subjects, jetstream::consumer::DeliverPolicy::New)
            .await?;
        let (tx, rx) = mpsc::channel(SUBSCRIPTION_CAPACITY);
        tokio::spawn(forward_history(
            messages,
            tx,
            None,
            std::collections::HashSet::new(),
        ));
        Ok(rx)
    }

    async fn consume(&self, consumer: DurableConsumer) -> EventBusResult<mpsc::Receiver<Delivery>> {
        let subjects = self
            .topology
            .work_filters(&consumer.recipient, &consumer.event_types)
            .map_err(EventBusError::SubscribeFailed)?;
        let name = consumer.recipient.to_string();
        // One durable pull consumer per receiver: replicas pulling under the
        // name share it, each event going to one of them. The work stream
        // keeps an event until it is acknowledged, so a consumer created
        // after the event, or recreated after a loss, still gets it.
        // Pulling (rather than a push queue group, which cannot carry
        // heartbeats) lets a lost or deleted consumer surface as an error,
        // after which it is reopened.
        let mut config = jetstream::consumer::pull::Config {
            durable_name: Some(name.clone()),
            deliver_policy: jetstream::consumer::DeliverPolicy::All,
            ack_policy: jetstream::consumer::AckPolicy::Explicit,
            // A delivery neither settled nor renewed in time (a hung or
            // killed consumer) is delivered again; no limit, so redelivery
            // never drops an event.
            ack_wait: self.topology.work_ack_wait,
            max_deliver: -1,
            filter_subjects: subjects,
            ..Default::default()
        };
        if consumer.ordered {
            // One unacknowledged event for the whole consumer: a message
            // negatively acknowledged with a delay stays pending until it is
            // redelivered, so no replica gets a later one meanwhile.
            config.max_ack_pending = 1;
        }
        let jetstream = self.jetstream.clone();
        let stream = self.topology.work_stream();
        let ack_wait = self.topology.work_ack_wait;
        // Opened once here, so a consumer that cannot be set up is refused to
        // the caller rather than retried unseen.
        let messages = open_durable(&jetstream, &stream, &name, &config).await?;

        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(async move {
            use async_nats::jetstream::AckKind;
            use futures::StreamExt;
            let mut messages = messages;
            loop {
                let msg = match messages.next().await {
                    Some(Ok(msg)) => msg,
                    // A missed heartbeat, a deleted consumer or an ended
                    // stream: reopen (recreating the consumer if it is gone)
                    // until it works or the consumer is dropped.
                    failed => {
                        match failed {
                            Some(Err(e)) => {
                                tracing::warn!(consumer = %name, "durable consumer: {e}");
                            }
                            _ => tracing::warn!(consumer = %name, "durable consumer ended"),
                        }
                        match reopen_durable(&jetstream, &stream, &name, &config, &tx).await {
                            Some(reopened) => {
                                messages = reopened;
                                continue;
                            }
                            None => break,
                        }
                    }
                };
                let event = match serde_json::from_slice::<Event>(&msg.payload) {
                    Ok(event) => event.validate().map(|()| event).map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                };
                let settlement = match event {
                    Err(e) => Settlement::Reject(format!("not an event: {e}")),
                    Ok(event) => {
                        let attempt = msg
                            .info()
                            .ok()
                            .and_then(|info| u64::try_from(info.delivered).ok())
                            .unwrap_or(1);
                        let first = renew(&msg, ack_wait)
                            .await
                            .unwrap_or_else(tokio::time::Instant::now);
                        let (deadline, hold) = tokio::sync::watch::channel(first);
                        let (mut delivery, mut outcome) =
                            Delivery::held(event, attempt, Hold::until(hold));
                        delivery.earlier = msg
                            .headers
                            .as_ref()
                            .is_some_and(|h| h.get(HANDED_OVER_FROM).is_some());
                        if tx.send(delivery).await.is_err() {
                            // The consumer stopped: the event stays its own.
                            if let Err(e) = msg.ack_with(AckKind::Nak(None)).await {
                                tracing::warn!(consumer = %name, "release an event: {e}");
                            }
                            break;
                        }
                        // Renewed while it is processed, so a slow consumer
                        // keeps it rather than another replica getting it.
                        let every = ack_wait / RENEWALS_PER_ACK_WAIT;
                        let mut renewal =
                            tokio::time::interval_at(tokio::time::Instant::now() + every, every);
                        loop {
                            tokio::select! {
                                // Dropped unsettled: delivered again.
                                settled = &mut outcome => {
                                    break settled.unwrap_or(Settlement::Retry(DURABLE_REDELIVERY));
                                }
                                _ = renewal.tick() => {
                                    let held = *deadline.borrow();
                                    if !may_renew(held, tokio::time::Instant::now()) {
                                        continue;
                                    }
                                    if let Some(until) = renew(&msg, ack_wait).await {
                                        deadline.send_replace(until);
                                    }
                                }
                            }
                        }
                    }
                };
                let acked = match &settlement {
                    Settlement::Done => msg.double_ack().await,
                    Settlement::Retry(delay) => msg.ack_with(AckKind::Nak(Some(*delay))).await,
                    Settlement::Reject(reason) => {
                        tracing::error!(consumer = %name, "event rejected: {reason}");
                        msg.ack_with(AckKind::Term).await
                    }
                };
                // An unconfirmed acknowledgement is delivered again; the
                // consumer's effect is idempotent under its own records.
                if let Err(e) = acked {
                    tracing::warn!(consumer = %name, "settle an event: {e}");
                }
            }
        });
        Ok(rx)
    }

    async fn replay(
        &self,
        from: chrono::DateTime<chrono::Utc>,
        to: Option<chrono::DateTime<chrono::Utc>>,
        filter: EventFilter,
    ) -> EventBusResult<mpsc::Receiver<Event>> {
        let subjects = self
            .topology
            .history_filters(&filter.event_types)
            .map_err(EventBusError::SubscribeFailed)?;

        // On the history only: replay reads facts and never hands anyone work.
        let nanos = from
            .timestamp_nanos_opt()
            .ok_or_else(|| EventBusError::InvalidReplayWindow(format!("start {from}")))?;
        let start_time = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(nanos))
            .map_err(|e| EventBusError::InvalidReplayWindow(format!("start {from}: {e}")))?;
        let archive = self.read_archive(start_time).await?;
        let messages = self
            .read_history(
                subjects,
                jetstream::consumer::DeliverPolicy::ByStartTime { start_time },
            )
            .await?;
        let (tx, rx) = mpsc::channel(SUBSCRIPTION_CAPACITY);
        tokio::spawn(async move {
            // The earlier version's history comes first; an event its outbox
            // published there and again into this history after the move is
            // read once.
            let seen = match archive {
                None => std::collections::HashSet::new(),
                Some(archive) => match forward_archive(archive, &filter, &tx, to).await {
                    Some(seen) => seen,
                    None => return,
                },
            };
            forward_history(messages, tx, to, seen).await;
        });
        Ok(rx)
    }

    async fn health_check(&self) -> EventBusResult<()> {
        // Verify connection is alive by checking server info.
        let state = self.client.connection_state();
        if state == async_nats::connection::State::Connected {
            Ok(())
        } else {
            Err(EventBusError::NotConnected)
        }
    }
}

/// Forward history `messages` into `tx` until the stream ends or fails, the
/// reader goes away, or an event at or after `cutoff` arrives, leaving out
/// the events whose relay id is in `seen`. While `tx` is full nothing more
/// is read, which is what holds the server back.
async fn forward_history(
    mut messages: jetstream::consumer::pull::Ordered,
    tx: mpsc::Sender<Event>,
    cutoff: Option<chrono::DateTime<chrono::Utc>>,
    seen: std::collections::HashSet<WorkId>,
) {
    use futures::StreamExt;
    while let Some(read) = messages.next().await {
        let msg = match read {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!("history read ended: {e}");
                break;
            }
        };
        match serde_json::from_slice::<Event>(&msg.payload) {
            Ok(event) if cutoff.is_some_and(|cutoff| event.time >= cutoff) => break,
            Ok(event) if seen.contains(&event.relay_id()) => {}
            Ok(event) => match event.validate() {
                Err(e) => tracing::warn!("invalid CloudEvents envelope, skipping: {e}"),
                Ok(()) => {
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
            },
            Err(e) => tracing::warn!("failed to deserialize NATS event: {e}"),
        }
    }
}

/// The messages of the durable consumer `name` on `stream`, created with
/// `config` when it does not exist. One message is pulled at a time: a
/// pulled message's acknowledgement deadline runs while it waits, so none
/// waits behind another.
async fn open_durable(
    jetstream: &jetstream::Context,
    stream: &str,
    name: &str,
    config: &jetstream::consumer::pull::Config,
) -> EventBusResult<jetstream::consumer::pull::Stream> {
    let stream = jetstream
        .get_stream(stream)
        .await
        .map_err(|e| EventBusError::SubscribeFailed(format!("get stream: {e}")))?;
    let mut durable: jetstream::consumer::Consumer<jetstream::consumer::pull::Config> = stream
        .get_or_create_consumer(name, config.clone())
        .await
        .map_err(|e| EventBusError::SubscribeFailed(format!("durable consumer {name}: {e}")))?;
    // An existing consumer is taken as it is (only push or pull is
    // checked): one defined otherwise would weaken the receiver's guarantees
    // unseen, so it is refused, and no process changes it.
    let found = durable
        .info()
        .await
        .map_err(|e| EventBusError::SubscribeFailed(format!("durable consumer {name}: {e}")))?;
    if let Some(field) = durable_differs(&found.config, config) {
        return Err(EventBusError::SubscribeFailed(format!(
            "durable consumer {name} exists with another {field}"
        )));
    }
    durable
        .stream()
        .max_messages_per_batch(1)
        .heartbeat(DURABLE_HEARTBEAT)
        .expires(DURABLE_PULL_EXPIRES)
        .messages()
        .await
        .map_err(|e| EventBusError::SubscribeFailed(format!("messages stream: {e}")))
}

/// The first setting of `wanted` that the existing consumer `found` does not
/// have. The pending limit counts only when `wanted` sets one (an ordered
/// consumer); otherwise the server's default stands.
fn durable_differs(
    found: &jetstream::consumer::Config,
    wanted: &jetstream::consumer::pull::Config,
) -> Option<&'static str> {
    let subjects = |single: &String, many: &[String]| {
        let mut all: Vec<String> = many.to_vec();
        if !single.is_empty() {
            all.push(single.clone());
        }
        all.sort();
        all
    };
    if found.deliver_policy != wanted.deliver_policy {
        Some("deliver policy")
    } else if found.ack_policy != wanted.ack_policy {
        Some("ack policy")
    } else if found.ack_wait != wanted.ack_wait {
        Some("acknowledgement wait")
    } else if found.backoff != wanted.backoff {
        // A backoff replaces the acknowledgement wait for redelivery, so a
        // held event would be handed on before its hold ends.
        Some("redelivery backoff")
    } else if found.headers_only != wanted.headers_only {
        // Without its payload every event would be settled as malformed.
        Some("payload delivery")
    } else if found.max_deliver != wanted.max_deliver {
        Some("delivery limit")
    } else if wanted.max_ack_pending != 0 && found.max_ack_pending != wanted.max_ack_pending {
        Some("pending limit")
    } else if subjects(&found.filter_subject, &found.filter_subjects)
        != subjects(&wanted.filter_subject, &wanted.filter_subjects)
    {
        Some("subject filter")
    } else {
        None
    }
}

/// Open the durable consumer `name` again, pausing between failed tries,
/// until it opens or `tx`'s receiver is dropped (`None`).
async fn reopen_durable(
    jetstream: &jetstream::Context,
    stream: &str,
    name: &str,
    config: &jetstream::consumer::pull::Config,
    tx: &mpsc::Sender<Delivery>,
) -> Option<jetstream::consumer::pull::Stream> {
    loop {
        tokio::select! {
            () = tx.closed() => return None,
            () = tokio::time::sleep(DURABLE_REOPEN) => {}
        }
        match open_durable(jetstream, stream, name, config).await {
            Ok(messages) => return Some(messages),
            Err(e) => tracing::warn!(consumer = %name, "reopen: {e}"),
        }
    }
}

#[cfg(test)]
mod tests;
