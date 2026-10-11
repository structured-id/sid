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
    Delivery, DurableConsumer, EventBus, EventBusError, EventBusResult, SUBSCRIPTION_CAPACITY,
    Settlement,
};
use tokio::sync::mpsc;

use crate::nats_topology::{Topology, TopologyRole};

/// How long a durable consumer may hold a delivery unsettled before it is
/// delivered again.
const DURABLE_ACK_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// When a delivery dropped unsettled is delivered again.
const DURABLE_REDELIVERY: std::time::Duration = std::time::Duration::from_secs(5);

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
        // An observer: an ephemeral consumer that sees what is published
        // while it exists and keeps nothing for it.
        let deliver_subject = self.client.new_inbox();
        let config = jetstream::consumer::push::Config {
            filter_subjects: subjects,
            deliver_policy: jetstream::consumer::DeliverPolicy::New,
            ack_policy: jetstream::consumer::AckPolicy::None,
            deliver_subject,
            ..Default::default()
        };
        let stream = self
            .jetstream
            .get_stream(self.topology.history_stream())
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("get stream: {e}")))?;
        let consumer = stream
            .create_consumer(config)
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("create consumer: {e}")))?;
        let messages = consumer
            .messages()
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("messages stream: {e}")))?;

        let (tx, rx) = mpsc::channel(SUBSCRIPTION_CAPACITY);
        // Forward NATS messages into the bounded channel: a full channel makes
        // this task wait, so a slow subscriber slows its own consumer only.
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut messages = messages;
            while let Some(Ok(msg)) = messages.next().await {
                match serde_json::from_slice::<Event>(&msg.payload) {
                    Ok(event) => {
                        if let Err(e) = event.validate() {
                            tracing::warn!("invalid CloudEvents envelope, skipping: {e}");
                        } else if tx.send(event).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => tracing::warn!("failed to deserialize NATS event: {e}"),
                }
            }
        });
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
        let config = jetstream::consumer::pull::Config {
            durable_name: Some(name.clone()),
            deliver_policy: jetstream::consumer::DeliverPolicy::All,
            ack_policy: jetstream::consumer::AckPolicy::Explicit,
            // A delivery not settled in time (a hung or killed consumer) is
            // delivered again; no limit, so redelivery never drops an event.
            ack_wait: DURABLE_ACK_WAIT,
            max_deliver: -1,
            filter_subjects: subjects,
            ..Default::default()
        };
        let jetstream = self.jetstream.clone();
        let stream = self.topology.work_stream();
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
                        let (delivery, outcome) = Delivery::new(event);
                        if tx.send(delivery).await.is_err() {
                            // The consumer stopped: the event stays its own.
                            if let Err(e) = msg.ack_with(AckKind::Nak(None)).await {
                                tracing::warn!(consumer = %name, "release an event: {e}");
                            }
                            break;
                        }
                        // Dropped unsettled: delivered again.
                        outcome
                            .await
                            .unwrap_or(Settlement::Retry(DURABLE_REDELIVERY))
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

        // Ephemeral consumer on the history only: replay reads facts and
        // never hands anyone work.
        let nanos = from
            .timestamp_nanos_opt()
            .ok_or_else(|| EventBusError::InvalidReplayWindow(format!("start {from}")))?;
        let opt_start_time = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(nanos))
            .map_err(|e| EventBusError::InvalidReplayWindow(format!("start {from}: {e}")))?;
        let config = jetstream::consumer::push::Config {
            filter_subjects: subjects,
            deliver_policy: jetstream::consumer::DeliverPolicy::ByStartTime {
                start_time: opt_start_time,
            },
            ack_policy: jetstream::consumer::AckPolicy::None,
            deliver_subject: self.client.new_inbox(),
            ..Default::default()
        };

        let stream = self
            .jetstream
            .get_stream(self.topology.history_stream())
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("get stream: {e}")))?;
        let consumer = stream
            .create_consumer(config)
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("create replay consumer: {e}")))?;
        let messages = consumer
            .messages()
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("replay messages: {e}")))?;

        let (tx, rx) = mpsc::channel(SUBSCRIPTION_CAPACITY);
        // Forward replayed events until `to` cutoff or stream end.
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut messages = messages;
            while let Some(Ok(msg)) = messages.next().await {
                match serde_json::from_slice::<Event>(&msg.payload) {
                    Ok(event) => {
                        if to.is_some_and(|cutoff| event.time >= cutoff) {
                            break;
                        }
                        if let Err(e) = event.validate() {
                            tracing::warn!("replay: invalid CloudEvents envelope, skipping: {e}");
                        } else if tx.send(event).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => tracing::warn!("replay: failed to deserialize event: {e}"),
                }
            }
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
    let durable = stream
        .get_or_create_consumer(name, config.clone())
        .await
        .map_err(|e| EventBusError::SubscribeFailed(format!("durable consumer {name}: {e}")))?;
    durable
        .stream()
        .max_messages_per_batch(1)
        .heartbeat(DURABLE_HEARTBEAT)
        .expires(DURABLE_PULL_EXPIRES)
        .messages()
        .await
        .map_err(|e| EventBusError::SubscribeFailed(format!("messages stream: {e}")))
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
