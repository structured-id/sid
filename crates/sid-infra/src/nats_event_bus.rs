// SPDX-License-Identifier: AGPL-3.0-only
//! NATS JetStream event bus implementation.
//!
//! Production EventBus for multi-binary deployments.
//! Uses NATS JetStream for durable, at-least-once event delivery.
//!
//! Connects to an embedded or external NATS server.

use async_nats::jetstream::{self, Context as JsContext, stream};
use async_trait::async_trait;
use sid_core::models::event::{Event, EventFilter};
use sid_plugin::event_bus::{
    Delivery, DurableConsumer, EventBus, EventBusError, EventBusResult, SUBSCRIPTION_CAPACITY,
    Settlement,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

/// NATS JetStream stream name for all SID events.
const STREAM_NAME: &str = "SID_EVENTS";

/// NATS subject prefix for SID events.
/// Events are published as `sid.{category}.{action}.v1`.
const SUBJECT_PREFIX: &str = "sid.>";

/// Default max age for events in the stream (7 days).
const DEFAULT_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

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
///
/// Publishes events to JetStream stream `SID_EVENTS`.
/// Subscribers create ephemeral consumers with filter subjects.
pub struct NatsEventBus {
    /// NATS client connection.
    client: async_nats::Client,
    /// JetStream context for stream operations.
    jetstream: JsContext,
    /// Consumer name counter for unique consumer names.
    consumer_counter: AtomicU64,
}

impl NatsEventBus {
    /// Connect to NATS server and ensure the events stream exists.
    ///
    /// Creates the `SID_EVENTS` stream if it doesn't exist,
    /// or updates its configuration if needed.
    pub async fn connect(nats_url: &str) -> EventBusResult<Self> {
        let client = async_nats::connect(nats_url)
            .await
            .map_err(|e| EventBusError::Other(format!("NATS connect failed: {e}")))?;

        let jetstream = jetstream::new(client.clone());

        // Create or update the events stream.
        let stream_config = stream::Config {
            name: STREAM_NAME.to_string(),
            subjects: vec![SUBJECT_PREFIX.to_string()],
            max_age: std::time::Duration::from_secs(DEFAULT_MAX_AGE_SECS),
            storage: stream::StorageType::File,
            retention: stream::RetentionPolicy::Limits,
            ..Default::default()
        };

        jetstream
            .get_or_create_stream(stream_config)
            .await
            .map_err(|e| EventBusError::Other(format!("stream setup failed: {e}")))?;

        Ok(Self {
            client,
            jetstream,
            consumer_counter: AtomicU64::new(0),
        })
    }

    /// Generate a unique ephemeral consumer name.
    fn next_consumer_name(&self) -> String {
        let id = self.consumer_counter.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        format!("sid-consumer-{pid}-{id}")
    }

    /// Convert EventFilter patterns to NATS subject filters.
    ///
    /// - `sid.user.*` → `sid.user.*` (NATS wildcard: single token)
    /// - `sid.security.>` → `sid.security.>` (NATS wildcard: multi-token)
    /// - exact match → exact subject
    /// - empty filter → `sid.>` (all events)
    fn filter_to_subjects(filter: &EventFilter) -> Vec<String> {
        if filter.event_types.is_empty() {
            return vec![SUBJECT_PREFIX.to_string()];
        }

        filter.event_types.to_vec()
    }
}

#[async_trait]
impl EventBus for NatsEventBus {
    async fn publish(&self, event: Event) -> EventBusResult<()> {
        let subject = event.event_type.clone();
        let payload = serde_json::to_vec(&event)
            .map_err(|e| EventBusError::PublishFailed(format!("serialize: {e}")))?;

        // The event id travels as the message id, so JetStream drops a
        // republished event (a retry after a lost PubAck) within its
        // duplicate window instead of storing it twice.
        let message = jetstream::message::PublishMessage::build()
            .payload(payload.into())
            .message_id(event.id.as_str());
        self.jetstream
            .send_publish(subject, message)
            .await
            .map_err(|e| EventBusError::PublishFailed(format!("publish: {e}")))?
            .await
            .map_err(|e| EventBusError::PublishFailed(format!("ack: {e}")))?;

        Ok(())
    }

    async fn subscribe(&self, filter: EventFilter) -> EventBusResult<mpsc::Receiver<Event>> {
        let subjects = Self::filter_to_subjects(&filter);
        let consumer_name = self.next_consumer_name();

        // Build filter subject config.
        // When queue_group is set, use durable_name + deliver_group for load-balanced
        // consumption (each event → exactly one instance in the group).
        // When queue_group is None, use ephemeral consumer (fan-out / broadcast).
        let (durable_name, deliver_group) = match &filter.queue_group {
            Some(group) => {
                // Durable name: queue group + filter hash for uniqueness per subscription type.
                let durable = format!("{group}-{}", subjects.join("_").replace('.', "-"));
                (Some(durable), Some(group.clone()))
            }
            None => (None, None),
        };

        // Push consumers require a deliver_subject (inbox for message delivery).
        let deliver_subject = format!("_INBOX.{}", self.next_consumer_name());

        let consumer_config = if subjects.len() == 1 {
            jetstream::consumer::push::Config {
                filter_subject: subjects.into_iter().next().unwrap(),
                deliver_policy: jetstream::consumer::DeliverPolicy::New,
                deliver_subject: deliver_subject.clone(),
                durable_name,
                deliver_group,
                ..Default::default()
            }
        } else {
            jetstream::consumer::push::Config {
                filter_subjects: subjects,
                deliver_policy: jetstream::consumer::DeliverPolicy::New,
                deliver_subject,
                durable_name,
                deliver_group,
                ..Default::default()
            }
        };

        let stream = self
            .jetstream
            .get_stream(STREAM_NAME)
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("get stream: {e}")))?;

        let consumer = stream.create_consumer(consumer_config).await.map_err(|e| {
            EventBusError::SubscribeFailed(format!("create consumer {consumer_name}: {e}"))
        })?;

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
                        // Validate CloudEvents required fields.
                        if let Err(e) = event.validate() {
                            tracing::warn!("invalid CloudEvents envelope, skipping: {e}");
                        } else if tx.send(event).await.is_err() {
                            // Receiver dropped, stop consuming
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("failed to deserialize NATS event: {e}");
                    }
                }
                // Acknowledge the message.
                if let Err(e) = msg.ack().await {
                    tracing::warn!("failed to ack NATS message: {e}");
                }
            }
        });

        Ok(rx)
    }

    async fn consume(&self, consumer: DurableConsumer) -> EventBusResult<mpsc::Receiver<Delivery>> {
        let subjects = Self::filter_to_subjects(&EventFilter {
            event_types: consumer.event_types.clone(),
            ..Default::default()
        });
        // One durable pull consumer per name: its position and every
        // unsettled event outlive this process, and replicas pulling under the
        // name share it, each event going to one of them. Pulling (rather than
        // a push queue group, which cannot carry heartbeats) lets a lost or
        // deleted consumer surface as an error, after which it is reopened.
        let config = jetstream::consumer::pull::Config {
            durable_name: Some(consumer.name.clone()),
            // Every event since the consumer was created, never only those
            // published while a replica happens to be connected.
            deliver_policy: jetstream::consumer::DeliverPolicy::All,
            ack_policy: jetstream::consumer::AckPolicy::Explicit,
            // A delivery not settled in time (a hung or killed consumer) is
            // delivered again; no limit, so redelivery never drops an event.
            // The stream's own age and size limits still apply to an event
            // nobody consumed: a producer whose effect must not be lost keeps
            // it owed on its side until the consumer reports the effect, and
            // publishes it again meanwhile, rather than relying on the stream.
            ack_wait: DURABLE_ACK_WAIT,
            max_deliver: -1,
            filter_subjects: subjects,
            ..Default::default()
        };
        let jetstream = self.jetstream.clone();
        let name = consumer.name;
        // Opened once here, so a consumer that cannot be set up is refused to
        // the caller rather than retried unseen.
        let messages = open_durable(&jetstream, &name, &config).await?;

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
                    // until it works or the consumer is dropped. A recreated
                    // consumer starts from the stream's oldest event again;
                    // every consumer's effect is idempotent under its own
                    // records.
                    failed => {
                        match failed {
                            Some(Err(e)) => {
                                tracing::warn!(consumer = %name, "durable consumer: {e}");
                            }
                            _ => tracing::warn!(consumer = %name, "durable consumer ended"),
                        }
                        match reopen_durable(&jetstream, &name, &config, &tx).await {
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
                    Settlement::Done => msg.ack().await,
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
        let subjects = Self::filter_to_subjects(&filter);
        let deliver_subject = format!("_INBOX.replay-{}", self.next_consumer_name());

        // Ephemeral consumer with DeliverPolicy::ByStartTime for historical replay.
        let nanos = from
            .timestamp_nanos_opt()
            .ok_or_else(|| EventBusError::InvalidReplayWindow(format!("start {from}")))?;
        let opt_start_time = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(nanos))
            .map_err(|e| EventBusError::InvalidReplayWindow(format!("start {from}: {e}")))?;

        let consumer_config = if subjects.len() == 1 {
            jetstream::consumer::push::Config {
                filter_subject: subjects.into_iter().next().unwrap(),
                deliver_policy: jetstream::consumer::DeliverPolicy::ByStartTime {
                    start_time: opt_start_time,
                },
                deliver_subject,
                ..Default::default()
            }
        } else {
            jetstream::consumer::push::Config {
                filter_subjects: subjects,
                deliver_policy: jetstream::consumer::DeliverPolicy::ByStartTime {
                    start_time: opt_start_time,
                },
                deliver_subject,
                ..Default::default()
            }
        };

        let stream = self
            .jetstream
            .get_stream(STREAM_NAME)
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("get stream: {e}")))?;

        let consumer = stream
            .create_consumer(consumer_config)
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("create replay consumer: {e}")))?;

        let messages = consumer
            .messages()
            .await
            .map_err(|e| EventBusError::SubscribeFailed(format!("replay messages: {e}")))?;

        let (tx, rx) = mpsc::channel(SUBSCRIPTION_CAPACITY);
        let to_cutoff = to;

        // Forward replayed events until `to` cutoff or stream end.
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut messages = messages;
            while let Some(Ok(msg)) = messages.next().await {
                match serde_json::from_slice::<Event>(&msg.payload) {
                    Ok(event) => {
                        // Stop if past the `to` cutoff.
                        if let Some(cutoff) = to_cutoff
                            && event.time >= cutoff
                        {
                            if let Err(e) = msg.ack().await {
                                tracing::warn!("replay: failed to ack event: {e}");
                            }
                            break;
                        }

                        if let Err(e) = event.validate() {
                            tracing::warn!("replay: invalid CloudEvents envelope, skipping: {e}");
                        } else if tx.send(event).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("replay: failed to deserialize event: {e}");
                    }
                }
                if let Err(e) = msg.ack().await {
                    tracing::warn!("replay: failed to ack event: {e}");
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

/// The messages of the durable consumer `name`, created with `config` when
/// it does not exist. One message is pulled at a time: a pulled message's
/// acknowledgement deadline runs while it waits, so none waits behind another.
async fn open_durable(
    jetstream: &jetstream::Context,
    name: &str,
    config: &jetstream::consumer::pull::Config,
) -> EventBusResult<jetstream::consumer::pull::Stream> {
    let stream = jetstream
        .get_stream(STREAM_NAME)
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
    name: &str,
    config: &jetstream::consumer::pull::Config,
    tx: &mpsc::Sender<Delivery>,
) -> Option<jetstream::consumer::pull::Stream> {
    loop {
        tokio::select! {
            () = tx.closed() => return None,
            () = tokio::time::sleep(DURABLE_REOPEN) => {}
        }
        match open_durable(jetstream, name, config).await {
            Ok(messages) => return Some(messages),
            Err(e) => tracing::warn!(consumer = %name, "reopen: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_to_subjects_empty() {
        let filter = EventFilter::default();
        let subjects = NatsEventBus::filter_to_subjects(&filter);
        assert_eq!(subjects, vec!["sid.>"]);
    }

    #[test]
    fn test_filter_to_subjects_exact() {
        let filter = EventFilter {
            event_types: vec!["sid.user.created.v1".to_string()],
            ..Default::default()
        };
        let subjects = NatsEventBus::filter_to_subjects(&filter);
        assert_eq!(subjects, vec!["sid.user.created.v1"]);
    }

    #[test]
    fn test_filter_to_subjects_wildcard() {
        let filter = EventFilter {
            event_types: vec!["sid.user.*".to_string()],
            ..Default::default()
        };
        let subjects = NatsEventBus::filter_to_subjects(&filter);
        assert_eq!(subjects, vec!["sid.user.*"]);
    }

    #[test]
    fn test_filter_to_subjects_nats_wildcard() {
        let filter = EventFilter {
            event_types: vec!["sid.security.>".to_string()],
            ..Default::default()
        };
        let subjects = NatsEventBus::filter_to_subjects(&filter);
        assert_eq!(subjects, vec!["sid.security.>"]);
    }

    #[test]
    fn test_filter_to_subjects_multiple() {
        let filter = EventFilter {
            event_types: vec![
                "sid.user.created.v1".to_string(),
                "sid.security.*".to_string(),
            ],
            ..Default::default()
        };
        let subjects = NatsEventBus::filter_to_subjects(&filter);
        assert_eq!(subjects.len(), 2);
        assert!(subjects.contains(&"sid.user.created.v1".to_string()));
        assert!(subjects.contains(&"sid.security.*".to_string()));
    }

    #[test]
    fn test_consumer_name_format() {
        let pid = std::process::id();
        let counter = AtomicU64::new(0);
        let id = counter.fetch_add(1, Ordering::Relaxed);
        let name = format!("sid-consumer-{pid}-{id}");
        assert!(name.starts_with("sid-consumer-"));
        assert!(name.ends_with("-0"));

        let id2 = counter.fetch_add(1, Ordering::Relaxed);
        let name2 = format!("sid-consumer-{pid}-{id2}");
        assert!(name2.ends_with("-1"));
        assert_ne!(name, name2);
    }
}
