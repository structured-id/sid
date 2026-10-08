// SPDX-License-Identifier: AGPL-3.0-only
//! NATS JetStream event bus implementation.
//!
//! Production EventBus for multi-binary deployments.
//! Uses NATS JetStream for durable, at-least-once event delivery.
//!
//! CE: connects to embedded or external NATS server.
//! EE: extends with NKey auth, subject ACLs, DLQ.

use async_nats::jetstream::{self, Context as JsContext, stream};
use async_trait::async_trait;
use sid_core::models::event::{Event, EventFilter};
use sid_plugin::event_bus::{EventBus, EventBusError, EventBusResult, SUBSCRIPTION_CAPACITY};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

/// NATS JetStream stream name for all SID events.
const STREAM_NAME: &str = "SID_EVENTS";

/// NATS subject prefix for SID events.
/// Events are published as `sid.{category}.{action}.v1`.
const SUBJECT_PREFIX: &str = "sid.>";

/// Default max age for events in the stream (7 days).
const DEFAULT_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

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
