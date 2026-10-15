// SPDX-License-Identifier: AGPL-3.0-only
//! The controlled move of an installation's earlier broad events stream
//! (`<ROOT>_EVENTS` on `<root>.>`, kept by age) into the identity topology,
//! run by the deployment's topology owner at start-up.
//!
//! 1. [`fence`]: the stream's subjects narrow to an archive subject no
//!    publisher uses. A publisher of the earlier version then reaches no
//!    stream, so its outbox keeps the event owed instead of the stream
//!    taking it; the stored events stay where they are.
//! 2. The identity streams are created as usual.
//! 3. [`retire`]: every durable consumer of the stream that still owes
//!    events is drained through itself, which hands out only what it never
//!    settled: each event becomes its receiver's work under the event's
//!    delivery id and is acknowledged on the earlier consumer only after the
//!    work stream accepted it, one at a time and in order. A consumer owing
//!    nothing more is removed. Once the stream holds nothing and serves
//!    nobody, it is removed too.
//!
//! History is not copied: a copy would make an earlier event younger and
//! restart its retention, so the stream stays a read-only archive until its
//! own age limit empties it. Every step is idempotent and safe for several
//! owner replicas at once: an interrupted move resumes on the next start.

use std::time::Duration;

use async_nats::jetstream::{self, AckKind, consumer, stream};
use futures::StreamExt;
use sid_core::models::event::{Event, EventFamily, WorkRecipient, event_route};

use super::{Topology, TopologyError};

/// How long a drain waits for the next event before asking the server
/// whether the consumer still owes any: an event a stopped earlier replica
/// held comes back only once its acknowledgement wait ran out.
const DRAIN_IDLE: Duration = Duration::from_secs(5);

/// The receivers named by `SID_NATS_EARLIER_CONSUMERS`:
/// `<consumer>=<receiver>[,<consumer>=<receiver>...]`.
pub(super) fn parse_receivers(list: &str) -> Result<Vec<(String, WorkRecipient)>, TopologyError> {
    let invalid = |entry: &str| {
        TopologyError::Config(format!(
            "SID_NATS_EARLIER_CONSUMERS entries are <consumer>=<receiver>, got `{entry}`"
        ))
    };
    list.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (consumer, receiver) = entry.split_once('=').ok_or_else(|| invalid(entry))?;
            let consumer = consumer.trim();
            if consumer.is_empty() {
                return Err(invalid(entry));
            }
            let receiver = WorkRecipient::new(receiver.trim()).map_err(|_| invalid(entry))?;
            Ok((consumer.to_owned(), receiver))
        })
        .collect()
}

fn nats(what: &str, e: impl std::fmt::Display) -> TopologyError {
    TopologyError::Nats(format!("{what}: {e}"))
}

/// The earlier stream, or `None` when this installation has none.
async fn earlier_stream(
    t: &Topology,
    js: &jetstream::Context,
) -> Result<Option<stream::Stream>, TopologyError> {
    use async_nats::jetstream::ErrorCode;
    use async_nats::jetstream::context::GetStreamErrorKind;
    match js.get_stream(t.earlier_stream()).await {
        Ok(stream) => Ok(Some(stream)),
        Err(e)
            if matches!(
                e.kind(),
                GetStreamErrorKind::JetStream(je) if je.error_code() == ErrorCode::STREAM_NOT_FOUND
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(nats(&format!("get {}", t.earlier_stream()), e)),
    }
}

/// Narrow the earlier stream's subjects from `<root>.>` to the archive
/// subject. A stream of that name on other subjects is not the earlier
/// stream and is refused untouched.
pub(super) async fn fence(t: &Topology, js: &jetstream::Context) -> Result<(), TopologyError> {
    let Some(mut stream) = earlier_stream(t, js).await? else {
        return Ok(());
    };
    let mut config = stream
        .info()
        .await
        .map_err(|e| nats(&format!("info {}", t.earlier_stream()), e))?
        .config
        .clone();
    let broad = format!("{}.>", t.root);
    let archive = archive_subject(t);
    if config.subjects == [archive.clone()] {
        return Ok(());
    }
    if config.subjects != [broad.clone()] {
        return Err(TopologyError::Conflict {
            subjects: broad,
            held_by: t.earlier_stream(),
        });
    }
    tracing::info!(
        stream = %t.earlier_stream(),
        "moving the earlier events stream out of the identity topology"
    );
    config.subjects = vec![archive];
    match js.update_stream(config).await {
        Ok(_) => Ok(()),
        // Another owner replica removed it meanwhile: nothing left to fence.
        Err(_) if earlier_stream(t, js).await?.is_none() => Ok(()),
        Err(e) => Err(nats(&format!("fence {}", t.earlier_stream()), e)),
    }
}

/// The subject the earlier stream keeps once fenced: under the root, apart
/// from every family of the identity topology, and taken by no publisher.
fn archive_subject(t: &Topology) -> String {
    format!("{}.archive.>", t.root)
}

/// Hand what the earlier stream's durable consumers still owe to their
/// receivers, remove the consumers that owe nothing, and the stream once it
/// is empty and unused.
pub(super) async fn retire(t: &Topology, js: &jetstream::Context) -> Result<(), TopologyError> {
    let Some(mut stream) = earlier_stream(t, js).await? else {
        return Ok(());
    };
    let mut consumers = Vec::new();
    let mut listed = stream.consumers();
    while let Some(info) = listed.next().await {
        consumers.push(info.map_err(|e| nats(&format!("consumers of {}", t.earlier_stream()), e))?);
    }
    for info in consumers {
        // An ephemeral consumer (an observer, a replay) owed nothing to
        // anyone and goes with its connection.
        if info.config.durable_name.is_none() {
            continue;
        }
        let owed = info.num_pending + info.num_ack_pending as u64;
        if owed > 0 {
            let receiver = t
                .earlier_receivers
                .iter()
                .find(|(name, _)| *name == info.name)
                .map(|(_, receiver)| receiver)
                .ok_or_else(|| TopologyError::NotReady {
                    stream: t.earlier_stream(),
                    reason: format!(
                        "consumer {} still owes {owed} events and no receiver is configured \
                         for it (SID_NATS_EARLIER_CONSUMERS)",
                        info.name
                    ),
                })?;
            drain(t, js, &stream, &info, receiver).await?;
        }
        if let Err(e) = stream.delete_consumer(&info.name).await {
            // Another owner replica removed it already.
            tracing::debug!(consumer = %info.name, "remove an earlier consumer: {e}");
        }
    }
    let state = stream
        .info()
        .await
        .map_err(|e| nats(&format!("info {}", t.earlier_stream()), e))?
        .state
        .clone();
    if state.messages == 0 && state.consumer_count == 0 {
        if let Err(e) = js.delete_stream(t.earlier_stream()).await {
            tracing::debug!(stream = %t.earlier_stream(), "remove the earlier stream: {e}");
        }
        tracing::info!(stream = %t.earlier_stream(), "the earlier events stream is gone");
    }
    Ok(())
}

/// The events durable consumer `info` still owes, read through it so that
/// only what it never settled comes out.
type Owed =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<jetstream::Message, String>> + Send>>;

async fn owed(stream: &stream::Stream, info: &consumer::Info) -> Result<Owed, TopologyError> {
    let what = |e: &dyn std::fmt::Display| nats(&format!("drain {}", info.name), e);
    if info.config.deliver_subject.is_some() {
        // A push consumer: its own subscription, in its delivery group.
        let consumer: consumer::PushConsumer = stream
            .get_consumer(&info.name)
            .await
            .map_err(|e| what(&e))?;
        let messages = consumer.messages().await.map_err(|e| what(&e))?;
        Ok(Box::pin(messages.map(|m| m.map_err(|e| e.to_string()))))
    } else {
        let consumer: consumer::PullConsumer = stream
            .get_consumer(&info.name)
            .await
            .map_err(|e| what(&e))?;
        let messages = consumer
            .stream()
            .max_messages_per_batch(1)
            .expires(DRAIN_IDLE)
            .messages()
            .await
            .map_err(|e| what(&e))?;
        Ok(Box::pin(messages.map(|m| m.map_err(|e| e.to_string()))))
    }
}

/// Hand every event durable consumer `info` still owes to `receiver`'s
/// work, acknowledging each on the earlier consumer once the work stream
/// accepted it, until the consumer owes nothing.
async fn drain(
    t: &Topology,
    js: &jetstream::Context,
    stream: &stream::Stream,
    info: &consumer::Info,
    receiver: &WorkRecipient,
) -> Result<(), TopologyError> {
    tracing::info!(
        consumer = %info.name,
        receiver = %receiver,
        "handing the earlier consumer's unsettled events to its receiver"
    );
    let Some(mut messages) = reopen(stream, info).await? else {
        return Ok(());
    };
    loop {
        match tokio::time::timeout(DRAIN_IDLE, messages.next()).await {
            Ok(Some(Ok(msg))) => hand_over(t, js, receiver, &msg).await?,
            Ok(Some(Err(e))) => {
                tracing::warn!(consumer = %info.name, "drain: {e}");
                let Some(reopened) = reopen(stream, info).await? else {
                    return Ok(());
                };
                messages = reopened;
            }
            // Idle, or the pull ended: done once the consumer owes nothing;
            // an event a stopped replica holds comes back after its wait.
            Ok(None) | Err(_) => {
                match consumer_state(stream, &info.name).await? {
                    None => return Ok(()),
                    Some(now) if now.num_pending == 0 && now.num_ack_pending == 0 => {
                        return Ok(());
                    }
                    Some(_) => {}
                }
                let Some(reopened) = reopen(stream, info).await? else {
                    return Ok(());
                };
                messages = reopened;
            }
        }
    }
}

/// The current state of earlier consumer `name`, or `None` once it is gone:
/// another owner replica removed it after handing over everything it owed.
/// Only the server's "not found" means gone; any other failure is an error,
/// never taken for a consumer that owes nothing.
async fn consumer_state(
    stream: &stream::Stream,
    name: &str,
) -> Result<Option<consumer::Info>, TopologyError> {
    use async_nats::jetstream::context::ConsumerInfoErrorKind;
    match stream.consumer_info(name).await {
        Ok(info) => Ok(Some(info)),
        Err(e) if e.kind() == ConsumerInfoErrorKind::NotFound => Ok(None),
        Err(e) => Err(nats(&format!("info {name}"), e)),
    }
}

/// [`owed`], or `None` when the consumer is gone (see [`consumer_state`]).
async fn reopen(
    stream: &stream::Stream,
    info: &consumer::Info,
) -> Result<Option<Owed>, TopologyError> {
    match owed(stream, info).await {
        Ok(messages) => Ok(Some(messages)),
        Err(e) => match consumer_state(stream, &info.name).await? {
            None => Ok(None),
            Some(_) => Err(e),
        },
    }
}

/// Make `msg` `receiver`'s work and settle it on the earlier consumer.
async fn hand_over(
    t: &Topology,
    js: &jetstream::Context,
    receiver: &WorkRecipient,
    msg: &jetstream::Message,
) -> Result<(), TopologyError> {
    let event = match serde_json::from_slice::<Event>(&msg.payload)
        .map_err(|e| e.to_string())
        .and_then(|event| event.validate().map(|()| event).map_err(|e| e.to_string()))
    {
        Ok(event) => event,
        // Not an event: the earlier consumer refused such a message too, and
        // nobody is owed anything for it.
        Err(e) => {
            tracing::warn!(subject = %msg.subject, "earlier stream: not an event, dropped: {e}");
            msg.ack_with(AckKind::Term)
                .await
                .map_err(|e| nats("terminate a non-event", e))?;
            return Ok(());
        }
    };
    // Work of the identity family only; anything else stays owed on the
    // earlier consumer and keeps the owner not ready.
    let subject = match event_route(&event.event_type) {
        Some(route) if route.family() == EventFamily::Identity => {
            t.work_subject(receiver, &event.event_type)
        }
        _ => None,
    }
    .ok_or_else(|| TopologyError::NotReady {
        stream: t.earlier_stream(),
        reason: format!(
            "event type {} of the earlier stream has no identity work route",
            event.event_type
        ),
    })?;
    let message = jetstream::message::PublishMessage::build()
        .payload(msg.payload.clone())
        .message_id(event.delivery_id(receiver).to_string())
        .expected_stream(t.work_stream());
    js.send_publish(subject, message)
        .await
        .map_err(|e| nats("hand over", e))?
        .await
        .map_err(|e| nats("hand over: acknowledgement", e))?;
    // Unconfirmed, the event is delivered again and handed over under the
    // same delivery id, which its receiver takes once.
    if let Err(e) = msg.double_ack().await {
        tracing::warn!(subject = %msg.subject, "earlier stream: settle a handed-over event: {e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
