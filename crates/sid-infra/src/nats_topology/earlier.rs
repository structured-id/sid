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
//! 3. [`retire`]: while any durable consumer of the stream still owes
//!    events, the stream's age limit is suspended, so nothing owed expires
//!    before it is handed over. Each owing consumer's receiver is recorded
//!    in a key-value bucket once, first writer wins, and an owner configured
//!    otherwise is not ready; the work stream must have room for all of it.
//!    Every owing consumer is then drained through itself, which hands out
//!    only what it never settled: each event becomes its receiver's work
//!    under the event's delivery id, marked as handed over from that
//!    consumer, and is acknowledged on the earlier consumer only after the
//!    work stream accepted it, one at a time and in order. A consumer owing
//!    nothing more is removed; once none owes anything the age limit is
//!    restored, and the stream goes once it holds nothing and serves nobody.
//!
//! History is not copied: a copy would make an earlier event younger and
//! restart its retention. The stream stays a read-only archive that replay
//! reads before the identity history, until its own age limit empties it.
//! Every step is idempotent and safe for several owner replicas at once: an
//! interrupted move resumes on the next start.

use std::time::Duration;

use async_nats::jetstream::{self, consumer, stream};
use futures::StreamExt;
use sid_core::models::event::{Event, EventFamily, WorkRecipient, event_route};

use super::{Topology, TopologyError};

/// How long a drain waits for the next event before asking the server
/// whether the consumer still owes any: an event a stopped earlier replica
/// held comes back only once its acknowledgement wait ran out.
const DRAIN_IDLE: Duration = Duration::from_secs(5);

/// Stream metadata keeping the earlier stream's age limit (seconds) while
/// it is suspended for the handover.
const SUSPENDED_AGE_KEY: &str = "sid.earlier.max_age_secs";

/// Header naming the earlier consumer a delivery was handed over from: its
/// receiver may have recorded its effect under the earlier version's key.
pub const HANDED_OVER_FROM: &str = "Sid-Earlier-Consumer";

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
            // A consumer name is one subject token of its receiver record.
            if consumer.is_empty() || consumer.contains(['.', '*', '>', ' ']) {
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
pub(crate) async fn earlier_stream(
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
    update(t, js, config).await
}

/// Apply `config` to the earlier stream; a stream another owner replica
/// removed meanwhile needs nothing more.
async fn update(
    t: &Topology,
    js: &jetstream::Context,
    config: stream::Config,
) -> Result<(), TopologyError> {
    match js.update_stream(config).await {
        Ok(_) => Ok(()),
        Err(_) if earlier_stream(t, js).await?.is_none() => Ok(()),
        Err(e) => Err(nats(&format!("update {}", t.earlier_stream()), e)),
    }
}

/// The subject the earlier stream keeps once fenced: under the root, apart
/// from every family of the identity topology, and taken by no publisher.
fn archive_subject(t: &Topology) -> String {
    format!("{}.archive.>", t.root)
}

/// The key-value bucket recording the receiver of each earlier consumer
/// being handed over: apart from the earlier stream, whose consumers would
/// otherwise owe the records themselves.
fn receivers_bucket(t: &Topology) -> String {
    format!("{}_EARLIER_RECEIVERS", t.stream_prefix())
}

/// Hand what the earlier stream's durable consumers still owe to their
/// receivers, remove the consumers that owe nothing, and the stream once it
/// is empty and unused.
pub(super) async fn retire(t: &Topology, js: &jetstream::Context) -> Result<(), TopologyError> {
    let Some(mut stream) = earlier_stream(t, js).await? else {
        return Ok(());
    };
    let mut durable = Vec::new();
    let mut listed = stream.consumers();
    while let Some(info) = listed.next().await {
        let info = info.map_err(|e| nats(&format!("consumers of {}", t.earlier_stream()), e))?;
        // An ephemeral consumer (an observer, a replay) owed nothing to
        // anyone and goes with its connection.
        if info.config.durable_name.is_some() {
            durable.push(info);
        }
    }
    let owing: Vec<&consumer::Info> = durable
        .iter()
        .filter(|info| info.num_pending + info.num_ack_pending as u64 > 0)
        .collect();

    if !owing.is_empty() {
        // Nothing owed may expire while it waits for its turn.
        suspend_age(t, js, &mut stream).await?;
        let mut receivers = Vec::with_capacity(owing.len());
        let bucket = receiver_records(t, js).await?;
        for info in &owing {
            receivers.push(recorded_receiver(t, &bucket, info).await?);
        }
        ensure_room(t, js, &mut stream, &owing).await?;
        for (info, receiver) in owing.iter().zip(&receivers) {
            drain(t, js, &stream, info, receiver).await?;
        }
    }
    for info in &durable {
        if let Err(e) = stream.delete_consumer(&info.name).await {
            // Another owner replica removed it already.
            tracing::debug!(consumer = %info.name, "remove an earlier consumer: {e}");
        }
    }
    restore_age(t, js, &mut stream).await?;

    let consumers = match stream.info().await {
        Ok(info) => info.state.consumer_count,
        // Another owner replica removed the stream meanwhile.
        Err(_) if earlier_stream(t, js).await?.is_none() => return Ok(()),
        Err(e) => return Err(nats(&format!("info {}", t.earlier_stream()), e)),
    };
    if consumers == 0
        && let Err(e) = js.delete_key_value(receivers_bucket(t)).await
    {
        // The receiver records served the consumers that are gone; absent
        // when nothing was handed over or another replica removed them.
        tracing::debug!(bucket = %receivers_bucket(t), "remove the receiver records: {e}");
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

/// Lift the earlier stream's age limit, keeping it in the stream's metadata
/// to restore once nothing is owed.
async fn suspend_age(
    t: &Topology,
    js: &jetstream::Context,
    stream: &mut stream::Stream,
) -> Result<(), TopologyError> {
    let mut config = stream
        .info()
        .await
        .map_err(|e| nats(&format!("info {}", t.earlier_stream()), e))?
        .config
        .clone();
    if config.metadata.contains_key(SUSPENDED_AGE_KEY) {
        return Ok(());
    }
    config.metadata.insert(
        SUSPENDED_AGE_KEY.to_owned(),
        config.max_age.as_secs().to_string(),
    );
    config.max_age = Duration::ZERO;
    update(t, js, config).await
}

/// Put back the age limit [`suspend_age`] lifted, once no earlier consumer
/// owes anything.
async fn restore_age(
    t: &Topology,
    js: &jetstream::Context,
    stream: &mut stream::Stream,
) -> Result<(), TopologyError> {
    let info = stream
        .info()
        .await
        .map_err(|e| nats(&format!("info {}", t.earlier_stream()), e))?;
    let mut config = info.config.clone();
    let Some(kept) = config.metadata.remove(SUSPENDED_AGE_KEY) else {
        return Ok(());
    };
    // Another owner replica may still be handing over.
    if info.state.consumer_count > 0 {
        return Ok(());
    }
    let secs = kept.parse::<u64>().map_err(|_| TopologyError::NotReady {
        stream: t.earlier_stream(),
        reason: format!("unreadable suspended age limit {kept:?}"),
    })?;
    config.max_age = Duration::from_secs(secs);
    update(t, js, config).await
}

/// The bucket of receiver records, created by the first owner to need it.
async fn receiver_records(
    t: &Topology,
    js: &jetstream::Context,
) -> Result<jetstream::kv::Store, TopologyError> {
    let bucket = receivers_bucket(t);
    if let Ok(store) = js.get_key_value(&bucket).await {
        return Ok(store);
    }
    let created = js
        .create_key_value(jetstream::kv::Config {
            bucket: bucket.clone(),
            history: 1,
            num_replicas: t.replicas,
            ..Default::default()
        })
        .await;
    match created {
        Ok(store) => Ok(store),
        // Another owner replica created it meanwhile.
        Err(e) => js
            .get_key_value(&bucket)
            .await
            .map_err(|_| nats(&format!("create {bucket}"), e)),
    }
}

/// The receiver consumer `info` owes its events to: the one recorded in
/// `bucket`, recording this owner's own first. Only the first record lands,
/// so every owner reads the same one and a consumer's events never split
/// between receivers; an owner configured otherwise is not ready.
async fn recorded_receiver(
    t: &Topology,
    bucket: &jetstream::kv::Store,
    info: &consumer::Info,
) -> Result<WorkRecipient, TopologyError> {
    let configured = t
        .earlier_receivers
        .iter()
        .find(|(name, _)| *name == info.name)
        .map(|(_, receiver)| receiver.clone())
        .ok_or_else(|| TopologyError::NotReady {
            stream: t.earlier_stream(),
            reason: format!(
                "consumer {} still owes events and no receiver is configured for it \
                 (SID_NATS_EARLIER_CONSUMERS)",
                info.name
            ),
        })?;
    if let Err(e) = bucket
        .create(&info.name, configured.as_str().to_owned().into())
        .await
    {
        // Refused when a record exists: then the existing one decides.
        tracing::debug!(consumer = %info.name, "receiver already recorded: {e}");
    }
    let recorded = bucket
        .get(&info.name)
        .await
        .map_err(|e| nats(&format!("read the receiver of {}", info.name), e))?
        .ok_or_else(|| nats("record a receiver", format!("no record for {}", info.name)))?;
    let recorded = String::from_utf8_lossy(&recorded).into_owned();
    if recorded != configured.as_str() {
        return Err(TopologyError::NotReady {
            stream: t.earlier_stream(),
            reason: format!(
                "consumer {} is being handed over to {recorded}, this owner is configured \
                 with {configured}",
                info.name
            ),
        });
    }
    Ok(configured)
}

/// Refuse the handover unless the work stream has room for everything the
/// owing consumers hand over: a handover stopped by a full work stream would
/// keep the owner from starting the receivers that could free it. The bytes
/// are estimated from the earlier stream's mean message size.
async fn ensure_room(
    t: &Topology,
    js: &jetstream::Context,
    earlier: &mut stream::Stream,
    owing: &[&consumer::Info],
) -> Result<(), TopologyError> {
    let messages: u64 = owing
        .iter()
        .map(|info| info.num_pending + info.num_ack_pending as u64)
        .sum();
    let held = earlier
        .info()
        .await
        .map_err(|e| nats(&format!("info {}", t.earlier_stream()), e))?
        .state
        .clone();
    let mean = held.bytes.div_ceil(held.messages.max(1));
    let bytes = mean.checked_mul(messages);
    let work = js
        .get_stream(t.work_stream())
        .await
        .map_err(|e| nats(&format!("get {}", t.work_stream()), e))?
        .info()
        .await
        .map_err(|e| nats(&format!("info {}", t.work_stream()), e))?
        .clone();
    // Whether `need` more fits under `limit` beside `used`: a negative limit
    // is unlimited, an overflow more than any stream holds.
    let fits = |limit: i64, used: u64, need: Option<u64>| match u64::try_from(limit) {
        Err(_) => true,
        Ok(limit) => need
            .and_then(|need| used.checked_add(need))
            .is_some_and(|total| total <= limit),
    };
    if !fits(
        work.config.max_messages,
        work.state.messages,
        Some(messages),
    ) || !fits(work.config.max_bytes, work.state.bytes, bytes)
    {
        // Reported only: a stream over its limit has no room left, not less.
        let free = |limit: i64, used: u64| {
            u64::try_from(limit).map_or("unlimited".to_owned(), |limit| {
                limit.saturating_sub(used).to_string()
            })
        };
        let (free_messages, free_bytes) = (
            free(work.config.max_messages, work.state.messages),
            free(work.config.max_bytes, work.state.bytes),
        );
        let bytes = bytes.map_or("more than any stream holds".to_owned(), |b| b.to_string());
        return Err(TopologyError::NotReady {
            stream: t.work_stream(),
            reason: format!(
                "handing over the earlier consumers' {messages} events (up to {bytes} bytes) \
                 needs room the work stream lacks ({free_messages} messages, {free_bytes} \
                 bytes free); raise SID_NATS_WORK_MAX_MESSAGES / SID_NATS_WORK_MAX_BYTES"
            ),
        });
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
            Ok(Some(Ok(msg))) => hand_over(t, js, &info.name, receiver, &msg).await?,
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

/// Make `msg` `receiver`'s work and settle it on earlier consumer `from`.
/// A message that is not an identity event stays owed there and keeps the
/// owner not ready: nothing the consumer owes is dropped.
async fn hand_over(
    t: &Topology,
    js: &jetstream::Context,
    from: &str,
    receiver: &WorkRecipient,
    msg: &jetstream::Message,
) -> Result<(), TopologyError> {
    let not_ready = |reason: String| TopologyError::NotReady {
        stream: t.earlier_stream(),
        reason,
    };
    let event = serde_json::from_slice::<Event>(&msg.payload)
        .map_err(|e| e.to_string())
        .and_then(|event| event.validate().map(|()| event).map_err(|e| e.to_string()))
        .map_err(|e| {
            not_ready(format!(
                "consumer {from} owes a message on {} that is not an event ({e})",
                msg.subject
            ))
        })?;
    let subject = match event_route(&event.event_type) {
        Some(route) if route.family() == EventFamily::Identity => {
            t.work_subject(receiver, &event.event_type)
        }
        _ => None,
    }
    .ok_or_else(|| {
        not_ready(format!(
            "consumer {from} owes event type {}, which has no identity work route",
            event.event_type
        ))
    })?;
    let mut headers = async_nats::HeaderMap::new();
    headers.insert(HANDED_OVER_FROM, from);
    let message = jetstream::message::PublishMessage::build()
        .payload(msg.payload.clone())
        .headers(headers)
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
