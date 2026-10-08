// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC EventStreamService implementation.
//!
//! Real-time CloudEvents streaming over gRPC server-streaming RPCs.
//! Delegates to EventBus (NATS JetStream or in-process) for event delivery.
//! Events carry profile, session and provisioning data of every user, so the
//! stream serves administrators only.

use dashmap::DashMap;
use sid_authn::caller::authenticate;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::grpc_error::refuse::{
    dependency_unavailable, internal, invalid_field, missing_field, not_configured,
};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::ProfileId;
use sid_core::models::event::{Event, EventFilter};
use sid_plugin::event_bus::{EventBus, EventBusError};
use sid_proto::sid::v1::events::event_stream_service_server::EventStreamService;
use sid_proto::sid::v1::events::*;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, instrument};

/// Events buffered per stream before the forwarder waits for the client.
const STREAM_BUFFER: usize = 256;

/// Open streams this instance serves at once, across all callers.
const MAX_STREAMS: usize = 64;

/// Open streams one administrator may hold on this instance.
const MAX_STREAMS_PER_CALLER: usize = 4;

/// Events one replay delivers before it ends with `RESOURCE_EXHAUSTED`; a
/// larger history is read in narrower windows.
const MAX_REPLAY_EVENTS: usize = 10_000;

pub struct EventStreamServiceImpl {
    event_bus: Arc<dyn EventBus>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    streams: Arc<Semaphore>,
    per_caller: Arc<DashMap<ProfileId, usize>>,
}

/// One open stream's share of the limits, released when the stream ends.
struct StreamSlot {
    _permit: OwnedSemaphorePermit,
    caller: ProfileId,
    per_caller: Arc<DashMap<ProfileId, usize>>,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.per_caller.remove_if_mut(&self.caller, |_, open| {
            *open -= 1;
            *open == 0
        });
    }
}

impl EventStreamServiceImpl {
    pub fn new(
        event_bus: Arc<dyn EventBus>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            event_bus,
            jwt,
            revocation,
            streams: Arc::new(Semaphore::new(MAX_STREAMS)),
            per_caller: Arc::new(DashMap::new()),
        }
    }

    /// Authenticate an administrator and reserve a stream for them.
    #[allow(clippy::result_large_err)]
    async fn open_stream<T>(&self, request: &Request<T>) -> Result<StreamSlot, Status> {
        let caller = authenticate(request, self.jwt.verifier(), &self.revocation).await?;
        caller.require_admin()?;
        let permit = self
            .streams
            .clone()
            .try_acquire_owned()
            .map_err(|_| too_many_streams("event_streams", MAX_STREAMS))?;
        {
            let mut open = self.per_caller.entry(caller.profile_id).or_insert(0);
            if *open >= MAX_STREAMS_PER_CALLER {
                return Err(too_many_streams(
                    "event_streams_per_caller",
                    MAX_STREAMS_PER_CALLER,
                ));
            }
            *open += 1;
        }
        Ok(StreamSlot {
            _permit: permit,
            caller: caller.profile_id,
            per_caller: self.per_caller.clone(),
        })
    }
}

/// How long a client waits before opening a stream again when the limit is
/// reached: open streams end when their clients leave.
const STREAM_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(5);

/// QUOTA_EXCEEDED: `limit` streams of `quota` are already open.
fn too_many_streams(quota: &'static str, limit: usize) -> Status {
    ApiError::new(ErrorReason::QuotaExceeded, "too many open event streams")
        .with_quota_violation(quota, format!("at most {limit} open streams"))
        .with_metadata("limit", limit.to_string())
        .with_retry_after(STREAM_RETRY_AFTER)
        .into()
}

/// Convert domain Event → proto CloudEvent for gRPC streaming.
fn event_to_proto(event: &Event) -> Result<CloudEvent, serde_json::Error> {
    let time = prost_types::Timestamp {
        seconds: event.time.timestamp(),
        nanos: event.time.timestamp_subsec_nanos() as i32,
    };

    let data = if event.data.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&event.data)?
    };

    Ok(CloudEvent {
        id: event.id.clone(),
        source: event.source.clone(),
        spec_version: event.specversion.clone(),
        r#type: event.event_type.clone(),
        subject: event.subject.clone().unwrap_or_default(),
        time: Some(time),
        datacontenttype: event.datacontenttype.clone(),
        data,
        sequence: event.sequence,
    })
}

/// Forward bus events into a bounded gRPC stream until the client
/// disconnects, an event cannot be encoded, or `limit` events were sent.
fn forward(
    mut event_rx: mpsc::Receiver<Event>,
    slot: StreamSlot,
    limit: Option<usize>,
) -> ReceiverStream<Result<CloudEvent, Status>> {
    let (tx, rx) = mpsc::channel(STREAM_BUFFER);
    tokio::spawn(async move {
        let _slot = slot;
        let mut sent = 0usize;
        loop {
            // A client that leaves frees its stream at once, not on the next event.
            let event = tokio::select! {
                event = event_rx.recv() => match event {
                    Some(event) => event,
                    None => break,
                },
                () = tx.closed() => break,
            };
            if limit.is_some_and(|max| sent >= max) {
                // The client is told the window was cut short, never shown
                // a partial history as complete.
                let cut: Status = ApiError::new(
                    ErrorReason::QuotaExceeded,
                    "the replay window holds more events than one replay delivers; narrow it with `to`",
                )
                .with_quota_violation(
                    "replay_events",
                    format!("at most {MAX_REPLAY_EVENTS} events per replay"),
                )
                .with_metadata("limit", MAX_REPLAY_EVENTS.to_string())
                .into();
                if tx.send(Err(cut)).await.is_err() {
                    info!("replay client left before the window was cut");
                }
                break;
            }
            let item = event_to_proto(&event).map_err(|e| internal("encode event", e));
            let failed = item.is_err();
            if tx.send(item).await.is_err() || failed {
                break;
            }
            sent += 1;
        }
    });
    ReceiverStream::new(rx)
}

/// A request timestamp as a UTC time, or `InvalidArgument` naming the field.
#[allow(clippy::result_large_err)]
fn timestamp(
    field: &'static str,
    ts: prost_types::Timestamp,
) -> Result<chrono::DateTime<chrono::Utc>, Status> {
    u32::try_from(ts.nanos)
        .ok()
        .and_then(|nanos| chrono::DateTime::from_timestamp(ts.seconds, nanos))
        .ok_or_else(|| invalid_field(field, "not a valid timestamp"))
}

#[tonic::async_trait]
impl EventStreamService for EventStreamServiceImpl {
    type SubscribeStream = ReceiverStream<Result<CloudEvent, Status>>;

    #[instrument(skip_all, fields(method = "subscribe"))]
    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let slot = self.open_stream(&request).await?;
        let req = request.into_inner();

        let filter = EventFilter {
            event_types: req.event_types,
            attributes: req.filters,
            queue_group: None, // gRPC streams are per-client (fan-out)
        };

        info!("New event stream subscription: {:?}", filter.event_types);

        let event_rx = self
            .event_bus
            .subscribe(filter)
            .await
            .map_err(|e| dependency_unavailable("event bus", e))?;

        Ok(Response::new(forward(event_rx, slot, None)))
    }

    type ReplayStream = ReceiverStream<Result<CloudEvent, Status>>;

    #[instrument(skip_all, fields(method = "replay"))]
    async fn replay(
        &self,
        request: Request<ReplayRequest>,
    ) -> Result<Response<Self::ReplayStream>, Status> {
        let slot = self.open_stream(&request).await?;
        let req = request.into_inner();

        let from = timestamp("from", req.from.ok_or_else(|| missing_field("from"))?)?;
        let to = req.to.map(|ts| timestamp("to", ts)).transpose()?;
        if to.is_some_and(|to| to <= from) {
            return Err(invalid_field("to", "not after from"));
        }

        let filter = EventFilter {
            event_types: req.event_types,
            attributes: Default::default(),
            queue_group: None,
        };

        info!(
            from = %from,
            to = ?to,
            types = ?filter.event_types,
            "Replay request"
        );

        let event_rx = self
            .event_bus
            .replay(from, to, filter)
            .await
            .map_err(|e| match e {
                // A deployment without a persistent event bus keeps no history.
                EventBusError::ReplayUnsupported => not_configured("event_history"),
                EventBusError::InvalidReplayWindow(_) => {
                    invalid_field("from", "not a time the event history can start from")
                }
                other => dependency_unavailable("event bus", other),
            })?;

        Ok(Response::new(forward(
            event_rx,
            slot,
            Some(MAX_REPLAY_EVENTS),
        )))
    }
}

#[cfg(test)]
mod tests;
