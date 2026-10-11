// SPDX-License-Identifier: AGPL-3.0-only
//! NatsEventBus against the test NATS server (`SID_TEST_NATS_URL`, default
//! `nats://localhost:4399`). An unreachable server fails the test. Each test
//! runs on a topology of its own subject root, so tests sharing the server
//! never see each other's streams.

use async_nats::jetstream::{self, stream};
use sid_core::models::event::{Event, EventFilter, WorkRecipient, event_types};
use sid_infra::{NatsEventBus, Topology, TopologyError, TopologyRole};
use sid_plugin::event_bus::{Delivery, DurableConsumer, EventBus, EventBusError, Settlement};
use std::time::Duration;
use tokio::sync::mpsc;

fn nats_url() -> String {
    std::env::var("SID_TEST_NATS_URL").unwrap_or_else(|_| "nats://localhost:4399".to_string())
}

/// A topology no other test uses.
fn topology() -> Topology {
    let mut t = Topology::with_root(format!("t{}", uuid::Uuid::now_v7().simple())).unwrap();
    // The server reserves a work stream's byte bound, and tests run at once.
    t.work_max_bytes = 8 << 20;
    t
}

async fn jetstream() -> jetstream::Context {
    jetstream::new(
        async_nats::connect(nats_url())
            .await
            .expect("test NATS unreachable; start docker-compose.test.yml"),
    )
}

/// The bus of the topology's owner.
async fn owner(topology: &Topology) -> NatsEventBus {
    NatsEventBus::connect(&nats_url(), topology.clone(), TopologyRole::Own)
        .await
        .expect("test NATS unreachable; start docker-compose.test.yml")
}

/// Messages stream `name` holds.
async fn stored(name: &str) -> u64 {
    jetstream()
        .await
        .get_stream(name)
        .await
        .unwrap()
        .info()
        .await
        .unwrap()
        .state
        .messages
}

/// Remove the test's streams from the shared server.
async fn drop_topology(topology: &Topology) {
    let js = jetstream().await;
    for name in [topology.history_stream(), topology.work_stream()] {
        if let Err(e) = js.delete_stream(&name).await {
            eprintln!("delete {name}: {e}");
        }
    }
}

fn recipient(name: &str) -> WorkRecipient {
    WorkRecipient::new(name).unwrap()
}

/// The next delivery, within a bound a redelivery fits in.
async fn next(deliveries: &mut mpsc::Receiver<Delivery>) -> Delivery {
    tokio::time::timeout(Duration::from_secs(20), deliveries.recv())
        .await
        .expect("a delivery in time")
        .expect("the consumer is open")
}

/// Nothing more arrives within a short wait.
async fn quiet(deliveries: &mut mpsc::Receiver<Delivery>) -> bool {
    tokio::time::timeout(Duration::from_secs(3), deliveries.recv())
        .await
        .is_err()
}

fn consumer_of(name: &str) -> DurableConsumer {
    DurableConsumer {
        recipient: recipient(name),
        event_types: Vec::new(),
    }
}

/// Publishing the same fact again (a relay retry after a lost PubAck) stores
/// it once in history; another producer's event with the same id is a
/// different fact and is stored too.
#[tokio::test]
async fn test_republished_fact_is_stored_once() {
    let t = topology();
    let bus = owner(&t).await;
    let event = Event::new("sid-test", event_types::USER_CREATED);
    bus.publish(event.clone()).await.unwrap();
    bus.publish(event.clone()).await.unwrap();
    assert_eq!(stored(&t.history_stream()).await, 1, "stored twice");

    let mut other_source = event.clone();
    other_source.source = "sid-other".into();
    bus.publish(other_source).await.unwrap();
    assert_eq!(
        stored(&t.history_stream()).await,
        2,
        "a distinct fact was dropped"
    );
    drop_topology(&t).await;
}

/// The core of the retention contract: work handed to a receiver that is
/// not running survives past the history's age limit, while the same fact
/// in history is gone, and work is not history.
#[tokio::test]
async fn test_unsettled_work_outlives_history_retention() {
    let mut t = topology();
    t.history_max_age = Duration::from_secs(1);
    let bus = owner(&t).await;
    let notify = recipient("notify");
    let event = Event::new("sid-test", event_types::SESSION_REVOKED);
    bus.publish(event.clone()).await.unwrap();
    bus.deliver(&notify, event.delivery_id(&notify), &event)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        stored(&t.history_stream()).await,
        0,
        "history kept past its age"
    );
    assert_eq!(stored(&t.work_stream()).await, 1, "work was lost to age");

    let mut deliveries = bus.consume(consumer_of("notify")).await.unwrap();
    let delivered = next(&mut deliveries).await;
    assert_eq!(delivered.event.id, event.id);
    delivered.settle(Settlement::Done);
    assert!(quiet(&mut deliveries).await);
    assert_eq!(stored(&t.work_stream()).await, 0, "settled work kept");
    drop_topology(&t).await;
}

/// A durable consumer gets work handed over before it existed and keeps
/// each until it is settled done: one settled for retry comes again, one
/// dropped unsettled goes to the next consumer of the same receiver (a
/// restart), and one settled done never comes back. A redelivered handoff
/// under the same id is held once.
#[tokio::test]
async fn test_durable_consumer_keeps_work_until_settled_done() {
    let t = topology();
    let bus = owner(&t).await;
    let receiver = recipient("evaluator");
    let first = Event::new("sid-test", event_types::PASSWORD_HISTORY_OWNER_PURGED);
    let second = Event::new("sid-test", event_types::PASSWORD_HISTORY_OWNER_PURGED);
    for event in [&first, &first, &second] {
        bus.deliver(&receiver, event.delivery_id(&receiver), event)
            .await
            .unwrap();
    }
    assert_eq!(
        stored(&t.work_stream()).await,
        2,
        "a repeated handoff was held twice"
    );

    let mut deliveries = bus.consume(consumer_of("evaluator")).await.unwrap();
    let delivered = next(&mut deliveries).await;
    assert_eq!(
        delivered.event.id, first.id,
        "handed over before the consumer"
    );
    delivered.settle(Settlement::Retry(Duration::from_millis(200)));
    let delivered = next(&mut deliveries).await;
    assert_eq!(delivered.event.id, second.id);
    delivered.settle(Settlement::Done);
    let delivered = next(&mut deliveries).await;
    assert_eq!(delivered.event.id, first.id, "the retried event came again");
    delivered.settle(Settlement::Done);

    let third = Event::new("sid-test", event_types::PASSWORD_HISTORY_OWNER_PURGED);
    bus.deliver(&receiver, third.delivery_id(&receiver), &third)
        .await
        .unwrap();
    let unsettled = next(&mut deliveries).await;
    assert_eq!(unsettled.event.id, third.id);
    drop(unsettled);
    drop(deliveries);

    let mut restarted = bus.consume(consumer_of("evaluator")).await.unwrap();
    let delivered = next(&mut restarted).await;
    assert_eq!(delivered.event.id, third.id, "the unsettled event survived");
    delivered.settle(Settlement::Done);
    assert!(quiet(&mut restarted).await, "settled work came back");
    drop_topology(&t).await;
}

/// A consumer lost on the server while it holds pending work (deleted, or
/// gone with a server failure) is reopened and the pending work, and work
/// handed over afterwards, still reach it; settled work does not come back.
#[tokio::test]
async fn test_durable_consumer_recovers_from_a_lost_consumer() {
    let t = topology();
    let bus = owner(&t).await;
    let receiver = recipient("recover");
    let mut deliveries = bus.consume(consumer_of("recover")).await.unwrap();
    let settled = Event::new("sid-test", event_types::PASSWORD_HISTORY_CLEANUP_SETTLED);
    bus.deliver(&receiver, settled.delivery_id(&receiver), &settled)
        .await
        .unwrap();
    let delivered = next(&mut deliveries).await;
    delivered.settle(Settlement::Done);
    let pending = Event::new("sid-test", event_types::PASSWORD_HISTORY_CLEANUP_SETTLED);
    bus.deliver(&receiver, pending.delivery_id(&receiver), &pending)
        .await
        .unwrap();
    let held = next(&mut deliveries).await;
    assert_eq!(held.event.id, pending.id);

    jetstream()
        .await
        .get_stream(t.work_stream())
        .await
        .unwrap()
        .delete_consumer("recover")
        .await
        .unwrap();
    drop(held);

    let after = Event::new("sid-test", event_types::PASSWORD_HISTORY_CLEANUP_SETTLED);
    bus.deliver(&receiver, after.delivery_id(&receiver), &after)
        .await
        .unwrap();
    let mut seen = Vec::new();
    for _ in 0..2 {
        let delivered = next(&mut deliveries).await;
        seen.push(delivered.event.id.clone());
        delivered.settle(Settlement::Done);
    }
    seen.sort();
    let mut wanted = vec![pending.id, after.id];
    wanted.sort();
    assert_eq!(seen, wanted, "pending and later work after the loss");
    assert!(quiet(&mut deliveries).await, "settled work came back");
    drop_topology(&t).await;
}

/// Independent receivers each hold their own copy, so one settling does not
/// settle the other; replicas of one receiver share its work, each event
/// going to one of them.
#[tokio::test]
async fn test_receivers_are_independent_and_replicas_share() {
    let t = topology();
    let bus = owner(&t).await;
    let (a, b) = (recipient("a"), recipient("b"));
    let event = Event::new("sid-test", event_types::USER_CREATED);
    for receiver in [&a, &b] {
        bus.deliver(receiver, event.delivery_id(receiver), &event)
            .await
            .unwrap();
    }
    let mut at_a = bus.consume(consumer_of("a")).await.unwrap();
    next(&mut at_a).await.settle(Settlement::Done);
    let mut at_b = bus.consume(consumer_of("b")).await.unwrap();
    let delivered = next(&mut at_b).await;
    assert_eq!(
        delivered.event.id, event.id,
        "b's copy went with a's settlement"
    );
    delivered.settle(Settlement::Done);

    let replica = owner(&t).await;
    let mut other = replica.consume(consumer_of("a")).await.unwrap();
    let events: Vec<Event> = (0..4)
        .map(|_| Event::new("sid-test", event_types::USER_CREATED))
        .collect();
    for event in &events {
        bus.deliver(&a, event.delivery_id(&a), event).await.unwrap();
    }
    let mut seen = Vec::new();
    while seen.len() < events.len() {
        let delivered = tokio::select! {
            d = next(&mut at_a) => d,
            d = next(&mut other) => d,
        };
        seen.push(delivered.event.id.clone());
        delivered.settle(Settlement::Done);
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), events.len(), "an event went to both replicas");
    drop_topology(&t).await;
}

/// A full work stream refuses new work instead of evicting what it holds:
/// the producer keeps its obligation and the held work is still delivered.
#[tokio::test]
async fn test_full_work_stream_refuses_new_work() {
    let mut t = topology();
    t.work_max_messages = 1;
    let bus = owner(&t).await;
    let receiver = recipient("full");
    let held = Event::new("sid-test", event_types::USER_CREATED);
    bus.deliver(&receiver, held.delivery_id(&receiver), &held)
        .await
        .unwrap();
    let refused = Event::new("sid-test", event_types::USER_CREATED);
    let result = bus
        .deliver(&receiver, refused.delivery_id(&receiver), &refused)
        .await;
    assert!(
        matches!(result, Err(EventBusError::PublishFailed(_))),
        "{result:?}"
    );
    let mut deliveries = bus.consume(consumer_of("full")).await.unwrap();
    let delivered = next(&mut deliveries).await;
    assert_eq!(delivered.event.id, held.id, "held work was evicted");
    delivered.settle(Settlement::Done);
    drop_topology(&t).await;
}

/// Each way of carrying an event takes only the types the registry gives
/// it: history takes identity facts, delivery takes identity facts and
/// addressed work, and nothing takes a platform or unknown type.
#[tokio::test]
async fn test_unroutable_types_are_refused() {
    let t = topology();
    let bus = owner(&t).await;
    let receiver = recipient("r");
    for (event_type, publish_ok, deliver_ok) in [
        (event_types::USER_CREATED, true, true),
        (event_types::PASSWORD_HISTORY_OWNER_PURGED, false, true),
        (event_types::ORG_TRIAL_ACTIVATED, false, false),
        ("sid.unknown.v1", false, false),
    ] {
        let event = Event::new("sid-test", event_type);
        let published = bus.publish(event.clone()).await;
        assert_eq!(published.is_ok(), publish_ok, "publish {event_type}");
        if !publish_ok {
            assert!(matches!(published, Err(EventBusError::Unroutable(_))));
        }
        let delivered = bus
            .deliver(&receiver, event.delivery_id(&receiver), &event)
            .await;
        assert_eq!(delivered.is_ok(), deliver_ok, "deliver {event_type}");
    }
    assert_eq!(stored(&t.history_stream()).await, 1);
    assert_eq!(stored(&t.work_stream()).await, 2);
    drop_topology(&t).await;
}

/// Replay reads facts only: work handed to a receiver is never replayed,
/// and replaying hands nobody anything.
#[tokio::test]
async fn test_replay_reads_history_only() {
    let t = topology();
    let bus = owner(&t).await;
    let receiver = recipient("r");
    let start = chrono::Utc::now() - chrono::Duration::seconds(5);
    let fact = Event::new("sid-test", event_types::USER_CREATED);
    bus.publish(fact.clone()).await.unwrap();
    let work = Event::new("sid-test", event_types::PASSWORD_HISTORY_OWNER_PURGED);
    bus.deliver(&receiver, work.delivery_id(&receiver), &work)
        .await
        .unwrap();
    let mut replayed = bus
        .replay(start, None, EventFilter::default())
        .await
        .unwrap();
    let first = tokio::time::timeout(Duration::from_secs(5), replayed.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.id, fact.id);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), replayed.recv())
            .await
            .map_or(true, |e| e.is_none()),
        "replay showed work"
    );
    assert_eq!(stored(&t.work_stream()).await, 1, "replay touched work");
    drop_topology(&t).await;
}

/// Only the owner creates the streams; a process that verifies is not ready
/// while they are missing or differ, and works once they are as defined.
#[tokio::test]
async fn test_only_the_owner_creates_the_topology() {
    let t = topology();
    let verify = NatsEventBus::connect(&nats_url(), t.clone(), TopologyRole::Verify).await;
    assert!(
        verify.is_err(),
        "a verifier created or accepted no topology"
    );
    let js = jetstream().await;
    assert!(js.get_stream(t.history_stream()).await.is_err());

    owner(&t).await;
    NatsEventBus::connect(&nats_url(), t.clone(), TopologyRole::Verify)
        .await
        .expect("a verifier accepts the owner's topology");

    let mut shorter = t.clone();
    shorter.history_max_age = Duration::from_secs(60);
    let differs = shorter.prepare(&js, TopologyRole::Verify).await;
    assert!(
        matches!(differs, Err(TopologyError::NotReady { .. })),
        "{differs:?}"
    );
    shorter.prepare(&js, TopologyRole::Own).await.unwrap();
    assert!(t.prepare(&js, TopologyRole::Verify).await.is_err());
    drop_topology(&t).await;
}

/// Replicas of the topology owner starting at once (each creating the
/// missing streams) both come up on the one set of streams, as defined.
#[tokio::test]
async fn test_owner_replicas_prepare_together() {
    let t = topology();
    let (a, b) = (jetstream().await, jetstream().await);
    let (first, second) = tokio::join!(
        t.prepare(&a, TopologyRole::Own),
        t.prepare(&b, TopologyRole::Own)
    );
    first.expect("first owner replica");
    second.expect("second owner replica");
    t.prepare(&a, TopologyRole::Verify)
        .await
        .expect("the streams are as defined");
    drop_topology(&t).await;
}

/// An earlier broad stream holding the subjects is refused, not changed:
/// its messages, cursors and settings stay as they are.
#[tokio::test]
async fn test_broad_earlier_stream_is_left_alone() {
    let t = topology();
    let root = t
        .history_subject(event_types::USER_CREATED)
        .unwrap()
        .split('.')
        .next()
        .unwrap()
        .to_string();
    let js = jetstream().await;
    let broad = format!("{}_EVENTS", root.to_ascii_uppercase());
    js.create_stream(stream::Config {
        name: broad.clone(),
        subjects: vec![format!("{root}.>")],
        max_age: Duration::from_secs(3600),
        ..Default::default()
    })
    .await
    .unwrap();
    js.publish(format!("{root}.user.created.v1"), "old".into())
        .await
        .unwrap()
        .await
        .unwrap();

    let refused = t.prepare(&js, TopologyRole::Own).await;
    assert!(
        matches!(&refused, Err(TopologyError::Conflict { held_by, .. }) if *held_by == broad),
        "{refused:?}"
    );
    assert_eq!(stored(&broad).await, 1, "the earlier backlog was touched");
    assert!(js.get_stream(t.history_stream()).await.is_err());
    js.delete_stream(&broad).await.unwrap();
}
