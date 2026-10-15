// SPDX-License-Identifier: AGPL-3.0-only
//! The topology owner moving an installation's earlier broad events stream
//! into the identity topology, against the test NATS server
//! (`SID_TEST_NATS_URL`, default `nats://localhost:4399`). Each test seeds the
//! earlier stream as a version before the identity topology left it, under a
//! subject root of its own.

use async_nats::jetstream::{self, consumer, stream};
use futures::StreamExt;
use sid_core::models::event::{Event, WorkRecipient, event_types};
use sid_infra::{NatsEventBus, Topology, TopologyError, TopologyRole};
use sid_plugin::event_bus::{Delivery, DurableConsumer, EventBus, Settlement};
use std::time::Duration;
use tokio::sync::mpsc;

fn nats_url() -> String {
    std::env::var("SID_TEST_NATS_URL").unwrap_or_else(|_| "nats://localhost:4399".to_string())
}

async fn jetstream() -> jetstream::Context {
    jetstream::new(
        async_nats::connect(nats_url())
            .await
            .expect("test NATS unreachable; start docker-compose.test.yml"),
    )
}

/// A topology no other test uses, whose earlier consumer `old-notify` is
/// owed to the receiver `sid-notify`.
fn topology() -> Topology {
    let mut t = Topology::with_root(format!("t{}", uuid::Uuid::now_v7().simple())).unwrap();
    t.work_max_bytes = 8 << 20;
    t.earlier_receivers = vec![("old-notify".into(), recipient("sid-notify"))];
    t
}

fn recipient(name: &str) -> WorkRecipient {
    WorkRecipient::new(name).unwrap()
}

/// The subject root of `t`, as its earlier stream used it.
fn root(t: &Topology) -> String {
    t.history_subject(event_types::USER_CREATED)
        .unwrap()
        .split('.')
        .next()
        .unwrap()
        .to_string()
}

/// The earlier stream as a version before the identity topology created it:
/// every event on `<root>.>`, retained by age.
async fn seed_earlier(t: &Topology, max_age: Duration) {
    jetstream()
        .await
        .create_stream(stream::Config {
            name: t.earlier_stream(),
            subjects: vec![format!("{}.>", root(t))],
            max_age,
            storage: stream::StorageType::File,
            retention: stream::RetentionPolicy::Limits,
            ..Default::default()
        })
        .await
        .unwrap();
}

/// Publish `event` as the earlier version did: on its type, under the root.
async fn publish_earlier(t: &Topology, event: &Event) {
    let subject = event.event_type.replacen("sid", &root(t), 1);
    jetstream()
        .await
        .publish(subject, serde_json::to_vec(event).unwrap().into())
        .await
        .unwrap()
        .await
        .unwrap();
}

/// A durable pull consumer of the earlier stream, as sid-server's password
/// history consumers were.
async fn earlier_pull(t: &Topology, name: &str) -> consumer::PullConsumer {
    jetstream()
        .await
        .get_stream(t.earlier_stream())
        .await
        .unwrap()
        .create_consumer(consumer::pull::Config {
            durable_name: Some(name.into()),
            deliver_policy: consumer::DeliverPolicy::All,
            ack_policy: consumer::AckPolicy::Explicit,
            ack_wait: Duration::from_secs(2),
            ..Default::default()
        })
        .await
        .unwrap()
}

/// Acknowledge the earlier consumer's next `count` events, as it did once it
/// handled them.
async fn settle_earlier(consumer: &consumer::PullConsumer, count: usize) {
    let mut batch = consumer
        .fetch()
        .max_messages(count)
        .expires(Duration::from_secs(2))
        .messages()
        .await
        .unwrap();
    for _ in 0..count {
        batch
            .next()
            .await
            .unwrap()
            .unwrap()
            .double_ack()
            .await
            .unwrap();
    }
}

async fn earlier_config(t: &Topology) -> Option<stream::Config> {
    let mut stream = jetstream()
        .await
        .get_stream(t.earlier_stream())
        .await
        .ok()?;
    Some(stream.info().await.unwrap().config.clone())
}

async fn earlier_messages(t: &Topology) -> u64 {
    jetstream()
        .await
        .get_stream(t.earlier_stream())
        .await
        .unwrap()
        .info()
        .await
        .unwrap()
        .state
        .messages
}

async fn has_earlier_consumer(t: &Topology, name: &str) -> bool {
    jetstream()
        .await
        .get_stream(t.earlier_stream())
        .await
        .unwrap()
        .consumer_info(name)
        .await
        .is_ok()
}

/// The ids of the events the receiver gets, settling each.
async fn received(t: &Topology, name: &str, count: usize) -> Vec<String> {
    let bus = NatsEventBus::connect(&nats_url(), t.clone(), TopologyRole::Verify)
        .await
        .unwrap();
    let mut deliveries = bus
        .consume(DurableConsumer {
            recipient: recipient(name),
            event_types: Vec::new(),
            ordered: false,
        })
        .await
        .unwrap();
    let mut ids = Vec::new();
    for _ in 0..count {
        let delivery = next(&mut deliveries).await;
        ids.push(delivery.event.id.clone());
        delivery.settle(Settlement::Done);
    }
    assert!(quiet(&mut deliveries).await, "{name} got more than owed");
    ids
}

async fn next(deliveries: &mut mpsc::Receiver<Delivery>) -> Delivery {
    tokio::time::timeout(Duration::from_secs(20), deliveries.recv())
        .await
        .expect("a delivery in time")
        .expect("the consumer is open")
}

async fn quiet(deliveries: &mut mpsc::Receiver<Delivery>) -> bool {
    tokio::time::timeout(Duration::from_secs(3), deliveries.recv())
        .await
        .is_err()
}

async fn drop_all(t: &Topology) {
    let js = jetstream().await;
    for name in [t.history_stream(), t.work_stream(), t.earlier_stream()] {
        if let Err(e) = js.delete_stream(&name).await {
            eprintln!("delete {name}: {e}");
        }
    }
}

/// An earlier stream holding nothing and serving no consumer owes nothing:
/// the owner removes it and the identity topology comes up in its place.
#[tokio::test]
async fn test_an_empty_earlier_stream_is_removed() {
    let t = topology();
    seed_earlier(&t, Duration::from_secs(3600)).await;

    let js = jetstream().await;
    t.prepare(&js, TopologyRole::Own)
        .await
        .expect("the owner moves an empty earlier stream");
    assert!(
        earlier_config(&t).await.is_none(),
        "the empty stream stayed"
    );
    t.prepare(&js, TopologyRole::Verify)
        .await
        .expect("the identity topology is as defined");
    drop_all(&t).await;
}

/// The events an earlier durable consumer never settled are its receiver's
/// work in the new topology, each once; those it settled are not. The
/// earlier stream stays as an archive no publisher reaches, and its
/// consumer, owing nothing more, is gone.
#[tokio::test]
async fn test_unsettled_events_of_a_pull_consumer_become_work() {
    let t = topology();
    seed_earlier(&t, Duration::from_secs(3600)).await;
    let old = earlier_pull(&t, "old-notify").await;
    let events: Vec<Event> = (0..3)
        .map(|_| Event::new("sid-test", event_types::USER_CREATED))
        .collect();
    for event in &events {
        publish_earlier(&t, event).await;
    }
    settle_earlier(&old, 1).await;

    t.prepare(&jetstream().await, TopologyRole::Own)
        .await
        .expect("the transition completes");

    let ids = received(&t, "sid-notify", 2).await;
    assert_eq!(ids, [events[1].id.clone(), events[2].id.clone()]);
    assert!(!has_earlier_consumer(&t, "old-notify").await);
    let config = earlier_config(&t).await.expect("the archive stays");
    assert_eq!(config.subjects, [format!("{}.archive.>", root(&t))]);
    assert_eq!(earlier_messages(&t).await, 3, "the archive lost history");
    drop_all(&t).await;
}

/// A push consumer with a delivery group (sid-notify's, SCIM's) is drained
/// through its own subscription, so only what it never settled moves.
#[tokio::test]
async fn test_unsettled_events_of_a_push_consumer_become_work() {
    let t = topology();
    seed_earlier(&t, Duration::from_secs(3600)).await;
    jetstream()
        .await
        .get_stream(t.earlier_stream())
        .await
        .unwrap()
        .create_consumer(consumer::push::Config {
            durable_name: Some("old-notify".into()),
            deliver_subject: format!("_INBOX.{}", uuid::Uuid::now_v7().simple()),
            deliver_group: Some("sid-notify".into()),
            deliver_policy: consumer::DeliverPolicy::All,
            ack_policy: consumer::AckPolicy::Explicit,
            ack_wait: Duration::from_secs(2),
            ..Default::default()
        })
        .await
        .unwrap();
    let event = Event::new("sid-test", event_types::SESSION_REVOKED);
    publish_earlier(&t, &event).await;

    t.prepare(&jetstream().await, TopologyRole::Own)
        .await
        .expect("the transition completes");

    assert_eq!(received(&t, "sid-notify", 1).await, [event.id]);
    assert!(!has_earlier_consumer(&t, "old-notify").await);
    drop_all(&t).await;
}

/// A consumer owing events that no receiver is configured for keeps the
/// owner not ready, and nothing it owes is lost or moved: once its receiver
/// is configured, the next start completes the transition.
#[tokio::test]
async fn test_an_unmapped_consumer_owing_events_keeps_the_owner_not_ready() {
    let mut t = topology();
    t.earlier_receivers.clear();
    seed_earlier(&t, Duration::from_secs(3600)).await;
    earlier_pull(&t, "old-notify").await;
    let event = Event::new("sid-test", event_types::USER_CREATED);
    publish_earlier(&t, &event).await;

    let js = jetstream().await;
    let refused = t.prepare(&js, TopologyRole::Own).await;
    assert!(
        matches!(&refused, Err(TopologyError::NotReady { reason, .. }) if reason.contains("old-notify")),
        "{refused:?}"
    );
    assert!(has_earlier_consumer(&t, "old-notify").await);
    assert_eq!(earlier_messages(&t).await, 1);

    let mut mapped = t.clone();
    mapped.earlier_receivers = vec![("old-notify".into(), recipient("sid-notify"))];
    mapped
        .prepare(&js, TopologyRole::Own)
        .await
        .expect("the next start completes the transition");
    assert_eq!(received(&mapped, "sid-notify", 1).await, [event.id]);
    drop_all(&t).await;
}

/// Two owners starting at once share the transition: every owed event is
/// work once, however the earlier consumer split between them.
#[tokio::test]
async fn test_owner_replicas_move_each_event_once() {
    let t = topology();
    seed_earlier(&t, Duration::from_secs(3600)).await;
    earlier_pull(&t, "old-notify").await;
    let mut ids = Vec::new();
    for _ in 0..6 {
        let event = Event::new("sid-test", event_types::USER_CREATED);
        publish_earlier(&t, &event).await;
        ids.push(event.id);
    }

    let (a, b) = (jetstream().await, jetstream().await);
    let (first, second) = tokio::join!(
        t.prepare(&a, TopologyRole::Own),
        t.prepare(&b, TopologyRole::Own)
    );
    first.expect("first owner replica");
    second.expect("second owner replica");

    let mut got = received(&t, "sid-notify", ids.len()).await;
    got.sort();
    ids.sort();
    assert_eq!(got, ids);
    drop_all(&t).await;
}

/// A publisher of the earlier version reaches no stream once the transition
/// fenced it: its publication fails, so its outbox keeps the event owed
/// instead of the archive swallowing it.
#[tokio::test]
async fn test_an_earlier_publisher_is_fenced() {
    let t = topology();
    seed_earlier(&t, Duration::from_secs(3600)).await;
    let kept = earlier_pull(&t, "kept").await;
    publish_earlier(&t, &Event::new("sid-test", event_types::USER_CREATED)).await;
    settle_earlier(&kept, 1).await;
    t.prepare(&jetstream().await, TopologyRole::Own)
        .await
        .unwrap();

    let subject = format!("{}.user.created.v1", root(&t));
    let published = jetstream()
        .await
        .publish(subject, "late".into())
        .await
        .unwrap()
        .await;
    assert!(
        published.is_err(),
        "an earlier publisher still reached a stream"
    );
    assert_eq!(
        earlier_messages(&t).await,
        1,
        "the archive took a publication"
    );
    drop_all(&t).await;
}

/// The archive goes once its own age limit emptied it; history never gets a
/// younger copy of an earlier event.
#[tokio::test]
async fn test_the_archive_goes_once_it_aged_out() {
    let t = topology();
    seed_earlier(&t, Duration::from_secs(2)).await;
    let old = earlier_pull(&t, "old-notify").await;
    publish_earlier(&t, &Event::new("sid-test", event_types::USER_CREATED)).await;
    settle_earlier(&old, 1).await;

    let js = jetstream().await;
    t.prepare(&js, TopologyRole::Own).await.unwrap();
    assert!(
        earlier_config(&t).await.is_some(),
        "history was dropped early"
    );
    assert_eq!(
        js.get_stream(t.history_stream())
            .await
            .unwrap()
            .info()
            .await
            .unwrap()
            .state
            .messages,
        0,
        "history got a younger copy"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;
    t.prepare(&js, TopologyRole::Own).await.unwrap();
    assert!(
        earlier_config(&t).await.is_none(),
        "the empty archive stayed"
    );
    drop_all(&t).await;
}

/// A process that only verifies leaves the earlier stream to the owner and
/// is not ready while it still holds the subjects.
#[tokio::test]
async fn test_a_verifier_waits_for_the_owner() {
    let t = topology();
    seed_earlier(&t, Duration::from_secs(3600)).await;
    let verify = NatsEventBus::connect(&nats_url(), t.clone(), TopologyRole::Verify).await;
    assert!(verify.is_err());
    assert_eq!(
        earlier_config(&t).await.unwrap().subjects,
        [format!("{}.>", root(&t))],
        "a verifier changed the earlier stream"
    );
    drop_all(&t).await;
}
