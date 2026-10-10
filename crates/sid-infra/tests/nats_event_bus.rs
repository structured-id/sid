// SPDX-License-Identifier: AGPL-3.0-only
//! NatsEventBus against the test NATS server (`SID_TEST_NATS_URL`, default
//! `nats://localhost:4399`). An unreachable server fails the test.

use async_nats::jetstream::{self, consumer};
use sid_core::models::event::Event;
use sid_infra::NatsEventBus;
use sid_plugin::event_bus::{Delivery, DurableConsumer, EventBus, Settlement};
use std::time::Duration;
use tokio::sync::mpsc;

fn nats_url() -> String {
    std::env::var("SID_TEST_NATS_URL").unwrap_or_else(|_| "nats://localhost:4399".to_string())
}

/// Messages the `SID_EVENTS` stream holds on `subject`.
async fn stored_on(subject: &str) -> u64 {
    let client = async_nats::connect(nats_url()).await.unwrap();
    let stream = jetstream::new(client)
        .get_stream("SID_EVENTS")
        .await
        .unwrap();
    let mut probe = stream
        .create_consumer(consumer::pull::Config {
            filter_subject: subject.to_string(),
            deliver_policy: consumer::DeliverPolicy::All,
            ..Default::default()
        })
        .await
        .unwrap();
    probe.info().await.unwrap().num_pending
}

/// Publishing the same event again (a relay retry after a lost PubAck) stores
/// it once: the event id is the JetStream message id.
#[tokio::test]
async fn test_republished_event_is_stored_once() {
    let bus = NatsEventBus::connect(&nats_url())
        .await
        .expect("test NATS unreachable; start docker-compose.test.yml");
    let subject = format!("sid.test.dedup_{}.v1", uuid::Uuid::now_v7().simple());
    let event = Event::new("sid-test", &subject);

    bus.publish(event.clone()).await.unwrap();
    bus.publish(event.clone()).await.unwrap();
    assert_eq!(
        stored_on(&subject).await,
        1,
        "a republished event was stored twice"
    );

    bus.publish(Event::new("sid-test", &subject)).await.unwrap();
    assert_eq!(stored_on(&subject).await, 2, "a distinct event was dropped");
}

/// The next delivery, within a bound a redelivery fits in.
async fn next(deliveries: &mut mpsc::Receiver<Delivery>) -> Delivery {
    tokio::time::timeout(Duration::from_secs(20), deliveries.recv())
        .await
        .expect("a delivery in time")
        .expect("the consumer is open")
}

/// A durable consumer gets what was published before it existed, keeps every
/// event until it is settled done: one settled for retry comes again, one
/// dropped unsettled goes to the next consumer of the same name (a restart),
/// and one settled done never comes back.
#[tokio::test]
async fn test_durable_consumer_keeps_events_until_settled_done() {
    let bus = NatsEventBus::connect(&nats_url())
        .await
        .expect("test NATS unreachable; start docker-compose.test.yml");
    let tag = uuid::Uuid::now_v7().simple().to_string();
    let subject = format!("sid.test.durable_{tag}.v1");
    let consumer = DurableConsumer {
        name: format!("test-durable-{tag}"),
        event_types: vec![subject.clone()],
    };
    let first = Event::new("sid-test", &subject);
    let second = Event::new("sid-test", &subject);
    bus.publish(first.clone()).await.unwrap();
    bus.publish(second.clone()).await.unwrap();

    let mut deliveries = bus.consume(consumer.clone()).await.unwrap();
    let delivered = next(&mut deliveries).await;
    assert_eq!(
        delivered.event.id, first.id,
        "published before the consumer"
    );
    delivered.settle(Settlement::Retry(Duration::from_millis(200)));
    let delivered = next(&mut deliveries).await;
    assert_eq!(delivered.event.id, second.id);
    delivered.settle(Settlement::Done);
    let delivered = next(&mut deliveries).await;
    assert_eq!(delivered.event.id, first.id, "the retried event came again");
    delivered.settle(Settlement::Done);

    let third = Event::new("sid-test", &subject);
    bus.publish(third.clone()).await.unwrap();
    let unsettled = next(&mut deliveries).await;
    assert_eq!(unsettled.event.id, third.id);
    drop(unsettled);
    drop(deliveries);

    let mut restarted = bus.consume(consumer).await.unwrap();
    let delivered = next(&mut restarted).await;
    assert_eq!(delivered.event.id, third.id, "the unsettled event survived");
    delivered.settle(Settlement::Done);
    assert!(
        tokio::time::timeout(Duration::from_secs(3), restarted.recv())
            .await
            .is_err(),
        "an event settled done was delivered again"
    );
}
