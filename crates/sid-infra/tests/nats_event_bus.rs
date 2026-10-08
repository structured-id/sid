// SPDX-License-Identifier: AGPL-3.0-only
//! NatsEventBus against the test NATS server (`SID_TEST_NATS_URL`, default
//! `nats://localhost:4399`). An unreachable server fails the test.

use async_nats::jetstream::{self, consumer};
use sid_core::models::event::Event;
use sid_infra::NatsEventBus;
use sid_plugin::event_bus::EventBus;

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
