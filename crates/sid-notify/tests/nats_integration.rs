// SPDX-License-Identifier: AGPL-3.0-only
//! sid-notify against the test stack's NATS (`SID_TEST_NATS_URL`, default
//! `nats://localhost:4399`) and PostgreSQL (`SID_NOTIFY_TEST_DATABASE_URL`,
//! default database `sid_notify_test` on port 54399). An unreachable server
//! fails the test.

use async_nats::jetstream::{self, consumer};
use futures::StreamExt;
use sid_core::models::WorkState;
use sid_core::models::event::Event;
use sid_notify::channels::smtp::SmtpConfig;
use sid_notify::delivery::route_job_id as route_job;
use sid_notify::delivery::{self, REDELIVER_AFTER};
use sid_notify::{NotifyConfig, NotifyServer};
use sid_plugin::WorkStore;
use sid_storage::PgWorkStore;
use std::time::Duration;

fn nats_url() -> String {
    std::env::var("SID_TEST_NATS_URL").unwrap_or_else(|_| "nats://localhost:4399".into())
}

fn database_url() -> String {
    std::env::var("SID_NOTIFY_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid_notify_test".into())
}

async fn job_store() -> PgWorkStore {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("test PostgreSQL unreachable; start docker-compose.test.yml");
    let store = PgWorkStore::new(pool);
    store.ensure_schema().await.unwrap();
    store
}

/// An event is acknowledged only once its routing job is stored. Refused
/// (the job store is full), it stays with the broker and comes back; the
/// redelivered copy is then accepted and acknowledged.
#[tokio::test]
async fn test_event_is_acknowledged_only_after_its_job_is_stored() {
    let store = job_store().await;
    // Creates the events stream as SID services configure it.
    sid_infra::NatsEventBus::connect(&nats_url())
        .await
        .expect("test NATS unreachable; start docker-compose.test.yml");
    let js = jetstream::new(async_nats::connect(nats_url()).await.unwrap());
    let subject = format!("sid.test.notify_{}.v1", uuid::Uuid::now_v7().simple());
    let stream = js.get_stream("SID_EVENTS").await.unwrap();
    let mut consumer = stream
        .create_consumer(consumer::push::Config {
            filter_subject: subject.clone(),
            deliver_policy: consumer::DeliverPolicy::All,
            ack_policy: consumer::AckPolicy::Explicit,
            ack_wait: Duration::from_secs(60),
            deliver_subject: format!("_INBOX.{}", uuid::Uuid::now_v7().simple()),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut messages = consumer.messages().await.unwrap();

    let event = Event::new("sid-test", &subject);
    js.publish(subject.clone(), serde_json::to_vec(&event).unwrap().into())
        .await
        .unwrap()
        .await
        .unwrap();

    let first = tokio::time::timeout(Duration::from_secs(5), messages.next())
        .await
        .expect("event not delivered")
        .unwrap()
        .unwrap();
    // Capacity 0: nothing can be accepted.
    delivery::accept_message(&store, 0, &first).await;
    assert!(
        store.get_work(route_job(&event)).await.unwrap().is_none(),
        "a refused event was stored"
    );

    let second = tokio::time::timeout(REDELIVER_AFTER * 3, messages.next())
        .await
        .expect("a refused event was acknowledged: the broker never redelivered it")
        .unwrap()
        .unwrap();
    assert_eq!(second.info().unwrap().delivered, 2);
    delivery::accept_message(&store, 1_000, &second).await;

    let job = store
        .get_work(route_job(&event))
        .await
        .unwrap()
        .expect("an accepted event has no routing job");
    assert_eq!(job.state, WorkState::Pending);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        consumer.info().await.unwrap().num_ack_pending,
        0,
        "an accepted event was left unacknowledged"
    );
}

/// The service starts with its database and the configured channels.
#[tokio::test]
async fn test_notify_server_init() {
    let config = NotifyConfig {
        nats_url: nats_url(),
        grpc_bind: "127.0.0.1:0".parse().unwrap(),
        queue_group: "sid-notify-test".into(),
        smtp: SmtpConfig::default(),
        smtp_enabled: true,
        webhook_enabled: false,
        vapid: None,
        database_url: database_url(),
        job_capacity: sid_notify::config::DEFAULT_JOB_CAPACITY,
        identity_grpc_address: None,
        jwt_public_key_path: Some(format!(
            "{}/../sid-authn/tests/fixtures/test_ed25519_public.pem",
            env!("CARGO_MANIFEST_DIR")
        )),
        jwt_issuer: "https://sid.example.com".into(),
    };

    let server = NotifyServer::new(config).await.unwrap();
    let channels = server.dispatcher().channel_ids();
    assert!(channels.contains(&"email".to_string()));
    assert!(!channels.contains(&"webhook".to_string()));
    assert!(!channels.contains(&"web_push".to_string()));
}
