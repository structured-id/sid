// SPDX-License-Identifier: AGPL-3.0-only
//! sid-notify against the test stack's NATS (`SID_TEST_NATS_URL`, default
//! `nats://localhost:4399`) and PostgreSQL (`SID_NOTIFY_TEST_DATABASE_URL`,
//! default database `sid_notify_test` on port 54399). An unreachable server
//! fails the test. Each test runs on an event topology of its own.

use async_nats::jetstream;
use sid_core::models::WorkState;
use sid_core::models::event::{Event, WorkRecipient, event_types};
use sid_infra::{NatsEventBus, Topology, TopologyRole};
use sid_notify::channels::smtp::SmtpConfig;
use sid_notify::delivery::{self, route_job_id};
use sid_notify::{NotifyConfig, NotifyServer};
use sid_plugin::WorkStore;
use sid_plugin::event_bus::EventBus;
use sid_storage::PgWorkStore;
use std::sync::Arc;
use std::time::Duration;

fn nats_url() -> String {
    std::env::var("SID_TEST_NATS_URL").unwrap_or_else(|_| "nats://localhost:4399".into())
}

fn database_url() -> String {
    std::env::var("SID_NOTIFY_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid_notify_test".into())
}

async fn job_store() -> Arc<PgWorkStore> {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("test PostgreSQL unreachable; start docker-compose.test.yml");
    let store = PgWorkStore::new(pool);
    store.ensure_schema().await.unwrap();
    Arc::new(store)
}

/// A topology no other test uses, prepared by its owner.
async fn topology() -> (Topology, NatsEventBus) {
    let mut t = Topology::with_root(format!("n{}", uuid::Uuid::now_v7().simple())).unwrap();
    // The server reserves a work stream's byte bound, and tests run at once.
    t.work_max_bytes = 8 << 20;
    let bus = NatsEventBus::connect(&nats_url(), t.clone(), TopologyRole::Own)
        .await
        .expect("test NATS unreachable; start docker-compose.test.yml");
    (t, bus)
}

/// Messages stream `name` holds.
async fn stored(name: &str) -> u64 {
    jetstream::new(async_nats::connect(nats_url()).await.unwrap())
        .get_stream(name)
        .await
        .unwrap()
        .info()
        .await
        .unwrap()
        .state
        .messages
}

async fn drop_topology(t: &Topology) {
    let js = jetstream::new(async_nats::connect(nats_url()).await.unwrap());
    for name in [t.history_stream(), t.work_stream()] {
        if let Err(e) = js.delete_stream(&name).await {
            eprintln!("delete {name}: {e}");
        }
    }
}

fn receiver() -> WorkRecipient {
    WorkRecipient::new("sid-notify").unwrap()
}

/// A fact owed to notify, as a producer's relay hands it over.
async fn owe(bus: &NatsEventBus, event: &Event) {
    let notify = receiver();
    bus.deliver(&notify, event.delivery_id(&notify), event)
        .await
        .unwrap();
}

/// A notify consumer over `bus` storing into `store` with `capacity`, until
/// the returned sender is dropped or fired.
fn run_notify(
    bus: Arc<NatsEventBus>,
    store: Arc<PgWorkStore>,
    capacity: u64,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let deliveries = delivery::open_work(bus.as_ref(), receiver()).await.unwrap();
        delivery::accept_work(deliveries, store.as_ref(), capacity, || {}, async move {
            let _ = stopped.await;
        })
        .await;
    });
    (stop, handle)
}

/// Whether `event`'s routing job appears within `wait`.
async fn accepted(store: &PgWorkStore, event: &Event, wait: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        if store.get_work(route_job_id(event)).await.unwrap().is_some() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Facts owed to notify while it was not running, longer than the history
/// keeps them, are accepted when it starts: the work stream, not history,
/// holds them, and each is settled once its routing job is stored.
#[tokio::test]
async fn test_work_owed_while_notify_was_down_is_accepted() {
    let store = job_store().await;
    let (mut t, _) = topology().await;
    drop_topology(&t).await;
    t.history_max_age = Duration::from_secs(1);
    let bus = Arc::new(
        NatsEventBus::connect(&nats_url(), t.clone(), TopologyRole::Own)
            .await
            .unwrap(),
    );
    let event = Event::new("sid-test", event_types::SECURITY_BRUTE_FORCE);
    bus.publish(event.clone()).await.unwrap();
    owe(&bus, &event).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        stored(&t.history_stream()).await,
        0,
        "history outlived its age"
    );

    let (stop, handle) = run_notify(bus.clone(), store.clone(), 1_000);
    assert!(
        accepted(&store, &event, Duration::from_secs(10)).await,
        "owed work was lost while notify was down"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        stored(&t.work_stream()).await,
        0,
        "accepted work was not settled"
    );
    stop.send(()).unwrap();
    handle.await.unwrap();
    drop_topology(&t).await;
}

/// An event notify cannot accept (its job store full) stays with the bus
/// and is accepted once there is room.
#[tokio::test]
async fn test_refused_event_stays_owed() {
    let store = job_store().await;
    let (t, bus) = topology().await;
    let bus = Arc::new(bus);
    let event = Event::new("sid-test", event_types::SESSION_CREATED);
    owe(&bus, &event).await;

    let (stop, handle) = run_notify(bus.clone(), store.clone(), 0);
    assert!(
        !accepted(&store, &event, Duration::from_secs(2)).await,
        "a refused event was stored"
    );
    stop.send(()).unwrap();
    handle.await.unwrap();
    assert_eq!(
        stored(&t.work_stream()).await,
        1,
        "a refused event was settled"
    );

    let (stop, handle) = run_notify(bus.clone(), store.clone(), 1_000);
    assert!(
        accepted(&store, &event, Duration::from_secs(15)).await,
        "the refused event never came back"
    );
    stop.send(()).unwrap();
    handle.await.unwrap();
    drop_topology(&t).await;
}

/// A crash after the routing job was stored but before the event was
/// settled delivers it again; it is stored once and settled then.
#[tokio::test]
async fn test_redelivery_after_a_stored_job_is_stored_once() {
    let store = job_store().await;
    let (t, bus) = topology().await;
    let bus = Arc::new(bus);
    let event = Event::new("sid-test", event_types::PRINCIPAL_CONTESTED);
    delivery::accept_event(store.as_ref(), &event, 1_000)
        .await
        .unwrap();
    owe(&bus, &event).await;

    let (stop, handle) = run_notify(bus.clone(), store.clone(), 1_000);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while stored(&t.work_stream()).await > 0 {
        assert!(tokio::time::Instant::now() < deadline, "never settled");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    stop.send(()).unwrap();
    handle.await.unwrap();
    let job = store.get_work(route_job_id(&event)).await.unwrap().unwrap();
    assert_eq!(job.state, WorkState::Pending);
    assert_eq!(job.attempts, 0, "the stored job was replaced");
    drop_topology(&t).await;
}

/// Two notify replicas share the receiver's work: every event is accepted
/// exactly once between them.
#[tokio::test]
async fn test_replicas_share_the_work() {
    let store = job_store().await;
    let (t, bus) = topology().await;
    let bus = Arc::new(bus);
    let replica = Arc::new(
        NatsEventBus::connect(&nats_url(), t.clone(), TopologyRole::Verify)
            .await
            .unwrap(),
    );
    let events: Vec<Event> = (0..6)
        .map(|_| Event::new("sid-test", event_types::USER_CREATED))
        .collect();
    let (stop_a, a) = run_notify(bus.clone(), store.clone(), 1_000);
    let (stop_b, b) = run_notify(replica, store.clone(), 1_000);
    for event in &events {
        owe(&bus, event).await;
    }
    for event in &events {
        assert!(accepted(&store, event, Duration::from_secs(10)).await);
    }
    stop_a.send(()).unwrap();
    stop_b.send(()).unwrap();
    a.await.unwrap();
    b.await.unwrap();
    assert_eq!(stored(&t.work_stream()).await, 0);
    drop_topology(&t).await;
}

/// History feeds no notification: a fact only published, or only
/// replayed, owes notify nothing.
#[tokio::test]
async fn test_history_alone_is_not_work() {
    let store = job_store().await;
    let (t, bus) = topology().await;
    let bus = Arc::new(bus);
    let event = Event::new("sid-test", event_types::USER_CREATED);
    bus.publish(event.clone()).await.unwrap();
    let _replayed = bus
        .replay(
            chrono::Utc::now() - chrono::Duration::seconds(5),
            None,
            Default::default(),
        )
        .await
        .unwrap();
    let (stop, handle) = run_notify(bus.clone(), store.clone(), 1_000);
    assert!(
        !accepted(&store, &event, Duration::from_secs(2)).await,
        "history became notification work"
    );
    stop.send(()).unwrap();
    handle.await.unwrap();
    drop_topology(&t).await;
}

/// A standalone notify needs no sid-server: named the topology owner it
/// prepares the streams itself and takes the work producers hand over;
/// without an owner having prepared them it is not ready rather than
/// creating them unasked.
#[tokio::test]
async fn test_standalone_notify_without_sid_server() {
    let store = job_store().await;
    let mut t = Topology::with_root(format!("s{}", uuid::Uuid::now_v7().simple())).unwrap();
    t.work_max_bytes = 8 << 20;
    let unprepared = NatsEventBus::connect(&nats_url(), t.clone(), TopologyRole::Verify).await;
    assert!(unprepared.is_err(), "a verifier ran on a missing topology");

    let notify = Arc::new(
        NatsEventBus::connect(&nats_url(), t.clone(), TopologyRole::Own)
            .await
            .expect("notify owns the topology"),
    );
    let producer = NatsEventBus::connect(&nats_url(), t.clone(), TopologyRole::Verify)
        .await
        .expect("a producer verifies notify's topology");
    let event = Event::new("sid-test", event_types::SESSION_REVOKED);
    owe(&producer, &event).await;
    let (stop, handle) = run_notify(notify, store.clone(), 1_000);
    assert!(accepted(&store, &event, Duration::from_secs(10)).await);
    stop.send(()).unwrap();
    handle.await.unwrap();
    drop_topology(&t).await;
}

/// The service starts with its database and the configured channels.
#[tokio::test]
async fn test_notify_server_init() {
    let config = NotifyConfig {
        nats_url: nats_url(),
        grpc_bind: "127.0.0.1:0".parse().unwrap(),
        receiver: receiver(),
        event_receivers: Vec::new(),
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
