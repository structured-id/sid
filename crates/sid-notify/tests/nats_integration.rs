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

/// A job store whose database cannot be reached: every write fails.
async fn unreachable_store() -> Arc<PgWorkStore> {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("test PostgreSQL unreachable; start docker-compose.test.yml");
    pool.close().await;
    Arc::new(PgWorkStore::new(pool))
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

/// A notify consumer over `bus` storing into `store`, until the returned
/// sender is dropped or fired.
fn run_notify(
    bus: Arc<NatsEventBus>,
    store: Arc<PgWorkStore>,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let deliveries = delivery::open_work(bus.as_ref(), receiver()).await.unwrap();
        delivery::accept_work(deliveries, store.as_ref(), || {}, async move {
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

    let (stop, handle) = run_notify(bus.clone(), store.clone());
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

/// An event notify cannot accept (its job store unreachable) stays with the
/// bus and is accepted once the store answers again.
#[tokio::test]
async fn test_refused_event_stays_owed() {
    let store = job_store().await;
    let (t, bus) = topology().await;
    let bus = Arc::new(bus);
    let event = Event::new("sid-test", event_types::SESSION_CREATED);
    owe(&bus, &event).await;

    let (stop, handle) = run_notify(bus.clone(), unreachable_store().await);
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

    let (stop, handle) = run_notify(bus.clone(), store.clone());
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
    delivery::accept_event(store.as_ref(), &event)
        .await
        .unwrap();
    owe(&bus, &event).await;

    let (stop, handle) = run_notify(bus.clone(), store.clone());
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

/// A relay retrying the same delivery (same event, same delivery id) within
/// the broker's duplicate window is stored once; retrying it after the window
/// has passed stores it again. Notify gets both copies, accepts the fact into
/// one routing job and settles both. The test's own work stream is given a
/// one-second window so the real window passes during the test.
#[tokio::test]
async fn test_work_republished_beyond_the_duplicate_window_is_accepted_once() {
    let store = job_store().await;
    let (t, bus) = topology().await;
    let bus = Arc::new(bus);
    let js = jetstream::new(async_nats::connect(nats_url()).await.unwrap());
    let mut config = js
        .get_stream(t.work_stream())
        .await
        .unwrap()
        .info()
        .await
        .unwrap()
        .config
        .clone();
    config.duplicate_window = Duration::from_secs(1);
    js.update_stream(config).await.unwrap();

    let event = Event::new("sid-test", event_types::SECURITY_SUSPICIOUS_LOGIN);
    owe(&bus, &event).await;
    owe(&bus, &event).await;
    assert_eq!(
        stored(&t.work_stream()).await,
        1,
        "a retry within the window was stored again"
    );
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    owe(&bus, &event).await;
    assert_eq!(
        stored(&t.work_stream()).await,
        2,
        "a retry after the window was not stored again"
    );

    let (stop, handle) = run_notify(bus.clone(), store.clone());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while stored(&t.work_stream()).await > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a copy was never settled"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    stop.send(()).unwrap();
    handle.await.unwrap();
    let job = store.get_work(route_job_id(&event)).await.unwrap().unwrap();
    assert_eq!(job.state, WorkState::Pending);
    assert_eq!(job.attempts, 0, "the second copy replaced the routing job");
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
    let (stop_a, a) = run_notify(bus.clone(), store.clone());
    let (stop_b, b) = run_notify(replica, store.clone());
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
            jiff::Timestamp::now() - jiff::SignedDuration::from_secs(5),
            None,
            Default::default(),
        )
        .await
        .unwrap();
    let (stop, handle) = run_notify(bus.clone(), store.clone());
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
    let (stop, handle) = run_notify(notify, store.clone());
    assert!(accepted(&store, &event, Duration::from_secs(10)).await);
    stop.send(()).unwrap();
    handle.await.unwrap();
    drop_topology(&t).await;
}

/// A notifier bound to the identity and the platform source takes the work
/// owed to it on each into its one job store, under the same receiver, and
/// settles it there only: a trial activation owed on the platform bus is
/// accepted although the identity bus never carries it.
#[tokio::test]
async fn test_both_sources_are_accepted() {
    let store = job_store().await;
    let (identity, identity_bus) = topology().await;
    let platform = identity
        .clone()
        .for_family(sid_core::models::event::EventFamily::Platform);
    let platform_bus = NatsEventBus::connect(&nats_url(), platform.clone(), TopologyRole::Own)
        .await
        .expect("test NATS unreachable; start docker-compose.test.yml");
    let session = Event::new("sid-test", event_types::SESSION_REVOKED);
    let trial = Event::new("sid-ee-saas", event_types::ORG_TRIAL_ACTIVATED);
    owe(&identity_bus, &session).await;
    owe(&platform_bus, &trial).await;

    let identity_bus = Arc::new(identity_bus);
    let platform_bus = Arc::new(platform_bus);
    let (stop_identity, identity_run) = run_notify(identity_bus, store.clone());
    let (stop_platform, platform_run) = run_notify(platform_bus, store.clone());
    assert!(accepted(&store, &session, Duration::from_secs(10)).await);
    assert!(accepted(&store, &trial, Duration::from_secs(10)).await);
    stop_identity.send(()).unwrap();
    stop_platform.send(()).unwrap();
    identity_run.await.unwrap();
    platform_run.await.unwrap();

    // Each source's work was settled once accepted.
    assert_eq!(stored(&identity.work_stream()).await, 0);
    assert_eq!(stored(&platform.work_stream()).await, 0);
    drop_topology(&identity).await;
    drop_topology(&platform).await;
}

/// A job store in a schema of its own, so a runner claiming from it takes
/// none of the other tests' work; and the schema, to drop afterwards.
async fn isolated_store() -> (Arc<PgWorkStore>, String) {
    let schema = format!("w{}", uuid::Uuid::now_v7().simple());
    let admin = sqlx::PgPool::connect(&database_url())
        .await
        .expect("test PostgreSQL unreachable; start docker-compose.test.yml");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .unwrap();
    let options: sqlx::postgres::PgConnectOptions = database_url().parse().unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_with(options.options([("search_path", schema.as_str())]))
        .await
        .unwrap();
    let store = PgWorkStore::new(pool);
    store.ensure_schema().await.unwrap();
    (Arc::new(store), schema)
}

async fn drop_schema(schema: &str) {
    let admin = sqlx::PgPool::connect(&database_url()).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .unwrap();
}

/// A runner over `store` with `handlers`: short leases and scans, so an
/// abandoned claim lapses within the test.
fn runner(
    store: &Arc<PgWorkStore>,
    worker: &str,
    handlers: Vec<Arc<dyn sid_authn::work_runner::WorkHandler>>,
) -> sid_authn::work_runner::WorkRunner {
    sid_authn::work_runner::WorkRunner::new(
        store.clone(),
        worker,
        handlers,
        sid_authn::work_runner::RunnerConfig {
            concurrency: 4,
            lease: Duration::from_secs(2),
            scan_interval: Duration::from_millis(100),
        },
    )
    .unwrap()
}

/// The stored record of `id` once `done` holds for it, within `wait`.
async fn record_when(
    store: &PgWorkStore,
    id: sid_core::models::WorkId,
    wait: Duration,
    done: impl Fn(&sid_core::models::WorkRecord) -> bool,
) -> sid_core::models::WorkRecord {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        if let Some(record) = store.get_work(id).await.unwrap()
            && done(&record)
        {
            return record;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "not reached: {:?}",
            store.get_work(id).await.unwrap()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The work of `kind` `store` holds.
async fn count_kind(store: &PgWorkStore, kind: &str) -> usize {
    store
        .export_work()
        .await
        .unwrap()
        .iter()
        .filter(|w| w.record.kind.as_str() == kind)
        .count()
}

/// A producer's bus whose history publication never returns: a producer
/// stopped there has owed and handed over the addressed work, not the
/// history.
struct CutBeforeHistory(Arc<NatsEventBus>);

#[async_trait::async_trait]
impl EventBus for CutBeforeHistory {
    async fn publish(&self, _event: Event) -> sid_plugin::event_bus::EventBusResult<()> {
        std::future::pending().await
    }

    async fn deliver(
        &self,
        recipient: &WorkRecipient,
        delivery: sid_core::models::WorkId,
        event: &Event,
    ) -> sid_plugin::event_bus::EventBusResult<()> {
        self.0.deliver(recipient, delivery, event).await
    }

    async fn subscribe(
        &self,
        filter: sid_core::models::event::EventFilter,
    ) -> sid_plugin::event_bus::EventBusResult<tokio::sync::mpsc::Receiver<Event>> {
        self.0.subscribe(filter).await
    }

    async fn health_check(&self) -> sid_plugin::event_bus::EventBusResult<()> {
        self.0.health_check().await
    }
}

/// The producer's relay, fan-out and delivery handlers over `store`, with
/// the history published on `history` and the work handed to `work`.
fn producer_handlers(
    store: &Arc<PgWorkStore>,
    history: Arc<dyn EventBus>,
    work: Arc<dyn EventBus>,
) -> Vec<Arc<dyn sid_authn::work_runner::WorkHandler>> {
    use sid_authn::event_relay::{EventDeliveryHandler, EventFanoutHandler, EventRelayHandler};
    let owed: Arc<dyn WorkStore> = store.clone();
    vec![
        Arc::new(EventRelayHandler::new(
            owed.clone(),
            vec![sid_core::models::event::RequiredReceiver {
                recipient: receiver(),
                event_types: Vec::new(),
            }],
        )),
        Arc::new(EventFanoutHandler::new(history, owed)),
        Arc::new(EventDeliveryHandler::new(work)),
    ]
}

/// A producer cut between handing a fact's addressed work to the broker and
/// publishing its history (the process gone, its claim left to lapse)
/// resumes the same obligations from PostgreSQL after a restart: the
/// history is published once, the addressed work is the one already handed
/// over (not owed or delivered again), and notify accepts the fact once.
#[tokio::test]
async fn test_a_producer_cut_before_history_resumes_the_same_obligations() {
    let (store, schema) = isolated_store().await;
    let (t, bus) = topology().await;
    let bus = Arc::new(bus);
    let event = Event::new("sid-test", event_types::SECURITY_BRUTE_FORCE);
    store.enqueue_work(&event.relay()).await.unwrap();
    let fanout = event.fanout(&[receiver()]).id;
    let delivery = event.delivery_id(&receiver());

    // The first producer hands the work over and hangs on the history.
    let cut = runner(
        &store,
        "producer-1",
        producer_handlers(&store, Arc::new(CutBeforeHistory(bus.clone())), bus.clone()),
    );
    let crashed = tokio::spawn(cut.run(std::future::pending()));
    record_when(&store, delivery, Duration::from_secs(10), |r| {
        r.state == WorkState::Completed
    })
    .await;
    assert_eq!(stored(&t.work_stream()).await, 1);
    assert_eq!(
        store.get_work(fanout).await.unwrap().unwrap().state,
        WorkState::Claimed
    );
    // The process dies: its attempt and its claim are abandoned as they are.
    crashed.abort();
    let _ = crashed.await;
    assert_eq!(stored(&t.history_stream()).await, 0);

    // A restarted producer takes the lapsed plan over.
    let resumed = runner(
        &store,
        "producer-2",
        producer_handlers(&store, bus.clone(), bus.clone()),
    );
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(resumed.run(async move {
        let _ = stopped.await;
    }));
    let plan = record_when(&store, fanout, Duration::from_secs(15), |r| {
        r.state == WorkState::Completed
    })
    .await;
    stop.send(()).unwrap();
    running.await.unwrap();
    assert_eq!(plan.attempts, 2, "the plan ran other than once more");
    assert_eq!(
        stored(&t.history_stream()).await,
        1,
        "history not published once"
    );
    let handed = store.get_work(delivery).await.unwrap().unwrap();
    assert_eq!(handed.attempts, 1, "the handed-over work was handed again");
    assert_eq!(
        count_kind(&store, sid_core::models::EVENT_DELIVERY_KIND).await,
        1
    );
    assert_eq!(
        store
            .get_work(event.relay_id())
            .await
            .unwrap()
            .unwrap()
            .attempts,
        1,
        "the relay ran again"
    );
    assert_eq!(
        stored(&t.work_stream()).await,
        1,
        "the work was handed twice"
    );

    // Notify accepts the fact once and settles it.
    let (stop, handle) = run_notify(bus.clone(), store.clone());
    assert!(accepted(&store, &event, Duration::from_secs(10)).await);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while stored(&t.work_stream()).await > 0 {
        assert!(tokio::time::Instant::now() < deadline, "never settled");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    stop.send(()).unwrap();
    handle.await.unwrap();
    let route = store.get_work(route_job_id(&event)).await.unwrap().unwrap();
    assert_eq!(route.attempts, 0, "the fact was accepted again");
    drop_topology(&t).await;
    drop_schema(&schema).await;
}

/// The recipient source of a routed fact whose subject is gone: routing
/// ends permanently, as a removed Profile ends it.
struct Gone;

#[async_trait::async_trait]
impl sid_notify::recipient::RecipientSource for Gone {
    async fn resolve(
        &self,
        _event: &Event,
    ) -> Result<sid_plugin::notification::Recipient, sid_notify::recipient::ResolveError> {
        Err(sid_notify::recipient::ResolveError::ProfileGone(
            "subject removed".into(),
        ))
    }
}

/// Notify's real routing and plan handlers, over a source whose subjects
/// are gone.
fn routing_handlers() -> Vec<Arc<dyn sid_authn::work_runner::WorkHandler>> {
    vec![
        Arc::new(delivery::RouteHandler::new(
            sid_notify::routing::RoutingTable::default_ce_rules(),
            Arc::new(Gone),
        )),
        Arc::new(delivery::PlanHandler::new()),
    ]
}

/// Delivery after a durable handoff that ends terminally: a fact notify
/// accepted from JetStream whose routing fails for good is failed with its
/// dead-letter alert owed in the same commit, and a later copy of the same
/// fact (republished beyond the broker's duplicate window) is settled
/// without reviving it or owing a second alert. The same holds for a fact
/// whose routing claim lapsed on its last attempt (its worker gone): the
/// next worker ends it with its own alert, and a later copy does not revive
/// it. Bug prevented: the store failed such work by itself and its
/// dead-letter alert was never owed.
#[tokio::test]
async fn test_a_terminal_outcome_after_handoff_is_not_revived() {
    let (store, schema) = isolated_store().await;
    let (t, bus) = topology().await;
    let bus = Arc::new(bus);
    let js = jetstream::new(async_nats::connect(nats_url()).await.unwrap());
    let mut config = js
        .get_stream(t.work_stream())
        .await
        .unwrap()
        .info()
        .await
        .unwrap()
        .config
        .clone();
    config.duplicate_window = Duration::from_secs(1);
    js.update_stream(config).await.unwrap();

    let failed = Event::new("sid-test", event_types::SECURITY_BRUTE_FORCE);
    let abandoned = Event::new("sid-test", event_types::SECURITY_SUSPICIOUS_LOGIN);

    // The first fact is accepted and routed by the real handler: its
    // subject is gone, so its routing fails for good.
    owe(&bus, &failed).await;
    let (stop, handle) = run_notify(bus.clone(), store.clone());
    assert!(accepted(&store, &failed, Duration::from_secs(10)).await);
    stop.send(()).unwrap();
    handle.await.unwrap();
    let notifier = runner(&store, "notify", routing_handlers());
    let (stop_runner, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(notifier.run(async move {
        let _ = stopped.await;
    }));
    let dead = record_when(
        &store,
        route_job_id(&failed),
        Duration::from_secs(15),
        |r| r.state == WorkState::Failed,
    )
    .await;
    stop_runner.send(()).unwrap();
    running.await.unwrap();
    let alerts = count_kind(&store, sid_core::models::EVENT_RELAY_KIND).await;
    assert_eq!(alerts, 1, "the permanent failure owed other than one alert");

    // The second fact is accepted; its routing is claimed on its last
    // attempt by a worker that never finishes, so its claim lapses.
    owe(&bus, &abandoned).await;
    let (stop, handle) = run_notify(bus.clone(), store.clone());
    assert!(accepted(&store, &abandoned, Duration::from_secs(10)).await);
    stop.send(()).unwrap();
    handle.await.unwrap();
    let route_kind = sid_core::models::WorkKind::new(delivery::ROUTE).unwrap();
    for attempt in 1.. {
        let claimed = store
            .claim_work(
                std::slice::from_ref(&route_kind),
                "lost-worker",
                10,
                Duration::from_millis(200),
            )
            .await
            .unwrap();
        let Some(work) = claimed
            .into_iter()
            .find(|w| w.id == route_job_id(&abandoned))
        else {
            panic!("the abandoned fact's routing was not claimed");
        };
        if work.attempt >= work.max_attempts {
            break;
        }
        assert!(attempt < 100, "never reached the last attempt");
        store
            .fail_work(
                work.id,
                work.generation,
                &sid_core::models::WorkFailure {
                    error: "worker restarted".into(),
                    ambiguous: false,
                    retry_at: Some(jiff::Timestamp::now()),
                    on_dead: None,
                },
            )
            .await
            .unwrap();
    }
    // The next routing worker ends the lapsed last attempt.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let notifier = runner(&store, "notify-restarted", routing_handlers());
    let (stop_runner, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(notifier.run(async move {
        let _ = stopped.await;
    }));
    let lapsed = record_when(
        &store,
        route_job_id(&abandoned),
        Duration::from_secs(15),
        |r| r.state == WorkState::Failed,
    )
    .await;
    stop_runner.send(()).unwrap();
    running.await.unwrap();
    let alerts = count_kind(&store, sid_core::models::EVENT_RELAY_KIND).await;
    assert_eq!(alerts, 2, "a terminal failure lacks its dead-letter alert");

    // Later copies of both facts, beyond the broker's duplicate window.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    owe(&bus, &failed).await;
    owe(&bus, &abandoned).await;
    assert_eq!(
        stored(&t.work_stream()).await,
        2,
        "the copies were not handed over"
    );
    let (stop, handle) = run_notify(bus.clone(), store.clone());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while stored(&t.work_stream()).await > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a copy was never settled"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    stop.send(()).unwrap();
    handle.await.unwrap();

    // A terminal routing stays as it ended: no revival, no second alert.
    let notifier = runner(&store, "notify-again", routing_handlers());
    let (stop_runner, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(notifier.run(async move {
        let _ = stopped.await;
    }));
    tokio::time::sleep(Duration::from_secs(1)).await;
    stop_runner.send(()).unwrap();
    running.await.unwrap();
    for (before, event) in [(&dead, &failed), (&lapsed, &abandoned)] {
        let after = store.get_work(route_job_id(event)).await.unwrap().unwrap();
        assert_eq!(after.state, WorkState::Failed, "revived: {after:?}");
        assert_eq!(
            after.attempts, before.attempts,
            "attempted again: {after:?}"
        );
        assert_eq!(
            after.generation, before.generation,
            "claimed again: {after:?}"
        );
    }
    assert_eq!(
        count_kind(&store, sid_core::models::EVENT_RELAY_KIND).await,
        alerts,
        "a second alert was owed"
    );
    drop_topology(&t).await;
    drop_schema(&schema).await;
}

/// The service starts with its database and the configured channels.
#[tokio::test]
async fn test_notify_server_init() {
    let issuer = sid_test_issuer::TestIssuer::start(sid_test_issuer::Setup {
        resources: vec!["https://sid.example.com/api".into()],
        checkers: vec![sid_test_issuer::Checker {
            client_id: "sid-notify".into(),
            secret: "notify-checker-secret".into(),
            confirms_proofs: false,
        }],
    })
    .await;
    let secret = std::env::temp_dir().join(format!("sid-notify-init-{}", uuid::Uuid::now_v7()));
    std::fs::write(&secret, "notify-checker-secret").unwrap();
    let config = NotifyConfig {
        nats_url: nats_url(),
        platform_nats_url: None,
        grpc_bind: "127.0.0.1:0".parse().unwrap(),
        receiver: receiver(),
        event_receivers: Vec::new(),
        smtp: SmtpConfig::default(),
        smtp_enabled: true,
        webhook_enabled: false,
        vapid: None,
        database_url: database_url(),
        identity_grpc_address: None,
        api: issuer.receiver_config(
            "https://sid.example.com/api",
            "https://sid.example.com",
            "sid-notify",
            &secret,
        ),
    };

    let server = NotifyServer::new(config).await.unwrap();
    std::fs::remove_file(&secret).ok();
    let channels = server.dispatcher().channel_ids();
    assert!(channels.contains(&"email".to_string()));
    assert!(!channels.contains(&"webhook".to_string()));
    assert!(!channels.contains(&"web_push".to_string()));
}
