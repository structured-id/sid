// SPDX-License-Identifier: AGPL-3.0-only
//! Durable delivery cost in the supported modes:
//!
//! - `accept`: P50/P99/P999 of committing one owed event (its routing job);
//! - `deliver`: P50/P99/P999 of one event, accepted on a running idle runner,
//!   until both channels of its route (email and webhook) were sent it;
//! - `drain`: the rate a backlog of `BACKLOG` owed events is routed, planned
//!   and delivered at;
//! - `handoff`: P50/P99/P999 of handing a producer's work to JetStream
//!   (publish and PubAck), and the rate that backlog is accepted into the
//!   receiver's store;
//!
//! on file-backed SQLite (embedded) and PostgreSQL (a fresh `sid_notify_bench`
//! on the server `SID_BENCH_POSTGRES_URL`, default port 54399), and the test
//! NATS (`SID_TEST_NATS_URL`, default port 4399). Each run starts on an empty
//! database and its own streams. Progress is counted where it happens (the
//! channels, the consumer), never by reading the store, so the measurement
//! puts no load of its own on it. The channels answer at once: these are the
//! internal effects, not an external provider's latency.
//!
//! `cargo bench -p sid-notify --bench durable_delivery`

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sid_authn::work_runner::{RunnerConfig, WorkHandler, WorkRunner};
use sid_core::models::event::{Event, WorkRecipient, event_types};
use sid_infra::{NatsEventBus, Topology, TopologyRole};
use sid_notify::delivery::{
    DeliverHandler, PlanHandler, RouteHandler, accept_event, accept_work, open_work,
};
use sid_notify::{
    NotificationDispatcher, RecipientSource, ResolveError, RoutingTable, TemplateEngine,
};
use sid_plugin::WorkStore;
use sid_plugin::event_bus::EventBus;
use sid_plugin::notification::{
    ChannelHealth, DeliveryError, DeliveryReceipt, NotificationChannel, Recipient, RenderedMessage,
};

/// Events committed one at a time for `accept`.
const ACCEPTS: usize = 2_000;
/// Events delivered one at a time for `deliver`.
const SINGLES: usize = 500;
/// Events owed at once for `drain` and `handoff`.
const BACKLOG: usize = 5_000;
/// Deliveries each event's route makes.
const FAN_OUT: usize = 2;
/// Room the store and the stream give the work.
const CAPACITY: u64 = 1_000_000;
/// How often progress counters are looked at.
const TICK: Duration = Duration::from_micros(200);

/// The PostgreSQL server, without a database.
fn postgres_url() -> String {
    std::env::var("SID_BENCH_POSTGRES_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399".into())
}

fn nats_url() -> String {
    std::env::var("SID_TEST_NATS_URL").unwrap_or_else(|_| "nats://localhost:4399".into())
}

/// The fact every measurement routes: one rule, `FAN_OUT` channels.
fn event() -> Event {
    Event::new("sid-bench", event_types::SECURITY_BRUTE_FORCE).with_subject("profile/p-bench")
}

/// One recipient for every event, resolved without a lookup.
struct Fixed;

#[async_trait]
impl RecipientSource for Fixed {
    async fn resolve(&self, _event: &Event) -> Result<Recipient, ResolveError> {
        Ok(Recipient {
            profile_id: "p-bench".into(),
            email: Some("bench@sid.example.com".into()),
            phone: None,
            push_endpoint: None,
            device_token: None,
            locale: "en".into(),
        })
    }
}

/// A channel accepting every message at once, counting them in `sent`.
struct Immediate {
    id: &'static str,
    sent: Arc<AtomicUsize>,
}

#[async_trait]
impl NotificationChannel for Immediate {
    fn channel_id(&self) -> &str {
        self.id
    }

    async fn deliver(
        &self,
        _recipient: &Recipient,
        _message: &RenderedMessage,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        self.sent.fetch_add(1, Ordering::Release);
        Ok(DeliveryReceipt {
            message_id: "m".into(),
            channel: self.id.into(),
            timestamp: chrono::Utc::now(),
            provider: "bench".into(),
        })
    }

    async fn health(&self) -> Result<ChannelHealth, DeliveryError> {
        Ok(ChannelHealth {
            healthy: true,
            message: None,
            last_success: None,
        })
    }
}

/// P50, P99 and P999 of `samples`.
fn report(mode: &str, what: &str, mut samples: Vec<Duration>) {
    samples.sort_unstable();
    let at = |q: usize| samples[(samples.len() * q / 1000).min(samples.len() - 1)];
    println!(
        "{mode:<10} {what:<9} n={:<6} p50={:>9.3?} p99={:>9.3?} p999={:>9.3?} max={:>9.3?}",
        samples.len(),
        at(500),
        at(990),
        at(999),
        samples[samples.len() - 1],
    );
}

fn rate(mode: &str, what: &str, items: usize, took: Duration) {
    println!(
        "{mode:<10} {what:<9} {items} in {took:.3?}: {:.0}/s",
        items as f64 / took.as_secs_f64()
    );
}

/// Wait until `counter` reaches `target`.
async fn reach(counter: &AtomicUsize, target: usize) {
    while counter.load(Ordering::Acquire) < target {
        tokio::time::sleep(TICK).await;
    }
}

/// A runner over `store` delivering to channels counting into `sent`.
fn runner(store: &Arc<dyn WorkStore>, sent: &Arc<AtomicUsize>) -> WorkRunner {
    let mut dispatcher = NotificationDispatcher::new(Arc::new(tokio::sync::RwLock::new(
        TemplateEngine::with_default_ce_templates(),
    )));
    for id in ["email", "webhook"] {
        dispatcher.register_channel(Arc::new(Immediate {
            id,
            sent: sent.clone(),
        }));
    }
    let source: Arc<dyn RecipientSource> = Arc::new(Fixed);
    let handlers: Vec<Arc<dyn WorkHandler>> = vec![
        Arc::new(RouteHandler::new(
            RoutingTable::default_ce_rules(),
            source.clone(),
            store.clone(),
            CAPACITY,
        )),
        Arc::new(PlanHandler::new(store.clone(), CAPACITY)),
        Arc::new(DeliverHandler::new(Arc::new(dispatcher), source)),
    ];
    WorkRunner::new(
        store.clone(),
        "bench",
        handlers,
        RunnerConfig {
            concurrency: 32,
            lease: Duration::from_secs(60),
            scan_interval: Duration::from_millis(5),
        },
    )
    .unwrap()
}

/// `accept`, `drain` and `deliver` over `store`.
async fn store_modes(mode: &str, store: Arc<dyn WorkStore>) {
    let mut samples = Vec::with_capacity(ACCEPTS);
    let mut owed = 0;
    for _ in 0..ACCEPTS {
        let event = event();
        let started = Instant::now();
        accept_event(store.as_ref(), &event, CAPACITY)
            .await
            .unwrap();
        samples.push(started.elapsed());
        owed += 1;
    }
    report(mode, "accept", samples);

    for _ in 0..BACKLOG {
        accept_event(store.as_ref(), &event(), CAPACITY)
            .await
            .unwrap();
        owed += 1;
    }
    let sent = Arc::new(AtomicUsize::new(0));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let started = Instant::now();
    let running =
        tokio::spawn(runner(&store, &sent).run(async move { stopped.await.unwrap_or(()) }));
    reach(&sent, owed * FAN_OUT).await;
    // The accepted ones of `accept` drain with the backlog.
    rate(mode, "drain", owed, started.elapsed());

    let mut samples = Vec::with_capacity(SINGLES);
    for _ in 0..SINGLES {
        let before = sent.load(Ordering::Acquire);
        let started = Instant::now();
        accept_event(store.as_ref(), &event(), CAPACITY)
            .await
            .unwrap();
        reach(&sent, before + FAN_OUT).await;
        samples.push(started.elapsed());
    }
    report(mode, "deliver", samples);
    stop.send(()).unwrap();
    running.await.unwrap();
}

/// A store of its own on a fresh PostgreSQL database.
async fn postgres() -> Arc<dyn WorkStore> {
    let server = postgres_url();
    let admin = sqlx::PgPool::connect(&format!("{server}/sid"))
        .await
        .expect("bench PostgreSQL unreachable; start docker-compose.test.yml");
    sqlx::query("DROP DATABASE IF EXISTS sid_notify_bench WITH (FORCE)")
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("CREATE DATABASE sid_notify_bench")
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    let store = sid_storage::PgWorkStore::new(
        sqlx::PgPool::connect(&format!("{server}/sid_notify_bench"))
            .await
            .unwrap(),
    );
    store.ensure_schema().await.unwrap();
    Arc::new(store)
}

/// `handoff` through JetStream into `store`, on streams of its own.
async fn handoff(store: Arc<dyn WorkStore>) {
    let mut topology = Topology::with_root(format!("b{}", uuid::Uuid::now_v7().simple())).unwrap();
    topology.work_max_bytes = 256 << 20;
    let bus = NatsEventBus::connect(&nats_url(), topology.clone(), TopologyRole::Own)
        .await
        .expect("bench NATS unreachable; start docker-compose.test.yml");
    let receiver = WorkRecipient::new("sid-notify").unwrap();

    let mut samples = Vec::with_capacity(BACKLOG);
    for _ in 0..BACKLOG {
        let event = event();
        let started = Instant::now();
        bus.deliver(&receiver, event.delivery_id(&receiver), &event)
            .await
            .unwrap();
        samples.push(started.elapsed());
    }
    report("jetstream", "handoff", samples);

    let accepted = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let deliveries = open_work(&bus, receiver).await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let consumer = {
        let (store, accepted) = (store.clone(), accepted.clone());
        tokio::spawn(async move {
            accept_work(
                deliveries,
                store.as_ref(),
                CAPACITY,
                || {
                    accepted.fetch_add(1, Ordering::Release);
                },
                async move {
                    let _ = stopped.await;
                },
            )
            .await;
        })
    };
    reach(&accepted, BACKLOG).await;
    rate("jetstream", "drain", BACKLOG, started.elapsed());
    stop.send(()).unwrap();
    consumer.await.unwrap();

    let js = async_nats::jetstream::new(async_nats::connect(nats_url()).await.unwrap());
    for name in [topology.history_stream(), topology.work_stream()] {
        if let Err(e) = js.delete_stream(&name).await {
            eprintln!("delete {name}: {e}");
        }
    }
}

/// The modes `SID_BENCH_MODES` names (comma-separated: `sqlite`, `postgres`,
/// `jetstream`), all of them when unset.
fn modes() -> Vec<String> {
    match std::env::var("SID_BENCH_MODES") {
        Ok(list) => list.split(',').map(|m| m.trim().to_string()).collect(),
        Err(_) => vec!["sqlite".into(), "postgres".into(), "jetstream".into()],
    }
}

#[tokio::main]
async fn main() {
    if let Ok(phase) = std::env::var("CXBR_BENCHMARK_PHASE") {
        // The measurement host's quiet window: everything below is measured.
        std::process::Command::new(&phase)
            .arg("begin")
            .status()
            .unwrap();
    }
    for mode in modes() {
        match mode.as_str() {
            "sqlite" => {
                let dir = tempfile::tempdir().unwrap();
                let file = dir.path().join("work.db");
                let sqlite =
                    sid_storage::sqlite::SqliteBackend::new(&format!("sqlite:{}", file.display()))
                        .await
                        .unwrap();
                store_modes("sqlite", Arc::new(sqlite)).await;
            }
            "postgres" => store_modes("postgres", postgres().await).await,
            "jetstream" => handoff(postgres().await).await,
            other => panic!("unknown mode {other}: sqlite, postgres or jetstream"),
        }
    }
    if let Ok(phase) = std::env::var("CXBR_BENCHMARK_PHASE") {
        std::process::Command::new(&phase)
            .arg("end")
            .status()
            .unwrap();
    }
}
