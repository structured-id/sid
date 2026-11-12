// SPDX-License-Identifier: AGPL-3.0-only
//! Durable delivery cost, measured the same way on every work store:
//!
//! - `accept`: P50/P99/P999 of committing one owed event (its routing job);
//! - `deliver`: P50/P99/P999 of one event, accepted on a running idle runner,
//!   until both channels of its route (email and webhook) were sent it;
//! - `drain`: the rate a backlog of `BACKLOG` owed events is routed, planned
//!   and delivered at, until every delivery reached its channel; `settle`:
//!   until every work item's completion was committed; `settled`: the same
//!   for one event on an idle runner;
//! - `handoff`: P50/P99/P999 of handing a producer's work to JetStream
//!   (publish and PubAck), and the rate that backlog is accepted into the
//!   receiver's store.
//!
//! A harness builds its store and calls [`store_modes`] (and [`handoff`]);
//! templates live in a fresh database on the PostgreSQL server
//! `SID_BENCH_POSTGRES_URL` (default port 54399), as the notifier keeps them,
//! and JetStream is the test NATS (`SID_TEST_NATS_URL`, default port 4399).
//! Each run starts on an empty database and its own streams. Progress is
//! counted where it happens (the channels, the consumer), never by reading the
//! store, so the measurement puts no load of its own on it. The channels answer
//! at once: these are the internal effects, not an external provider's latency.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sid_authn::work_runner::{RunnerConfig, WorkHandler, WorkRunner};
use sid_core::models::event::{Event, WorkRecipient, event_types};
use sid_infra::{NatsEventBus, Topology, TopologyRole};
use sid_plugin::WorkStore;
use sid_plugin::event_bus::EventBus;
use sid_plugin::notification::{
    ChannelHealth, DeliveryError, DeliveryReceipt, NotificationChannel, Recipient, RenderedMessage,
};

use crate::delivery::{
    DeliverHandler, PlanHandler, RouteHandler, accept_event, accept_work, open_work,
};
use crate::{
    NotificationDispatcher, RecipientSource, ResolveError, RoutingTable, TemplateEngine,
    TemplateStore,
};

/// Events committed one at a time for `accept`.
const ACCEPTS: usize = 2_000;
/// Events delivered one at a time for `deliver`.
const SINGLES: usize = 500;
/// Events owed at once for `drain` and `handoff`.
const BACKLOG: usize = 5_000;
/// Deliveries each event's route makes.
const FAN_OUT: usize = 2;
/// Work items each event completes in the store: its route, its plan and
/// one delivery per channel.
const COMPLETIONS: usize = 2 + FAN_OUT;

/// Progress counted where it happens: how many, and when the last one was,
/// stamped by the one that made it, so a sample never includes the time a
/// waiter takes to wake.
#[derive(Default)]
struct Progress {
    count: AtomicUsize,
    last: std::sync::Mutex<Option<Instant>>,
    changed: tokio::sync::Notify,
}

impl Progress {
    /// One more, now.
    fn add(&self) {
        let now = Instant::now();
        *self.last.lock().unwrap() = Some(now);
        self.count.fetch_add(1, Ordering::AcqRel);
        self.changed.notify_waiters();
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Wait until the count reaches `target`; when the last one was made.
    async fn reach(&self, target: usize) -> Instant {
        loop {
            let changed = self.changed.notified();
            if self.count() >= target {
                return self
                    .last
                    .lock()
                    .unwrap()
                    .expect("a count above zero was stamped");
            }
            changed.await;
        }
    }
}

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
    sent: Arc<Progress>,
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
        self.sent.add();
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

/// A store recording the latency of each call the runner and handlers make,
/// and how many items each claim returned: where a drain's time goes. The
/// runner claims from one loop, so the summed claim time against the
/// drain's wall time tells whether that loop bounds it. `completed` counts
/// each completion the store answered as committed, stamped on its answer:
/// the durable end of a work item, which a channel's send precedes.
struct Timed {
    inner: Arc<dyn WorkStore>,
    calls: std::sync::Mutex<std::collections::HashMap<&'static str, Vec<Duration>>>,
    claimed: std::sync::Mutex<Vec<usize>>,
    completed: Progress,
}

impl Timed {
    fn new(inner: Arc<dyn WorkStore>) -> Self {
        Self {
            inner,
            calls: Default::default(),
            claimed: Default::default(),
            completed: Progress::default(),
        }
    }

    fn record(&self, call: &'static str, took: Duration) {
        self.calls
            .lock()
            .unwrap()
            .entry(call)
            .or_default()
            .push(took);
    }

    /// Each call's count, total and P50/P99, the claim loop's share of
    /// `wall`, and the items per claim.
    fn report(&self, mode: &str, wall: Duration) {
        let calls = std::mem::take(&mut *self.calls.lock().unwrap());
        let mut names: Vec<_> = calls.keys().copied().collect();
        names.sort_unstable();
        for name in names {
            let mut samples = calls[name].clone();
            samples.sort_unstable();
            let total: Duration = samples.iter().sum();
            let at = |q: usize| samples[(samples.len() * q / 1000).min(samples.len() - 1)];
            println!(
                "{mode:<10} {name:<9} n={:<6} total={total:>9.3?} share={:>5.1}% p50={:>9.3?} p99={:>9.3?}",
                samples.len(),
                100.0 * total.as_secs_f64() / wall.as_secs_f64(),
                at(500),
                at(990),
            );
        }
        let claimed = std::mem::take(&mut *self.claimed.lock().unwrap());
        let items: usize = claimed.iter().sum();
        let empty = claimed.iter().filter(|n| **n == 0).count();
        println!(
            "{mode:<10} claims    {} claims, {items} items, {:.2} per claim, {empty} empty",
            claimed.len(),
            items as f64 / claimed.len().max(1) as f64,
        );
    }
}

#[async_trait]
impl WorkStore for Timed {
    async fn enqueue_work(&self, work: &sid_core::models::NewWork) -> sid_core::Result<bool> {
        let started = Instant::now();
        let done = self.inner.enqueue_work(work).await;
        self.record("enqueue", started.elapsed());
        done
    }

    async fn claim_work(
        &self,
        kinds: &[sid_core::models::WorkKind],
        worker: &str,
        limit: u32,
        lease: Duration,
    ) -> sid_core::Result<Vec<sid_core::models::ClaimedWork>> {
        let started = Instant::now();
        let claimed = self.inner.claim_work(kinds, worker, limit, lease).await;
        self.record("claim", started.elapsed());
        if let Ok(items) = &claimed {
            self.claimed.lock().unwrap().push(items.len());
        }
        claimed
    }

    async fn complete_work(
        &self,
        id: sid_core::models::WorkId,
        generation: i64,
        result: Option<&str>,
    ) -> sid_core::Result<bool> {
        let started = Instant::now();
        let done = self.inner.complete_work(id, generation, result).await;
        self.record("complete", started.elapsed());
        if matches!(done, Ok(true)) {
            self.completed.add();
        }
        done
    }

    async fn complete_work_owing(
        &self,
        id: sid_core::models::WorkId,
        generation: i64,
        result: Option<&str>,
        owed: &[sid_core::models::NewWork],
    ) -> sid_core::Result<bool> {
        let started = Instant::now();
        let done = self
            .inner
            .complete_work_owing(id, generation, result, owed)
            .await;
        self.record("complete+", started.elapsed());
        if matches!(done, Ok(true)) {
            self.completed.add();
        }
        done
    }

    async fn complete_works(
        &self,
        works: &[sid_core::models::WorkCompletion],
    ) -> sid_core::Result<Vec<bool>> {
        let started = Instant::now();
        let done = self.inner.complete_works(works).await;
        self.record("complete*", started.elapsed());
        if let Ok(done) = &done {
            for _ in done.iter().filter(|done| **done) {
                self.completed.add();
            }
        }
        done
    }

    async fn fail_work(
        &self,
        id: sid_core::models::WorkId,
        generation: i64,
        failure: &sid_core::models::WorkFailure,
    ) -> sid_core::Result<bool> {
        let started = Instant::now();
        let done = self.inner.fail_work(id, generation, failure).await;
        self.record("fail", started.elapsed());
        done
    }

    async fn get_work(
        &self,
        id: sid_core::models::WorkId,
    ) -> sid_core::Result<Option<sid_core::models::WorkRecord>> {
        self.inner.get_work(id).await
    }

    async fn purge_ended_work(
        &self,
        kind: &sid_core::models::WorkKind,
        before: chrono::DateTime<chrono::Utc>,
    ) -> sid_core::Result<u64> {
        self.inner.purge_ended_work(kind, before).await
    }

    async fn export_work(&self) -> sid_core::Result<Vec<sid_core::models::WorkSnapshot>> {
        self.inner.export_work().await
    }

    async fn import_work(&self, work: &sid_core::models::WorkSnapshot) -> sid_core::Result<bool> {
        self.inner.import_work(work).await
    }
}

/// What the store's server sessions are doing, sampled from a connection of
/// its own while a drain runs: per state, wait event and statement, how many
/// sessions were seen there. Tells a lock queue or an exhausted pool (sessions
/// idle in transaction, or fewer sessions than workers) from slow statements.
struct Waits {
    stop: tokio::sync::oneshot::Sender<()>,
    sampling: tokio::task::JoinHandle<(usize, std::collections::HashMap<String, u64>)>,
}

impl Waits {
    async fn start(pool: &sqlx::PgPool) -> Self {
        use sqlx::Connection;
        let mut conn = sqlx::PgConnection::connect_with(&pool.connect_options())
            .await
            .unwrap();
        let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
        let sampling = tokio::spawn(async move {
            let mut seen = std::collections::HashMap::new();
            let mut samples = 0;
            loop {
                let rows: Vec<(String, i64)> = sqlx::query_as(
                    "SELECT state || ' ' || COALESCE(wait_event_type || ':' || wait_event, 'running') \
                     || ' ' || left(regexp_replace(query, '\\s+', ' ', 'g'), 60), count(*) \
                     FROM pg_stat_activity \
                     WHERE datname = current_database() AND pid <> pg_backend_pid() \
                     GROUP BY 1",
                )
                .fetch_all(&mut conn)
                .await
                .unwrap();
                samples += 1;
                for (what, n) in rows {
                    *seen.entry(what).or_default() += n as u64;
                }
                tokio::select! {
                    _ = &mut stopped => break,
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            }
            (samples, seen)
        });
        Self { stop, sampling }
    }

    /// The most frequent states, each as sessions per sample.
    async fn report(self, mode: &str) {
        self.stop.send(()).unwrap();
        let (samples, seen) = self.sampling.await.unwrap();
        let mut seen: Vec<_> = seen.into_iter().collect();
        seen.sort_unstable_by_key(|(_, n)| std::cmp::Reverse(*n));
        for (what, n) in seen.into_iter().take(15) {
            println!(
                "{mode:<10} sessions  {:>6.2} {what}",
                n as f64 / samples.max(1) as f64
            );
        }
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

/// A runner over `store` delivering to channels counting into `sent`,
/// rendering from `templates` as the service does.
fn runner(
    store: &Arc<dyn WorkStore>,
    sent: &Arc<Progress>,
    templates: &Arc<TemplateStore>,
) -> WorkRunner {
    let mut dispatcher = NotificationDispatcher::new();
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
        )),
        Arc::new(PlanHandler::new()),
        Arc::new(DeliverHandler::new(
            Arc::new(dispatcher),
            templates.clone(),
            source,
        )),
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

/// `accept`, `drain` and `deliver` over `store`, printed under `mode`; every
/// delivery reads its template from the service's own PostgreSQL database.
/// `sessions`, the store's own PostgreSQL pool when it has one, is sampled
/// for where a drain's sessions wait.
pub async fn store_modes(mode: &str, store: Arc<dyn WorkStore>, sessions: Option<&sqlx::PgPool>) {
    let templates = Arc::new(
        TemplateStore::new(
            &RoutingTable::default_ce_rules(),
            Arc::new(tokio::sync::RwLock::new(
                TemplateEngine::with_default_ce_templates(),
            )),
            fresh_database("sid_notify_bench_templates").await,
        )
        .await
        .unwrap(),
    );
    let mut samples = Vec::with_capacity(ACCEPTS);
    let mut owed = 0;
    for _ in 0..ACCEPTS {
        let event = event();
        let started = Instant::now();
        accept_event(store.as_ref(), &event).await.unwrap();
        samples.push(started.elapsed());
        owed += 1;
    }
    report(mode, "accept", samples);

    for _ in 0..BACKLOG {
        accept_event(store.as_ref(), &event()).await.unwrap();
        owed += 1;
    }
    let sent = Arc::new(Progress::default());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let timed = Arc::new(Timed::new(store.clone()));
    let timed_store: Arc<dyn WorkStore> = timed.clone();
    let waits = match sessions {
        Some(pool) => Some(Waits::start(pool).await),
        None => None,
    };
    let started = Instant::now();
    let runner = runner(&timed_store, &sent, &templates);
    // Woken after each acceptance, as the notifier's consumer does.
    let waker = runner.waker();
    let running = tokio::spawn(runner.run(async move { stopped.await.unwrap_or(()) }));
    let done = sent.reach(owed * FAN_OUT).await;
    // The accepted ones of `accept` drain with the backlog: `drain` until
    // every delivery reached its channel, `settle` until every work item's
    // completion was committed.
    rate(mode, "drain", owed, done - started);
    let settled = timed.completed.reach(owed * COMPLETIONS).await;
    rate(mode, "settle", owed, settled - started);
    timed.report(mode, settled - started);
    if let Some(waits) = waits {
        waits.report(mode).await;
    }

    let mut samples = Vec::with_capacity(SINGLES);
    let mut settled_samples = Vec::with_capacity(SINGLES);
    for _ in 0..SINGLES {
        let before = sent.count();
        let completed = timed.completed.count();
        let started = Instant::now();
        accept_event(store.as_ref(), &event()).await.unwrap();
        waker.wake();
        let delivered = sent.reach(before + FAN_OUT).await;
        samples.push(delivered - started);
        let settled = timed.completed.reach(completed + COMPLETIONS).await;
        settled_samples.push(settled - started);
    }
    report(mode, "deliver", samples);
    report(mode, "settled", settled_samples);
    stop.send(()).unwrap();
    running.await.unwrap();
}

/// A pool on `name`, created empty on the bench server.
pub async fn fresh_database(name: &str) -> sqlx::PgPool {
    let server = postgres_url();
    let admin = sqlx::PgPool::connect(&format!("{server}/sid"))
        .await
        .expect("bench PostgreSQL unreachable; start docker-compose.test.yml");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
    )))
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    sqlx::PgPool::connect(&format!("{server}/{name}"))
        .await
        .unwrap()
}

/// A store of its own on a fresh PostgreSQL database, and its pool.
pub async fn postgres() -> (Arc<dyn WorkStore>, sqlx::PgPool) {
    let pool = fresh_database("sid_notify_bench").await;
    let store = sid_storage::PgWorkStore::new(pool.clone());
    store.ensure_schema().await.unwrap();
    (Arc::new(store), pool)
}

/// The PostgreSQL server's durability settings the measurement ran under.
pub async fn durability(pool: &sqlx::PgPool) {
    for setting in [
        "fsync",
        "synchronous_commit",
        "wal_sync_method",
        "full_page_writes",
        "commit_delay",
        "wal_level",
    ] {
        let value: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SHOW {setting}")))
            .fetch_one(pool)
            .await
            .unwrap();
        println!("postgres   setting   {setting}={value}");
    }
}

/// `handoff` through JetStream into `store`, on streams of its own.
pub async fn handoff(store: Arc<dyn WorkStore>) {
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

    let accepted = Arc::new(Progress::default());
    let started = Instant::now();
    let deliveries = open_work(&bus, receiver).await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let consumer = {
        let (store, accepted) = (store.clone(), accepted.clone());
        tokio::spawn(async move {
            accept_work(deliveries, store.as_ref(), || accepted.add(), async move {
                let _ = stopped.await;
            })
            .await;
        })
    };
    let done = accepted.reach(BACKLOG).await;
    rate("jetstream", "drain", BACKLOG, done - started);
    stop.send(()).unwrap();
    consumer.await.unwrap();

    let js = async_nats::jetstream::new(async_nats::connect(nats_url()).await.unwrap());
    for name in [topology.history_stream(), topology.work_stream()] {
        if let Err(e) = js.delete_stream(&name).await {
            eprintln!("delete {name}: {e}");
        }
    }
}
