// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use sid_core::models::{WorkId, WorkState};
use sid_storage::sqlite::SqliteBackend;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::oneshot;

fn kind() -> WorkKind {
    WorkKind::new("test.work").unwrap()
}

fn fast_config() -> RunnerConfig {
    RunnerConfig {
        concurrency: 4,
        lease: Duration::from_secs(30),
        scan_interval: Duration::from_millis(20),
    }
}

const FAST_RETRIES: RetrySchedule = RetrySchedule::new(&[Duration::from_millis(1)]);

/// Counts attempts, answers with a fixed outcome after an optional delay,
/// and records the most attempts seen running at once.
struct Probe {
    kind: WorkKind,
    outcome: WorkOutcome,
    delay: Duration,
    attempts: AtomicUsize,
    running: AtomicUsize,
    peak: AtomicUsize,
}

impl Probe {
    fn new(outcome: WorkOutcome, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            kind: kind(),
            outcome,
            delay,
            attempts: AtomicUsize::new(0),
            running: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl WorkHandler for Probe {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        FAST_RETRIES
    }

    fn on_dead(&self, work: &ClaimedWork, error: &str) -> Option<NewWork> {
        let mut alert = NewWork::new(dead_kind(), error.as_bytes().to_vec());
        // One alert per dead work: its id follows from the work's.
        alert.id = WorkId(uuid::Uuid::new_v5(&work.id.0, b"dead"));
        Some(alert)
    }

    async fn handle(&self, _work: &ClaimedWork) -> WorkOutcome {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        self.running.fetch_sub(1, Ordering::SeqCst);
        self.outcome.clone()
    }
}

fn dead_kind() -> WorkKind {
    WorkKind::new("test.work.dead").unwrap()
}

async fn storage() -> Arc<dyn WorkStore> {
    Arc::new(SqliteBackend::new_in_memory().await.unwrap())
}

async fn enqueue(storage: &dyn WorkStore, max_attempts: u32) -> WorkId {
    let mut work = NewWork::new(kind(), b"p".to_vec());
    work.max_attempts = max_attempts;
    storage.enqueue_work(&work).await.unwrap();
    work.id
}

/// The dead-letter alert the probe raises for `id`.
async fn dead_alert(storage: &dyn WorkStore, id: WorkId) -> Option<sid_core::models::WorkRecord> {
    storage
        .get_work(WorkId(uuid::Uuid::new_v5(&id.0, b"dead")))
        .await
        .unwrap()
}

/// Start `runner`; the returned sender stops it and the handle ends when it
/// has finished its attempts in flight.
fn start(runner: WorkRunner) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let (stop, stopped) = oneshot::channel::<()>();
    // A dropped sender stops the runner too.
    let handle = tokio::spawn(runner.run(async move { stopped.await.unwrap_or(()) }));
    (stop, handle)
}

async fn wait_for_state(storage: &dyn WorkStore, id: WorkId, state: WorkState) {
    for _ in 0..500 {
        if storage.get_work(id).await.unwrap().unwrap().state == state {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "work {id} never reached {state:?}: {:?}",
        storage.get_work(id).await.unwrap()
    );
}

/// Work committed before the runner started is found in storage and done;
/// no wake-up is needed.
#[tokio::test]
async fn test_runner_finds_pending_work_on_start() {
    let storage = storage().await;
    let ids = [
        enqueue(storage.as_ref(), 3).await,
        enqueue(storage.as_ref(), 3).await,
    ];
    let probe = Probe::new(WorkOutcome::Done(None), Duration::ZERO);
    let mut config = fast_config();
    config.scan_interval = Duration::from_secs(3600);
    let runner = WorkRunner::new(Arc::clone(&storage), "w", vec![probe.clone()], config).unwrap();
    let (stop, handle) = start(runner);

    for id in ids {
        wait_for_state(storage.as_ref(), id, WorkState::Completed).await;
    }
    stop.send(()).unwrap();
    handle.await.unwrap();
    assert_eq!(probe.attempts.load(Ordering::SeqCst), 2);
}

/// Work committed while the runner waits is picked up as soon as it is woken,
/// without waiting for the next scan.
#[tokio::test]
async fn test_runner_wakes_for_new_work() {
    let storage = storage().await;
    let probe = Probe::new(WorkOutcome::Done(None), Duration::ZERO);
    let mut config = fast_config();
    config.scan_interval = Duration::from_secs(3600);
    let runner = WorkRunner::new(Arc::clone(&storage), "w", vec![probe], config).unwrap();
    let waker = runner.waker();
    let (stop, handle) = start(runner);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let id = enqueue(storage.as_ref(), 3).await;
    waker.wake();
    wait_for_state(storage.as_ref(), id, WorkState::Completed).await;
    stop.send(()).unwrap();
    handle.await.unwrap();
}

fn follow_up_kind() -> WorkKind {
    WorkKind::new("test.work.next").unwrap()
}

/// Work done with a next stage completes with it in one commit: the parent
/// completed, the child pending.
#[tokio::test]
async fn test_runner_commits_the_next_stage_with_the_completion() {
    let storage = storage().await;
    let id = enqueue(storage.as_ref(), 3).await;
    let child = NewWork::new(follow_up_kind(), b"next".to_vec());
    let probe = Probe::new(
        WorkOutcome::DoneWith {
            result: Some("staged".into()),
            follow_up: vec![child.clone()],
        },
        Duration::ZERO,
    );
    let runner = WorkRunner::new(Arc::clone(&storage), "w", vec![probe], fast_config()).unwrap();
    let (stop, handle) = start(runner);

    wait_for_state(storage.as_ref(), id, WorkState::Completed).await;
    stop.send(()).unwrap();
    handle.await.unwrap();
    let record = storage.get_work(id).await.unwrap().unwrap();
    assert_eq!(record.result.as_deref(), Some("staged"));
    let child = storage.get_work(child.id).await.unwrap().unwrap();
    assert_eq!(child.state, WorkState::Pending);
}

/// A failing handler is retried after a backoff, and the work ends failed
/// with its error once attempts run out.
#[tokio::test]
async fn test_runner_retries_until_failed() {
    let storage = storage().await;
    let id = enqueue(storage.as_ref(), 3).await;
    let probe = Probe::new(WorkOutcome::Retry("provider down".into()), Duration::ZERO);
    let runner = WorkRunner::new(
        Arc::clone(&storage),
        "w",
        vec![probe.clone()],
        fast_config(),
    )
    .unwrap();
    let (stop, handle) = start(runner);

    wait_for_state(storage.as_ref(), id, WorkState::Failed).await;
    stop.send(()).unwrap();
    handle.await.unwrap();
    let record = storage.get_work(id).await.unwrap().unwrap();
    assert_eq!(record.attempts, 3);
    assert_eq!(record.last_error.as_deref(), Some("provider down"));
    assert!(!record.ambiguous);
    assert_eq!(probe.attempts.load(Ordering::SeqCst), 3);
    let alert = dead_alert(storage.as_ref(), id)
        .await
        .expect("dead work raised no alert");
    assert_eq!(alert.state, WorkState::Pending);
    assert_eq!(alert.kind, dead_kind());
}

/// A permanent failure ends the work on its first attempt, with its alert.
#[tokio::test]
async fn test_runner_permanent_failure_is_not_retried() {
    let storage = storage().await;
    let id = enqueue(storage.as_ref(), 5).await;
    let probe = Probe::new(
        WorkOutcome::Permanent("mailbox does not exist".into()),
        Duration::ZERO,
    );
    let runner = WorkRunner::new(
        Arc::clone(&storage),
        "w",
        vec![probe.clone()],
        fast_config(),
    )
    .unwrap();
    let (stop, handle) = start(runner);

    wait_for_state(storage.as_ref(), id, WorkState::Failed).await;
    stop.send(()).unwrap();
    handle.await.unwrap();
    assert_eq!(storage.get_work(id).await.unwrap().unwrap().attempts, 1);
    assert_eq!(probe.attempts.load(Ordering::SeqCst), 1);
    assert!(dead_alert(storage.as_ref(), id).await.is_some());
}

/// An ambiguous attempt is retried and stays marked ambiguous; a completed
/// attempt keeps its receipt; neither raises a dead-letter alert while the
/// work lives.
#[tokio::test]
async fn test_runner_records_ambiguous_and_receipt() {
    let storage = storage().await;
    let id = enqueue(storage.as_ref(), 2).await;
    let probe = Probe::new(WorkOutcome::Ambiguous("reply lost".into()), Duration::ZERO);
    // The retry comes due after the attempt that scheduled it, so it is found
    // by the periodic scan: keep that scan short.
    let runner = WorkRunner::new(Arc::clone(&storage), "w", vec![probe], fast_config()).unwrap();
    let (stop, handle) = start(runner);
    wait_for_state(storage.as_ref(), id, WorkState::Failed).await;
    stop.send(()).unwrap();
    handle.await.unwrap();
    let record = storage.get_work(id).await.unwrap().unwrap();
    assert!(
        record.ambiguous,
        "an ambiguous attempt was recorded as a clean failure"
    );
    assert_eq!(record.attempts, 2);

    let done = enqueue(storage.as_ref(), 2).await;
    let probe = Probe::new(
        WorkOutcome::Done(Some("250 2.0.0 queued as 7F3A".into())),
        Duration::ZERO,
    );
    let runner = WorkRunner::new(Arc::clone(&storage), "w", vec![probe], fast_config()).unwrap();
    let (stop, handle) = start(runner);
    wait_for_state(storage.as_ref(), done, WorkState::Completed).await;
    stop.send(()).unwrap();
    handle.await.unwrap();
    let record = storage.get_work(done).await.unwrap().unwrap();
    assert_eq!(record.result.as_deref(), Some("250 2.0.0 queued as 7F3A"));
    assert!(dead_alert(storage.as_ref(), done).await.is_none());
}

/// No more attempts run at once than the configured concurrency, and all
/// work still gets done.
#[tokio::test]
async fn test_runner_bounds_concurrency() {
    let storage = storage().await;
    let mut ids = Vec::new();
    for _ in 0..10 {
        ids.push(enqueue(storage.as_ref(), 3).await);
    }
    let probe = Probe::new(WorkOutcome::Done(None), Duration::from_millis(30));
    let mut config = fast_config();
    config.concurrency = 2;
    let runner = WorkRunner::new(Arc::clone(&storage), "w", vec![probe.clone()], config).unwrap();
    let (stop, handle) = start(runner);

    for id in ids {
        wait_for_state(storage.as_ref(), id, WorkState::Completed).await;
    }
    stop.send(()).unwrap();
    handle.await.unwrap();
    assert_eq!(probe.attempts.load(Ordering::SeqCst), 10);
    assert!(
        probe.peak.load(Ordering::SeqCst) <= 2,
        "concurrency bound exceeded"
    );
}

/// Stopping the runner lets the attempt in flight finish and record its
/// outcome before `run` returns.
#[tokio::test]
async fn test_runner_shutdown_waits_for_attempts() {
    let storage = storage().await;
    let id = enqueue(storage.as_ref(), 3).await;
    let probe = Probe::new(WorkOutcome::Done(None), Duration::from_millis(150));
    let runner = WorkRunner::new(
        Arc::clone(&storage),
        "w",
        vec![probe.clone()],
        fast_config(),
    )
    .unwrap();
    let (stop, handle) = start(runner);
    while probe.running.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    stop.send(()).unwrap();
    handle.await.unwrap();
    assert_eq!(
        storage.get_work(id).await.unwrap().unwrap().state,
        WorkState::Completed,
        "run returned before its attempt was recorded"
    );
}

/// A runner is refused for a configuration it cannot honour.
#[tokio::test]
async fn test_runner_rejects_invalid_configuration() {
    let storage = storage().await;
    let probe = || -> Arc<dyn WorkHandler> { Probe::new(WorkOutcome::Done(None), Duration::ZERO) };
    let build = |handlers: Vec<Arc<dyn WorkHandler>>, config: RunnerConfig| {
        WorkRunner::new(Arc::clone(&storage), "w", handlers, config).is_err()
    };

    assert!(
        build(vec![probe(), probe()], fast_config()),
        "two handlers for one kind"
    );
    let mut config = fast_config();
    config.concurrency = 0;
    assert!(build(vec![probe()], config));
    let mut config = fast_config();
    config.lease = Duration::ZERO;
    assert!(build(vec![probe()], config));
    let mut config = fast_config();
    config.scan_interval = Duration::ZERO;
    assert!(build(vec![probe()], config));
    assert!(!build(vec![probe()], fast_config()));
}

/// The delay after attempt `n` is the schedule's entry `n`, and the last
/// entry repeats once the schedule is exhausted.
#[test]
fn test_retry_schedule_steps_then_repeats_last() {
    const SCHEDULE: RetrySchedule = RetrySchedule::new(&[
        Duration::from_secs(1),
        Duration::from_secs(5),
        Duration::from_secs(30),
    ]);
    assert_eq!(SCHEDULE.after(1), Duration::from_secs(1));
    assert_eq!(SCHEDULE.after(2), Duration::from_secs(5));
    assert_eq!(SCHEDULE.after(3), Duration::from_secs(30));
    assert_eq!(SCHEDULE.after(4), Duration::from_secs(30));
    assert_eq!(SCHEDULE.after(u32::MAX), Duration::from_secs(30));
}

/// A schedule with a delay over one day is refused when it is built.
#[test]
#[should_panic(expected = "a retry delay is at most one day")]
fn test_retry_schedule_refuses_long_delay() {
    static TOO_LONG: [Duration; 1] = [Duration::from_secs(86_401)];
    RetrySchedule::new(&TOO_LONG);
}

/// One attempt at fresh work with `max_attempts`, answered with `outcome`:
/// how the runner settled it and the state the store then holds.
async fn settle(outcome: WorkOutcome, max_attempts: u32) -> (Settled, WorkState) {
    let storage = storage().await;
    let id = enqueue(storage.as_ref(), max_attempts).await;
    let work = storage
        .claim_work(&[kind()], "w", 1, Duration::from_secs(30))
        .await
        .unwrap()
        .remove(0);
    let settled = attempt(
        storage.as_ref(),
        Probe::new(outcome, Duration::ZERO).as_ref(),
        &work,
    )
    .await;
    (settled, storage.get_work(id).await.unwrap().unwrap().state)
}

/// The outcome the runner observes is the one the store recorded: a retry
/// on the last attempt and a permanent failure both end the work, as the
/// store ends it, and only a retry with attempts left keeps it pending.
#[tokio::test]
async fn test_attempt_settles_as_the_store_records_it() {
    assert_eq!(
        settle(WorkOutcome::Done(None), 3).await,
        (Settled::Completed, WorkState::Completed)
    );
    assert_eq!(
        settle(
            WorkOutcome::DoneWith {
                result: None,
                follow_up: Vec::new()
            },
            3
        )
        .await,
        (Settled::Completed, WorkState::Completed)
    );
    assert_eq!(
        settle(WorkOutcome::Retry("down".into()), 3).await,
        (Settled::Retried, WorkState::Pending)
    );
    assert_eq!(
        settle(WorkOutcome::Ambiguous("no reply".into()), 3).await,
        (Settled::Ambiguous, WorkState::Pending)
    );
    assert_eq!(
        settle(WorkOutcome::Retry("down".into()), 1).await,
        (Settled::Failed, WorkState::Failed)
    );
    assert_eq!(
        settle(WorkOutcome::Ambiguous("no reply".into()), 1).await,
        (Settled::Failed, WorkState::Failed)
    );
    assert_eq!(
        settle(WorkOutcome::Permanent("rejected".into()), 3).await,
        (Settled::Failed, WorkState::Failed)
    );
}

/// An attempt whose claim was taken over records nothing and is observed as
/// reclaimed, not as the outcome it would have recorded.
#[tokio::test]
async fn test_attempt_under_a_lost_claim_is_reclaimed() {
    let storage = storage().await;
    let id = enqueue(storage.as_ref(), 3).await;
    let mut work = storage
        .claim_work(&[kind()], "w", 1, Duration::from_secs(30))
        .await
        .unwrap()
        .remove(0);
    work.generation -= 1;
    let settled = attempt(
        storage.as_ref(),
        Probe::new(WorkOutcome::Done(None), Duration::ZERO).as_ref(),
        &work,
    )
    .await;
    assert_eq!(settled, Settled::Reclaimed);
    assert_eq!(
        storage.get_work(id).await.unwrap().unwrap().state,
        WorkState::Claimed
    );
}

#[cfg(feature = "telemetry")]
mod observed {
    use super::*;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

    /// The value of the counter `name` at the point labelled `labels`.
    fn sum(metrics: &[ResourceMetrics], name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        let labelled = |attributes: &mut dyn Iterator<Item = &opentelemetry::KeyValue>| {
            let attributes: Vec<_> = attributes.collect();
            labels.iter().all(|(k, v)| {
                attributes
                    .iter()
                    .any(|a| a.key.as_str() == *k && a.value.as_str() == *v)
            })
        };
        let mut found = None;
        for metric in metrics
            .iter()
            .flat_map(ResourceMetrics::scope_metrics)
            .flat_map(|scope| scope.metrics())
            .filter(|m| m.name() == name)
        {
            match metric.data() {
                AggregatedMetrics::U64(MetricData::Sum(s)) => {
                    for p in s.data_points() {
                        if labelled(&mut p.attributes()) {
                            found = Some(p.value() as f64);
                        }
                    }
                }
                AggregatedMetrics::I64(MetricData::Sum(s)) => {
                    for p in s.data_points() {
                        if labelled(&mut p.attributes()) {
                            found = Some(p.value() as f64);
                        }
                    }
                }
                AggregatedMetrics::F64(MetricData::Histogram(h)) => {
                    for p in h.data_points() {
                        if labelled(&mut p.attributes()) {
                            found = Some(p.count() as f64);
                        }
                    }
                }
                _ => {}
            }
        }
        found
    }

    /// A meter provider read through the returned exporter. It is global, so
    /// each test labels its work with a kind of its own: other runners in the
    /// same process record under theirs.
    fn observe() -> (SdkMeterProvider, InMemoryMetricExporter) {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter.clone()).build())
            .build();
        opentelemetry::global::set_meter_provider(provider.clone());
        (provider, exporter)
    }

    /// A kind of its own for one test.
    fn own_kind() -> WorkKind {
        WorkKind::new(&format!("test.observed.{}", uuid::Uuid::now_v7().simple())).unwrap()
    }

    /// Work of `kind` with one attempt.
    async fn enqueue_of(storage: &dyn WorkStore, kind: &WorkKind) -> WorkId {
        let mut work = NewWork::new(kind.clone(), b"p".to_vec());
        work.max_attempts = 1;
        storage.enqueue_work(&work).await.unwrap();
        work.id
    }

    /// A probe of `kind` answering `outcome`.
    fn probe_of(kind: &WorkKind, outcome: WorkOutcome) -> Arc<Probe> {
        Arc::new(Probe {
            kind: kind.clone(),
            outcome,
            delay: Duration::ZERO,
            attempts: AtomicUsize::new(0),
            running: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        })
    }

    /// Run a runner over `handler` until `id` reaches `state`.
    async fn run_until(
        storage: &Arc<dyn WorkStore>,
        handler: Arc<dyn WorkHandler>,
        id: WorkId,
        state: WorkState,
    ) {
        let runner =
            WorkRunner::new(Arc::clone(storage), "w", vec![handler], fast_config()).unwrap();
        let (stop, handle) = start(runner);
        wait_for_state(storage.as_ref(), id, state).await;
        stop.send(()).unwrap();
        handle.await.unwrap();
    }

    /// A handler whose attempt panics.
    struct Panics(WorkKind, AtomicUsize);

    #[async_trait]
    impl WorkHandler for Panics {
        fn kind(&self) -> &WorkKind {
            &self.0
        }

        fn retry_schedule(&self) -> RetrySchedule {
            FAST_RETRIES
        }

        fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
            None
        }

        async fn handle(&self, _work: &ClaimedWork) -> WorkOutcome {
            self.1.fetch_add(1, Ordering::SeqCst);
            panic!("the handler failed")
        }
    }

    /// An attempt whose handler panics leaves the in-flight count where it was
    /// and is observed as abandoned; the runner goes on.
    #[tokio::test]
    async fn test_a_panicking_attempt_is_observed_as_abandoned() {
        let (provider, exporter) = observe();
        let kind = own_kind();
        let storage = storage().await;
        enqueue_of(storage.as_ref(), &kind).await;
        let handler = Arc::new(Panics(kind.clone(), AtomicUsize::new(0)));
        let runner = WorkRunner::new(
            Arc::clone(&storage),
            "w",
            vec![Arc::clone(&handler) as Arc<dyn WorkHandler>],
            fast_config(),
        )
        .unwrap();
        let (stop, handle) = start(runner);
        for _ in 0..500 {
            if handler.1.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Past the scan interval: the panicked task has been reaped.
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.send(()).unwrap();
        handle.await.unwrap();

        provider.force_flush().unwrap();
        let metrics = exporter.get_finished_metrics().unwrap();
        let kind = ("kind", kind.as_str());
        assert_eq!(
            sum(&metrics, "sid_work_attempts_active", &[kind]),
            Some(0.0)
        );
        assert_eq!(
            sum(
                &metrics,
                "sid_work_attempts_settled_total",
                &[kind, ("outcome", "abandoned")]
            ),
            Some(1.0)
        );
    }

    /// A runner observes each attempt it runs, by kind and outcome: attempts
    /// started, their outcomes, none left in flight once they ended, one
    /// queue wait per attempt and one completion latency per completed work.
    #[tokio::test]
    async fn test_runner_observes_its_attempts() {
        let (provider, exporter) = observe();
        let kind = own_kind();

        let storage = storage().await;
        let done = enqueue_of(storage.as_ref(), &kind).await;
        run_until(
            &storage,
            probe_of(&kind, WorkOutcome::Done(None)),
            done,
            WorkState::Completed,
        )
        .await;
        let failed = enqueue_of(storage.as_ref(), &kind).await;
        run_until(
            &storage,
            probe_of(&kind, WorkOutcome::Permanent("no".into())),
            failed,
            WorkState::Failed,
        )
        .await;

        provider.force_flush().unwrap();
        let metrics = exporter.get_finished_metrics().unwrap();
        let kind = ("kind", kind.as_str());
        assert_eq!(
            sum(
                &metrics,
                "sid_work_attempts_started_total",
                &[kind, ("attempt", "first")]
            ),
            Some(2.0)
        );
        for outcome in ["completed", "failed"] {
            assert_eq!(
                sum(
                    &metrics,
                    "sid_work_attempts_settled_total",
                    &[kind, ("outcome", outcome)]
                ),
                Some(1.0),
                "{outcome}"
            );
        }
        assert_eq!(
            sum(&metrics, "sid_work_attempts_active", &[kind]),
            Some(0.0)
        );
        assert_eq!(
            sum(&metrics, "sid_work_queue_wait_seconds", &[kind]),
            Some(2.0)
        );
        assert_eq!(
            sum(&metrics, "sid_work_attempt_duration_seconds", &[kind]),
            Some(2.0)
        );
        assert_eq!(
            sum(&metrics, "sid_work_completion_seconds", &[kind]),
            Some(1.0)
        );
    }
}
