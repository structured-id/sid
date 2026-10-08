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
    storage.enqueue_work(&work, 1_000).await.unwrap();
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
