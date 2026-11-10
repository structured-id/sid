use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use sid_authn::work_runner::{RetrySchedule, RunnerConfig, WorkHandler, WorkOutcome};
use sid_core::models::{ClaimedWork, NewWork, WorkKind, WorkState};
use sid_plugin::storage::StorageBackend;
use tokio::sync::Notify;

use super::*;
use crate::maintenance::{FirstRun, Job, Maintenance};

const KIND: &str = "engine_probe";

fn kind() -> WorkKind {
    WorkKind::new(KIND).unwrap()
}

async fn store() -> Arc<dyn StorageBackend> {
    Arc::new(
        sid_storage::sqlite::SqliteBackend::new_in_memory()
            .await
            .unwrap(),
    )
}

fn fast() -> RunnerConfig {
    RunnerConfig {
        concurrency: 2,
        lease: Duration::from_secs(30),
        scan_interval: Duration::from_millis(10),
    }
}

/// A handler that announces each attempt, waits `hold`, and records that the
/// attempt finished.
struct Probe {
    kind: WorkKind,
    started: Notify,
    hold: Duration,
    finished: AtomicBool,
}

impl Probe {
    fn new(hold: Duration) -> Arc<Self> {
        Arc::new(Self {
            kind: kind(),
            started: Notify::new(),
            hold,
            finished: AtomicBool::new(false),
        })
    }
}

#[async_trait::async_trait]
impl WorkHandler for Probe {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        const RETRY: RetrySchedule = RetrySchedule::new(&[Duration::from_millis(10)]);
        RETRY
    }

    fn on_dead(&self, _: &ClaimedWork, _: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, _: &ClaimedWork) -> WorkOutcome {
        self.started.notify_one();
        tokio::time::sleep(self.hold).await;
        self.finished.store(true, Ordering::SeqCst);
        WorkOutcome::Done(None)
    }
}

fn parts(
    storage: &Arc<dyn StorageBackend>,
    handlers: Vec<Arc<dyn WorkHandler>>,
    maintenance: Maintenance,
) -> EngineParts {
    EngineParts {
        storage: storage.clone(),
        worker: format!("test-{}", uuid::Uuid::now_v7()),
        handlers,
        runner: fast(),
        maintenance,
    }
}

async fn state(storage: &Arc<dyn StorageBackend>, work: &NewWork) -> WorkState {
    storage.get_work(work.id).await.unwrap().unwrap().state
}

/// A drain lets an attempt in flight finish and record its outcome before it
/// returns: a host stopping the engine leaves no work claimed by nobody.
#[tokio::test]
async fn drain_waits_for_an_attempt_in_flight() {
    let storage = store().await;
    let probe = Probe::new(Duration::from_millis(150));
    let work = NewWork::new(kind(), vec![]);
    storage.enqueue_work(&work).await.unwrap();

    let running = Engine::new(parts(&storage, vec![probe.clone()], Maintenance::default()))
        .unwrap()
        .start();
    probe.started.notified().await;
    running.drain().await.unwrap();

    assert!(probe.finished.load(Ordering::SeqCst));
    assert_eq!(state(&storage, &work).await, WorkState::Completed);
}

/// Work committed while no engine handled it, or left pending at a drain, is
/// executed after a new start on the same store.
#[tokio::test]
async fn pending_work_resumes_after_a_new_start() {
    let storage = store().await;
    let idle = Engine::new(parts(&storage, vec![], Maintenance::default()))
        .unwrap()
        .start();
    let work = NewWork::new(kind(), vec![]);
    storage.enqueue_work(&work).await.unwrap();
    idle.drain().await.unwrap();
    assert_eq!(state(&storage, &work).await, WorkState::Pending);

    let probe = Probe::new(Duration::ZERO);
    let running = Engine::new(parts(&storage, vec![probe.clone()], Maintenance::default()))
        .unwrap()
        .start();
    tokio::time::timeout(Duration::from_secs(5), async {
        while state(&storage, &work).await != WorkState::Completed {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the resumed engine completes the pending work");
    running.drain().await.unwrap();
}

/// A drain stops every maintenance schedule: no job runs after it returns.
#[tokio::test]
async fn drain_stops_the_maintenance() {
    let storage = store().await;
    let runs = Arc::new(AtomicUsize::new(0));
    let counted = runs.clone();
    let maintenance = Maintenance::default().with(Job::shared(
        "count",
        Duration::from_millis(5),
        FirstRun::AtStart,
        Arc::new(move || {
            let counted = counted.clone();
            Box::pin(async move {
                counted.fetch_add(1, Ordering::SeqCst);
            })
        }),
    ));
    let running = Engine::new(parts(&storage, vec![], maintenance))
        .unwrap()
        .start();
    tokio::time::sleep(Duration::from_millis(40)).await;
    running.drain().await.unwrap();
    let after = runs.load(Ordering::SeqCst);
    assert!(after > 0, "the job ran while the engine ran");
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        after,
        "a job ran after the drain"
    );
}

/// An exclusive job runs on one engine at a time even when two engines share
/// the store, as two replicas do.
#[tokio::test]
async fn an_exclusive_job_runs_once_at_a_time_across_engines() {
    let storage = store().await;
    let (inside, most) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let job = || {
        let (inside, most) = (inside.clone(), most.clone());
        Job::exclusive(
            "exclusive",
            Duration::from_millis(5),
            FirstRun::AtStart,
            9_001,
            Arc::new(move || {
                let (inside, most) = (inside.clone(), most.clone());
                Box::pin(async move {
                    let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                    most.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    inside.fetch_sub(1, Ordering::SeqCst);
                })
            }),
        )
    };
    let a = Engine::new(parts(&storage, vec![], Maintenance::default().with(job())))
        .unwrap()
        .start();
    let b = Engine::new(parts(&storage, vec![], Maintenance::default().with(job())))
        .unwrap()
        .start();
    tokio::time::sleep(Duration::from_millis(150)).await;
    a.drain().await.unwrap();
    b.drain().await.unwrap();
    assert_eq!(most.load(Ordering::SeqCst), 1);
}

/// An engine whose runner cannot run (two handlers for one kind) is refused
/// before anything starts.
#[tokio::test]
async fn an_unrunnable_handler_set_is_refused() {
    let storage = store().await;
    let probe = Probe::new(Duration::ZERO);
    let refused = Engine::new(parts(
        &storage,
        vec![probe.clone(), probe],
        Maintenance::default(),
    ));
    assert!(matches!(refused, Err(EngineError::Runner(_))));
}

/// The CE maintenance names every job an installation owes.
#[tokio::test]
async fn the_ce_maintenance_owes_its_jobs() {
    use crate::maintenance::CeMaintenance;
    let storage = store().await;
    let cascade = Arc::new(
        sid_authn::revocation_cascade::RevocationCascadeService::new(
            storage.clone(),
            Arc::new(sid_authn::revocation_cache::RevocationCache::new(
                Duration::from_secs(900),
                Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
            )),
        ),
    );
    let maintenance = Maintenance::ce(CeMaintenance {
        closures: Arc::new(sid_authn::account_closure::AccountClosureService::new(
            storage.clone(),
            cascade,
        )),
        storage,
        history_evaluation: None,
        audit_retention: crate::AuditRetention::default(),
        migration_deadline_days: crate::maintenance::DEFAULT_MIGRATION_DEADLINE_DAYS,
        source: "test".into(),
    });
    assert_eq!(
        maintenance.job_names(),
        [
            "enrollment_compaction",
            "operation_upkeep",
            "ceremony_state_expiry",
            "pat_auto_revoke",
            "credential_expiry",
            "role_expiry",
            "quarantine_cleanup",
            "profile_purge",
            "migration_deadline",
            "audit_partition",
            "principal_expiry",
        ]
    );
}
