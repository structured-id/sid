// SPDX-License-Identifier: AGPL-3.0-only
//! Replicas over one PostgreSQL database with no broker: their work runners
//! claim committed work from that database under fenced leases, so every
//! piece of work is done exactly once whichever replica takes it, and work
//! committed while a replica is down is done by the one still running.
//!
//! Requires sid-test-postgres on port 54399.

use async_trait::async_trait;
use sid_authn::work_runner::{RetrySchedule, RunnerConfig, WorkHandler, WorkOutcome, WorkRunner};
use sid_core::models::{ClaimedWork, NewWork, WorkId, WorkKind, WorkState};
use sid_plugin::WorkStore;
use sid_storage::PostgresBackend;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

const KIND: &str = "test.shared_replica";

const RETRY: RetrySchedule = RetrySchedule::new(&[Duration::from_secs(1)]);

/// Counts every attempt per work id and which replica made it.
struct Counting {
    kind: WorkKind,
    replica: &'static str,
    attempts: Arc<Mutex<HashMap<WorkId, Vec<&'static str>>>>,
}

#[async_trait]
impl WorkHandler for Counting {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RETRY
    }

    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        self.attempts
            .lock()
            .unwrap()
            .entry(work.id)
            .or_default()
            .push(self.replica);
        // Long enough that both replicas hold claims at once.
        tokio::time::sleep(Duration::from_millis(20)).await;
        WorkOutcome::Done(None)
    }
}

/// One replica: its own connection pool to the shared schema and its runner.
async fn replica(schema: &str) -> Arc<PostgresBackend> {
    Arc::new(
        PostgresBackend::new(&database_url(), Some(schema.to_string()))
            .await
            .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?"),
    )
}

fn start(
    store: Arc<PostgresBackend>,
    replica: &'static str,
    attempts: &Arc<Mutex<HashMap<WorkId, Vec<&'static str>>>>,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let handler: Arc<dyn WorkHandler> = Arc::new(Counting {
        kind: WorkKind::new(KIND).unwrap(),
        replica,
        attempts: attempts.clone(),
    });
    let config = RunnerConfig {
        concurrency: 4,
        lease: Duration::from_secs(30),
        scan_interval: Duration::from_millis(20),
    };
    let runner = WorkRunner::new(store, replica, vec![handler], config).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    (
        stop,
        tokio::spawn(runner.run(async move { stopped.await.unwrap_or(()) })),
    )
}

async fn wait_completed(store: &PostgresBackend, ids: &[WorkId]) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let mut done = 0;
        for id in ids {
            if store.get_work(*id).await.unwrap().unwrap().state == WorkState::Completed {
                done += 1;
            }
        }
        if done == ids.len() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{done} of {} completed",
            ids.len()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn replicas_share_the_database(schema: String) {
    let (a, b) = (replica(&schema).await, replica(&schema).await);
    let attempts = Arc::new(Mutex::new(HashMap::new()));
    let (stop_a, run_a) = start(a.clone(), "a", &attempts);
    let (stop_b, run_b) = start(b.clone(), "b", &attempts);

    let mut ids = Vec::new();
    for i in 0..40u32 {
        let work = NewWork::new(WorkKind::new(KIND).unwrap(), i.to_be_bytes().to_vec());
        ids.push(work.id);
        // Committed through either replica, as a mutation on it would.
        let through = if i % 2 == 0 { &a } else { &b };
        through.enqueue_work(&work).await.unwrap();
    }
    wait_completed(&a, &ids).await;

    // Replica a goes down; work committed now is done by b alone.
    stop_a.send(()).unwrap();
    run_a.await.unwrap();
    let mut later = Vec::new();
    for i in 0..5u32 {
        let work = NewWork::new(WorkKind::new(KIND).unwrap(), i.to_be_bytes().to_vec());
        later.push(work.id);
        a.enqueue_work(&work).await.unwrap();
    }
    wait_completed(&b, &later).await;
    stop_b.send(()).unwrap();
    run_b.await.unwrap();

    let attempts = attempts.lock().unwrap();
    for id in ids.iter().chain(&later) {
        assert_eq!(
            attempts.get(id).map(Vec::len),
            Some(1),
            "work {id} was not done exactly once"
        );
    }
    let by_a = ids.iter().filter(|id| attempts[*id] == ["a"]).count();
    assert!(
        by_a > 0 && by_a < ids.len(),
        "one replica did all the work ({by_a} of {} by a)",
        ids.len()
    );
    assert!(later.iter().all(|id| attempts[id] == ["b"]));
}

/// Two replicas over one database and no broker do every piece of work
/// once, share it between them, and the survivor does what is committed
/// while the other is down.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicas_without_a_broker_do_each_work_once() {
    let schema = format!("shared_replicas_{}", uuid::Uuid::now_v7().simple());
    let setup = PostgresBackend::new(&database_url(), Some(schema.clone()))
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(setup.pool(), Some(&schema))
        .await
        .expect("migrations in an isolated schema");
    let pool = setup.pool().clone();
    let outcome = tokio::spawn(replicas_share_the_database(schema.clone())).await;
    for statement in [
        format!("DROP SCHEMA \"{schema}\" CASCADE"),
        format!("DROP ROLE IF EXISTS \"{schema}_reader\""),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}
