// SPDX-License-Identifier: AGPL-3.0-only
//! Start and drain of the engine's required work on the host's runtime: the
//! durable work runner and the maintenance jobs. Work an engine commits is
//! stored before anything runs it, so a drain loses none: a new start on the
//! same store resumes whatever was still pending.

use std::sync::Arc;

use sid_authn::work_runner::{RunnerConfig, WorkHandler, WorkRunner, WorkWaker};
use sid_plugin::storage::StorageBackend;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::maintenance::Maintenance;

/// Why the engine did not start or did not drain cleanly.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The work runner refused its configuration or its handlers.
    #[error("work runner: {0}")]
    Runner(sid_core::Error),
    /// A task of the engine panicked or was aborted.
    #[error("engine task {task} ended abnormally: {source}")]
    Task {
        task: &'static str,
        #[source]
        source: tokio::task::JoinError,
    },
}

/// What a host hands the engine to run.
pub struct EngineParts {
    /// The store the work and the maintenance act on.
    pub storage: Arc<dyn StorageBackend>,
    /// This process's name among the workers claiming work; distinct per
    /// process, so leases tell attempts apart.
    pub worker: String,
    /// One handler per work kind the engine owes.
    pub handlers: Vec<Arc<dyn WorkHandler>>,
    pub runner: RunnerConfig,
    pub maintenance: Maintenance,
}

/// The engine's required work, not yet running.
pub struct Engine {
    storage: Arc<dyn StorageBackend>,
    runner: WorkRunner,
    maintenance: Maintenance,
}

impl Engine {
    /// The engine over `parts`; refuses a runner configuration or handler set
    /// it could not run.
    pub fn new(parts: EngineParts) -> Result<Self, EngineError> {
        let runner = WorkRunner::new(
            parts.storage.clone(),
            parts.worker,
            parts.handlers,
            parts.runner,
        )
        .map_err(EngineError::Runner)?;
        Ok(Self {
            storage: parts.storage,
            runner,
            maintenance: parts.maintenance,
        })
    }

    /// Wakes the runner after work was committed, shortening its wait.
    pub fn waker(&self) -> WorkWaker {
        self.runner.waker()
    }

    /// Start the runner and the maintenance schedules on the current tokio
    /// runtime. Pending work stored earlier, by this or a previous run, is
    /// claimed like any other.
    pub fn start(self) -> Running {
        let (stop, stopped) = watch::channel(false);
        let jobs = self.maintenance.spawn(self.storage.clone(), &stopped);
        let mut runner_stop = stopped.clone();
        let runner = tokio::spawn(self.runner.run(async move {
            // A dropped sender stops the runner as a drain does.
            while !*runner_stop.borrow() {
                if runner_stop.changed().await.is_err() {
                    break;
                }
            }
        }));
        Running { stop, runner, jobs }
    }
}

/// The engine's work running on the host's runtime.
pub struct Running {
    stop: watch::Sender<bool>,
    runner: JoinHandle<()>,
    jobs: Vec<JoinHandle<()>>,
}

/// Proof that an engine's work stopped: its runner and maintenance ended
/// and nothing they started is still in flight. What needs a quiesced
/// engine, a snapshot export among it, takes this.
#[derive(Debug)]
pub struct Drained(());

impl Running {
    /// Stop claiming work and starting job runs; attempts and runs in flight
    /// finish and record their outcome before this returns. Work still
    /// pending stays stored for the next start.
    pub async fn drain(self) -> Result<Drained, EngineError> {
        // Stored even when every task already ended and dropped its receiver.
        self.stop.send_replace(true);
        let mut failure = None;
        if let Err(source) = self.runner.await {
            failure = Some(EngineError::Task {
                task: "work runner",
                source,
            });
        }
        for job in self.jobs {
            if let Err(source) = job.await {
                failure.get_or_insert(EngineError::Task {
                    task: "maintenance",
                    source,
                });
            }
        }
        failure.map_or(Ok(Drained(())), Err)
    }
}

#[cfg(test)]
mod tests;
