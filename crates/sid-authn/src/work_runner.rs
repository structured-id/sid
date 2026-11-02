// SPDX-License-Identifier: AGPL-3.0-only
//! Storage-backed worker for durable work. It finds pending work in storage
//! on start and while running (a wake-up only shortens the wait, losing one
//! strands nothing), runs each item under a lease with bounded concurrency,
//! and records every outcome fenced by the claim generation.

use async_trait::async_trait;
use sid_core::models::{ClaimedWork, NewWork, WorkFailure, WorkKind};
use sid_plugin::WorkStore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;

/// Result of one attempt at a piece of work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkOutcome {
    /// Done: recorded completed, with what it produced (a provider receipt).
    Done(Option<String>),
    /// Not done this time; tried again on the handler's schedule until
    /// attempts run out.
    Retry(String),
    /// Unknown whether the effect happened (the reply was lost); recorded as
    /// such and tried again under the kind's idempotency rules.
    Ambiguous(String),
    /// Can never succeed (a rejected recipient): failed now, no retry.
    Permanent(String),
}

/// Delays between attempts: the delay after attempt `n` is entry `n - 1`,
/// the last entry repeating once the schedule is exhausted.
#[derive(Debug, Clone, Copy)]
pub struct RetrySchedule(&'static [Duration]);

impl RetrySchedule {
    /// A schedule of at least one delay, each at most one day (so a retry
    /// time is always representable).
    pub const fn new(delays: &'static [Duration]) -> Self {
        assert!(!delays.is_empty(), "a retry schedule needs a delay");
        let mut i = 0;
        while i < delays.len() {
            assert!(
                delays[i].as_secs() <= 86_400,
                "a retry delay is at most one day"
            );
            i += 1;
        }
        Self(delays)
    }

    /// Delay after attempt `attempt` (counted from 1).
    pub fn after(&self, attempt: u32) -> Duration {
        debug_assert!(attempt >= 1, "a claimed attempt counts from 1");
        let index = usize::try_from(attempt.max(1) - 1).unwrap_or(usize::MAX);
        self.0[index.min(self.0.len() - 1)]
    }
}

/// Performs one kind of work. A handler may run more than once for the same
/// work (a lease can run out mid-attempt), so its effect must tolerate that.
#[async_trait]
pub trait WorkHandler: Send + Sync + 'static {
    fn kind(&self) -> &WorkKind;

    /// When a failed attempt is tried again; the policy belongs to the kind
    /// (a delivery channel, a relay) rather than to the runner.
    fn retry_schedule(&self) -> RetrySchedule;

    /// Work committed together with the failure that ends `work` (its
    /// dead-letter alert), or `None` when the kind raises none.
    fn on_dead(&self, work: &ClaimedWork, error: &str) -> Option<NewWork>;

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome;
}

/// Bounds and timing of a runner.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Attempts running at once.
    pub concurrency: usize,
    /// How long a claim is held; an attempt should finish well within it.
    pub lease: Duration,
    /// How often storage is scanned when nothing wakes the runner.
    pub scan_interval: Duration,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            concurrency: 8,
            lease: Duration::from_secs(60),
            scan_interval: Duration::from_secs(5),
        }
    }
}

/// Shortens the runner's wait after work was committed.
#[derive(Clone)]
pub struct WorkWaker(Arc<Notify>);

impl WorkWaker {
    pub fn wake(&self) {
        self.0.notify_one();
    }
}

pub struct WorkRunner {
    storage: Arc<dyn WorkStore>,
    handlers: HashMap<WorkKind, Arc<dyn WorkHandler>>,
    kinds: Vec<WorkKind>,
    worker: String,
    config: RunnerConfig,
    wake: Arc<Notify>,
    slots: Arc<Semaphore>,
}

impl WorkRunner {
    /// A runner named `worker` (distinct per process) over `handlers`, one per kind.
    pub fn new(
        storage: Arc<dyn WorkStore>,
        worker: impl Into<String>,
        handlers: Vec<Arc<dyn WorkHandler>>,
        config: RunnerConfig,
    ) -> sid_core::Result<Self> {
        let invalid = |what: &str| Err(sid_core::Error::Validation(format!("work runner: {what}")));
        if config.concurrency == 0 {
            return invalid("concurrency must be positive");
        }
        if config.lease.is_zero() || config.scan_interval.is_zero() {
            return invalid("lease and scan interval must be positive");
        }
        let mut by_kind = HashMap::with_capacity(handlers.len());
        for handler in handlers {
            let kind = handler.kind().clone();
            if by_kind.insert(kind.clone(), handler).is_some() {
                return invalid(&format!("two handlers for work kind {}", kind.as_str()));
            }
        }
        Ok(Self {
            storage,
            kinds: by_kind.keys().cloned().collect(),
            handlers: by_kind,
            worker: worker.into(),
            slots: Arc::new(Semaphore::new(config.concurrency)),
            config,
            wake: Arc::new(Notify::new()),
        })
    }

    pub fn waker(&self) -> WorkWaker {
        WorkWaker(Arc::clone(&self.wake))
    }

    /// Run until `shutdown` resolves, then wait for attempts in flight.
    pub async fn run(self, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        let mut in_flight = JoinSet::new();
        loop {
            while in_flight.try_join_next().is_some() {}
            if self.claim_into(&mut in_flight).await == Some(true) {
                // Every free slot was filled: more work may be due right away.
                continue;
            }
            tokio::select! {
                () = &mut shutdown => break,
                () = self.wake.notified() => {}
                () = tokio::time::sleep(self.config.scan_interval) => {}
            }
        }
        while in_flight.join_next().await.is_some() {}
    }

    /// Claim due work for the free slots and start it. Returns whether every
    /// free slot was filled, or `None` when nothing could be claimed.
    async fn claim_into(&self, in_flight: &mut JoinSet<()>) -> Option<bool> {
        let free = self.slots.available_permits();
        if free == 0 || self.kinds.is_empty() {
            return None;
        }
        let limit = u32::try_from(free).unwrap_or(u32::MAX);
        let claimed = match self
            .storage
            .claim_work(&self.kinds, &self.worker, limit, self.config.lease)
            .await
        {
            Ok(claimed) => claimed,
            Err(e) => {
                tracing::warn!(error = %e, "claiming durable work failed");
                return None;
            }
        };
        let full = claimed.len() == free;
        for work in claimed {
            let Some(handler) = self.handlers.get(&work.kind).map(Arc::clone) else {
                // Storage returned a kind that was not asked for; its lease runs
                // out and a runner that handles it takes it.
                tracing::error!(work = %work.id, kind = work.kind.as_str(), "claimed work of an unhandled kind");
                continue;
            };
            let slot = Arc::clone(&self.slots)
                .try_acquire_owned()
                .expect("only this loop takes slots and it claimed no more than were free");
            let storage = Arc::clone(&self.storage);
            let wake = Arc::clone(&self.wake);
            in_flight.spawn(async move {
                attempt(storage.as_ref(), handler.as_ref(), &work).await;
                drop(slot);
                wake.notify_one();
            });
        }
        Some(full)
    }
}

/// Run one attempt and record its outcome.
async fn attempt(storage: &dyn WorkStore, handler: &dyn WorkHandler, work: &ClaimedWork) {
    let (error, ambiguous, retry) = match handler.handle(work).await {
        WorkOutcome::Done(result) => {
            let recorded = storage
                .complete_work(work.id, work.generation, result.as_deref())
                .await;
            return report(work, recorded);
        }
        WorkOutcome::Retry(error) => (error, false, true),
        WorkOutcome::Ambiguous(error) => (error, true, true),
        WorkOutcome::Permanent(error) => (error, false, false),
    };
    let retry_at = retry.then(|| {
        let delay = handler.retry_schedule().after(work.attempt);
        chrono::Utc::now()
            + chrono::Duration::from_std(delay).expect("a retry delay is at most one day")
    });
    // The alert is offered on every failure; storage commits it only when
    // this failure ends the work.
    let failure = WorkFailure {
        on_dead: handler.on_dead(work, &error),
        error,
        ambiguous,
        retry_at,
    };
    report(
        work,
        storage.fail_work(work.id, work.generation, &failure).await,
    );
}

fn report(work: &ClaimedWork, recorded: sid_core::Result<bool>) {
    match recorded {
        Ok(true) => {}
        Ok(false) => tracing::warn!(
            work = %work.id,
            "durable work was reclaimed before its outcome was recorded"
        ),
        // The claim stays until its lease runs out; the work is then retried.
        Err(e) => tracing::warn!(work = %work.id, error = %e, "recording a work outcome failed"),
    }
}

#[cfg(test)]
mod tests;
