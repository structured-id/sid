// SPDX-License-Identifier: AGPL-3.0-only
//! In-process observation of the work a runner executes: attempts started,
//! their outcomes, attempts in flight, how long due work waited for a worker,
//! attempt duration and the time from storing work to completing it. Labels
//! are the work kind and the outcome, never a work id. Counters describe this
//! process only, so their sum over replicas is not a durable backlog.
//!
//! Recording touches no storage and takes no lock of its own: the instruments
//! and each kind's labels are built once when the runner is made. Without the
//! `telemetry` feature every call is empty.

use chrono::{DateTime, Utc};
use sid_core::models::{ClaimedWork, WorkKind};
use std::time::{Duration, Instant};

/// How an attempt ended, as far as this runner knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Settled {
    Completed,
    /// Failed and due again.
    Retried,
    /// The effect may have happened; due again.
    Ambiguous,
    /// Failed with no attempt left, or permanently: the dead-letter outcome.
    Failed,
    /// Another worker holds the work now; this outcome was refused.
    Reclaimed,
    /// Recording the outcome failed; the lease runs out and the work is retried.
    Unrecorded,
}

impl Settled {
    const ALL: [Self; 6] = [
        Self::Completed,
        Self::Retried,
        Self::Ambiguous,
        Self::Failed,
        Self::Reclaimed,
        Self::Unrecorded,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Retried => "retried",
            Self::Ambiguous => "ambiguous",
            Self::Failed => "failed",
            Self::Reclaimed => "reclaimed",
            Self::Unrecorded => "unrecorded",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Time from `since` to `now`, zero when `since` is later: the store's clock
/// stamps due and creation times, and a store clock ahead of this process
/// is not a negative wait.
fn elapsed(since: DateTime<Utc>, now: DateTime<Utc>) -> Duration {
    (now - since).to_std().unwrap_or(Duration::ZERO)
}

/// One kind's instruments and labels.
pub(super) struct KindObservation {
    #[cfg(feature = "telemetry")]
    inner: telemetry::Instruments,
}

impl KindObservation {
    pub(super) fn new(kind: &WorkKind) -> Self {
        #[cfg(not(feature = "telemetry"))]
        let _ = kind;
        Self {
            #[cfg(feature = "telemetry")]
            inner: telemetry::Instruments::new(kind),
        }
    }

    /// An attempt at `work` starts now; returns when it started.
    pub(super) fn started(&self, work: &ClaimedWork) -> Instant {
        #[cfg(feature = "telemetry")]
        self.inner.started(work, elapsed(work.due_at, Utc::now()));
        #[cfg(not(feature = "telemetry"))]
        let _ = work;
        Instant::now()
    }

    /// The attempt at `work` that began at `started` ended as `settled`.
    pub(super) fn finished(&self, work: &ClaimedWork, started: Instant, settled: Settled) {
        #[cfg(feature = "telemetry")]
        self.inner.finished(
            started.elapsed(),
            (settled == Settled::Completed).then(|| elapsed(work.created_at, Utc::now())),
            settled,
        );
        #[cfg(not(feature = "telemetry"))]
        let _ = (work, started, settled);
    }
}

#[cfg(feature = "telemetry")]
mod telemetry {
    use super::{Settled, WorkKind};
    use opentelemetry::KeyValue;
    use opentelemetry::global;
    use opentelemetry::metrics::{Counter, Histogram, UpDownCounter};
    use sid_core::models::ClaimedWork;
    use std::time::Duration;

    pub(super) struct Instruments {
        started: Counter<u64>,
        settled: Counter<u64>,
        active: UpDownCounter<i64>,
        queue_wait: Histogram<f64>,
        attempt: Histogram<f64>,
        completion: Histogram<f64>,
        kind: [KeyValue; 1],
        first_attempt: [KeyValue; 2],
        later_attempt: [KeyValue; 2],
        outcomes: [[KeyValue; 2]; Settled::ALL.len()],
    }

    impl Instruments {
        pub(super) fn new(kind: &WorkKind) -> Self {
            let meter = global::meter("sid");
            let kind = KeyValue::new("kind", kind.as_str().to_owned());
            let with =
                |key: &'static str, value: &'static str| [kind.clone(), KeyValue::new(key, value)];
            Self {
                started: meter
                    .u64_counter("sid_work_attempts_started_total")
                    .with_description("Durable work attempts started by this process")
                    .build(),
                settled: meter
                    .u64_counter("sid_work_attempts_settled_total")
                    .with_description("Durable work attempts ended by this process, by outcome")
                    .build(),
                active: meter
                    .i64_up_down_counter("sid_work_attempts_active")
                    .with_description("Durable work attempts in flight in this process")
                    .build(),
                queue_wait: meter
                    .f64_histogram("sid_work_queue_wait_seconds")
                    .with_description("Time from due to claimed for durable work")
                    .with_unit("s")
                    .build(),
                attempt: meter
                    .f64_histogram("sid_work_attempt_duration_seconds")
                    .with_description("Duration of one durable work attempt")
                    .with_unit("s")
                    .build(),
                completion: meter
                    .f64_histogram("sid_work_completion_seconds")
                    .with_description("Time from storing durable work to completing it")
                    .with_unit("s")
                    .build(),
                first_attempt: with("attempt", "first"),
                later_attempt: with("attempt", "later"),
                outcomes: Settled::ALL.map(|s| with("outcome", s.as_str())),
                kind: [kind],
            }
        }

        pub(super) fn started(&self, work: &ClaimedWork, waited: Duration) {
            let attempt = if work.attempt <= 1 {
                &self.first_attempt
            } else {
                &self.later_attempt
            };
            self.started.add(1, attempt);
            self.active.add(1, &self.kind);
            self.queue_wait.record(waited.as_secs_f64(), &self.kind);
        }

        pub(super) fn finished(
            &self,
            attempt: Duration,
            completion: Option<Duration>,
            settled: Settled,
        ) {
            self.active.add(-1, &self.kind);
            self.attempt.record(attempt.as_secs_f64(), &self.kind);
            self.settled.add(1, &self.outcomes[settled.index()]);
            if let Some(completion) = completion {
                self.completion.record(completion.as_secs_f64(), &self.kind);
            }
        }
    }
}

#[cfg(test)]
mod tests;
