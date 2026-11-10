// SPDX-License-Identifier: AGPL-3.0-only
//! In-process observation of the work a runner executes: attempts started,
//! their outcomes, attempts in flight, how long due work waited for a worker,
//! attempt duration and the time from storing work to completing it. Labels
//! are the work kind and the outcome, never a work id. Counters describe this
//! process only, so their sum over replicas is not a durable backlog.
//!
//! Recording touches no storage and takes no lock of its own: the instruments
//! and each kind's labels are built once when the runner is made. Without the
//! `telemetry` feature the observation is a zero-sized value: no allocation,
//! reference count, clock read or recording.
//!
//! Intake is not observed here: work is accepted where its owner commits it,
//! not in the runner, and attempts started are the start of processing, which
//! is zero while no runner runs however much work is accepted.

#[cfg(feature = "telemetry")]
use chrono::{DateTime, Utc};
use sid_core::models::{ClaimedWork, WorkKind};
#[cfg(feature = "telemetry")]
use std::sync::Arc;
#[cfg(any(feature = "telemetry", test))]
use std::time::Duration;

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
    /// The attempt ended without an outcome (its handler panicked or the
    /// runner was stopped mid-attempt); the lease runs out and the work is
    /// retried.
    Abandoned,
}

impl Settled {
    const ALL: [Self; 7] = [
        Self::Completed,
        Self::Retried,
        Self::Ambiguous,
        Self::Failed,
        Self::Reclaimed,
        Self::Unrecorded,
        Self::Abandoned,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Retried => "retried",
            Self::Ambiguous => "ambiguous",
            Self::Failed => "failed",
            Self::Reclaimed => "reclaimed",
            Self::Unrecorded => "unrecorded",
            Self::Abandoned => "abandoned",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Time from `since` to `now`, zero when `since` is later: the store's clock
/// stamps due and creation times, and a store clock ahead of this process
/// is not a negative wait.
#[cfg(any(feature = "telemetry", test))]
fn elapsed(since: chrono::DateTime<chrono::Utc>, now: chrono::DateTime<chrono::Utc>) -> Duration {
    (now - since).to_std().unwrap_or(Duration::ZERO)
}

/// One kind's instruments and labels, shared by its attempts.
#[derive(Clone)]
pub(super) struct KindObservation {
    #[cfg(feature = "telemetry")]
    inner: Arc<telemetry::Instruments>,
}

impl KindObservation {
    pub(super) fn new(kind: &WorkKind) -> Self {
        #[cfg(not(feature = "telemetry"))]
        let _ = kind;
        Self {
            #[cfg(feature = "telemetry")]
            inner: Arc::new(telemetry::Instruments::new(kind)),
        }
    }

    /// An attempt at `work` starts now. The attempt is observed as abandoned
    /// if it is dropped before it settles (a panic, or the runner stopping it).
    pub(super) fn start(&self, work: &ClaimedWork) -> Attempt {
        #[cfg(not(feature = "telemetry"))]
        let _ = work;
        Attempt {
            #[cfg(feature = "telemetry")]
            in_flight: self.inner.start(work, elapsed(work.due_at, Utc::now())),
        }
    }
}

/// An attempt in flight.
pub(super) struct Attempt {
    #[cfg(feature = "telemetry")]
    in_flight: telemetry::InFlight,
}

impl Attempt {
    /// The attempt ended as `settled`.
    pub(super) fn settle(self, settled: Settled) {
        #[cfg(feature = "telemetry")]
        self.in_flight.settle(settled);
        #[cfg(not(feature = "telemetry"))]
        let _ = settled;
    }
}

#[cfg(feature = "telemetry")]
mod telemetry {
    use super::{DateTime, Settled, Utc, WorkKind, elapsed};
    use opentelemetry::KeyValue;
    use opentelemetry::global;
    use opentelemetry::metrics::{Counter, Histogram, UpDownCounter};
    use sid_core::models::ClaimedWork;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

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

        pub(super) fn start(self: &Arc<Self>, work: &ClaimedWork, waited: Duration) -> InFlight {
            let attempt = if work.attempt <= 1 {
                &self.first_attempt
            } else {
                &self.later_attempt
            };
            self.started.add(1, attempt);
            self.active.add(1, &self.kind);
            self.queue_wait.record(waited.as_secs_f64(), &self.kind);
            InFlight {
                instruments: Arc::clone(self),
                started: Instant::now(),
                created_at: work.created_at,
                settled: false,
            }
        }

        fn finished(&self, attempt: Duration, completion: Option<Duration>, settled: Settled) {
            self.active.add(-1, &self.kind);
            self.attempt.record(attempt.as_secs_f64(), &self.kind);
            self.settled.add(1, &self.outcomes[settled.index()]);
            if let Some(completion) = completion {
                self.completion.record(completion.as_secs_f64(), &self.kind);
            }
        }
    }

    /// An attempt counted in flight until it settles or is dropped.
    pub(super) struct InFlight {
        instruments: Arc<Instruments>,
        started: Instant,
        created_at: DateTime<Utc>,
        settled: bool,
    }

    impl InFlight {
        pub(super) fn settle(mut self, settled: Settled) {
            self.settled = true;
            let completion =
                (settled == Settled::Completed).then(|| elapsed(self.created_at, Utc::now()));
            self.instruments
                .finished(self.started.elapsed(), completion, settled);
        }
    }

    impl Drop for InFlight {
        fn drop(&mut self) {
            if !self.settled {
                self.instruments
                    .finished(self.started.elapsed(), None, Settled::Abandoned);
            }
        }
    }
}

#[cfg(test)]
mod tests;
