// SPDX-License-Identifier: AGPL-3.0-only
//! The terminal step of a first enrollment. The credential authority admits
//! a new owner's registration as durable work before the evaluator makes the
//! owner's key; at the registration's expiry the work runs once:
//!
//! - when the registration committed, its commit recorded the operation's
//!   completion and there is nothing to do;
//! - otherwise the work records the operation's abort as its completion,
//!   which a later commit of the operation can no longer write over (the two
//!   race on one key: exactly one wins), and the evaluator is told to
//!   reclaim the key the operation created. In a standalone installation it
//!   runs in this process and is told directly; a separate evaluator gets the
//!   fact as an event relayed with the abort, through the event bus.

use std::sync::Arc;

use sid_authn::event_relay::RELAY_RETRY;
use sid_authn::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use sid_core::models::event::event_types;
use sid_core::models::{
    AuditEntry, ClaimedWork, ENROLLMENT_ADMISSION_KIND, EnrollmentAdmission, EnrollmentCleanup,
    Event, MutationContext, NewWork, OperationCompletion, OperationKey, RelayedCleanup, WorkId,
    WorkKind, cleanup_successor,
};
use sid_plugin::storage::StorageBackend;
use tracing::{error, info};

use super::{HistoryEvaluation, RESULT_NAMESPACE};

/// The method an aborted operation's completion records; any other method
/// under the operation's key is its commit.
const ABORT_METHOD: &str = "password_history.enrollment_abort";

/// Namespace of the relayed abort events' ids, one per operation.
const ABORT_EVENT_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x6a1e_93c4_2f0b_4c7d_8e55_b3a9_10d2_7f64);

/// How long the records of an ended first enrollment are kept: its ended
/// work, its abort's completion and the evaluator's fence. Past an
/// operation's lifetime and the tolerated clock skew no preparation, finish
/// or commit of it can still arrive, so each is then no longer needed.
const ENROLLMENT_RECORD_RETENTION: chrono::Duration = chrono::Duration::days(1);

/// Drop the records of first enrollments and owner purges that ended more
/// than a day ago: their ended work, the aborts' completions and, with the
/// evaluator in this process, its fences. Open work, a commit's completion
/// and every key are untouched. Returns how many records were dropped.
pub(crate) async fn compact_enrollments(
    storage: &dyn StorageBackend,
    evaluation: Option<&HistoryEvaluation>,
    now: chrono::DateTime<chrono::Utc>,
) -> sid_core::Result<u64> {
    let before = now - ENROLLMENT_RECORD_RETENTION;
    let mut dropped = 0;
    // Ended purges of deleted owners go with them: their fences are
    // compacted below on the same terms.
    for kind in [
        ENROLLMENT_ADMISSION_KIND,
        sid_core::models::OWNER_PURGE_KIND,
    ] {
        let kind = WorkKind::new(kind).expect("the history work kinds are valid");
        dropped += storage.purge_ended_work(&kind, before).await?;
    }
    dropped += storage
        .purge_operation_results(RESULT_NAMESPACE, ABORT_METHOD, before)
        .await?;
    // A settlement dropped before its work saw it costs one more relay,
    // which the evaluator settles again harmlessly.
    dropped += storage
        .purge_operation_results(
            sid_core::models::CLEANUP_SETTLED_NAMESPACE,
            super::relayed::SETTLED_METHOD,
            before,
        )
        .await?;
    if let Some(evaluation) = evaluation {
        dropped += evaluation.compact_abandoned(before).await?;
    }
    Ok(dropped)
}

/// Where the evaluator is told of what the credential authority settled: an
/// aborted enrollment, a deleted owner.
#[derive(Clone)]
pub(crate) enum EvaluatorDelivery {
    /// The evaluator in this process.
    InProcess(Arc<HistoryEvaluation>),
    /// A separate evaluator, through an event relayed in the same
    /// transaction; `source` names this credential authority in the event.
    Relay { source: String },
}

/// Ends each first enrollment at its expiry.
pub(crate) struct EnrollmentHandler {
    kind: WorkKind,
    storage: Arc<dyn StorageBackend>,
    delivery: EvaluatorDelivery,
}

impl EnrollmentHandler {
    pub(crate) fn new(storage: Arc<dyn StorageBackend>, delivery: EvaluatorDelivery) -> Self {
        Self {
            kind: WorkKind::new(ENROLLMENT_ADMISSION_KIND).expect("the enrollment kind is valid"),
            storage,
            delivery,
        }
    }

    /// Record `admission`'s abort, unless the registration committed first;
    /// an error when its outcome cannot be settled now.
    async fn abort(&self, admission: &EnrollmentAdmission) -> Result<Abort, String> {
        let key = OperationKey::parse(&admission.operation.to_string())
            .map_err(|e| format!("operation key: {e}"))?;
        let completion =
            OperationCompletion::new(RESULT_NAMESPACE, key.clone(), ABORT_METHOD, &[], Vec::new());
        let mut ctx = MutationContext::from(AuditEntry::system(
            "password_history.enrollment_aborted",
            "password_history",
        ))
        .with_operation(completion);
        if let EvaluatorDelivery::Relay { source } = &self.delivery {
            // Owed in the abort's own transaction: the separate evaluator
            // learns of every abort that is recorded, and of no other.
            ctx = ctx.with_work(abort_event(source, admission, None)?);
        }
        match self.storage.record_outcome(ctx).await {
            Ok(()) => Ok(Abort::Now),
            Err(sid_core::Error::OperationCompleted(_)) => {
                match self
                    .storage
                    .get_operation_result(RESULT_NAMESPACE, &key)
                    .await
                {
                    Ok(Some(record)) if record.completion.method == ABORT_METHOD => {
                        Ok(Abort::Earlier)
                    }
                    Ok(Some(_)) => Ok(Abort::Committed),
                    Ok(None) => Err("the operation's completion vanished".into()),
                    Err(e) => Err(format!("operation completion: {e}")),
                }
            }
            Err(e) => Err(format!("record the abort: {e}")),
        }
    }

    /// Relay `admission`'s abort once more, as a new event of `attempt` of
    /// the work `work`: the earlier one may have aged out unconsumed.
    async fn relay_again(
        &self,
        source: &str,
        admission: &EnrollmentAdmission,
        work: WorkId,
        attempt: u32,
    ) -> Result<(), String> {
        let ctx = MutationContext::from(AuditEntry::system(
            "password_history.enrollment_abort_relayed",
            "password_history",
        ))
        .with_work(abort_event(source, admission, Some((work, attempt)))?);
        self.storage
            .record_outcome(ctx)
            .await
            .map_err(|e| format!("relay the abort again: {e}"))
    }
}

/// What an attempt found of its operation's outcome.
enum Abort {
    /// The registration committed first: nothing to clean up.
    Committed,
    /// This attempt recorded the abort, and with it the first relayed event.
    Now,
    /// An earlier attempt (of this work or the one it continues) recorded it.
    Earlier,
}

/// The id of the event telling a separate evaluator that `operation`
/// aborted: the one owed with the abort itself (`relay` none; a retried
/// abort owes the same one), then one per (work, attempt) relaying it again.
pub(crate) fn abort_event_id(operation: uuid::Uuid, relay: Option<(WorkId, u32)>) -> uuid::Uuid {
    match relay {
        None => uuid::Uuid::new_v5(&ABORT_EVENT_NAMESPACE, operation.as_bytes()),
        Some((work, attempt)) => uuid::Uuid::new_v5(
            &ABORT_EVENT_NAMESPACE,
            format!("{operation}:{}:{attempt}", work.0).as_bytes(),
        ),
    }
}

/// The relayed event telling a separate evaluator that `admission` aborted
/// (see [`abort_event_id`]).
fn abort_event(
    source: &str,
    admission: &EnrollmentAdmission,
    relay: Option<(WorkId, u32)>,
) -> Result<NewWork, String> {
    let mut event = Event::new(source, event_types::PASSWORD_HISTORY_ENROLLMENT_ABORTED)
        .with_data(serde_json::to_value(admission).map_err(|e| format!("event data: {e}"))?);
    event.id = abort_event_id(admission.operation, relay).to_string();
    Ok(event.relay())
}

#[tonic::async_trait]
impl WorkHandler for EnrollmentHandler {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RELAY_RETRY
    }

    /// The failed work is the actionable record of an aborted enrollment
    /// whose key could not be reclaimed yet; the cleanup goes on in its
    /// successor, so the key goes once the evaluator is back.
    fn on_dead(&self, work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        cleanup_successor(work)
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let admission = match EnrollmentAdmission::from_work(&work.payload) {
            Ok(admission) => admission,
            Err(e) => return WorkOutcome::Permanent(e.to_string()),
        };
        let aborted = match self.abort(&admission).await {
            Ok(Abort::Committed) => return WorkOutcome::Done(Some("committed".into())),
            Ok(aborted) => aborted,
            Err(e) => return WorkOutcome::Retry(e),
        };
        match &self.delivery {
            // The first relayed event is owed in the abort's transaction; the
            // separate evaluator reclaims the key as it consumes it
            // ([`super::consume_relayed_cleanup`]) and reports the
            // settlement. Until that is recorded the abort stays owed and a
            // later attempt relays it again, so an event that aged out of the
            // stream or met an evaluator outage is not lost.
            EvaluatorDelivery::Relay { source } => {
                let cleanup = RelayedCleanup::Enrollment {
                    operation: admission.operation,
                };
                match super::relayed::settled(self.storage.as_ref(), &cleanup).await {
                    Ok(true) => WorkOutcome::Done(Some("settled by the evaluator".into())),
                    Ok(false) if matches!(aborted, Abort::Now) => {
                        WorkOutcome::Retry("abort relayed; awaiting the evaluator".into())
                    }
                    Ok(false) => match self
                        .relay_again(source, &admission, work.id, work.attempt)
                        .await
                    {
                        Ok(()) => {
                            WorkOutcome::Retry("abort relayed again; awaiting the evaluator".into())
                        }
                        Err(e) => WorkOutcome::Retry(e),
                    },
                    Err(e) => WorkOutcome::Retry(format!("settlement: {e}")),
                }
            }
            EvaluatorDelivery::InProcess(evaluation) => match evaluation
                .abandon_enrollment(&admission.owner_domain, admission.operation)
                .await
            {
                Ok(EnrollmentCleanup::Reclaimed) => {
                    info!(operation = %admission.operation, "aborted enrollment's key reclaimed");
                    WorkOutcome::Done(Some("reclaimed".into()))
                }
                Ok(EnrollmentCleanup::NothingCreated) => {
                    WorkOutcome::Done(Some("no key created".into()))
                }
                Ok(EnrollmentCleanup::Retained(reason)) => {
                    error!(
                        operation = %admission.operation,
                        "an aborted enrollment's key is still needed: {reason}"
                    );
                    WorkOutcome::Permanent(format!("key retained: {reason}"))
                }
                Err(e) => WorkOutcome::Retry(format!("reclaim: {e}")),
            },
        }
    }
}

#[cfg(test)]
mod tests;
