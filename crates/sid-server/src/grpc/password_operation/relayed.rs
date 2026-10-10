// SPDX-License-Identifier: AGPL-3.0-only
//! A separate evaluator's side of the relayed cleanup. The credential
//! authority owes an aborted first enrollment's and a deleted owner's cleanup
//! as an event relayed with the decision that made it; the evaluator consumes
//! those events durably and acts on each: it reclaims the enrollment's key,
//! or destroys the owner's keys. An event is acknowledged only once its
//! effect is recorded in the evaluator's store, so a crash, a lost
//! acknowledgement or an evaluator outage delivers it again; both effects
//! are idempotent there. A standalone installation does neither: its
//! evaluator runs in process and is told directly.

use std::sync::Arc;
use std::time::Duration;

use sid_core::models::event::{Event, event_types};
use sid_core::models::{EnrollmentAdmission, EnrollmentCleanup, OwnerPurge};
use sid_plugin::event_bus::{DurableConsumer, EventBus, EventBusResult, Settlement};
use tracing::{error, info, warn};

use super::HistoryEvaluation;

/// The durable consumer every replica of a separate evaluator shares.
pub const CLEANUP_CONSUMER: &str = "password-history-evaluator-cleanup";

/// When an event whose effect failed (the evaluator's store unavailable) is
/// delivered again.
const RETRY: Duration = Duration::from_secs(30);

/// When an aborted enrollment whose key is still needed is looked at again:
/// what holds the key (another operation, a recorded lifecycle) can end, and
/// the obligation stays until it does.
const RETAINED_RETRY: Duration = Duration::from_secs(60 * 60);

/// Consume the relayed cleanup of the credential authority named `source` on
/// `bus`, acting on each event through `evaluation`, until the bus ends the
/// consumer. The authenticity of an event is the bus's: only the credential
/// authority may publish on its subjects; `source` keeps another authority's
/// events, which this evaluator does not serve, from being acted on.
pub async fn consume_relayed_cleanup(
    bus: &dyn EventBus,
    evaluation: Arc<HistoryEvaluation>,
    source: &str,
) -> EventBusResult<()> {
    let mut deliveries = bus
        .consume(DurableConsumer {
            name: CLEANUP_CONSUMER.into(),
            event_types: vec![
                event_types::PASSWORD_HISTORY_ENROLLMENT_ABORTED.into(),
                event_types::PASSWORD_HISTORY_OWNER_PURGED.into(),
            ],
        })
        .await?;
    while let Some(delivery) = deliveries.recv().await {
        let settlement = settle(&evaluation, source, &delivery.event).await;
        delivery.settle(settlement);
    }
    Ok(())
}

/// What acting on `event` came to.
async fn settle(evaluation: &HistoryEvaluation, source: &str, event: &Event) -> Settlement {
    if event.source != source {
        return Settlement::Reject(format!(
            "event {} is from another credential authority",
            event.id
        ));
    }
    match event.event_type.as_str() {
        event_types::PASSWORD_HISTORY_ENROLLMENT_ABORTED => {
            let admission: EnrollmentAdmission = match serde_json::from_value(event.data.clone()) {
                Ok(admission) => admission,
                Err(e) => return Settlement::Reject(format!("aborted enrollment: {e}")),
            };
            match evaluation
                .abandon_enrollment(&admission.owner_domain, admission.operation)
                .await
            {
                Ok(EnrollmentCleanup::Reclaimed) => {
                    info!(operation = %admission.operation, "aborted enrollment's key reclaimed");
                    Settlement::Done
                }
                Ok(EnrollmentCleanup::NothingCreated) => Settlement::Done,
                Ok(EnrollmentCleanup::Retained(reason)) => {
                    error!(
                        operation = %admission.operation,
                        "an aborted enrollment's key is still needed: {reason}"
                    );
                    Settlement::Retry(RETAINED_RETRY)
                }
                Err(e) => {
                    warn!(operation = %admission.operation, "reclaim: {e}");
                    Settlement::Retry(RETRY)
                }
            }
        }
        event_types::PASSWORD_HISTORY_OWNER_PURGED => {
            let purge: OwnerPurge = match serde_json::from_value(event.data.clone()) {
                Ok(purge) => purge,
                Err(e) => return Settlement::Reject(format!("owner purge: {e}")),
            };
            match evaluation.purge_owner(&purge.owner_domain).await {
                Ok(destroyed) => {
                    info!(destroyed, "a deleted owner's history keys were destroyed");
                    Settlement::Done
                }
                Err(e) => {
                    warn!("purge: {e}");
                    Settlement::Retry(RETRY)
                }
            }
        }
        other => Settlement::Reject(format!("not a cleanup event: {other}")),
    }
}

#[cfg(test)]
mod tests;
