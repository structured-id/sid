// SPDX-License-Identifier: AGPL-3.0-only
//! The relayed cleanup between a credential authority and a separate
//! evaluator. The credential authority owes an aborted first enrollment's
//! and a deleted owner's cleanup as an event addressed to its evaluator,
//! committed with the decision that made it. The evaluator consumes those
//! events durably and acts on each (it reclaims the enrollment's key, or
//! destroys the owner's keys), addresses the settlement back to the
//! authority, and acknowledges the event once the effect is done; both
//! effects are idempotent in its store. The credential authority records the
//! settlements it consumes and keeps each cleanup owed, relaying it again,
//! until its settlement is recorded: the settlement, not the handoff,
//! establishes that the keys are gone. A standalone installation does
//! neither: its evaluator runs in process and is told directly.

use std::sync::Arc;
use std::time::Duration;

use sid_core::models::event::{Event, WorkRecipient, event_types};
use sid_core::models::{
    AuditEntry, CLEANUP_SETTLED_NAMESPACE, CleanupSettled, EnrollmentAdmission, EnrollmentCleanup,
    MutationContext, OperationCompletion, OwnerPurge, RelayedCleanup,
};
use sid_plugin::event_bus::{DurableConsumer, EventBus, EventBusResult, Settlement};
use sid_plugin::storage::StorageBackend;
use tracing::{error, info, warn};

use super::HistoryEvaluation;

/// Namespace of the authority tag in durable consumer names.
const CONSUMER_AUTHORITY_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x71c4_2e9a_5b03_4f68_a2d7_c815_3e6f_09b4);

/// A receiver for credential authority `authority`: every replica serving
/// that authority shares it, and deployments of different authorities on
/// one bus each have their own rather than sharing, and rejecting, each
/// other's work. The tag keeps the name within an address token.
fn receiver(prefix: &str, authority: &str) -> WorkRecipient {
    let tag = uuid::Uuid::new_v5(&CONSUMER_AUTHORITY_NAMESPACE, authority.as_bytes());
    WorkRecipient::new(format!("{prefix}-{}", tag.simple())).expect("a tagged prefix is a token")
}

/// The separate evaluator serving `authority`: the cleanup is addressed
/// to it.
pub fn cleanup_consumer(authority: &str) -> WorkRecipient {
    receiver("password-history-evaluator-cleanup", authority)
}

/// Credential authority `authority`, with a separate evaluator: the
/// settlements are addressed to it.
pub fn settlement_consumer(authority: &str) -> WorkRecipient {
    receiver("password-history-cleanup-settlements", authority)
}

/// The method a recorded settlement carries.
pub(crate) const SETTLED_METHOD: &str = "settled";

/// Who reports a settlement: the separate evaluator.
const EVALUATOR_SOURCE: &str = "sid-password-history-evaluator";

/// Namespace of the settlement events' ids, one per cleanup.
const SETTLED_EVENT_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x3f9e_5a21_c847_4d06_a1b3_6e2d_8c90_f475);

/// Whether the evaluator's settlement of `cleanup` is recorded.
pub(crate) async fn settled(
    storage: &dyn StorageBackend,
    cleanup: &RelayedCleanup,
) -> sid_core::Result<bool> {
    Ok(storage
        .get_operation_result(CLEANUP_SETTLED_NAMESPACE, &cleanup.settlement_key())
        .await?
        .is_some())
}

/// Record the evaluator's settlement of `cleanup`; recording it again is
/// harmless.
pub(crate) async fn record_settlement(
    storage: &dyn StorageBackend,
    cleanup: &RelayedCleanup,
) -> sid_core::Result<()> {
    let completion = OperationCompletion::new(
        CLEANUP_SETTLED_NAMESPACE,
        cleanup.settlement_key(),
        SETTLED_METHOD,
        &[],
        Vec::new(),
    );
    let ctx = MutationContext::from(AuditEntry::system(
        "password_history.cleanup_settled",
        "password_history",
    ))
    .with_operation(completion);
    match storage.record_outcome(ctx).await {
        Ok(()) | Err(sid_core::Error::OperationCompleted(_)) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Consume, as the credential authority named `authority`, the settlements
/// its separate evaluator reports on `bus`, recording each in `storage`,
/// until the bus ends the consumer.
pub async fn consume_cleanup_settlements(
    bus: &dyn EventBus,
    storage: Arc<dyn StorageBackend>,
    authority: &str,
) -> EventBusResult<()> {
    let mut deliveries = bus
        .consume(DurableConsumer {
            recipient: settlement_consumer(authority),
            event_types: vec![event_types::PASSWORD_HISTORY_CLEANUP_SETTLED.into()],
            ordered: false,
        })
        .await?;
    while let Some(delivery) = deliveries.recv().await {
        let settlement = match serde_json::from_value::<CleanupSettled>(delivery.event.data.clone())
        {
            Err(e) => Settlement::Reject(format!("cleanup settlement: {e}")),
            Ok(settled) if settled.authority != authority => {
                Settlement::Reject("a settlement for another credential authority".into())
            }
            Ok(settled) => match record_settlement(storage.as_ref(), &settled.cleanup).await {
                Ok(()) => Settlement::Done,
                Err(e) => {
                    warn!("record a cleanup settlement: {e}");
                    Settlement::Retry(RETRY)
                }
            },
        };
        delivery.settle(settlement);
    }
    Ok(())
}

/// When an event whose effect failed (the evaluator's store unavailable) is
/// delivered again.
const RETRY: Duration = Duration::from_secs(30);

/// When an aborted enrollment whose key is still needed is looked at again:
/// what holds the key (another operation, a recorded lifecycle) can end, and
/// the obligation stays until it does.
const RETAINED_RETRY: Duration = Duration::from_secs(60 * 60);

/// Consume the relayed cleanup of the credential authority named `source` on
/// `bus`, acting on each event through `evaluation`, until the bus ends the
/// consumer. The authenticity of an event is the bus's: the NATS account holds
/// one authority, and only its runtime may publish the cleanup subjects there;
/// `source` keeps a misconfigured deployment from acting on another
/// authority's events.
pub async fn consume_relayed_cleanup(
    bus: &dyn EventBus,
    evaluation: Arc<HistoryEvaluation>,
    source: &str,
) -> EventBusResult<()> {
    let mut deliveries = bus
        .consume(DurableConsumer {
            recipient: cleanup_consumer(source),
            event_types: vec![
                event_types::PASSWORD_HISTORY_ENROLLMENT_ABORTED.into(),
                event_types::PASSWORD_HISTORY_OWNER_PURGED.into(),
            ],
            ordered: false,
        })
        .await?;
    while let Some(delivery) = deliveries.recv().await {
        let settlement = match settle(&evaluation, source, &delivery.event).await {
            // The effect is done, so the event is acknowledged whether or not
            // its report goes out: holding it until the report does would keep
            // a full work stream full, the report and the event waiting on each
            // other. A report that did not go out is not lost: the authority
            // keeps the cleanup owed and relays it again until a settlement is
            // recorded, and the repeat is done again harmlessly and reported.
            (Settlement::Done, Some(cleanup)) => {
                if let Err(e) = report(bus, source, cleanup).await {
                    warn!("report a cleanup settlement: {e}; the authority relays it again");
                }
                Settlement::Done
            }
            (settlement, _) => settlement,
        };
        delivery.settle(settlement);
    }
    Ok(())
}

/// Tell the credential authority `authority` that `cleanup` is settled.
async fn report(
    bus: &dyn EventBus,
    authority: &str,
    cleanup: RelayedCleanup,
) -> EventBusResult<()> {
    let settled = CleanupSettled {
        authority: authority.to_string(),
        cleanup,
    };
    let mut event = Event::new(
        EVALUATOR_SOURCE,
        event_types::PASSWORD_HISTORY_CLEANUP_SETTLED,
    )
    .with_data(serde_json::to_value(&settled).expect("a settlement serializes"));
    // One per cleanup: a repeated report is the same event and the same
    // handoff. Its owner until the bus accepts it is the cleanup event this
    // evaluator has not yet acknowledged.
    event.id = uuid::Uuid::new_v5(
        &SETTLED_EVENT_NAMESPACE,
        cleanup.settlement_key().as_str().as_bytes(),
    )
    .to_string();
    let authority = settlement_consumer(authority);
    bus.deliver(&authority, event.delivery_id(&authority), &event)
        .await
}

/// What acting on `event` came to, and the cleanup it settled.
async fn settle(
    evaluation: &HistoryEvaluation,
    source: &str,
    event: &Event,
) -> (Settlement, Option<RelayedCleanup>) {
    // `source` is the envelope's claim, not an authentication: what makes an
    // event this authority's is the NATS account it arrives in, which holds
    // one authority and grants publishing on these subjects to that
    // authority's runtime only; independent authorities never share an
    // account. This check only keeps a misconfigured deployment from acting
    // on another authority's cleanup.
    if event.source != source {
        let reason = format!("event {} is from another credential authority", event.id);
        return (Settlement::Reject(reason), None);
    }
    match event.event_type.as_str() {
        event_types::PASSWORD_HISTORY_ENROLLMENT_ABORTED => {
            let admission: EnrollmentAdmission = match serde_json::from_value(event.data.clone()) {
                Ok(admission) => admission,
                Err(e) => return (Settlement::Reject(format!("aborted enrollment: {e}")), None),
            };
            let cleanup = RelayedCleanup::Enrollment {
                operation: admission.operation,
            };
            let settlement = match evaluation
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
            };
            (settlement, Some(cleanup))
        }
        event_types::PASSWORD_HISTORY_OWNER_PURGED => {
            let purge: OwnerPurge = match serde_json::from_value(event.data.clone()) {
                Ok(purge) => purge,
                Err(e) => return (Settlement::Reject(format!("owner purge: {e}")), None),
            };
            let cleanup = RelayedCleanup::OwnerPurge {
                owner_domain: purge.owner_domain,
            };
            let settlement = match evaluation.purge_owner(&purge.owner_domain).await {
                Ok(destroyed) => {
                    info!(destroyed, "a deleted owner's history keys were destroyed");
                    Settlement::Done
                }
                Err(e) => {
                    warn!("purge: {e}");
                    Settlement::Retry(RETRY)
                }
            };
            (settlement, Some(cleanup))
        }
        other => (
            Settlement::Reject(format!("not a cleanup event: {other}")),
            None,
        ),
    }
}

#[cfg(test)]
mod tests;
