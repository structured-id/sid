// SPDX-License-Identifier: AGPL-3.0-only
//! A deleted owner's history keys. The transaction that deletes a profile
//! owes its purge as durable work; the work runs once and has the evaluator
//! destroy the owner's keys and lifecycle and fence the owner's domain, so a
//! preparation still in flight creates nothing afterwards. In a standalone
//! installation the evaluator runs in this process and is told directly; a
//! separate evaluator gets the fact as a relayed event.

use std::sync::Arc;

use sid_authn::event_relay::RELAY_RETRY;
use sid_authn::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use sid_core::models::event::event_types;
use sid_core::models::{
    AuditEntry, ClaimedWork, Event, MutationContext, NewWork, OWNER_PURGE_KIND, OwnerPurge,
    ProfileId, RelayedCleanup, WorkKind,
};
use sid_plugin::storage::StorageBackend;
use tracing::info;

use super::EvaluatorDelivery;

/// Namespace of the relayed purge events' ids, one per owner domain.
const PURGE_EVENT_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x8b47_0d2e_61f5_4a3c_b9d8_2e7a_5c10_f396);

/// The purge the deletion of `profile` owes the evaluator, to be committed
/// with the deletion; `None` when the installation has no authority yet, and
/// so no history domain any key could be under.
pub(crate) async fn owner_purge(
    storage: &dyn StorageBackend,
    profile: ProfileId,
) -> sid_core::Result<Option<NewWork>> {
    Ok(storage.instance_organization().await?.map(|org| {
        OwnerPurge {
            owner_domain: sid_authn::password_history::owner_domain(org.id.as_bytes(), profile),
        }
        .work()
    }))
}

/// Has the evaluator destroy each deleted owner's keys.
pub(crate) struct OwnerPurgeHandler {
    kind: WorkKind,
    delivery: EvaluatorDelivery,
    storage: Arc<dyn StorageBackend>,
}

impl OwnerPurgeHandler {
    pub(crate) fn new(storage: Arc<dyn StorageBackend>, delivery: EvaluatorDelivery) -> Self {
        Self {
            kind: WorkKind::new(OWNER_PURGE_KIND).expect("the owner purge kind is valid"),
            delivery,
            storage,
        }
    }
}

/// The relayed event telling a separate evaluator that `purge`'s owner was
/// deleted: one per owner domain at the first attempt (a repeated deletion
/// owes the same one), then one per later `attempt` that relays it again.
fn purge_event(source: &str, purge: &OwnerPurge, attempt: u32) -> Result<NewWork, String> {
    let mut event = Event::new(source, event_types::PASSWORD_HISTORY_OWNER_PURGED)
        .with_data(serde_json::to_value(purge).map_err(|e| format!("event data: {e}"))?);
    event.id = if attempt <= 1 {
        uuid::Uuid::new_v5(&PURGE_EVENT_NAMESPACE, &purge.owner_domain)
    } else {
        uuid::Uuid::new_v5(
            &PURGE_EVENT_NAMESPACE,
            &[purge.owner_domain.as_slice(), &attempt.to_be_bytes()].concat(),
        )
    }
    .to_string();
    Ok(event.relay())
}

#[tonic::async_trait]
impl WorkHandler for OwnerPurgeHandler {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        RELAY_RETRY
    }

    /// The failed work is itself the actionable record: a deleted owner
    /// whose keys are still held.
    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let purge = match OwnerPurge::from_work(&work.payload) {
            Ok(purge) => purge,
            Err(e) => return WorkOutcome::Permanent(e.to_string()),
        };
        match &self.delivery {
            EvaluatorDelivery::InProcess(evaluation) => {
                match evaluation.purge_owner(&purge.owner_domain).await {
                    Ok(destroyed) => {
                        info!(destroyed, "a deleted owner's history keys were destroyed");
                        WorkOutcome::Done(Some(format!("{destroyed} keys destroyed")))
                    }
                    Err(e) => WorkOutcome::Retry(format!("purge: {e}")),
                }
            }
            // The purge stays owed until the separate evaluator's settlement
            // is recorded: each attempt before then relays it again, so an
            // event that aged out of the stream or met an evaluator outage
            // is not lost ([`super::consume_cleanup_settlements`]).
            EvaluatorDelivery::Relay { source } => {
                let cleanup = RelayedCleanup::OwnerPurge {
                    owner_domain: purge.owner_domain,
                };
                match super::relayed::settled(self.storage.as_ref(), &cleanup).await {
                    Ok(true) => return WorkOutcome::Done(Some("settled by the evaluator".into())),
                    Ok(false) => {}
                    Err(e) => return WorkOutcome::Retry(format!("settlement: {e}")),
                }
                let event = match purge_event(source, &purge, work.attempt) {
                    Ok(event) => event,
                    Err(e) => return WorkOutcome::Permanent(e),
                };
                let ctx = MutationContext::from(AuditEntry::system(
                    "password_history.owner_purge_relayed",
                    "password_history",
                ))
                .with_work(event);
                match self.storage.record_outcome(ctx).await {
                    Ok(()) => WorkOutcome::Retry("purge relayed; awaiting the evaluator".into()),
                    Err(e) => WorkOutcome::Retry(format!("relay the purge: {e}")),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
