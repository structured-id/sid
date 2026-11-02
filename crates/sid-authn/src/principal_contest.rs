// SPDX-License-Identifier: AGPL-3.0-only
//! Runs the contestation check a new login-handle binding owes.
//!
//! The binding commits a [`ContestCheck`]; this handler reads the committed
//! bindings of the identifier and, when two or more active profiles hold it,
//! owes every other holder a `sid.principal.contested.v1` event. Event ids
//! follow from the binding and the holder, so a repeated attempt owes
//! nothing new.

use crate::event_relay::relay_observed;
use crate::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use async_trait::async_trait;
use sid_core::models::{
    ClaimedWork, ContestCheck, NewWork, PRINCIPAL_CONTEST_CHECK_KIND, WorkKind,
};
use sid_plugin::StorageBackend;
use std::sync::Arc;
use std::time::Duration;

/// Delays between attempts while storage is unavailable.
pub const CONTEST_RETRY: RetrySchedule = RetrySchedule::new(&[
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(300),
    Duration::from_secs(3600),
]);

/// Tells the other holders of a newly bound identifier that it is contested.
pub struct PrincipalContestHandler {
    kind: WorkKind,
    storage: Arc<dyn StorageBackend>,
}

impl PrincipalContestHandler {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self {
            kind: WorkKind::new(PRINCIPAL_CONTEST_CHECK_KIND).expect("the contest kind is valid"),
            storage,
        }
    }
}

#[async_trait]
impl WorkHandler for PrincipalContestHandler {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        CONTEST_RETRY
    }

    /// The failed check is its own record; it raises no further work.
    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let check: ContestCheck = match serde_json::from_slice(&work.payload) {
            Ok(check) => check,
            Err(e) => return WorkOutcome::Permanent(format!("malformed contest check: {e}")),
        };
        let principal = match self
            .storage
            .get_principal_by_value(check.principal_type, &check.value)
            .await
        {
            Ok(Some(principal)) => principal,
            // The binding is gone again: nothing is contested.
            Ok(None) => return WorkOutcome::Done(None),
            Err(e) => return WorkOutcome::Retry(format!("principal lookup: {e}")),
        };
        match self
            .storage
            .count_active_principal_bindings(principal.id)
            .await
        {
            Ok(count) if count < 2 => return WorkOutcome::Done(None),
            Ok(_) => {}
            Err(e) => return WorkOutcome::Retry(format!("binding count: {e}")),
        }
        let bindings = match self.storage.get_principal_bindings(principal.id).await {
            Ok(bindings) => bindings,
            Err(e) => return WorkOutcome::Retry(format!("bindings: {e}")),
        };
        for binding in &bindings {
            let holder = binding.profile_id;
            if holder == check.new_holder {
                continue;
            }
            if let Err(e) = relay_observed(&*self.storage, &check.contested_event(holder)).await {
                return WorkOutcome::Retry(format!("relay contested event: {e}"));
            }
        }
        WorkOutcome::Done(None)
    }
}

#[cfg(test)]
mod tests;
