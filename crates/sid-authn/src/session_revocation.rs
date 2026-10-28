// SPDX-License-Identifier: AGPL-3.0-only
//! Revocation of an ended session's access tokens in every process: the
//! storage commits it with the session's deletion, and this handler publishes
//! it for the durable work runner, so a crash between the commit and the
//! publication leaves no token of that session live until it expires.

use crate::revocation_cache::RevocationCache;
use crate::work_runner::{RetrySchedule, WorkHandler, WorkOutcome};
use async_trait::async_trait;
use sid_core::models::{
    ClaimedWork, NewWork, SESSION_REVOCATION_KIND, SessionRevocation, WorkKind,
};
use std::sync::Arc;
use std::time::Duration;

/// Delays between attempts: soon, as a live token waits on it, then every
/// half minute for the work's attempts (`SESSION_REVOCATION_ATTEMPTS`).
const REVOCATION_RETRY: RetrySchedule = RetrySchedule::new(&[
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(30),
]);

/// Publishes owed session revocations.
pub struct SessionRevocationHandler {
    kind: WorkKind,
    revocation: Arc<RevocationCache>,
}

impl SessionRevocationHandler {
    pub fn new(revocation: Arc<RevocationCache>) -> Self {
        Self {
            kind: WorkKind::new(SESSION_REVOCATION_KIND).expect("the revocation kind is valid"),
            revocation,
        }
    }
}

#[async_trait]
impl WorkHandler for SessionRevocationHandler {
    fn kind(&self) -> &WorkKind {
        &self.kind
    }

    fn retry_schedule(&self) -> RetrySchedule {
        REVOCATION_RETRY
    }

    /// The failed work is the durable dead-letter record.
    fn on_dead(&self, _work: &ClaimedWork, _error: &str) -> Option<NewWork> {
        None
    }

    /// Revoking a session twice revokes it once, so a repeated attempt is
    /// harmless.
    async fn handle(&self, work: &ClaimedWork) -> WorkOutcome {
        let revocation: SessionRevocation = match serde_json::from_slice(&work.payload) {
            Ok(revocation) => revocation,
            Err(e) => return WorkOutcome::Permanent(format!("malformed session revocation: {e}")),
        };
        match self.revocation.revoke_session(revocation.session_id).await {
            Ok(()) => WorkOutcome::Done(None),
            Err(e) => WorkOutcome::Retry(format!("publish the revocation: {e}")),
        }
    }
}

#[cfg(test)]
mod tests;
