// SPDX-License-Identifier: AGPL-3.0-only
//! Required work committed together with the state change that needs it
//! (transactional outbox): stored, claimed by one worker at a time under a
//! fenced lease, retried, and ended in a recorded outcome.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable logical identity of one piece of work. Enqueuing the same id twice
/// stores it once, so a retried command creates no second obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkId(pub Uuid);

impl WorkId {
    /// A new, time-ordered identity.
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for WorkId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for WorkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// What a piece of work is, naming the handler that performs it
/// (for example `logout.backchannel`, `notify.email`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkKind(String);

impl WorkKind {
    /// A kind: lowercase ASCII letters, digits, `.` and `_`, 1-64 characters.
    pub fn new(kind: &str) -> crate::Result<Self> {
        let valid = (1..=64).contains(&kind.len())
            && kind
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_');
        if valid {
            Ok(Self(kind.to_string()))
        } else {
            Err(crate::Error::Validation(format!(
                "invalid work kind: {kind:?}"
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where a piece of work is in its life. Terminal states stay distinguishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkState {
    /// Waiting for a worker (initially, or after a failed attempt).
    Pending,
    /// Held by a worker under a lease.
    Claimed,
    Completed,
    /// Attempts exhausted or a permanent failure: the dead-letter outcome.
    Failed,
    /// Its validity ended before it could be done (an expired code is not resent).
    Expired,
    Cancelled,
}

impl WorkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> crate::Result<Self> {
        Ok(match s {
            "pending" => Self::Pending,
            "claimed" => Self::Claimed,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "expired" => Self::Expired,
            "cancelled" => Self::Cancelled,
            other => {
                return Err(crate::Error::Storage(format!(
                    "unknown work state: {other}"
                )));
            }
        })
    }
}

/// Work to enqueue with a state change.
#[derive(Debug, Clone)]
pub struct NewWork {
    pub id: WorkId,
    pub kind: WorkKind,
    /// Handler input, in the owning data class's protection (sealed if secret).
    pub payload: Vec<u8>,
    /// Earliest time a worker may take it; `None` is due at once, stamped by
    /// the store's own clock so a skewed replica clock cannot delay it.
    pub not_before: Option<DateTime<Utc>>,
    /// After this the work is expired, never attempted.
    pub expires_at: Option<DateTime<Utc>>,
    /// Attempts before the work fails (dead-letter).
    pub max_attempts: u32,
}

impl NewWork {
    /// Work of `kind` due now, five attempts, no expiry.
    pub fn new(kind: WorkKind, payload: Vec<u8>) -> Self {
        Self {
            id: WorkId::new(),
            kind,
            payload,
            not_before: None,
            expires_at: None,
            max_attempts: 5,
        }
    }
}

/// Work held by a worker. `generation` fences its outcome: once the lease
/// expired and another worker claimed the work, this holder's outcome is
/// refused.
#[derive(Debug, Clone)]
pub struct ClaimedWork {
    pub id: WorkId,
    pub kind: WorkKind,
    pub payload: Vec<u8>,
    /// Attempts including this one.
    pub attempt: u32,
    pub max_attempts: u32,
    pub generation: i64,
    pub expires_at: Option<DateTime<Utc>>,
}

/// A failed attempt as recorded on its work.
#[derive(Debug, Clone)]
pub struct WorkFailure {
    pub error: String,
    /// The effect may have happened (a provider accepted the request but its
    /// reply was lost); recorded so it is never reported as a clean failure.
    pub ambiguous: bool,
    /// When to try again; `None` is a permanent failure. The work also fails
    /// when no attempts remain.
    pub retry_at: Option<DateTime<Utc>>,
    /// Work enqueued in the same transaction when this failure ends the work
    /// (the dead-letter alert), so a recorded failure never lacks it.
    pub on_dead: Option<NewWork>,
}

/// Stored record of a piece of work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkRecord {
    pub id: WorkId,
    pub kind: WorkKind,
    pub state: WorkState,
    pub attempts: u32,
    pub max_attempts: u32,
    pub generation: i64,
    pub last_error: Option<String>,
    /// Whether the last failed attempt had an ambiguous outcome.
    pub ambiguous: bool,
    /// What completing it produced (a provider receipt), if anything.
    pub result: Option<String>,
    pub not_before: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A piece of work as carried from one store to another: its record and
/// its payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkSnapshot {
    pub record: WorkRecord,
    pub payload: Vec<u8>,
}

impl WorkSnapshot {
    /// The record as the receiving store keeps it. A claim does not travel
    /// (its worker belongs to the other store): claimed work is due again,
    /// or failed when that claim was its last attempt, as an abandoned claim
    /// ends in the store it came from.
    pub fn at_rest(&self) -> WorkRecord {
        let mut record = self.record.clone();
        if record.state == WorkState::Claimed {
            if record.attempts >= record.max_attempts {
                record.state = WorkState::Failed;
                record
                    .last_error
                    .get_or_insert_with(|| "lease expired on the last attempt".into());
            } else {
                record.state = WorkState::Pending;
            }
        }
        record
    }
}

#[cfg(test)]
mod tests;
