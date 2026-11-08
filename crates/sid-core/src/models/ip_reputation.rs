// SPDX-License-Identifier: AGPL-3.0-only
//! The reputation an installation learned for a client address from its
//! sign-in outcomes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The sign-in outcomes counted for one address. Its score,
/// `failed / (failed + succeeded + 1)`, follows from the counts: a store
/// computes it, so it is not carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpReputation {
    pub ip: String,
    pub failed_count: i64,
    pub success_count: i64,
    pub first_seen_at: DateTime<Utc>,
    pub last_failed_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}
