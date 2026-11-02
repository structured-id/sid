// SPDX-License-Identifier: AGPL-3.0-only
//! Password reset session model.
//!
//! Reset sessions are separate from regular sessions — shorter TTL (30m),
//! limited capabilities (only password reset operations), single-use token.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ProfileId;

/// Password reset session TTL: 30 minutes.
pub const RESET_SESSION_TTL_SECS: i64 = 1800;

/// Unique identifier for a password reset session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResetSessionId(pub Uuid);

impl ResetSessionId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ResetSessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ResetSessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Password reset session status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetSessionStatus {
    /// Token sent via email, not yet verified.
    Pending,
    /// Token verified, reset in progress.
    Verified,
    /// Reset completed (new OPAQUE credential set).
    Completed,
    /// Token consumed but reset not completed (expired or abandoned).
    Expired,
}

impl ResetSessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Completed => "completed",
            Self::Expired => "expired",
        }
    }
}

impl std::str::FromStr for ResetSessionStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "verified" => Ok(Self::Verified),
            "completed" => Ok(Self::Completed),
            "expired" => Ok(Self::Expired),
            other => Err(format!("unknown reset session status: {other}")),
        }
    }
}

impl std::fmt::Display for ResetSessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Password reset session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetSession {
    pub id: ResetSessionId,
    pub profile_id: ProfileId,
    pub email: String,
    /// Argon2 hash of the magic link token.
    pub token_hash: String,
    pub status: ResetSessionStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl PasswordResetSession {
    pub fn new(profile_id: ProfileId, email: String, token_hash: String) -> Self {
        let now = Utc::now();
        Self {
            id: ResetSessionId::new(),
            profile_id,
            email,
            token_hash,
            status: ResetSessionStatus::Pending,
            created_at: now,
            expires_at: now + Duration::seconds(RESET_SESSION_TTL_SECS),
            verified_at: None,
            completed_at: None,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

#[cfg(test)]
mod tests;
