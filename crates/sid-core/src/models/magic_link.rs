// SPDX-License-Identifier: AGPL-3.0-only
//! Magic link session model for database persistence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Magic link token expiry in seconds (15 minutes).
pub const MAGIC_LINK_EXPIRY_SECS: i64 = 900;

/// Rate limit: max requests per email within the window.
pub const MAGIC_LINK_RATE_LIMIT_MAX: u32 = 3;

/// A persisted magic link session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkSession {
    /// Session identifier (UUID v7).
    pub id: Uuid,
    /// Target email address.
    pub email: String,
    /// Argon2 hash of the URL-safe token.
    pub token_hash: String,
    /// Whether this link has been consumed (single-use).
    pub consumed: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl MagicLinkSession {
    pub fn new(email: impl Into<String>, token_hash: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            email: email.into(),
            token_hash,
            consumed: false,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(MAGIC_LINK_EXPIRY_SECS),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_link_session_new() {
        let session = MagicLinkSession::new("alice@sid.example.com", "hash123".to_string());
        assert_eq!(session.email, "alice@sid.example.com");
        assert_eq!(session.token_hash, "hash123");
        assert!(!session.consumed);
        assert!(!session.is_expired());
    }

    #[test]
    fn test_magic_link_session_expiry() {
        let mut session = MagicLinkSession::new("alice@sid.example.com", "hash".to_string());
        session.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(session.is_expired());
    }
}
