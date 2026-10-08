// SPDX-License-Identifier: AGPL-3.0-only
//! Invite code entity for gated registration.
//!
//! Used when enrollment mode is `InviteOnly`. Each invite has a cryptographically
//! random code, configurable max uses, optional expiry, and metadata for
//! pre-filling profile fields on registration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::profile::ProfileId;

// ── ID type ─────────────────────────────────────────────────────

/// Unique identifier for an invite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InviteId(pub Uuid);

impl InviteId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for InviteId {
    fn default() -> Self {
        Self::new()
    }
}

// ── Status enum ─────────────────────────────────────────────────

/// Invite status — computed from active flag, use_count, and expiry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteStatus {
    /// Active and can be used.
    #[default]
    Active,
    /// All uses consumed (use_count >= max_uses).
    Consumed,
    /// Manually revoked by admin.
    Revoked,
    /// Past expiration date.
    Expired,
}

impl InviteStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

impl std::fmt::Display for InviteStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Listing filter ──────────────────────────────────────────────

/// Which invites a listing returns; both conditions apply together.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InviteFilter {
    /// Only invites in this status.
    pub status: Option<InviteStatus>,
    /// Only invites whose code or creator's name contains this text,
    /// ignoring ASCII case.
    pub search: Option<String>,
}

impl InviteFilter {
    /// The SQL `LIKE` pattern of the search text: a substring match, with
    /// the text's own `%`, `_` and `\` escaped by `\` so they match
    /// themselves.
    pub fn search_pattern(&self) -> Option<String> {
        self.search.as_deref().map(|text| {
            let mut pattern = String::with_capacity(text.len() + 2);
            pattern.push('%');
            for c in text.chars() {
                if matches!(c, '%' | '_' | '\\') {
                    pattern.push('\\');
                }
                pattern.push(c);
            }
            pattern.push('%');
            pattern
        })
    }
}

// ── Invite entity ───────────────────────────────────────────────

/// Invite code for gated registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    /// Unique invite ID.
    pub id: InviteId,

    /// The code that the user enters during registration.
    /// Cryptographically random, URL-safe, 8-character alphanumeric (case-insensitive).
    pub code: String,

    /// Profile ID of the admin who created this invite.
    pub created_by: ProfileId,

    /// Display name of the creator (for admin-ui).
    pub created_by_name: String,

    /// Optional metadata to pre-fill profile fields on registration.
    pub metadata: std::collections::HashMap<String, String>,

    /// Maximum number of times this code can be used. 1 = single-use, 0 = unlimited.
    pub max_uses: u32,

    /// How many times this code has been used.
    pub use_count: u32,

    /// Expiration timestamp. None = no expiry.
    pub expires_at: Option<DateTime<Utc>>,

    /// Whether this invite is active (not revoked).
    pub active: bool,

    pub created_at: DateTime<Utc>,
}

impl Invite {
    /// Compute the current status based on active flag, usage, and expiry.
    pub fn status(&self) -> InviteStatus {
        if !self.active {
            return InviteStatus::Revoked;
        }
        if let Some(expires_at) = self.expires_at
            && Utc::now() > expires_at
        {
            return InviteStatus::Expired;
        }
        if self.max_uses > 0 && self.use_count >= self.max_uses {
            return InviteStatus::Consumed;
        }
        InviteStatus::Active
    }

    /// Check whether this invite can be used for registration right now.
    pub fn is_usable(&self) -> bool {
        self.status() == InviteStatus::Active
    }

    /// Revoke this invite (admin action).
    pub fn revoke(&mut self) {
        self.active = false;
    }
}

// ── Code generation ─────────────────────────────────────────────

/// Length of generated invite codes.
pub const INVITE_CODE_LENGTH: usize = 8;

/// Alphabet for invite codes: alphanumeric, case-insensitive (uppercase only).
/// Excludes ambiguous characters: 0/O, 1/I/L.
const INVITE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// Generate a cryptographically random invite code.
pub fn generate_invite_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..INVITE_CODE_LENGTH)
        .map(|_| {
            let idx = rng.gen_range(0..INVITE_ALPHABET.len());
            INVITE_ALPHABET[idx] as char
        })
        .collect()
}

/// Normalize an invite code for comparison (uppercase, trim whitespace).
pub fn normalize_invite_code(code: &str) -> String {
    code.trim().to_uppercase()
}

#[cfg(test)]
mod tests;
