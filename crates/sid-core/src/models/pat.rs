// SPDX-License-Identifier: AGPL-3.0-only
//! Personal Access Token (PAT) domain model.
//!
//! PATs provide API access with scoped permissions. The token value
//! is shown once at creation; only a SHA-256 hash is stored.
//!
//! Token format: `sid_pat_{base62_random}` (total ~48 chars).
//! Prefix `sid_pat_` enables secret scanning in CI/CD.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ProfileId;

/// Unique identifier for a PAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PatId(pub Uuid);

impl PatId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for PatId {
    fn default() -> Self {
        Self::new()
    }
}

/// PAT lifecycle status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatStatus {
    #[default]
    Active,
    Revoked,
    Expired,
}

impl PatStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active)
    }
}

impl std::str::FromStr for PatStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            other => Err(format!("unknown PAT status: {other}")),
        }
    }
}

impl std::fmt::Display for PatStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Personal Access Token — stored representation (no plaintext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalAccessToken {
    pub id: PatId,

    /// Owner profile.
    pub profile_id: ProfileId,

    /// Human-readable label (e.g. "CI deploy key").
    pub name: String,

    /// Purpose description (where/how this PAT is used).
    pub description: Option<String>,

    /// SHA-256 hash of the full token string.
    pub token_hash: String,

    /// First 8 chars of the token (for identification in UI).
    pub token_prefix: String,

    /// Scoped permissions (subset of profile's permissions).
    /// Empty = full profile permissions.
    pub scopes: Vec<String>,

    /// Allowed source IPs/CIDRs. Empty = no restriction.
    pub ip_allowlist: Vec<String>,

    pub status: PatStatus,

    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_used_ip: Option<String>,
    pub use_count: u64,

    /// When this token was revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Who revoked it (profile_id of revoker).
    pub revoked_by: Option<String>,

    pub created_at: DateTime<Utc>,
}

/// Token prefix for secret scanning.
pub const PAT_TOKEN_PREFIX: &str = "sid_pat_";

/// CE hardcoded PAT policy.
pub const PAT_MAX_ACTIVE_PER_USER: usize = 20;
pub const PAT_MAX_LIFETIME_DAYS: u32 = 365;
pub const PAT_AUTO_REVOKE_UNUSED_DAYS: u32 = 90;
pub const PAT_NOTIFY_BEFORE_EXPIRY_DAYS: u32 = 14;

/// PAT validation model — how the token is verified at runtime; the
/// administrator selects it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatModel {
    /// Opaque reference token. Every call → DB introspection.
    /// Instant revocation. Best for low-volume CE.
    Opaque,
    /// Long-lived JWT. Stateless validation. Delayed revocation.
    /// Best for high-throughput deployments.
    Jwt,
    /// Opaque + short-lived JWT swap (5 min). Best security trade-off.
    /// Near-instant revocation, no per-request DB lookup.
    #[default]
    OpaqueJwtSwap,
}

impl PatModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Opaque => "opaque",
            Self::Jwt => "jwt",
            Self::OpaqueJwtSwap => "opaque_jwt_swap",
        }
    }
}

impl std::fmt::Display for PatModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// JWT lifetime for opaque_jwt_swap model (seconds).
pub const PAT_SWAP_JWT_LIFETIME_SECONDS: u32 = 300;

impl PersonalAccessToken {
    /// Create a new PAT entry (caller must hash the token and extract prefix).
    pub fn new(
        profile_id: ProfileId,
        name: impl Into<String>,
        token_hash: impl Into<String>,
        token_prefix: impl Into<String>,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            id: PatId::new(),
            profile_id,
            name: name.into(),
            description: None,
            token_hash: token_hash.into(),
            token_prefix: token_prefix.into(),
            scopes,
            ip_allowlist: vec![],
            status: PatStatus::Active,
            expires_at: None,
            last_used_at: None,
            last_used_ip: None,
            use_count: 0,
            revoked_at: None,
            revoked_by: None,
            created_at: Utc::now(),
        }
    }

    /// Set expiration.
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Whether the token has expired (by time).
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Utc::now() >= exp)
            .unwrap_or(false)
    }

    /// Whether the token can be used for authentication right now.
    pub fn is_usable(&self) -> bool {
        self.status.is_usable() && !self.is_expired()
    }

    /// Record a usage event.
    pub fn record_use(&mut self, ip: Option<String>) {
        self.last_used_at = Some(Utc::now());
        self.last_used_ip = ip;
        self.use_count += 1;
    }

    /// Gateway: obtain typed wrapper if token is Active.
    ///
    /// Returns `None` if the token is already Revoked or Expired.
    pub fn as_active(&mut self) -> Option<ActivePat<'_>> {
        if self.status == PatStatus::Active {
            Some(ActivePat(self))
        } else {
            None
        }
    }

    /// Read-only accessor for status.
    pub fn status(&self) -> PatStatus {
        self.status
    }

    /// Check if token has a specific scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.is_empty() || self.scopes.iter().any(|s| s == scope)
    }
}

/// Typed wrapper for an Active personal access token.
///
/// Transition method consumes `self`, preventing double-revoke.
pub struct ActivePat<'a>(&'a mut PersonalAccessToken);

impl<'a> ActivePat<'a> {
    /// Revoke the token. Consumes wrapper.
    pub fn revoke(self, revoked_by: Option<String>) {
        self.0.status = PatStatus::Revoked;
        self.0.revoked_at = Some(Utc::now());
        self.0.revoked_by = revoked_by;
    }

    pub fn inner(&self) -> &PersonalAccessToken {
        self.0
    }
}

#[cfg(test)]
mod tests;
