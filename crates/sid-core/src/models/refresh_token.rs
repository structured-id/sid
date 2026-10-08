// SPDX-License-Identifier: AGPL-3.0-only
//! Refresh token domain model.
//!
//! Opaque refresh tokens with rotation family tracking and theft detection.
//! Uses consume-self pattern: `validate()` takes ownership, preventing reuse.
//!
//! Family model: tokens in a rotation chain share the same `family_id`.
//! When a token is rotated, the new token inherits the family. Theft detection
//! triggers when two different tokens from the same family are used for rotation.
//! Grace window (default 30s) allows concurrent retries after network failure.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

use super::{ProfileId, ResourceId, SessionId};

/// Default grace window after rotation: old tokens valid for 30 seconds.
pub const DEFAULT_GRACE_WINDOW_SECS: i64 = 30;

/// Errors during refresh token validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshTokenError {
    /// Token has been revoked and grace window expired. Contains session_id
    /// and family_id for cascade revocation in theft detection scenarios.
    Revoked {
        session_id: SessionId,
        family_id: Uuid,
    },
    /// Token TTL has expired.
    Expired,
    /// Token reuse detected outside grace window — theft suspected.
    /// Entire token family should be invalidated.
    TheftDetected {
        session_id: SessionId,
        family_id: Uuid,
    },
}

impl fmt::Display for RefreshTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revoked { .. } => write!(f, "refresh token revoked"),
            Self::Expired => write!(f, "refresh token expired"),
            Self::TheftDetected { .. } => write!(f, "token theft detected"),
        }
    }
}

impl std::error::Error for RefreshTokenError {}

/// Refresh token (stored as SHA-256 hash, never plaintext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    /// Token record ID (UUIDv7).
    pub id: Uuid,

    /// SHA-256 hash of the opaque token string.
    pub token_hash: Vec<u8>,

    /// Session this token belongs to.
    pub session_id: SessionId,

    /// Profile that owns this token.
    pub profile_id: ProfileId,

    /// OAuth2 client that requested this token.
    pub client_id: String,

    /// Granted scopes.
    pub scopes: Vec<String>,

    /// The resource the grant was issued for (RFC 8707); a refresh issues
    /// tokens for it and no other.
    pub resource: ResourceId,

    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,

    /// Whether this token has been revoked.
    pub revoked: bool,

    /// If rotated, the ID of the replacement token (theft detection chain).
    pub replaced_by: Option<Uuid>,

    /// Token family ID: groups all tokens in a rotation chain.
    /// First token in chain: `family_id == id`. Subsequent rotations inherit.
    pub family_id: Uuid,

    /// Grace window expiration: after rotation, old token remains valid until
    /// this timestamp for concurrent retry scenarios. `None` = no grace (active token).
    pub grace_expires_at: Option<DateTime<Utc>>,

    /// JWK thumbprint of the DPoP key this token is bound to: using it needs
    /// a proof for that key (RFC 9449 §5). `None` = not sender-constrained.
    #[serde(default)]
    pub dpop_jkt: Option<String>,
}

/// Result of validating a refresh token. Consumes the original `RefreshToken`.
///
/// Provides read access to token data needed for rotation and token issuance.
/// Cannot be "un-validated" — the original token is consumed by `validate()`.
#[derive(Debug)]
pub struct ValidatedRefreshToken {
    inner: RefreshToken,
}

impl ValidatedRefreshToken {
    /// Token record ID.
    pub fn id(&self) -> Uuid {
        self.inner.id
    }

    /// Session this token belongs to.
    pub fn session_id(&self) -> SessionId {
        self.inner.session_id
    }

    /// Profile that owns this token.
    pub fn profile_id(&self) -> ProfileId {
        self.inner.profile_id
    }

    /// OAuth2 client that requested this token.
    pub fn client_id(&self) -> &str {
        &self.inner.client_id
    }

    /// Granted scopes.
    pub fn scopes(&self) -> &[String] {
        &self.inner.scopes
    }

    /// The resource the grant was issued for.
    pub fn resource(&self) -> ResourceId {
        self.inner.resource
    }

    /// SHA-256 hash of the token (for storage lookup).
    pub fn token_hash(&self) -> &[u8] {
        &self.inner.token_hash
    }

    /// Token family ID for rotation chain tracking.
    pub fn family_id(&self) -> Uuid {
        self.inner.family_id
    }

    /// JWK thumbprint of the DPoP key the token is bound to, if any.
    pub fn dpop_jkt(&self) -> Option<&str> {
        self.inner.dpop_jkt.as_deref()
    }

    /// Whether this token was validated within its grace window
    /// (revoked but still within grace period).
    pub fn is_grace_period(&self) -> bool {
        self.inner.revoked && self.inner.is_within_grace_window()
    }

    /// Scopes as space-separated string.
    pub fn scopes_string(&self) -> String {
        self.inner.scopes.join(" ")
    }
}

impl RefreshToken {
    /// Check if token is expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if token is within its grace window (revoked but grace not yet expired).
    pub fn is_within_grace_window(&self) -> bool {
        match self.grace_expires_at {
            Some(grace) => Utc::now() < grace,
            None => false,
        }
    }

    /// Check if token is usable: either active (not revoked, not expired)
    /// or within grace window (revoked but grace period hasn't elapsed).
    pub fn is_valid(&self) -> bool {
        if self.is_expired() {
            return false;
        }
        !self.revoked || self.is_within_grace_window()
    }

    /// Validate this refresh token for rotation (consume-self pattern).
    ///
    /// Handles three cases:
    /// 1. Active token (not revoked) → success
    /// 2. Revoked but within grace window → success (concurrent retry)
    /// 3. Revoked and grace expired → `TheftDetected` (stolen token reuse)
    /// 4. Expired → `Expired`
    ///
    /// On `TheftDetected`, callers must revoke the entire token family.
    pub fn validate(self) -> Result<ValidatedRefreshToken, RefreshTokenError> {
        if self.is_expired() {
            return Err(RefreshTokenError::Expired);
        }
        if self.revoked {
            if self.is_within_grace_window() {
                // Grace window: allow concurrent retry (network failure scenario)
                return Ok(ValidatedRefreshToken { inner: self });
            }
            return Err(RefreshTokenError::TheftDetected {
                session_id: self.session_id,
                family_id: self.family_id,
            });
        }
        Ok(ValidatedRefreshToken { inner: self })
    }

    /// Scopes as space-separated string.
    pub fn scopes_string(&self) -> String {
        self.scopes.join(" ")
    }
}

#[cfg(test)]
mod tests;
