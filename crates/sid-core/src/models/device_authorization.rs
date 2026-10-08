// SPDX-License-Identifier: AGPL-3.0-only
//! Device Authorization Grant (RFC 8628) domain model.
//!
//! Stores device authorization requests: device_code + user_code pairs
//! with status tracking for the polling flow.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ProjectId;

/// Unique identifier for a device authorization request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceAuthCodeId(pub Uuid);

impl DeviceAuthCodeId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for DeviceAuthCodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DeviceAuthCodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Status of a device authorization request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAuthStatus {
    /// Waiting for user to enter code and authorize.
    Pending,
    /// User has authorized the device.
    Authorized,
    /// User explicitly denied authorization.
    Denied,
    /// Device code has expired without authorization.
    Expired,
    /// The device exchanged the authorized code for tokens; it is spent.
    Redeemed,
}

impl DeviceAuthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Authorized => "authorized",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Redeemed => "redeemed",
        }
    }

    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Pending)
    }
}

parse_stored!(
    DeviceAuthStatus,
    "device authorization status",
    [Pending, Authorized, Denied, Expired, Redeemed]
);

/// The user's decision on a pending device authorization request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAuthDecision {
    /// The profile signed in on the other device authorizes it.
    Authorize(super::ProfileId),
    /// The user refuses the device.
    Deny,
}

/// Outcome of recording a device's poll (RFC 8628 §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePoll {
    /// The poll respects the interval.
    Allowed,
    /// The poll came too soon; the interval grew by 5 seconds.
    SlowDown,
}

/// Outcome of redeeming a device code for tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCodeRedemption {
    /// This call redeemed the code: the session and refresh token are stored.
    Redeemed,
    /// The code was already redeemed; nothing was stored. Carries the session
    /// of the first redemption.
    AlreadyRedeemed {
        session_id: Option<super::SessionId>,
    },
    /// The code is not authorized (pending, denied, expired or unknown);
    /// nothing was stored.
    NotAuthorized,
}

impl std::fmt::Display for DeviceAuthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A device authorization request per RFC 8628.
///
/// Created when a device calls the device authorization endpoint.
/// The device receives `device_code` (secret, for polling) and `user_code`
/// (short, human-readable, for the user to enter on another device).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationCode {
    pub id: DeviceAuthCodeId,

    /// OAuth2 client that initiated the request.
    pub client_id: String,

    /// SHA-256 hash of the device code (secret, used by device to poll).
    /// The raw device_code is returned to the device once and never stored.
    pub device_code_hash: Vec<u8>,

    /// Code the user enters, normalized (e.g. "WDJBMJHT"; shown as
    /// "WDJB-MJHT"). Stored in plaintext for lookup when the user submits it.
    pub user_code: String,

    /// Requested OAuth2 scopes.
    pub scope: Option<String>,

    /// The resource the device requested a token for (RFC 8707), resolved
    /// when the request was made; redemption issues a token for it only.
    pub resource: super::ResourceId,

    /// Current status of this authorization request.
    pub status: DeviceAuthStatus,

    /// Profile ID of the user who authorized (set when status = Authorized).
    pub authorized_by: Option<super::ProfileId>,

    /// Project this client belongs to.
    pub project_id: ProjectId,

    /// Minimum polling interval in seconds (RFC 8628 §3.2).
    pub interval: i32,

    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub authorized_at: Option<DateTime<Utc>>,

    /// Last time the device polled for this code (for slow_down enforcement).
    pub last_polled_at: Option<DateTime<Utc>>,

    /// Session created when the code was redeemed.
    pub redeemed_session_id: Option<super::SessionId>,
}

/// CE defaults for device authorization.
pub const DEVICE_CODE_LIFETIME_SECS: i64 = 600;
pub const DEVICE_CODE_POLL_INTERVAL_SECS: i32 = 5;
pub const USER_CODE_LENGTH: usize = 8;

impl DeviceAuthorizationCode {
    /// Create a new pending device authorization request.
    pub fn new(
        client_id: String,
        device_code_hash: Vec<u8>,
        user_code: String,
        scope: Option<String>,
        resource: super::ResourceId,
        project_id: ProjectId,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: DeviceAuthCodeId::new(),
            client_id,
            device_code_hash,
            user_code,
            scope,
            resource,
            status: DeviceAuthStatus::Pending,
            authorized_by: None,
            project_id,
            interval: DEVICE_CODE_POLL_INTERVAL_SECS,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(DEVICE_CODE_LIFETIME_SECS),
            authorized_at: None,
            last_polled_at: None,
            redeemed_session_id: None,
        }
    }

    /// Check if this authorization request has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Gateway: obtain typed wrapper if code is in Pending state.
    ///
    /// Returns `None` if the code is already in a terminal state
    /// (Authorized, Denied, Expired). This is the ONLY way to transition
    /// a device authorization code — direct status mutation is not exposed.
    pub fn as_pending(&mut self) -> Option<PendingDeviceAuth<'_>> {
        if self.status == DeviceAuthStatus::Pending {
            Some(PendingDeviceAuth(self))
        } else {
            None
        }
    }

    /// Read-only accessor for status.
    pub fn status(&self) -> DeviceAuthStatus {
        self.status
    }
}

/// Typed wrapper for a device authorization code in Pending state.
///
/// All transition methods consume `self`, preventing:
/// - Calling both `authorize()` and `deny()` on the same code
/// - Transitioning from a terminal state (only `as_pending()` creates this)
///
/// This is the Transition Gateway pattern — runtime check at gateway creation,
/// compile-time safety for all transitions after that.
pub struct PendingDeviceAuth<'a>(&'a mut DeviceAuthorizationCode);

impl<'a> PendingDeviceAuth<'a> {
    /// User authorizes the device. Consumes the wrapper.
    pub fn authorize(self, profile_id: super::ProfileId) {
        self.0.status = DeviceAuthStatus::Authorized;
        self.0.authorized_by = Some(profile_id);
        self.0.authorized_at = Some(Utc::now());
    }

    /// User denies authorization. Consumes the wrapper.
    pub fn deny(self) {
        self.0.status = DeviceAuthStatus::Denied;
    }

    /// Code has expired (TTL reached). Consumes the wrapper.
    pub fn expire(self) {
        self.0.status = DeviceAuthStatus::Expired;
    }

    /// Read-only access to the inner device authorization code.
    pub fn inner(&self) -> &DeviceAuthorizationCode {
        self.0
    }
}

#[cfg(test)]
mod tests;
