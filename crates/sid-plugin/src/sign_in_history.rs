// SPDX-License-Identifier: AGPL-3.0-only
//! Sign-in history capability: the facts about an account's earlier
//! sign-ins that the fixed CE sign-in rules read and record. `Owner` is the
//! account type the authority authenticates; CE's is the local Profile.

use async_trait::async_trait;
use core::net::IpAddr;
use sid_core::Result;

#[async_trait]
pub trait SignInHistoryStore: Send + Sync {
    /// The account whose sign-ins are recorded.
    type Owner: Send + Sync;

    /// The address and time of the account's most recent session with one.
    /// A session started by a grant has none: its request came from the
    /// application's server, not from the user.
    ///
    /// Used for impossible travel detection: resolves previous IP via GeoIP
    /// to get lat/lon, then compares with current login location.
    async fn get_most_recent_session_ip(
        &self,
        profile_id: Self::Owner,
    ) -> Result<Option<(IpAddr, chrono::DateTime<chrono::Utc>)>>;

    /// Whether the account had a session from `ip` within `window`.
    ///
    /// Used for `new_ip` anomaly detection: returns `true` if the IP has been
    /// seen before, `false` if the IP is new for this account.
    async fn has_recent_session_from_ip(
        &self,
        profile_id: Self::Owner,
        ip: IpAddr,
        window: std::time::Duration,
    ) -> Result<bool>;

    /// Whether the account had a session from `device_id` within `window`.
    ///
    /// Used for `new_device` anomaly detection: returns `true` if the device
    /// has been seen before, `false` if the device is new for this account.
    async fn has_recent_session_from_device(
        &self,
        profile_id: Self::Owner,
        device_id: uuid::Uuid,
        window: std::time::Duration,
    ) -> Result<bool>;

    /// Record a login location for designated location tracking.
    ///
    /// UPSERT per (account, country): increments login_count, updates
    /// last_seen, sets designated=true when login_count >= threshold.
    async fn record_login_location(
        &self,
        profile_id: Self::Owner,
        country: &str,
        latitude: f64,
        longitude: f64,
        designated_threshold: u32,
    ) -> Result<()>;

    /// The account's designated countries (login_count >= threshold).
    ///
    /// Used by impossible travel rule to suppress false positives from
    /// roaming/network switching between known locations.
    async fn get_designated_countries(&self, profile_id: Self::Owner) -> Result<Vec<String>>;
}
