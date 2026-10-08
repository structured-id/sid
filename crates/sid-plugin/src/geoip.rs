// SPDX-License-Identifier: AGPL-3.0-only
//! GeoIP Provider — pluggable IP-to-location resolution.
//!
//! Enriches `LoginContext.country` (and lat/lon for impossible travel)
//! before anomaly rule evaluation.
//!
//! Providers: MaxMind MMDB (local file), HTTP API (configurable endpoint).

use std::net::IpAddr;

use async_trait::async_trait;

/// Geolocation data resolved from an IP address.
#[derive(Debug, Clone, PartialEq)]
pub struct GeoLocation {
    /// ISO 3166-1 alpha-2 country code (e.g., "US", "DE").
    pub country: String,
    /// City name (if available).
    pub city: Option<String>,
    /// Latitude (WGS84).
    pub latitude: f64,
    /// Longitude (WGS84).
    pub longitude: f64,
}

/// GeoIP resolution errors.
#[derive(Debug, thiserror::Error)]
pub enum GeoIpError {
    #[error("lookup failed: {0}")]
    LookupFailed(String),
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("address not found in database")]
    NotFound,
    #[error("database file error: {0}")]
    Database(String),
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("parse error: {0}")]
    Parse(String),
}

/// Pluggable GeoIP provider.
///
/// Resolves an IP address to a geographic location.
/// Providers are queried in priority order; first success wins.
///
/// Built-in:
/// - MaxMind MMDB (local file, zero latency)
/// - HTTP API (configurable URL, fallback)
#[async_trait]
pub trait GeoIpProvider: Send + Sync {
    /// Resolve an IP address to a geographic location.
    ///
    /// Returns `Ok(location)` on success, `Err(NotFound)` if the IP
    /// is not in the database, or other errors for provider failures.
    async fn resolve(&self, ip: IpAddr) -> Result<GeoLocation, GeoIpError>;

    /// Provider name (for logging and audit trail).
    fn provider_name(&self) -> &str;

    /// Priority (higher = preferred, queried first).
    fn priority(&self) -> i32 {
        0
    }
}
