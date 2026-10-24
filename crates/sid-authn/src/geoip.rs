// SPDX-License-Identifier: AGPL-3.0-only
//! GeoIP Resolution — priority chain with cache.
//!
//! Resolves IP addresses to geographic locations for anomaly detection.
//! Two CE providers: MaxMind MMDB (local, preferred) and HTTP API (fallback).

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, info, warn};

use sid_plugin::cache::CacheBackend;
use sid_plugin::geoip::{GeoIpError, GeoIpProvider, GeoLocation};

// ── GeoIP Chain (priority aggregator) ────────────────────────────

/// Priority-based GeoIP resolution chain with distributed cache.
///
/// Queries providers in priority order (highest first). First success wins.
/// Results are cached in CacheBackend with configurable TTL.
///
/// Multi-instance safe: cache-backed, no mutable in-process state.
pub struct GeoIpChain {
    providers: Vec<Arc<dyn GeoIpProvider>>,
    cache: Arc<dyn CacheBackend>,
    cache_ttl: Duration,
}

impl GeoIpChain {
    /// Create a new chain with the given providers and cache.
    ///
    /// Providers are sorted by priority (highest first) on construction.
    pub fn new(
        mut providers: Vec<Arc<dyn GeoIpProvider>>,
        cache: Arc<dyn CacheBackend>,
        cache_ttl: Duration,
    ) -> Self {
        // Sort by priority descending (highest first).
        providers.sort_by_key(|p| std::cmp::Reverse(p.priority()));
        Self {
            providers,
            cache,
            cache_ttl,
        }
    }

    /// Create a chain with no providers (returns None for all lookups).
    pub fn empty(cache: Arc<dyn CacheBackend>) -> Self {
        Self {
            providers: Vec::new(),
            cache,
            cache_ttl: Duration::from_secs(86400),
        }
    }

    /// Resolve an IP address to a geographic location.
    ///
    /// Checks cache first. On miss, queries providers in priority order.
    /// First successful result is cached and returned.
    pub async fn resolve(&self, ip: IpAddr) -> Option<GeoLocation> {
        if self.providers.is_empty() {
            return None;
        }

        // Check cache first.
        let cache_key = format!("geoip:{ip}");
        if let Ok(Some(data)) = self.cache.get(&cache_key).await
            && let Some(location) = deserialize_location(&data)
        {
            return Some(location);
        }

        // Query providers in priority order (already sorted).
        for provider in &self.providers {
            match provider.resolve(ip).await {
                Ok(location) => {
                    debug!(
                        ip = %ip,
                        provider = provider.provider_name(),
                        country = %location.country,
                        "GeoIP resolved"
                    );
                    // Cache the result; a failed fill only costs the next
                    // lookup another provider query.
                    if let Some(data) = serialize_location(&location)
                        && let Err(e) = self.cache.set(&cache_key, &data, self.cache_ttl).await
                    {
                        warn!(ip = %ip, error = %e, "GeoIP result not cached");
                    }
                    return Some(location);
                }
                Err(GeoIpError::NotFound) => {
                    debug!(
                        ip = %ip,
                        provider = provider.provider_name(),
                        "IP not found in provider, trying next"
                    );
                    continue;
                }
                Err(e) => {
                    warn!(
                        ip = %ip,
                        provider = provider.provider_name(),
                        error = %e,
                        "GeoIP provider error, trying next"
                    );
                    continue;
                }
            }
        }

        None
    }

    /// Number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

// ── MaxMind MMDB Provider ────────────────────────────────────────

/// MaxMind MMDB file-based GeoIP provider.
///
/// Reads a local GeoLite2-City or GeoLite2-Country MMDB file.
/// Zero network latency — all lookups are in-memory from mmap'd file.
///
/// Configuration: `SID_GEOIP_MMDB_PATH=/data/GeoLite2-City.mmdb`
pub struct MaxmindProvider {
    reader: maxminddb::Reader<Vec<u8>>,
    name: String,
}

impl MaxmindProvider {
    /// Open a MaxMind MMDB file.
    pub fn open(path: &PathBuf) -> Result<Self, GeoIpError> {
        let reader = maxminddb::Reader::open_readfile(path).map_err(|e| {
            GeoIpError::Database(format!("failed to open MMDB file {:?}: {}", path, e))
        })?;
        info!(path = ?path, "MaxMind MMDB database loaded");
        Ok(Self {
            reader,
            name: format!("mmdb:{}", path.display()),
        })
    }
}

/// MaxMind GeoLite2/GeoIP2 City record (subset of fields we use).
#[derive(Debug, serde::Deserialize)]
struct MmdbCityRecord {
    country: Option<MmdbCountry>,
    city: Option<MmdbCity>,
    location: Option<MmdbLocation>,
}

#[derive(Debug, serde::Deserialize)]
struct MmdbCountry {
    iso_code: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct MmdbCity {
    names: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, serde::Deserialize)]
struct MmdbLocation {
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[async_trait]
impl GeoIpProvider for MaxmindProvider {
    async fn resolve(&self, ip: IpAddr) -> Result<GeoLocation, GeoIpError> {
        // A lookup that finds no network for the address is not an error in the
        // reader: it yields a result holding no data, and decoding it gives None.
        let record: MmdbCityRecord = self
            .reader
            .lookup(ip)
            .map_err(|e| GeoIpError::LookupFailed(e.to_string()))?
            .decode()
            .map_err(|e| GeoIpError::LookupFailed(e.to_string()))?
            .ok_or(GeoIpError::NotFound)?;

        let country = record
            .country
            .and_then(|c| c.iso_code)
            .ok_or(GeoIpError::NotFound)?;

        let city = record
            .city
            .and_then(|c| c.names)
            .and_then(|n| n.get("en").cloned());

        let (latitude, longitude) = record
            .location
            .map(|l| (l.latitude.unwrap_or(0.0), l.longitude.unwrap_or(0.0)))
            .unwrap_or((0.0, 0.0));

        Ok(GeoLocation {
            country,
            city,
            latitude,
            longitude,
        })
    }

    fn provider_name(&self) -> &str {
        &self.name
    }

    fn priority(&self) -> i32 {
        100 // Highest priority — local file, zero latency
    }
}

// ── HTTP API Provider ────────────────────────────────────────────

/// HTTP API-based GeoIP provider (fallback when no MMDB file available).
///
/// Queries an HTTP endpoint that returns JSON with country, lat, lon.
/// Default: ip-api.com (free tier, 45 req/min, no API key).
///
/// Configuration:
/// - `SID_GEOIP_HTTP_URL=http://ip-api.com/json/{ip}?fields=status,countryCode,lat,lon,city`
/// - `SID_GEOIP_HTTP_TIMEOUT_MS=500`
///
/// The URL template uses `{ip}` as placeholder for the IP address.
pub struct HttpGeoIpProvider {
    http: reqwest::Client,
    url_template: String,
}

impl HttpGeoIpProvider {
    /// Create with a URL template. `{ip}` in the template is replaced with the IP.
    pub fn new(
        url_template: String,
        timeout: Duration,
    ) -> Result<Self, sid_plugin::http::HttpClientError> {
        let http = sid_plugin::client_builder()?.timeout(timeout).build()?;
        Ok(Self { http, url_template })
    }

    /// Create with default ip-api.com endpoint.
    pub fn ip_api_default() -> Result<Self, sid_plugin::http::HttpClientError> {
        Self::new(
            "http://ip-api.com/json/{ip}?fields=status,countryCode,lat,lon,city".to_string(),
            Duration::from_millis(500),
        )
    }
}

/// ip-api.com JSON response.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpApiResponse {
    status: Option<String>,
    country_code: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    city: Option<String>,
}

#[async_trait]
impl GeoIpProvider for HttpGeoIpProvider {
    async fn resolve(&self, ip: IpAddr) -> Result<GeoLocation, GeoIpError> {
        let url = self.url_template.replace("{ip}", &ip.to_string());

        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| GeoIpError::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(GeoIpError::Http(format!(
                "HTTP {} from {}",
                response.status(),
                url
            )));
        }

        let body: IpApiResponse = response
            .json()
            .await
            .map_err(|e| GeoIpError::Parse(e.to_string()))?;

        // ip-api.com returns status: "fail" for private/invalid IPs.
        if body.status.as_deref() == Some("fail") {
            return Err(GeoIpError::NotFound);
        }

        let country = body.country_code.ok_or(GeoIpError::NotFound)?;
        if country.is_empty() {
            return Err(GeoIpError::NotFound);
        }

        Ok(GeoLocation {
            country,
            city: body.city,
            latitude: body.lat.unwrap_or(0.0),
            longitude: body.lon.unwrap_or(0.0),
        })
    }

    fn provider_name(&self) -> &str {
        "http_api"
    }

    fn priority(&self) -> i32 {
        10 // Lower priority — network latency, rate limited
    }
}

// ── Serialization helpers for cache ──────────────────────────────

fn serialize_location(loc: &GeoLocation) -> Option<Vec<u8>> {
    // Format: country|city|lat|lon
    let city = loc.city.as_deref().unwrap_or("");
    let data = format!(
        "{}|{}|{}|{}",
        loc.country, city, loc.latitude, loc.longitude
    );
    Some(data.into_bytes())
}

fn deserialize_location(data: &[u8]) -> Option<GeoLocation> {
    let text = std::str::from_utf8(data).ok()?;
    let parts: Vec<&str> = text.splitn(4, '|').collect();
    if parts.len() != 4 {
        return None;
    }

    let country = parts[0].to_string();
    if country.is_empty() {
        return None;
    }

    let city = if parts[1].is_empty() {
        None
    } else {
        Some(parts[1].to_string())
    };

    let latitude = parts[2].parse::<f64>().ok()?;
    let longitude = parts[3].parse::<f64>().ok()?;

    Some(GeoLocation {
        country,
        city,
        latitude,
        longitude,
    })
}

// ── Factory: build chain from environment ────────────────────────

/// Build a GeoIP chain from environment variables.
///
/// Configuration:
/// - `SID_GEOIP_PROVIDERS=mmdb,http` (priority chain, default: "mmdb,http")
/// - `SID_GEOIP_MMDB_PATH=/data/GeoLite2-City.mmdb` (for MMDB provider)
/// - `SID_GEOIP_HTTP_URL=...` (for HTTP provider, default: ip-api.com)
/// - `SID_GEOIP_HTTP_TIMEOUT_MS=500` (HTTP timeout, default: 500)
/// - `SID_GEOIP_CACHE_TTL_SECS=86400` (cache TTL, default: 86400 = 24h)
pub fn build_geoip_chain_from_env(
    cache: Arc<dyn CacheBackend>,
) -> Result<GeoIpChain, sid_plugin::http::HttpClientError> {
    let provider_list =
        std::env::var("SID_GEOIP_PROVIDERS").unwrap_or_else(|_| "mmdb,http".to_string());
    let cache_ttl_secs: u64 = std::env::var("SID_GEOIP_CACHE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(86400);

    let mut providers: Vec<Arc<dyn GeoIpProvider>> = Vec::new();

    for name in provider_list.split(',').map(|s| s.trim()) {
        match name {
            "mmdb" => {
                if let Ok(path) = std::env::var("SID_GEOIP_MMDB_PATH") {
                    match MaxmindProvider::open(&PathBuf::from(&path)) {
                        Ok(provider) => {
                            info!(path = %path, "MaxMind MMDB GeoIP provider enabled");
                            providers.push(Arc::new(provider));
                        }
                        Err(e) => {
                            warn!(path = %path, error = %e, "Failed to load MaxMind MMDB, skipping");
                        }
                    }
                } else {
                    debug!("SID_GEOIP_MMDB_PATH not set, skipping MMDB provider");
                }
            }
            "http" => {
                let url = std::env::var("SID_GEOIP_HTTP_URL").unwrap_or_else(|_| {
                    "http://ip-api.com/json/{ip}?fields=status,countryCode,lat,lon,city".to_string()
                });
                let timeout_ms: u64 = std::env::var("SID_GEOIP_HTTP_TIMEOUT_MS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(500);

                info!(url = %url, timeout_ms, "HTTP GeoIP provider enabled");
                providers.push(Arc::new(HttpGeoIpProvider::new(
                    url,
                    Duration::from_millis(timeout_ms),
                )?));
            }
            other => {
                warn!(provider = other, "Unknown GeoIP provider, skipping");
            }
        }
    }

    if providers.is_empty() {
        info!("No GeoIP providers configured — country/location data will be unavailable");
    }

    Ok(GeoIpChain::new(
        providers,
        cache,
        Duration::from_secs(cache_ttl_secs),
    ))
}

#[cfg(test)]
mod tests;
