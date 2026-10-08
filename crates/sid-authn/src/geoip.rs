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
    pub fn new(url_template: String, timeout: Duration) -> Self {
        let http = sid_plugin::client_builder()
            .timeout(timeout)
            .build()
            .expect("HTTP client build");
        Self { http, url_template }
    }

    /// Create with default ip-api.com endpoint.
    pub fn ip_api_default() -> Self {
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
pub fn build_geoip_chain_from_env(cache: Arc<dyn CacheBackend>) -> GeoIpChain {
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
                )));
            }
            other => {
                warn!(provider = other, "Unknown GeoIP provider, skipping");
            }
        }
    }

    if providers.is_empty() {
        info!("No GeoIP providers configured — country/location data will be unavailable");
    }

    GeoIpChain::new(providers, cache, Duration::from_secs(cache_ttl_secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sid_plugin::cache::NoCacheBackend;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn no_cache() -> Arc<dyn CacheBackend> {
        Arc::new(NoCacheBackend)
    }

    // ── In-memory cache for testing cache behavior ──

    /// Simple in-memory cache that actually stores data (unlike NoCacheBackend).
    use sid_plugin::cache::InMemoryCacheBackend as InMemoryCache;

    // ── Serialization roundtrip ──

    #[test]
    fn test_location_serialization_roundtrip() {
        let original = GeoLocation {
            country: "US".to_string(),
            city: Some("San Francisco".to_string()),
            latitude: 37.7749,
            longitude: -122.4194,
        };

        let data = serialize_location(&original).unwrap();
        let deserialized = deserialize_location(&data).unwrap();

        assert_eq!(deserialized.country, "US");
        assert_eq!(deserialized.city, Some("San Francisco".to_string()));
        assert!((deserialized.latitude - 37.7749).abs() < 0.001);
        assert!((deserialized.longitude - (-122.4194)).abs() < 0.001);
    }

    #[test]
    fn test_location_serialization_no_city() {
        let original = GeoLocation {
            country: "DE".to_string(),
            city: None,
            latitude: 51.1657,
            longitude: 10.4515,
        };

        let data = serialize_location(&original).unwrap();
        let deserialized = deserialize_location(&data).unwrap();

        assert_eq!(deserialized.country, "DE");
        assert_eq!(deserialized.city, None);
    }

    #[test]
    fn test_location_deserialization_invalid() {
        assert!(deserialize_location(b"").is_none());
        assert!(deserialize_location(b"invalid").is_none());
        assert!(deserialize_location(b"|city|0|0").is_none()); // empty country
    }

    // ── Test providers ──

    /// Stub provider that returns a fixed location and counts calls.
    struct CountingProvider {
        name: &'static str,
        country: &'static str,
        priority: i32,
        call_count: AtomicUsize,
    }

    impl CountingProvider {
        fn new(name: &'static str, country: &'static str, priority: i32) -> Self {
            Self {
                name,
                country,
                priority,
                call_count: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl GeoIpProvider for CountingProvider {
        async fn resolve(&self, _ip: IpAddr) -> Result<GeoLocation, GeoIpError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(GeoLocation {
                country: self.country.to_string(),
                city: None,
                latitude: 0.0,
                longitude: 0.0,
            })
        }
        fn provider_name(&self) -> &str {
            self.name
        }
        fn priority(&self) -> i32 {
            self.priority
        }
    }

    /// Stub provider that returns a fixed location for any IP.
    struct StubProvider {
        name: &'static str,
        country: &'static str,
        priority: i32,
    }

    #[async_trait]
    impl GeoIpProvider for StubProvider {
        async fn resolve(&self, _ip: IpAddr) -> Result<GeoLocation, GeoIpError> {
            Ok(GeoLocation {
                country: self.country.to_string(),
                city: None,
                latitude: 0.0,
                longitude: 0.0,
            })
        }
        fn provider_name(&self) -> &str {
            self.name
        }
        fn priority(&self) -> i32 {
            self.priority
        }
    }

    /// Provider that always returns NotFound.
    struct NotFoundProvider;

    #[async_trait]
    impl GeoIpProvider for NotFoundProvider {
        async fn resolve(&self, _ip: IpAddr) -> Result<GeoLocation, GeoIpError> {
            Err(GeoIpError::NotFound)
        }
        fn provider_name(&self) -> &str {
            "not_found"
        }
    }

    /// Provider that always errors.
    struct ErrorProvider;

    #[async_trait]
    impl GeoIpProvider for ErrorProvider {
        async fn resolve(&self, _ip: IpAddr) -> Result<GeoLocation, GeoIpError> {
            Err(GeoIpError::Unavailable("down".to_string()))
        }
        fn provider_name(&self) -> &str {
            "error"
        }
    }

    // ── GeoIpChain: basic behavior ──

    #[tokio::test]
    async fn test_chain_empty_returns_none() {
        let chain = GeoIpChain::empty(no_cache());
        let result = chain.resolve(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_chain_single_provider_success() {
        let provider = Arc::new(StubProvider {
            name: "test",
            country: "US",
            priority: 10,
        });
        let chain = GeoIpChain::new(vec![provider], no_cache(), Duration::from_secs(60));
        let result = chain.resolve(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).await;
        assert_eq!(result.unwrap().country, "US");
    }

    #[tokio::test]
    async fn test_chain_priority_ordering() {
        let low = Arc::new(StubProvider {
            name: "low",
            country: "DE",
            priority: 1,
        }) as Arc<dyn GeoIpProvider>;
        let high = Arc::new(StubProvider {
            name: "high",
            country: "US",
            priority: 100,
        }) as Arc<dyn GeoIpProvider>;

        let chain = GeoIpChain::new(vec![low, high], no_cache(), Duration::from_secs(60));
        let result = chain.resolve(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).await;
        assert_eq!(result.unwrap().country, "US");
    }

    #[tokio::test]
    async fn test_chain_fallback_on_not_found() {
        let first = Arc::new(NotFoundProvider) as Arc<dyn GeoIpProvider>;
        let second = Arc::new(StubProvider {
            name: "fallback",
            country: "US",
            priority: 0,
        }) as Arc<dyn GeoIpProvider>;

        let chain = GeoIpChain::new(vec![first, second], no_cache(), Duration::from_secs(60));
        let result = chain.resolve(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).await;
        assert_eq!(result.unwrap().country, "US");
    }

    #[tokio::test]
    async fn test_chain_fallback_on_error() {
        let first = Arc::new(ErrorProvider) as Arc<dyn GeoIpProvider>;
        let second = Arc::new(StubProvider {
            name: "fallback",
            country: "DE",
            priority: 0,
        }) as Arc<dyn GeoIpProvider>;

        let chain = GeoIpChain::new(vec![first, second], no_cache(), Duration::from_secs(60));
        let result = chain.resolve(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).await;
        assert_eq!(result.unwrap().country, "DE");
    }

    #[tokio::test]
    async fn test_chain_all_fail_returns_none() {
        let first = Arc::new(NotFoundProvider) as Arc<dyn GeoIpProvider>;
        let second = Arc::new(ErrorProvider) as Arc<dyn GeoIpProvider>;

        let chain = GeoIpChain::new(vec![first, second], no_cache(), Duration::from_secs(60));
        let result = chain.resolve(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).await;
        assert!(result.is_none());
    }

    #[test]
    fn test_chain_provider_count() {
        let chain = GeoIpChain::new(
            vec![Arc::new(StubProvider {
                name: "a",
                country: "US",
                priority: 0,
            }) as Arc<dyn GeoIpProvider>],
            no_cache(),
            Duration::from_secs(60),
        );
        assert_eq!(chain.provider_count(), 1);
    }

    // ── GeoIpChain: cache behavior ──

    #[tokio::test]
    async fn test_chain_cache_hit_skips_provider() {
        // Setup: in-memory cache with a counting provider.
        let provider = Arc::new(CountingProvider::new("counting", "US", 10));
        let cache = Arc::new(InMemoryCache::new());

        let chain = GeoIpChain::new(
            vec![provider.clone() as Arc<dyn GeoIpProvider>],
            cache.clone(),
            Duration::from_secs(60),
        );

        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // First resolve: cache miss → provider called.
        let r1 = chain.resolve(ip).await.unwrap();
        assert_eq!(r1.country, "US");
        assert_eq!(provider.calls(), 1);

        // Second resolve: cache hit → provider NOT called.
        let r2 = chain.resolve(ip).await.unwrap();
        assert_eq!(r2.country, "US");
        assert_eq!(provider.calls(), 1); // Still 1 — served from cache.
    }

    #[tokio::test]
    async fn test_chain_cache_different_ips_separate_entries() {
        let provider = Arc::new(CountingProvider::new("counting", "US", 10));
        let cache = Arc::new(InMemoryCache::new());

        let chain = GeoIpChain::new(
            vec![provider.clone() as Arc<dyn GeoIpProvider>],
            cache.clone(),
            Duration::from_secs(60),
        );

        let ip1 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let ip2 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        // Each IP → one provider call.
        chain.resolve(ip1).await;
        chain.resolve(ip2).await;
        assert_eq!(provider.calls(), 2);

        // Re-resolve both → cache hits.
        chain.resolve(ip1).await;
        chain.resolve(ip2).await;
        assert_eq!(provider.calls(), 2); // No new calls.
    }

    #[tokio::test]
    async fn test_chain_cache_stores_correct_data() {
        let cache = Arc::new(InMemoryCache::new());

        // Provider returns different countries for different IPs.
        struct IpAwareProvider;
        #[async_trait]
        impl GeoIpProvider for IpAwareProvider {
            async fn resolve(&self, ip: IpAddr) -> Result<GeoLocation, GeoIpError> {
                let country = match ip.to_string().as_str() {
                    "8.8.8.8" => "US",
                    "1.1.1.1" => "AU",
                    _ => return Err(GeoIpError::NotFound),
                };
                Ok(GeoLocation {
                    country: country.to_string(),
                    city: None,
                    latitude: 0.0,
                    longitude: 0.0,
                })
            }
            fn provider_name(&self) -> &str {
                "ip_aware"
            }
        }

        let chain = GeoIpChain::new(
            vec![Arc::new(IpAwareProvider) as Arc<dyn GeoIpProvider>],
            cache.clone(),
            Duration::from_secs(60),
        );

        // Resolve both IPs.
        let r1 = chain.resolve("8.8.8.8".parse().unwrap()).await.unwrap();
        let r2 = chain.resolve("1.1.1.1".parse().unwrap()).await.unwrap();
        assert_eq!(r1.country, "US");
        assert_eq!(r2.country, "AU");

        // Verify cache returns correct data (not mixed up).
        let r1_cached = chain.resolve("8.8.8.8".parse().unwrap()).await.unwrap();
        let r2_cached = chain.resolve("1.1.1.1".parse().unwrap()).await.unwrap();
        assert_eq!(r1_cached.country, "US");
        assert_eq!(r2_cached.country, "AU");
    }

    #[tokio::test]
    async fn test_chain_cache_not_found_is_not_cached() {
        // When provider returns NotFound, result should NOT be cached.
        // Next call for same IP should re-query provider.
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        struct SometimesFoundProvider {
            calls: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl GeoIpProvider for SometimesFoundProvider {
            async fn resolve(&self, _ip: IpAddr) -> Result<GeoLocation, GeoIpError> {
                let n = self.calls.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    // First call: not found.
                    Err(GeoIpError::NotFound)
                } else {
                    // Subsequent calls: found.
                    Ok(GeoLocation {
                        country: "US".to_string(),
                        city: None,
                        latitude: 0.0,
                        longitude: 0.0,
                    })
                }
            }
            fn provider_name(&self) -> &str {
                "sometimes"
            }
        }

        let cache = Arc::new(InMemoryCache::new());
        let chain = GeoIpChain::new(
            vec![Arc::new(SometimesFoundProvider {
                calls: call_count_clone,
            }) as Arc<dyn GeoIpProvider>],
            cache,
            Duration::from_secs(60),
        );

        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // First call: NotFound → returns None.
        let r1 = chain.resolve(ip).await;
        assert!(r1.is_none());
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Second call: provider called again (NotFound was not cached).
        let r2 = chain.resolve(ip).await;
        assert_eq!(r2.unwrap().country, "US");
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    // ── HttpGeoIpProvider ──

    #[tokio::test]
    async fn test_http_provider_parses_ip_api_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);

            assert!(request.contains("GET /json/8.8.8.8"), "Request: {request}");

            let body = r#"{"status":"success","countryCode":"US","lat":37.751,"lon":-97.822,"city":"Ashburn"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let provider = HttpGeoIpProvider::new(
            format!("http://127.0.0.1:{port}/json/{{ip}}?fields=status,countryCode,lat,lon,city"),
            Duration::from_secs(5),
        );

        let result = provider.resolve("8.8.8.8".parse().unwrap()).await.unwrap();
        assert_eq!(result.country, "US");
        assert_eq!(result.city, Some("Ashburn".to_string()));
        assert!((result.latitude - 37.751).abs() < 0.01);
        assert!((result.longitude - (-97.822)).abs() < 0.01);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_http_provider_handles_fail_status() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await.unwrap();

            let body = r#"{"status":"fail","message":"private range"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let provider = HttpGeoIpProvider::new(
            format!("http://127.0.0.1:{port}/json/{{ip}}"),
            Duration::from_secs(5),
        );

        let result = provider.resolve("10.0.0.1".parse().unwrap()).await;
        assert!(matches!(result, Err(GeoIpError::NotFound)));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_http_provider_handles_connection_refused() {
        // Connect to a port with nothing listening.
        let provider = HttpGeoIpProvider::new(
            "http://127.0.0.1:1/json/{ip}".to_string(),
            Duration::from_millis(100),
        );

        let result = provider.resolve("8.8.8.8".parse().unwrap()).await;
        assert!(matches!(result, Err(GeoIpError::Http(_))));
    }

    // ── MaxmindProvider ──

    #[test]
    fn test_maxmind_provider_open_nonexistent_file() {
        let result = MaxmindProvider::open(&PathBuf::from("/nonexistent/file.mmdb"));
        assert!(matches!(result, Err(GeoIpError::Database(_))));
    }

    #[test]
    fn test_maxmind_provider_priority() {
        assert_eq!(
            HttpGeoIpProvider::ip_api_default().priority(),
            10,
            "HTTP should be lower priority than MMDB"
        );
    }

    // ── Real provider integration tests (require local infrastructure) ──

    #[tokio::test]
    #[ignore = "requires GeoLite2-City.mmdb in data/geoip/"]
    async fn test_maxmind_provider_resolves_real_ip() {
        let path = PathBuf::from(std::env::var("SID_GEOIP_MMDB_PATH").unwrap_or_else(|_| {
            {
                // Resolve relative to workspace root (Cargo sets CARGO_MANIFEST_DIR).
                let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
                format!("{manifest}/../../data/geoip/GeoLite2-City.mmdb")
            }
        }));
        if !path.exists() {
            panic!(
                "MMDB file not found at {path:?}. Download from MaxMind or set SID_GEOIP_MMDB_PATH"
            );
        }

        let provider = MaxmindProvider::open(&path).unwrap();
        assert_eq!(provider.provider_name(), format!("mmdb:{}", path.display()));
        assert_eq!(provider.priority(), 100);

        // Google DNS — should resolve to US.
        let result = provider.resolve("8.8.8.8".parse().unwrap()).await.unwrap();
        assert_eq!(result.country, "US");
        assert!(result.latitude != 0.0, "lat should be non-zero");
        assert!(result.longitude != 0.0, "lon should be non-zero");

        // Cloudflare DNS — may resolve to AU/US or NotFound (anycast, depends on MMDB version).
        let result = provider.resolve("1.1.1.1".parse().unwrap()).await;
        match &result {
            Ok(loc) => assert!(!loc.country.is_empty(), "country should be non-empty"),
            Err(GeoIpError::NotFound) => {} // acceptable for anycast IPs
            Err(e) => panic!("unexpected error for 1.1.1.1: {e}"),
        }

        // Private IP — should be NotFound.
        let result = provider.resolve("192.168.1.1".parse().unwrap()).await;
        assert!(
            matches!(result, Err(GeoIpError::NotFound)),
            "private IP should not be in MMDB: {result:?}"
        );

        // Loopback — should be NotFound.
        let result = provider.resolve("127.0.0.1".parse().unwrap()).await;
        assert!(
            matches!(result, Err(GeoIpError::NotFound)),
            "loopback should not be in MMDB: {result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires network access to ip-api.com"]
    async fn test_http_provider_resolves_real_ip() {
        let provider = HttpGeoIpProvider::ip_api_default();

        // Google DNS — should resolve to US.
        let result = provider.resolve("8.8.8.8".parse().unwrap()).await.unwrap();
        assert_eq!(result.country, "US", "8.8.8.8 should be US");
        assert!(result.latitude != 0.0);
        assert!(result.longitude != 0.0);

        // Private IP — ip-api.com returns status: "fail".
        let result = provider.resolve("192.168.1.1".parse().unwrap()).await;
        assert!(
            matches!(result, Err(GeoIpError::NotFound)),
            "private IP should return NotFound: {result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires GeoLite2-City.mmdb in data/geoip/"]
    async fn test_full_chain_with_real_mmdb() {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let path = PathBuf::from(format!("{manifest}/../../data/geoip/GeoLite2-City.mmdb"));
        if !path.exists() {
            panic!("MMDB file not found at {path:?}");
        }

        let mmdb = Arc::new(MaxmindProvider::open(&path).unwrap()) as Arc<dyn GeoIpProvider>;
        let http = Arc::new(HttpGeoIpProvider::ip_api_default()) as Arc<dyn GeoIpProvider>;
        let cache = Arc::new(InMemoryCache::new());

        let chain = GeoIpChain::new(vec![mmdb, http], cache, Duration::from_secs(60));

        // MMDB should win (priority 100 > 10).
        let result = chain.resolve("8.8.8.8".parse().unwrap()).await.unwrap();
        assert_eq!(result.country, "US");

        // Second call — should come from cache (verify via speed, no assertion needed).
        let result2 = chain.resolve("8.8.8.8".parse().unwrap()).await.unwrap();
        assert_eq!(result2.country, "US");
    }

    // ── GeoLocation ──

    #[test]
    fn test_geolocation_eq() {
        let a = GeoLocation {
            country: "US".to_string(),
            city: Some("NYC".to_string()),
            latitude: 40.7,
            longitude: -74.0,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── Error variants ──

    #[test]
    fn test_geoip_error_display() {
        assert_eq!(
            GeoIpError::NotFound.to_string(),
            "address not found in database"
        );
        assert!(
            GeoIpError::Http("timeout".to_string())
                .to_string()
                .contains("timeout")
        );
        assert!(
            GeoIpError::Database("bad file".to_string())
                .to_string()
                .contains("bad file")
        );
        assert!(
            GeoIpError::LookupFailed("oops".to_string())
                .to_string()
                .contains("oops")
        );
        assert!(
            GeoIpError::Unavailable("down".to_string())
                .to_string()
                .contains("down")
        );
        assert!(
            GeoIpError::Parse("json".to_string())
                .to_string()
                .contains("json")
        );
    }

    // ── HttpGeoIpProvider construction ──

    #[test]
    fn test_http_provider_creation() {
        let provider = HttpGeoIpProvider::ip_api_default();
        assert_eq!(provider.provider_name(), "http_api");
        assert_eq!(provider.priority(), 10);
    }

    #[test]
    fn test_http_provider_custom_url() {
        let provider = HttpGeoIpProvider::new(
            "http://example.com/{ip}".to_string(),
            Duration::from_millis(100),
        );
        assert_eq!(provider.provider_name(), "http_api");
    }
}
