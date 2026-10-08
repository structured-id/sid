// SPDX-License-Identifier: AGPL-3.0-only
//! IP Intelligence — pluggable provider chain for IP classification.
//!
//! Enriches `LoginContext` with Tor exit, datacenter, blocklist, and reputation labels
//! before anomaly rule evaluation.
//!
//! Pluggable providers feed an aggregator in cascading layers.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use sid_plugin::cache::CacheBackend;

// ── Types ────────────────────────────────────────────────────────

/// Classification labels for an IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpLabel {
    /// Known Tor exit node.
    TorExit,
    /// Datacenter/hosting/cloud provider IP.
    Datacenter,
    /// VPN service IP.
    Vpn,
    /// Open proxy.
    Proxy,
    /// Known bot/scanner.
    Bot,
    /// Appears on a threat blocklist.
    Blocklisted,
    /// Admin-configured allowlist — overrides ALL negative labels.
    /// When present, aggregator clears all other labels and sets risk_score=0.
    Allowed,
}

impl IpLabel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TorExit => "tor_exit",
            Self::Datacenter => "datacenter",
            Self::Vpn => "vpn",
            Self::Proxy => "proxy",
            Self::Bot => "bot",
            Self::Blocklisted => "blocklisted",
            Self::Allowed => "allowed",
        }
    }
}

/// Classification result from a provider.
#[derive(Debug, Clone)]
pub struct IpClassification {
    /// Labels assigned to the IP (tor_exit, datacenter, blocklisted, etc.).
    pub labels: Vec<IpLabel>,
    /// Provider-specific risk score (0.0 = safe, 1.0 = certain threat).
    pub risk_score: Option<f32>,
    /// Which provider produced this classification.
    pub source: String,
    /// When this classification expires (cache TTL).
    pub expires_at: DateTime<Utc>,
}

/// Aggregated classification from all providers.
#[derive(Debug, Clone, Default)]
pub struct AggregatedClassification {
    /// Merged labels from all providers.
    pub labels: HashSet<IpLabel>,
    /// Max risk score across all providers.
    pub risk_score: Option<f32>,
    /// Sources that contributed to this classification.
    pub sources: Vec<String>,
}

impl AggregatedClassification {
    /// Check if IP has a specific label.
    pub fn has_label(&self, label: IpLabel) -> bool {
        self.labels.contains(&label)
    }

    /// Whether the IP is classified as a Tor exit node.
    pub fn is_tor_exit(&self) -> bool {
        self.has_label(IpLabel::TorExit)
    }

    /// Whether the IP is classified as datacenter/hosting.
    pub fn is_datacenter(&self) -> bool {
        self.has_label(IpLabel::Datacenter)
    }

    /// Whether the IP appears on any blocklist.
    pub fn is_blocklisted(&self) -> bool {
        self.has_label(IpLabel::Blocklisted)
    }
}

// ── Provider trait ───────────────────────────────────────────────

/// Pluggable IP intelligence provider.
///
/// Both `classify()` and `refresh()` are async. Most providers do in-memory
/// lookups (<1μs) via ArcSwap, but `SelfLearnedReputationProvider` performs
/// a per-call DB query (~1ms) as specified by the architecture.
/// Background refresh task calls `refresh()` periodically to update local data.
#[async_trait]
pub trait IpIntelligenceProvider: Send + Sync {
    /// Classify an IP address. `Ok(None)` means this provider has no opinion;
    /// an error means it could not answer, which never reads as "no opinion".
    async fn classify(&self, ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError>;

    /// Refresh from the source and publish the result to the replicas
    /// (called on the replica holding the refresh lock).
    async fn refresh(&self) -> Result<(), IpIntelError>;

    /// Reload the state the refreshing replica published, without asking the
    /// external source (called on every other replica). Providers that keep
    /// no local copy of shared state have nothing to reload.
    async fn reload(&self) -> Result<(), IpIntelError> {
        Ok(())
    }

    /// Provider name (for audit trail / logging).
    fn source_name(&self) -> &str;
}

/// IP intelligence errors.
#[derive(Debug, thiserror::Error)]
pub enum IpIntelError {
    #[error("HTTP fetch failed: {0}")]
    Fetch(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("cache error: {0}")]
    Cache(String),
    #[error("provider unavailable: {0}")]
    Unavailable(String),
}

// ── Aggregator ───────────────────────────────────────────────────

/// Aggregates classifications from multiple providers.
///
/// Rules:
/// - Allowlist always wins — if ANY provider returns `Allowed`, all negative
///   labels are cleared and risk_score is set to 0.0 (prevents blocking
///   legitimate infrastructure like monitoring, CDN, CI/CD)
/// - Multiple labels merge (IP can be both `tor_exit` AND `blocklisted`)
/// - Risk score = max across providers (worst-case)
/// - Cache: IP → classification in CacheBackend with per-IP TTL
pub struct IpIntelligenceAggregator {
    providers: Vec<Arc<dyn IpIntelligenceProvider>>,
    cache: Arc<dyn CacheBackend>,
    /// Cache TTL for aggregated results.
    cache_ttl: Duration,
}

impl IpIntelligenceAggregator {
    pub fn new(
        providers: Vec<Arc<dyn IpIntelligenceProvider>>,
        cache: Arc<dyn CacheBackend>,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            providers,
            cache,
            cache_ttl,
        }
    }

    /// Classify an IP by querying all providers and merging results.
    ///
    /// Checks cache first. On miss, queries all providers, merges, and caches
    /// the result. A provider that cannot answer fails the classification:
    /// a partial one would miss exactly the labels that provider holds.
    pub async fn classify(&self, ip: IpAddr) -> Result<AggregatedClassification, IpIntelError> {
        // Check cache first; an unreadable cache only means asking the
        // providers.
        let cache_key = format!("ipintel:{ip}");
        if let Ok(Some(data)) = self.cache.get(&cache_key).await
            && let Some(cached) = deserialize_classification(&data)
        {
            return Ok(cached);
        }

        // Query all providers.
        let mut result = AggregatedClassification::default();

        for provider in &self.providers {
            if let Some(classification) = provider.classify(ip).await? {
                for label in &classification.labels {
                    result.labels.insert(*label);
                }
                // Max risk score.
                match (result.risk_score, classification.risk_score) {
                    (None, score) => result.risk_score = score,
                    (Some(current), Some(new)) if new > current => {
                        result.risk_score = Some(new);
                    }
                    _ => {}
                }
                result.sources.push(classification.source);
            }
        }

        // Allowlist always wins: if IP is on an admin allowlist,
        // clear all negative labels and reset risk score.
        if result.labels.contains(&IpLabel::Allowed) {
            result.labels.clear();
            result.labels.insert(IpLabel::Allowed);
            result.risk_score = Some(0.0);
        }

        // Cache the result; a failed fill only costs the next lookup another
        // round of provider queries.
        if let Some(data) = serialize_classification(&result)
            && let Err(e) = self.cache.set(&cache_key, &data, self.cache_ttl).await
        {
            warn!(ip = %ip, error = %e, "IP classification not cached");
        }

        Ok(result)
    }

    /// Refresh all providers (called by background task).
    pub async fn refresh_all(&self) -> Vec<(&str, Result<(), IpIntelError>)> {
        let mut results = Vec::new();
        for provider in &self.providers {
            let name = provider.source_name();
            let result = provider.refresh().await;
            if let Err(ref e) = result {
                warn!(provider = name, error = %e, "IP intelligence provider refresh failed");
            } else {
                info!(provider = name, "IP intelligence provider refreshed");
            }
            results.push((name, result));
        }
        results
    }

    /// Reload every provider from the state the refreshing replica
    /// published (called on the replicas that did not refresh).
    pub async fn reload_all(&self) -> Vec<(&str, Result<(), IpIntelError>)> {
        let mut results = Vec::new();
        for provider in &self.providers {
            let name = provider.source_name();
            let result = provider.reload().await;
            if let Err(ref e) = result {
                warn!(provider = name, error = %e, "IP intelligence provider reload failed");
            }
            results.push((name, result));
        }
        results
    }

    /// Number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

// ── Tor Exit Provider ────────────────────────────────────────────

/// URL for Tor Project's bulk exit list.
const TOR_EXIT_LIST_URL: &str = "https://check.torproject.org/torbulkexitlist";

/// Tor exit node detection via bulk exit list.
///
/// Fetches the list of all Tor exit nodes from the Tor Project,
/// stores them in a `HashSet<IpAddr>` behind `ArcSwap` for lock-free reads.
///
/// Refresh: hourly. Startup: load from cache, async fetch.
pub struct TorExitProvider {
    /// Current exit node set — atomic swap for lock-free reads.
    nodes: ArcSwap<HashSet<IpAddr>>,
    /// HTTP client for fetching the list.
    http: reqwest::Client,
    /// Cache backend for persisting across restarts.
    cache: Arc<dyn CacheBackend>,
    /// Fetch URL (overridable for testing).
    url: String,
    /// Refresh mutex — ensures only one refresh runs at a time.
    refresh_lock: Mutex<()>,
}

impl TorExitProvider {
    /// Create a new Tor exit provider.
    pub fn new(cache: Arc<dyn CacheBackend>) -> Self {
        Self {
            nodes: ArcSwap::new(Arc::new(HashSet::new())),
            http: sid_plugin::client_builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("HTTP client build"),
            cache,
            url: TOR_EXIT_LIST_URL.to_string(),
            refresh_lock: Mutex::new(()),
        }
    }

    /// Create with custom URL (for testing).
    pub fn with_url(cache: Arc<dyn CacheBackend>, url: String) -> Self {
        Self {
            url,
            ..Self::new(cache)
        }
    }

    /// Load the list the refreshing replica stored in the shared cache. None
    /// stored yet keeps the current list.
    pub async fn load_from_cache(&self) -> Result<(), IpIntelError> {
        let Some(data) = self
            .cache
            .get("ipintel:tor:nodes")
            .await
            .map_err(|e| IpIntelError::Cache(e.to_string()))?
        else {
            return Ok(());
        };
        let text = String::from_utf8(data).map_err(|e| IpIntelError::Parse(e.to_string()))?;
        let nodes = parse_tor_exit_list(&text);
        if !nodes.is_empty() {
            debug!(count = nodes.len(), "Loaded Tor exit nodes from cache");
            self.nodes.store(Arc::new(nodes));
        }
        Ok(())
    }

    /// Number of loaded exit nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.load().len()
    }

    /// Parse and load a Tor exit list from raw text (for testing).
    pub fn load_from_text(&self, text: &str) {
        let nodes = parse_tor_exit_list(text);
        self.nodes.store(Arc::new(nodes));
    }
}

#[async_trait]
impl IpIntelligenceProvider for TorExitProvider {
    async fn classify(&self, ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
        let nodes = self.nodes.load();
        Ok(nodes.contains(&ip).then(|| IpClassification {
            labels: vec![IpLabel::TorExit],
            risk_score: Some(0.8),
            source: "tor_bulk_exit_list".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }))
    }

    async fn refresh(&self) -> Result<(), IpIntelError> {
        // Single-flight: only one refresh at a time.
        let _guard = self.refresh_lock.lock().await;

        debug!(url = %self.url, "Fetching Tor exit node list");

        let response = self
            .http
            .get(&self.url)
            .send()
            .await
            .map_err(|e| IpIntelError::Fetch(e.to_string()))?;

        if !response.status().is_success() {
            return Err(IpIntelError::Fetch(format!(
                "HTTP {} from {}",
                response.status(),
                self.url
            )));
        }

        let text = response
            .text()
            .await
            .map_err(|e| IpIntelError::Parse(e.to_string()))?;

        let nodes = parse_tor_exit_list(&text);
        if nodes.is_empty() {
            return Err(IpIntelError::Parse(
                "Tor exit list is empty after parsing".to_string(),
            ));
        }

        let count = nodes.len();

        // Atomic swap — readers see new data immediately, no lock.
        self.nodes.store(Arc::new(nodes));

        // Publish the raw text: the other replicas load it from here.
        let cache_ttl = Duration::from_secs(7200); // 2h cache (refresh every 1h)
        self.cache
            .set("ipintel:tor:nodes", text.as_bytes(), cache_ttl)
            .await
            .map_err(|e| IpIntelError::Cache(e.to_string()))?;

        info!(count, "Tor exit node list updated");
        Ok(())
    }

    async fn reload(&self) -> Result<(), IpIntelError> {
        self.load_from_cache().await
    }

    fn source_name(&self) -> &str {
        "tor_exit"
    }
}

/// Parse the Tor bulk exit list text format.
///
/// Format: one IP per line, comments start with `#`, blank lines ignored.
fn parse_tor_exit_list(text: &str) -> HashSet<IpAddr> {
    text.lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.parse::<IpAddr>().ok())
        .collect()
}

// ── CIDR Set ────────────────────────────────────────────────────

/// Efficient CIDR range containment check.
///
/// Stores ranges as sorted (start, end) pairs of u128 (supporting both IPv4 and IPv6).
/// Containment check is O(log n) via binary search.
#[derive(Debug, Clone, Default)]
pub struct CidrSet {
    /// Sorted by start address: (start_inclusive, end_inclusive).
    ranges: Vec<(u128, u128)>,
}

impl CidrSet {
    /// Build a CidrSet from an iterator of CIDR networks.
    pub fn from_nets(nets: impl IntoIterator<Item = IpNet>) -> Self {
        let mut ranges: Vec<(u128, u128)> = nets
            .into_iter()
            .map(|net| {
                let start = ip_to_u128(net.network());
                let end = ip_to_u128(net.broadcast());
                (start, end)
            })
            .collect();
        ranges.sort_unstable_by_key(|&(start, _)| start);
        // Merge overlapping ranges for correctness.
        let merged = merge_ranges(ranges);
        Self { ranges: merged }
    }

    /// Check if an IP address is contained in any CIDR range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let val = ip_to_u128(ip);
        // Binary search: find the last range whose start <= val.
        let idx = self.ranges.partition_point(|&(start, _)| start <= val);
        if idx == 0 {
            return false;
        }
        let (_, end) = self.ranges[idx - 1];
        val <= end
    }

    /// Number of CIDR ranges stored.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// Convert an IP address to a u128 for unified IPv4/IPv6 comparison.
///
/// IPv4 addresses are mapped to their IPv4-mapped IPv6 representation:
/// `::ffff:a.b.c.d` → ensures IPv4 and IPv6 ranges never overlap.
fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            u128::from(u32::from_be_bytes(octets))
        }
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// Merge overlapping or adjacent sorted ranges.
fn merge_ranges(sorted: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    let mut result: Vec<(u128, u128)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        if let Some(last) = result.last_mut() {
            // Overlapping or adjacent: extend.
            if start <= last.1.saturating_add(1) {
                last.1 = last.1.max(end);
                continue;
            }
        }
        result.push((start, end));
    }
    result
}

// ── Cloud Range Provider ────────────────────────────────────────

/// Cloud provider IP range source.
#[derive(Debug, Clone)]
struct CloudSource {
    /// Source name (for logging).
    name: &'static str,
    /// URL to fetch IP ranges from.
    url: &'static str,
    /// Parser function.
    parser: fn(&str) -> Vec<IpNet>,
}

/// Default cloud IP range sources.
///
/// Azure is intentionally omitted — its download URL changes weekly.
/// To include Azure, set `SID_IPINTEL_AZURE_URL` to the current ServiceTags JSON URL
/// (from https://www.microsoft.com/en-us/download/details.aspx?id=56519).
const CLOUD_SOURCES: &[CloudSource] = &[
    CloudSource {
        name: "aws",
        url: "https://ip-ranges.amazonaws.com/ip-ranges.json",
        parser: parse_aws_ranges,
    },
    CloudSource {
        name: "gcp",
        url: "https://www.gstatic.com/ipranges/cloud.json",
        parser: parse_gcp_ranges,
    },
    CloudSource {
        name: "cloudflare_v4",
        url: "https://www.cloudflare.com/ips-v4",
        parser: parse_cidr_text,
    },
    CloudSource {
        name: "cloudflare_v6",
        url: "https://www.cloudflare.com/ips-v6",
        parser: parse_cidr_text,
    },
];

/// Datacenter/hosting/cloud IP range detection.
///
/// Fetches IP range lists from major cloud providers (AWS, GCP, Cloudflare),
/// stores them in a [`CidrSet`] behind `ArcSwap` for lock-free reads.
///
/// Refresh: daily. Startup: load from cache, async fetch.
pub struct CloudRangeProvider {
    /// Current CIDR set — atomic swap for lock-free reads.
    cidrs: ArcSwap<CidrSet>,
    /// HTTP client for fetching the lists.
    http: reqwest::Client,
    /// Cache backend for persisting across restarts.
    cache: Arc<dyn CacheBackend>,
    /// Optional Azure ServiceTags JSON URL (changes weekly, must be configured).
    azure_url: Option<String>,
    /// Refresh mutex — ensures only one refresh runs at a time.
    refresh_lock: Mutex<()>,
}

impl CloudRangeProvider {
    /// Create a new cloud range provider.
    pub fn new(cache: Arc<dyn CacheBackend>) -> Self {
        Self {
            cidrs: ArcSwap::new(Arc::new(CidrSet::default())),
            http: sid_plugin::client_builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("HTTP client build"),
            cache,
            azure_url: None,
            refresh_lock: Mutex::new(()),
        }
    }

    /// Create with Azure ServiceTags URL.
    ///
    /// Azure IP range download URLs change weekly. Set via `SID_IPINTEL_AZURE_URL` env var.
    /// Get the current URL from: https://www.microsoft.com/en-us/download/details.aspx?id=56519
    pub fn with_azure(cache: Arc<dyn CacheBackend>, azure_url: String) -> Self {
        Self {
            azure_url: Some(azure_url),
            ..Self::new(cache)
        }
    }

    /// Load the ranges the refreshing replica stored in the shared cache.
    /// None stored yet keeps the current ranges.
    pub async fn load_from_cache(&self) -> Result<(), IpIntelError> {
        let Some(data) = self
            .cache
            .get("ipintel:cloud:cidrs")
            .await
            .map_err(|e| IpIntelError::Cache(e.to_string()))?
        else {
            return Ok(());
        };
        let text = String::from_utf8(data).map_err(|e| IpIntelError::Parse(e.to_string()))?;
        let cidrs = parse_cidr_text(&text);
        if !cidrs.is_empty() {
            let set = CidrSet::from_nets(cidrs);
            debug!(ranges = set.len(), "Loaded cloud IP ranges from cache");
            self.cidrs.store(Arc::new(set));
        }
        Ok(())
    }

    /// Number of CIDR ranges loaded.
    pub fn range_count(&self) -> usize {
        self.cidrs.load().len()
    }

    /// Load from raw CIDR text (for testing).
    pub fn load_from_text(&self, text: &str) {
        let nets = parse_cidr_text(text);
        self.cidrs.store(Arc::new(CidrSet::from_nets(nets)));
    }
}

#[async_trait]
impl IpIntelligenceProvider for CloudRangeProvider {
    async fn classify(&self, ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
        let cidrs = self.cidrs.load();
        Ok(cidrs.contains(ip).then(|| IpClassification {
            labels: vec![IpLabel::Datacenter],
            risk_score: Some(0.4),
            source: "cloud_ranges".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
        }))
    }

    async fn refresh(&self) -> Result<(), IpIntelError> {
        let _guard = self.refresh_lock.lock().await;

        let mut all_nets: Vec<IpNet> = Vec::new();

        for source in CLOUD_SOURCES {
            debug!(
                source = source.name,
                url = source.url,
                "Fetching cloud IP ranges"
            );

            match self.http.get(source.url).send().await {
                Ok(response) if response.status().is_success() => match response.text().await {
                    Ok(text) => {
                        let nets = (source.parser)(&text);
                        debug!(
                            source = source.name,
                            count = nets.len(),
                            "Parsed cloud ranges"
                        );
                        all_nets.extend(nets);
                    }
                    Err(e) => {
                        warn!(source = source.name, error = %e, "Failed to read cloud range response body");
                    }
                },
                Ok(response) => {
                    warn!(source = source.name, status = %response.status(), "Cloud range fetch returned non-success status");
                }
                Err(e) => {
                    warn!(source = source.name, error = %e, "Cloud range fetch failed");
                }
            }
        }

        // Azure: optional, URL configured via env.
        if let Some(ref azure_url) = self.azure_url {
            debug!(url = %azure_url, "Fetching Azure ServiceTags IP ranges");
            match self.http.get(azure_url).send().await {
                Ok(response) if response.status().is_success() => {
                    if let Ok(text) = response.text().await {
                        let nets = parse_azure_ranges(&text);
                        debug!(source = "azure", count = nets.len(), "Parsed Azure ranges");
                        all_nets.extend(nets);
                    }
                }
                Ok(response) => {
                    warn!(source = "azure", status = %response.status(), "Azure range fetch returned non-success status");
                }
                Err(e) => {
                    warn!(source = "azure", error = %e, "Azure range fetch failed");
                }
            }
        }

        if all_nets.is_empty() {
            return Err(IpIntelError::Parse(
                "All cloud range sources returned empty data".to_string(),
            ));
        }

        let cache_text: String = all_nets.iter().map(|n| format!("{n}\n")).collect();
        let count = all_nets.len();
        let set = CidrSet::from_nets(all_nets);
        self.cidrs.store(Arc::new(set));

        // Publish as text (one CIDR per line): the other replicas load it
        // from here.
        let cache_ttl = Duration::from_secs(172800); // 2 days cache (refresh daily)
        self.cache
            .set("ipintel:cloud:cidrs", cache_text.as_bytes(), cache_ttl)
            .await
            .map_err(|e| IpIntelError::Cache(e.to_string()))?;

        info!(count, "Cloud IP ranges updated");
        Ok(())
    }

    async fn reload(&self) -> Result<(), IpIntelError> {
        self.load_from_cache().await
    }

    fn source_name(&self) -> &str {
        "cloud_ranges"
    }
}

/// Parse AWS ip-ranges.json: `{ "prefixes": [{ "ip_prefix": "..." }], "ipv6_prefixes": [{ "ipv6_prefix": "..." }] }`
fn parse_aws_ranges(json: &str) -> Vec<IpNet> {
    let mut nets = Vec::new();
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json) {
        if let Some(prefixes) = val.get("prefixes").and_then(|v| v.as_array()) {
            for p in prefixes {
                if let Some(cidr) = p.get("ip_prefix").and_then(|v| v.as_str())
                    && let Ok(net) = cidr.parse::<IpNet>()
                {
                    nets.push(net);
                }
            }
        }
        if let Some(prefixes) = val.get("ipv6_prefixes").and_then(|v| v.as_array()) {
            for p in prefixes {
                if let Some(cidr) = p.get("ipv6_prefix").and_then(|v| v.as_str())
                    && let Ok(net) = cidr.parse::<IpNet>()
                {
                    nets.push(net);
                }
            }
        }
    }
    nets
}

/// Parse GCP cloud.json: `{ "prefixes": [{ "ipv4Prefix": "..." }, { "ipv6Prefix": "..." }] }`
fn parse_gcp_ranges(json: &str) -> Vec<IpNet> {
    let mut nets = Vec::new();
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json)
        && let Some(prefixes) = val.get("prefixes").and_then(|v| v.as_array())
    {
        for p in prefixes {
            for key in &["ipv4Prefix", "ipv6Prefix"] {
                if let Some(cidr) = p.get(*key).and_then(|v| v.as_str())
                    && let Ok(net) = cidr.parse::<IpNet>()
                {
                    nets.push(net);
                }
            }
        }
    }
    nets
}

/// Parse Azure ServiceTags JSON: `{ "values": [{ "properties": { "addressPrefixes": ["..."] } }] }`
fn parse_azure_ranges(json: &str) -> Vec<IpNet> {
    let mut nets = Vec::new();
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json)
        && let Some(values) = val.get("values").and_then(|v| v.as_array())
    {
        for entry in values {
            if let Some(prefixes) = entry
                .get("properties")
                .and_then(|p| p.get("addressPrefixes"))
                .and_then(|a| a.as_array())
            {
                for prefix in prefixes {
                    if let Some(cidr) = prefix.as_str()
                        && let Ok(net) = cidr.parse::<IpNet>()
                    {
                        nets.push(net);
                    }
                }
            }
        }
    }
    nets
}

/// Parse plain-text CIDR list (one CIDR or IP per line, comments start with `#`).
///
/// Used for Cloudflare ips-v4/ips-v6 and FireHOL netset format.
fn parse_cidr_text(text: &str) -> Vec<IpNet> {
    text.lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            // Try CIDR first (e.g., "1.2.3.0/24"), then bare IP (e.g., "1.2.3.4" → /32).
            line.parse::<IpNet>().ok().or_else(|| {
                line.parse::<IpAddr>().ok().map(|ip| match ip {
                    IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::from(v4)),
                    IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::from(v6)),
                })
            })
        })
        .collect()
}

// ── FireHOL Provider ────────────────────────────────────────────

/// Default URL for FireHOL Level 1 blocklist.
const FIREHOL_LEVEL1_URL: &str = "https://iplists.firehol.org/files/firehol_level1.netset";

/// Threat intelligence from FireHOL Level 1 blocklist.
///
/// FireHOL level1 is a composite blocklist aggregating the most reliable
/// threat intelligence sources (fullbogons, spamhaus, dshield, etc.).
///
/// Format: one CIDR or IP per line, comments start with `#`.
/// Stores in a [`CidrSet`] behind `ArcSwap` for lock-free reads.
///
/// Refresh: hourly. Startup: load from cache, async fetch.
pub struct FireholProvider {
    /// Current CIDR set — atomic swap for lock-free reads.
    cidrs: ArcSwap<CidrSet>,
    /// HTTP client for fetching the list.
    http: reqwest::Client,
    /// Cache backend for persisting across restarts.
    cache: Arc<dyn CacheBackend>,
    /// Fetch URL (overridable for testing).
    url: String,
    /// Refresh mutex — ensures only one refresh runs at a time.
    refresh_lock: Mutex<()>,
}

impl FireholProvider {
    /// Create a new FireHOL Level 1 provider.
    pub fn new(cache: Arc<dyn CacheBackend>) -> Self {
        Self {
            cidrs: ArcSwap::new(Arc::new(CidrSet::default())),
            http: sid_plugin::client_builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("HTTP client build"),
            cache,
            url: FIREHOL_LEVEL1_URL.to_string(),
            refresh_lock: Mutex::new(()),
        }
    }

    /// Create with custom URL (for testing).
    pub fn with_url(cache: Arc<dyn CacheBackend>, url: String) -> Self {
        Self {
            url,
            ..Self::new(cache)
        }
    }

    /// Load the blocklist the refreshing replica stored in the shared cache.
    /// None stored yet keeps the current list.
    pub async fn load_from_cache(&self) -> Result<(), IpIntelError> {
        let Some(data) = self
            .cache
            .get("ipintel:firehol:cidrs")
            .await
            .map_err(|e| IpIntelError::Cache(e.to_string()))?
        else {
            return Ok(());
        };
        let text = String::from_utf8(data).map_err(|e| IpIntelError::Parse(e.to_string()))?;
        let nets = parse_cidr_text(&text);
        if !nets.is_empty() {
            let set = CidrSet::from_nets(nets);
            debug!(ranges = set.len(), "Loaded FireHOL blocklist from cache");
            self.cidrs.store(Arc::new(set));
        }
        Ok(())
    }

    /// Number of CIDR ranges loaded.
    pub fn range_count(&self) -> usize {
        self.cidrs.load().len()
    }

    /// Load from raw CIDR text (for testing).
    pub fn load_from_text(&self, text: &str) {
        let nets = parse_cidr_text(text);
        self.cidrs.store(Arc::new(CidrSet::from_nets(nets)));
    }
}

/// Whether `ip` can be a host on the public internet. Threat lists such as
/// FireHOL level1 also carry the bogon ranges (private, loopback, CGNAT, link
/// local, unspecified, reserved): a client there is on the operator's own
/// network, not on a threat list, and is never denied for such an entry.
fn is_public_address(ip: IpAddr) -> bool {
    fn is_public_v4(v4: std::net::Ipv4Addr) -> bool {
        let [a, b, ..] = v4.octets();
        !(v4.is_unspecified()
            || v4.is_loopback()
            || v4.is_private()
            || v4.is_link_local()
            || v4.is_broadcast()
            || v4.is_documentation()
            // Shared address space of carrier-grade NAT (100.64.0.0/10, RFC 6598).
            || (a == 100 && (b & 0xC0) == 64)
            // Benchmarking (198.18.0.0/15, RFC 2544) and reserved (240.0.0.0/4).
            || (a == 198 && (b & 0xFE) == 18)
            || a >= 240)
    }
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => {
                !(v6.is_unspecified()
                    || v6.is_loopback()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local())
            }
        },
    }
}

#[async_trait]
impl IpIntelligenceProvider for FireholProvider {
    async fn classify(&self, ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
        if !is_public_address(ip) {
            return Ok(None);
        }
        let cidrs = self.cidrs.load();
        Ok(cidrs.contains(ip).then(|| IpClassification {
            labels: vec![IpLabel::Blocklisted],
            risk_score: Some(0.9),
            source: "firehol_level1".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }))
    }

    async fn refresh(&self) -> Result<(), IpIntelError> {
        let _guard = self.refresh_lock.lock().await;

        debug!(url = %self.url, "Fetching FireHOL Level 1 blocklist");

        let response = self
            .http
            .get(&self.url)
            .send()
            .await
            .map_err(|e| IpIntelError::Fetch(e.to_string()))?;

        if !response.status().is_success() {
            return Err(IpIntelError::Fetch(format!(
                "HTTP {} from {}",
                response.status(),
                self.url
            )));
        }

        let text = response
            .text()
            .await
            .map_err(|e| IpIntelError::Parse(e.to_string()))?;

        let nets = parse_cidr_text(&text);
        if nets.is_empty() {
            return Err(IpIntelError::Parse(
                "FireHOL blocklist is empty after parsing".to_string(),
            ));
        }

        let count = nets.len();
        let set = CidrSet::from_nets(nets);
        self.cidrs.store(Arc::new(set));

        // Publish the raw text: the other replicas load it from here.
        let cache_ttl = Duration::from_secs(7200); // 2h cache (refresh every 1h)
        self.cache
            .set("ipintel:firehol:cidrs", text.as_bytes(), cache_ttl)
            .await
            .map_err(|e| IpIntelError::Cache(e.to_string()))?;

        info!(count, "FireHOL Level 1 blocklist updated");
        Ok(())
    }

    async fn reload(&self) -> Result<(), IpIntelError> {
        self.load_from_cache().await
    }

    fn source_name(&self) -> &str {
        "firehol_level1"
    }
}

// ── Self-Learned Reputation Provider ─────────────────────────────

/// Self-learned IP reputation from login history.
///
/// Tracks failed/successful login counts per IP in PostgreSQL.
/// Score = `failed_count / (failed_count + success_count + 1.0)`.
/// IPs with score above threshold are classified as `Blocklisted`.
///
/// Data model:
/// - Events written per-login via `StorageBackend::record_ip_reputation_event()`
/// - `classify()` queries DB per-call via `get_ip_reputation_score()` (~1ms PK lookup)
/// - `refresh()` pre-warms in-memory cache for bulk queries / admin dashboard
///
/// Configurable:
/// - `threshold`: min score to classify as suspicious (default 0.7)
/// - `max_ips`: max IPs to load in refresh cache (default 10_000)
pub struct SelfLearnedReputationProvider {
    /// Cached suspicious IPs for refresh/dashboard. Atomic swap for lock-free reads.
    suspicious: ArcSwap<std::collections::HashMap<IpAddr, f32>>,
    /// Storage backend for per-call IP reputation queries.
    storage: Arc<dyn sid_plugin::storage::StorageBackend>,
    /// Score threshold above which an IP is classified as suspicious.
    threshold: f32,
    /// Max IPs to load in refresh.
    max_ips: i64,
    /// Refresh mutex.
    refresh_lock: Mutex<()>,
}

impl SelfLearnedReputationProvider {
    /// Create a new self-learned reputation provider.
    pub fn new(storage: Arc<dyn sid_plugin::storage::StorageBackend>, threshold: f32) -> Self {
        Self {
            suspicious: ArcSwap::new(Arc::new(std::collections::HashMap::new())),
            storage,
            threshold,
            max_ips: 10_000,
            refresh_lock: Mutex::new(()),
        }
    }

    /// Number of currently tracked suspicious IPs (from last refresh).
    pub fn suspicious_count(&self) -> usize {
        self.suspicious.load().len()
    }

    /// Directly set suspicious IPs map (for testing / pre-seeding).
    pub fn set_suspicious(&self, map: std::collections::HashMap<IpAddr, f32>) {
        self.suspicious.store(Arc::new(map));
    }
}

#[async_trait]
impl IpIntelligenceProvider for SelfLearnedReputationProvider {
    async fn classify(&self, ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
        // Per-call DB query: single-row PK lookup on ip_reputation table (~1ms).
        // A failed read is an error: read as "no score" it would take the IP
        // off the blocklist exactly while the store is down.
        let score = self
            .storage
            .get_ip_reputation_score(&ip.to_string())
            .await
            .map_err(|e| IpIntelError::Unavailable(format!("reputation read failed: {e}")))?;

        Ok(score
            .filter(|score| *score >= self.threshold)
            .map(|score| IpClassification {
                labels: vec![IpLabel::Blocklisted],
                risk_score: Some(score),
                source: "self_learned".to_string(),
                expires_at: Utc::now() + chrono::Duration::seconds(60),
            }))
    }

    async fn refresh(&self) -> Result<(), IpIntelError> {
        let _guard = self.refresh_lock.lock().await;

        let rows = self
            .storage
            .list_suspicious_ips(self.threshold, self.max_ips)
            .await
            .map_err(|e| IpIntelError::Fetch(format!("DB query failed: {e}")))?;

        let mut map = std::collections::HashMap::with_capacity(rows.len());
        for (ip_str, score) in &rows {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                map.insert(ip, *score);
            }
        }

        let count = map.len();
        self.suspicious.store(Arc::new(map));

        if count > 0 {
            debug!(
                count,
                threshold = self.threshold,
                "Self-learned reputation refreshed"
            );
        }
        Ok(())
    }

    /// Every replica reads the shared table itself.
    async fn reload(&self) -> Result<(), IpIntelError> {
        self.refresh().await
    }

    fn source_name(&self) -> &str {
        "self_learned"
    }
}

// ── Allowlist Provider ───────────────────────────────────────────

/// Admin-configured IP/CIDR allowlist.
///
/// IPs matching any entry are classified as `Allowed`, which overrides
/// ALL negative labels in the aggregator (Tor, datacenter, blocklist).
///
/// Data stored in PostgreSQL (`ip_allowlist_entries` table), managed
/// via admin gRPC RPCs. In-memory CidrSet refreshed periodically.
pub struct AllowlistProvider {
    /// Current allowlist CIDRs — atomic swap for lock-free reads.
    cidrs: ArcSwap<CidrSet>,
    /// Storage backend for reading allowlist entries.
    storage: Arc<dyn sid_plugin::storage::StorageBackend>,
    /// Refresh mutex.
    refresh_lock: Mutex<()>,
}

impl AllowlistProvider {
    /// Create a new allowlist provider.
    pub fn new(storage: Arc<dyn sid_plugin::storage::StorageBackend>) -> Self {
        Self {
            cidrs: ArcSwap::new(Arc::new(CidrSet::default())),
            storage,
            refresh_lock: Mutex::new(()),
        }
    }

    /// Number of CIDR ranges in the allowlist.
    pub fn entry_count(&self) -> usize {
        self.cidrs.load().len()
    }

    /// Directly set allowlist CIDRs (for testing).
    pub fn set_cidrs(&self, cidrs: CidrSet) {
        self.cidrs.store(Arc::new(cidrs));
    }
}

#[async_trait]
impl IpIntelligenceProvider for AllowlistProvider {
    async fn classify(&self, ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
        let cidrs = self.cidrs.load();
        Ok(cidrs.contains(ip).then(|| IpClassification {
            labels: vec![IpLabel::Allowed],
            risk_score: Some(0.0),
            source: "admin_allowlist".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
        }))
    }

    async fn refresh(&self) -> Result<(), IpIntelError> {
        let _guard = self.refresh_lock.lock().await;

        let entries = self
            .storage
            .list_ip_allowlist_entries()
            .await
            .map_err(|e| IpIntelError::Fetch(format!("DB query failed: {e}")))?;

        let nets: Vec<IpNet> = entries
            .iter()
            .filter_map(|(cidr, _, _)| {
                cidr.parse::<IpNet>().ok().or_else(|| {
                    cidr.parse::<IpAddr>().ok().map(|ip| match ip {
                        IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::from(v4)),
                        IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::from(v6)),
                    })
                })
            })
            .collect();

        let count = nets.len();
        let set = CidrSet::from_nets(nets);
        self.cidrs.store(Arc::new(set));

        if count > 0 {
            debug!(count, "Admin IP allowlist refreshed");
        }
        Ok(())
    }

    /// Every replica reads the shared table itself, so an entry an
    /// administrator adds applies on all of them.
    async fn reload(&self) -> Result<(), IpIntelError> {
        self.refresh().await
    }

    fn source_name(&self) -> &str {
        "admin_allowlist"
    }
}

// ── Background refresh task ──────────────────────────────────────

/// Spawn a background task that refreshes all providers on an interval.
///
/// Multi-instance safety: a leased key in the shared cache (SETNX with TTL)
/// lets one instance perform the fetch; the others read from shared cache.
pub fn spawn_refresh_task(
    aggregator: Arc<IpIntelligenceAggregator>,
    interval: Duration,
    cache: Arc<dyn CacheBackend>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Initial refresh immediately.
        try_leader_refresh(&aggregator, &cache).await;

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // consume first immediate tick
        loop {
            ticker.tick().await;
            try_leader_refresh(&aggregator, &cache).await;
        }
    })
}

/// Refresh on the one replica that takes the lock; every other replica
/// reloads what that replica published.
async fn try_leader_refresh(aggregator: &IpIntelligenceAggregator, cache: &Arc<dyn CacheBackend>) {
    // SETNX-based leader election: set a lock key with TTL.
    // Only one instance succeeds; others skip.
    let lock_ttl = Duration::from_secs(300); // 5 min lock
    match cache.set_nx("ipintel:refresh:lock", b"1", lock_ttl).await {
        Ok(true) => {
            debug!("Acquired IP intelligence refresh leader lock");
            aggregator.refresh_all().await;
            // Lock auto-expires via TTL — no explicit delete needed.
        }
        Ok(false) => {
            debug!("Another instance is refreshing IP intelligence; reloading its data");
            aggregator.reload_all().await;
        }
        Err(e) => {
            // Cache unavailable — refresh locally anyway (best effort).
            warn!(error = %e, "Leader lock unavailable, refreshing locally");
            aggregator.refresh_all().await;
        }
    }
}

// ── Serialization helpers for cache ──────────────────────────────

fn serialize_classification(c: &AggregatedClassification) -> Option<Vec<u8>> {
    // Simple format: labels as comma-separated strings, then |score|sources
    let labels: Vec<&str> = c.labels.iter().map(|l| l.as_str()).collect();
    let score = c.risk_score.map(|s| s.to_string()).unwrap_or_default();
    let sources = c.sources.join(",");
    let data = format!("{}|{}|{}", labels.join(","), score, sources);
    Some(data.into_bytes())
}

fn deserialize_classification(data: &[u8]) -> Option<AggregatedClassification> {
    let text = std::str::from_utf8(data).ok()?;
    let parts: Vec<&str> = text.splitn(3, '|').collect();
    if parts.len() != 3 {
        return None;
    }

    let labels: HashSet<IpLabel> = parts[0]
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s {
            "tor_exit" => Some(IpLabel::TorExit),
            "datacenter" => Some(IpLabel::Datacenter),
            "vpn" => Some(IpLabel::Vpn),
            "proxy" => Some(IpLabel::Proxy),
            "bot" => Some(IpLabel::Bot),
            "blocklisted" => Some(IpLabel::Blocklisted),
            "allowed" => Some(IpLabel::Allowed),
            _ => None,
        })
        .collect();

    let risk_score = if parts[1].is_empty() {
        None
    } else {
        parts[1].parse::<f32>().ok()
    };

    let sources: Vec<String> = parts[2]
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    Some(AggregatedClassification {
        labels,
        risk_score,
        sources,
    })
}

#[cfg(test)]
mod tests;
