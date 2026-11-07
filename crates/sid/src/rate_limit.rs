// SPDX-License-Identifier: AGPL-3.0-only
//! Per-client rate limiter + distributed stats tracking, both over the shared
//! cache so every replica counts against the same numbers.
//!
//! `RateLimiter` enforces machine user request limits with a sliding window
//! counter. `RateLimitStats` records blocked requests for the
//! SecurityService.GetRateLimitDashboard RPC.

use chrono::Utc;
use sid_plugin::cache::{CacheBackend, CacheResult};
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// Sliding window counter: the estimate is the current window's count plus
/// the previous window's count weighted by how much of it still overlaps the
/// last `window`. Unlike a fixed window it allows no double burst at the
/// window edge, and it needs only two counters per client.
pub struct RateLimiter {
    cache: Arc<dyn CacheBackend>,
    window: Duration,
}

impl RateLimiter {
    /// A requests-per-minute limiter over the cache every replica shares.
    pub fn new(cache: Arc<dyn CacheBackend>) -> Self {
        Self {
            cache,
            window: Duration::from_secs(60),
        }
    }

    /// Count a request for `client_id` and report whether it is within
    /// `limit` per window. A `limit` of 0 means no rate limiting.
    ///
    /// The request is counted before the check, so concurrent requests on
    /// different replicas can never all see room under the limit; a refused
    /// request counts too, and a client that keeps retrying stays refused.
    pub async fn check_and_record(&self, client_id: &str, limit: u32) -> CacheResult<bool> {
        if limit == 0 {
            return Ok(true);
        }
        self.check_at(client_id, limit, Utc::now().timestamp_millis())
            .await
    }

    async fn check_at(&self, client_id: &str, limit: u32, now_ms: i64) -> CacheResult<bool> {
        // A window of 60 s fits in i64 milliseconds.
        let window_ms = self.window.as_millis() as i64;
        let index = now_ms.div_euclid(window_ms);
        let elapsed = now_ms.rem_euclid(window_ms);

        // A window's counter is read while the next window runs, so it lives
        // for two.
        let current = self
            .cache
            .incr(&window_key(client_id, index), self.window * 2)
            .await?;
        let previous = self
            .cache
            .get(&window_key(client_id, index - 1))
            .await?
            .and_then(|d| String::from_utf8_lossy(&d).parse::<u64>().ok())
            .unwrap_or(0);

        // 0 <= elapsed < window_ms, so the weight is in (0, 1]. Rounding the
        // weighted share up keeps the estimate from ever undercounting.
        let overlap = (window_ms - elapsed) as u64;
        let estimate = (previous * overlap).div_ceil(window_ms as u64) + current;
        Ok(estimate <= u64::from(limit))
    }
}

fn window_key(client_id: &str, index: i64) -> String {
    format!("rl:mu:{client_id}:{index}")
}

// ── Distributed rate limit stats (CacheBackend-backed) ──

const HOUR_TTL: Duration = Duration::from_secs(3600);
const DAY_TTL: Duration = Duration::from_secs(86400);
const KEY_TOTAL_HOUR: &str = "rl:blocked:total:hour";
const KEY_TOTAL_DAY: &str = "rl:blocked:total:day";
const KEY_IP_SET: &str = "rl:blocked:ip_set";
const KEY_EP_SET: &str = "rl:blocked:ep_set";

/// Tracks rate limit block events in shared CacheBackend for dashboard.
///
/// Multi-instance safe: all instances write to the same cache keys. A failed
/// write loses one dashboard sample and is logged; it never affects the
/// request that was blocked.
pub struct RateLimitStats {
    cache: Arc<dyn CacheBackend>,
}

impl RateLimitStats {
    pub fn new(cache: Arc<dyn CacheBackend>) -> Self {
        Self { cache }
    }

    /// Record a blocked request. Call this whenever a rate limit denies a request.
    pub async fn record_block(&self, ip: Option<&str>, endpoint: &str) {
        self.count(KEY_TOTAL_HOUR, HOUR_TTL).await;
        self.count(KEY_TOTAL_DAY, DAY_TTL).await;

        // Increment per-IP counter and track the IP in the set.
        if let Some(ip) = ip {
            self.count(&format!("rl:blocked:ip:{}:hour", ip), HOUR_TTL)
                .await;
            self.add_to_set(KEY_IP_SET, ip).await;
        }

        // Increment per-endpoint counter and track.
        self.count(&format!("rl:blocked:ep:{}:hour", endpoint), HOUR_TTL)
            .await;
        self.add_to_set(KEY_EP_SET, endpoint).await;
    }

    async fn count(&self, key: &str, ttl: Duration) {
        if let Err(e) = self.cache.incr(key, ttl).await {
            warn!(key, error = %e, "rate limit stats: counter not recorded");
        }
    }

    /// Get dashboard data: totals + top blocked IPs/endpoints. A cache that
    /// cannot answer is an error, never a dashboard of zeros.
    pub async fn get_dashboard(&self) -> CacheResult<RateLimitDashboardData> {
        let total_hour = self.get_counter(KEY_TOTAL_HOUR).await?;
        let total_day = self.get_counter(KEY_TOTAL_DAY).await?;

        let top_ips = self
            .get_top_entries(KEY_IP_SET, "rl:blocked:ip:", ":hour")
            .await?;
        let top_eps = self
            .get_top_entries(KEY_EP_SET, "rl:blocked:ep:", ":hour")
            .await?;

        Ok(RateLimitDashboardData {
            total_blocked_last_hour: total_hour as i32,
            total_blocked_last_day: total_day as i32,
            top_blocked_ips: top_ips,
            top_blocked_endpoints: top_eps,
        })
    }

    async fn get_counter(&self, key: &str) -> CacheResult<u64> {
        Ok(self
            .cache
            .get(key)
            .await?
            .and_then(|d| String::from_utf8_lossy(&d).parse::<u64>().ok())
            .unwrap_or(0))
    }

    /// A JSON set stored in cache; an unreadable value counts as empty.
    async fn get_set(&self, set_key: &str) -> CacheResult<Vec<String>> {
        Ok(self
            .cache
            .get(set_key)
            .await?
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default())
    }

    /// Add a value to a JSON set stored in cache. When the set cannot be
    /// read nothing is written, so a failed read never replaces the set.
    async fn add_to_set(&self, set_key: &str, value: &str) {
        let mut set = match self.get_set(set_key).await {
            Ok(set) => set,
            Err(e) => {
                warn!(key = set_key, error = %e, "rate limit stats: set not recorded");
                return;
            }
        };

        if !set.contains(&value.to_string()) {
            set.push(value.to_string());
            // Cap at 100 entries to prevent unbounded growth.
            if set.len() > 100 {
                set.drain(0..set.len() - 100);
            }
            if let Ok(data) = serde_json::to_vec(&set)
                && let Err(e) = self.cache.set(set_key, &data, HOUR_TTL).await
            {
                warn!(key = set_key, error = %e, "rate limit stats: set not recorded");
            }
        }
    }

    /// Read a set of keys, fetch their counters, sort descending, return top 10.
    async fn get_top_entries(
        &self,
        set_key: &str,
        prefix: &str,
        suffix: &str,
    ) -> CacheResult<Vec<(String, i32)>> {
        let set = self.get_set(set_key).await?;

        let mut entries: Vec<(String, i32)> = Vec::new();
        for key in &set {
            let cache_key = format!("{}{}{}", prefix, key, suffix);
            let count = self.get_counter(&cache_key).await? as i32;
            if count > 0 {
                entries.push((key.clone(), count));
            }
        }

        entries.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        entries.truncate(10);
        Ok(entries)
    }
}

/// Dashboard data returned by `RateLimitStats::get_dashboard()`.
pub struct RateLimitDashboardData {
    pub total_blocked_last_hour: i32,
    pub total_blocked_last_day: i32,
    pub top_blocked_ips: Vec<(String, i32)>,
    pub top_blocked_endpoints: Vec<(String, i32)>,
}

#[cfg(test)]
mod tests;
