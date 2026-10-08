// SPDX-License-Identifier: AGPL-3.0-only
//! Security shield middleware for sid-proxy.
//!
//! Runs BEFORE any request is forwarded to gRPC upstream.
//!
//! Checks (in order):
//! 1. IP blocklist (DashMap, populated externally)
//! 2. Rate limit per IP per endpoint class, and per principal on auth paths
//!
//! If ANY check fails → 429/403 immediately, NO gRPC call.
//!
//! # Counting across replicas
//!
//! A limit counted in this process is not the limit an attacker meets: with N
//! replicas behind a load balancer, spreading requests evenly gives `limit × N`,
//! and even a deployment configured for one replica runs two during a rolling
//! update. So the count is shared, through the same [`CacheBackend`] the rest
//! of the product uses for replay rejection.
//!
//! The local window stays, as the fast path: a caller already over the limit on
//! this instance is refused here, without asking the store. Everything else
//! costs one atomic increment, which is what makes the configured number mean
//! what it says. A deployment that really is one process passes
//! `NoCacheBackend` and keeps the local window as the whole answer.
//!
//! If the store cannot be reached the local decision stands rather than the
//! service failing: a cache blip must not turn into an outage, and the
//! degraded behaviour is exactly the per-instance limit that came before.

use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use dashmap::DashMap;
use sid_plugin::cache::CacheBackend;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

/// Shield configuration.
#[derive(Debug, Clone)]
pub struct ShieldConfig {
    /// Enable/disable shield (default: true).
    pub enabled: bool,
    /// Per-IP rate limit for auth endpoints (per minute).
    pub auth_rate: u32,
    /// Per-IP rate limit for registration endpoints (per minute).
    pub register_rate: u32,
    /// Per-IP default rate limit (per minute).
    pub default_rate: u32,
    /// Per-principal rate limit for auth/register endpoints (per minute).
    /// Protects against distributed brute-force targeting a single account.
    pub principal_rate: u32,
    /// Per-IP rate limit for magic-link endpoints (per minute).
    /// Stricter than auth_rate to prevent magic-link spam.
    pub magic_link_rate: u32,
    /// Per-principal rate limit for magic-link endpoints (per minute).
    /// Very strict: 1/min prevents email/SMS flooding for a single account.
    pub magic_link_principal_rate: u32,
    /// Window size in seconds.
    pub window_secs: u64,
    /// Endpoint class patterns: (prefix, class).
    /// Evaluated in order — first match wins.
    pub endpoint_classes: Vec<(String, EndpointClass)>,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auth_rate: 20,
            register_rate: 5,
            default_rate: 100,
            principal_rate: 5,
            magic_link_rate: 3,
            magic_link_principal_rate: 1,
            window_secs: 60,
            endpoint_classes: EndpointClass::default_patterns(),
        }
    }
}

/// Endpoint class for rate-limit bucketing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointClass {
    Auth,
    Register,
    MagicLink,
    Health,
    Default,
}

impl EndpointClass {
    /// Parse class name from config string.
    pub fn from_name(name: &str) -> Self {
        match name {
            "auth" => Self::Auth,
            "register" => Self::Register,
            "magic_link" => Self::MagicLink,
            "health" => Self::Health,
            _ => Self::Default,
        }
    }

    /// Default endpoint class patterns (prefix → class).
    pub fn default_patterns() -> Vec<(String, EndpointClass)> {
        vec![
            ("/health".into(), Self::Health),
            ("/v1/auth/magic-link".into(), Self::MagicLink),
            ("/v1/auth/opaque/register".into(), Self::Register),
            ("/v1/auth/webauthn/register".into(), Self::Register),
            ("/v1/identity/profiles".into(), Self::Register),
            ("/v1/auth/".into(), Self::Auth),
            ("/oauth2/token".into(), Self::Auth),
        ]
    }

    fn rate_limit(&self, config: &ShieldConfig) -> Option<u32> {
        match self {
            Self::Health => None, // no rate limit for health probes
            Self::Auth => Some(config.auth_rate),
            Self::Register => Some(config.register_rate),
            Self::MagicLink => Some(config.magic_link_rate),
            Self::Default => Some(config.default_rate),
        }
    }
}

impl ShieldConfig {
    /// Classify a request path using configured endpoint class patterns.
    /// First matching prefix wins. An issuer's endpoint
    /// (`/i/{handle}/oauth2/token`) is classified by the path after its
    /// handle, so every issuer's token endpoint gets the token endpoint's
    /// limit.
    fn classify_path(&self, path: &str) -> EndpointClass {
        let path = sid_auth::issuers::issuer_endpoint(path).unwrap_or(path);
        for (prefix, class) in &self.endpoint_classes {
            if path.starts_with(prefix.as_str()) {
                return *class;
            }
        }
        EndpointClass::Default
    }
}

/// Sliding window rate counter.
///
/// Tracks request count in the current and previous window to provide
/// smooth rate limiting (weighted average of two windows).
struct SlidingWindow {
    /// Start of current window.
    window_start: Instant,
    /// Count in current window.
    current: u32,
    /// Count in previous window.
    previous: u32,
    /// Window duration in seconds.
    window_secs: u64,
}

impl SlidingWindow {
    fn new(window_secs: u64) -> Self {
        Self {
            window_start: Instant::now(),
            current: 0,
            previous: 0,
            window_secs,
        }
    }

    /// Record a request and return the weighted rate estimate.
    fn record(&mut self) -> u32 {
        self.advance_window();
        self.current += 1;
        self.estimated_rate()
    }

    /// Estimated request count over the sliding window.
    fn estimated_rate(&self) -> u32 {
        let elapsed = self.window_start.elapsed().as_secs_f64();
        let window = self.window_secs as f64;
        let weight = if window > 0.0 {
            1.0 - (elapsed / window).min(1.0)
        } else {
            0.0
        };
        ((self.previous as f64 * weight) + self.current as f64) as u32
    }

    /// Advance to next window if needed.
    fn advance_window(&mut self) {
        let elapsed = self.window_start.elapsed().as_secs();
        if elapsed >= self.window_secs * 2 {
            // More than 2 windows elapsed — reset both
            self.previous = 0;
            self.current = 0;
            self.window_start = Instant::now();
        } else if elapsed >= self.window_secs {
            // Current window expired — rotate
            self.previous = self.current;
            self.current = 0;
            self.window_start = Instant::now();
        }
    }
}

/// Rate limit key: (IP, EndpointClass).
type RateLimitKey = (IpAddr, u8);

/// Shield state: a local window per key, over a shared counter.
#[derive(Clone)]
pub struct Shield {
    config: ShieldConfig,
    /// IP blocklist.
    blocklist: Arc<DashMap<IpAddr, ()>>,
    /// Per-(IP, endpoint_class) sliding windows.
    windows: Arc<DashMap<RateLimitKey, SlidingWindow>>,
    /// Per-principal sliding windows (protects against distributed brute-force).
    principal_windows: Arc<DashMap<String, SlidingWindow>>,
    /// The count every replica shares. See the module docs.
    cache: Arc<dyn CacheBackend>,
}

impl Shield {
    pub fn new(config: ShieldConfig, cache: Arc<dyn CacheBackend>) -> Self {
        Self {
            config,
            blocklist: Arc::new(DashMap::new()),
            windows: Arc::new(DashMap::new()),
            principal_windows: Arc::new(DashMap::new()),
            cache,
        }
    }

    /// Add an IP to the blocklist.
    pub fn block_ip(&self, ip: IpAddr) {
        self.blocklist.insert(ip, ());
    }

    /// Remove an IP from the blocklist.
    pub fn unblock_ip(&self, ip: &IpAddr) {
        self.blocklist.remove(ip);
    }

    /// Check if a request should be allowed.
    ///
    /// Returns `Ok(())` if allowed, `Err(StatusCode)` if blocked.
    pub async fn check(&self, ip: IpAddr, path: &str) -> Result<(), StatusCode> {
        if !self.config.enabled {
            return Ok(());
        }

        // 1. IP blocklist check
        if self.blocklist.contains_key(&ip) {
            return Err(StatusCode::FORBIDDEN);
        }

        // 2. Rate limit check
        let class = self.config.classify_path(path);
        if let Some(limit) = class.rate_limit(&self.config) {
            let key = (ip, class as u8);
            let rate = {
                // The guard is dropped before the await below: a DashMap entry
                // held across one would block every other request for this key.
                let mut entry = self
                    .windows
                    .entry(key)
                    .or_insert_with(|| SlidingWindow::new(self.config.window_secs));
                entry.value_mut().record()
            };

            if rate > limit {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }

            let shared_key = format!("shield:ip:{}:{ip}", class as u8);
            if self.over_shared_limit(&shared_key, limit).await {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
        }

        Ok(())
    }

    /// Count this request against every replica's shared total.
    ///
    /// An unreachable store leaves the local decision standing: the limit
    /// degrades to per-instance, which is where it was before, rather than the
    /// service refusing traffic it cannot count.
    async fn over_shared_limit(&self, key: &str, limit: u32) -> bool {
        let window = std::time::Duration::from_secs(self.config.window_secs);
        match self.cache.incr(key, window).await {
            Ok(count) => count > limit as u64,
            Err(e) => {
                tracing::warn!(error = %e, "shield: shared counter unavailable, limiting per instance");
                false
            }
        }
    }

    /// Check per-principal rate limit.
    ///
    /// Called with a normalized principal (email/phone/username) for auth endpoints.
    /// `path` is used to determine the endpoint-specific principal rate limit
    /// (magic-link has stricter per-principal limits to prevent email/SMS flooding).
    /// Returns `Ok(())` if allowed, `Err(429)` if the principal is over its limit.
    pub async fn check_principal(&self, principal: &str, path: &str) -> Result<(), StatusCode> {
        let class = self.config.classify_path(path);
        let limit = match class {
            EndpointClass::MagicLink => self.config.magic_link_principal_rate,
            _ => self.config.principal_rate,
        };

        if !self.config.enabled || limit == 0 {
            return Ok(());
        }

        // Use class-prefixed key so magic-link and auth have independent principal buckets
        let key = format!("{}:{}", class as u8, principal.to_lowercase());
        let rate = {
            let mut entry = self
                .principal_windows
                .entry(key.clone())
                .or_insert_with(|| SlidingWindow::new(self.config.window_secs));
            entry.value_mut().record()
        };

        if rate > limit {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        // This is the limit that matters most across replicas: a brute-force
        // against one account is spread over instances by the load balancer,
        // so a per-instance count is exactly the one an attacker defeats.
        if self
            .over_shared_limit(&format!("shield:principal:{key}"), limit)
            .await
        {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        Ok(())
    }

    /// Cleanup expired entries. Call periodically from a background task.
    pub fn cleanup(&self) {
        let threshold_secs = self.config.window_secs * 3;
        self.windows
            .retain(|_, window| window.window_start.elapsed().as_secs() < threshold_secs);
        self.principal_windows
            .retain(|_, window| window.window_start.elapsed().as_secs() < threshold_secs);
    }
}

/// Auth endpoint paths that may contain a `principal` field in their JSON body.
const PRINCIPAL_ENDPOINTS: &[&str] = &[
    "/v1/auth/opaque/login/start",
    "/v1/auth/opaque/register/start",
    "/v1/auth/webauthn/login/start",
    "/v1/auth/webauthn/register/start",
    "/v1/auth/magic-link/send",
    "/v1/auth/resolve",
];

/// Check if this path should have per-principal rate limiting.
fn needs_principal_check(path: &str) -> bool {
    PRINCIPAL_ENDPOINTS.iter().any(|ep| path.starts_with(ep))
}

/// Try to extract principal value from a JSON body (best-effort).
/// Reads the `principal` field from the request JSON.
fn extract_principal_from_body(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get("principal")?.as_str().map(|s| s.to_string())
}

/// Axum middleware function for Shield.
///
/// Extracts client IP from `ConnectInfo` and checks against Shield.
/// For auth endpoints with principal fields, also applies per-principal rate limiting.
pub async fn shield_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    shield: axum::extract::Extension<Shield>,
    request: Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path().to_string();
    shield.check(addr.ip(), &path).await?;

    // Per-principal rate limiting: buffer body for auth endpoints.
    if needs_principal_check(&path) {
        let (parts, body) = request.into_parts();
        let bytes = axum::body::to_bytes(body, 8192).await.unwrap_or_default();

        if let Some(principal) = extract_principal_from_body(&bytes) {
            shield.check_principal(&principal, &path).await?;
        }

        let request = Request::from_parts(parts, axum::body::Body::from(bytes));
        return Ok(next.run(request).await);
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests;
