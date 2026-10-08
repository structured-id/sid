// SPDX-License-Identifier: AGPL-3.0-only
//! CE Anomaly Detection — hardcoded binary rules.
//!
//! 9 deterministic rules evaluated in priority order. First match wins.
//! No scoring, no ML — predictable, auditable behavior.

use sid_core::models::security_policy::{CountryMode, NetworkPolicy, NetworkViolationReaction};
use sid_plugin::cache::{CacheBackend, CacheError, CacheResult};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Window of the per-IP attempt counter (credential stuffing).
const IP_WINDOW: Duration = Duration::from_secs(60);

/// Reaction to a security rule match.
///
/// CE rules produce direct reactions — no scoring aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleReaction {
    /// Allow the request to proceed.
    Allow,
    /// Require step-up authentication (MFA re-verification).
    StepUp,
    /// Require CAPTCHA verification before proceeding.
    RequireCaptcha,
    /// Block the request temporarily (lockout).
    Block,
    /// Absolute deny — no override, no escalation.
    HardNo,
}

impl RuleReaction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::StepUp => "step_up",
            Self::RequireCaptcha => "require_captcha",
            Self::Block => "block",
            Self::HardNo => "hard_no",
        }
    }
}

/// Which rule triggered the reaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    /// Rule identifier.
    pub rule: &'static str,
    /// Reaction produced by this rule.
    pub reaction: RuleReaction,
    /// Human-readable reason.
    pub reason: String,
}

/// CE anomaly detection configuration (hardcoded defaults).
#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    /// Maximum failed login attempts before lockout.
    pub brute_force_max_attempts: u32,
    /// Time window for brute force detection (seconds).
    pub brute_force_window_secs: u64,
    /// Lockout duration after max attempts exceeded (seconds).
    pub brute_force_lockout_secs: u64,
    /// Maximum login attempts per IP per minute (credential stuffing).
    pub credential_stuffing_threshold: u32,
    /// Minimum distance (km) for impossible travel detection.
    pub impossible_travel_min_distance_km: f64,
    /// Maximum plausible speed (km/h) — faster = impossible travel.
    pub impossible_travel_min_speed_kmh: f64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            brute_force_max_attempts: 5,
            brute_force_window_secs: 300,
            brute_force_lockout_secs: 900,
            credential_stuffing_threshold: 10,
            impossible_travel_min_distance_km: 500.0,
            impossible_travel_min_speed_kmh: 900.0,
        }
    }
}

/// Login context for anomaly evaluation.
#[derive(Debug, Clone)]
pub struct LoginContext {
    /// Profile identifier (email or username hash).
    pub identity: String,
    /// Client IP address.
    pub ip: Option<IpAddr>,
    /// ISO 3166-1 alpha-2 country code resolved from IP (via GeoIP).
    pub country: Option<String>,
    /// Whether the authentication attempt failed.
    pub failed: bool,
    /// Whether this IP + user-agent combination is new for this profile.
    pub new_device: bool,
    /// Whether this IP is new for this profile.
    pub new_ip: bool,
    /// Whether the IP belongs to a known Tor exit node.
    pub is_tor_exit: bool,
    /// Whether the IP belongs to a known datacenter/hosting provider (ASN-based).
    pub is_datacenter_ip: bool,
    /// Whether the IP appears on any threat blocklist.
    pub is_blocklisted: bool,
    /// Current login latitude (from GeoIP resolution).
    pub latitude: Option<f64>,
    /// Current login longitude (from GeoIP resolution).
    pub longitude: Option<f64>,
    /// Previous login latitude (from most recent session's IP via GeoIP).
    pub prev_latitude: Option<f64>,
    /// Previous login longitude (from most recent session's IP via GeoIP).
    pub prev_longitude: Option<f64>,
    /// When the profile last signed in; `None` for a profile that never has.
    /// The travel rule takes its speed from it, the new-device rule its baseline.
    pub prev_login_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Previous login country (ISO 3166-1 alpha-2, from GeoIP on previous session IP).
    pub prev_country: Option<String>,
    /// Countries where this profile regularly logs in (login_count >= threshold).
    /// Used to suppress impossible travel between known locations (roaming scenario).
    pub designated_countries: Vec<String>,
}

/// CE Anomaly Detection Service.
///
/// Evaluates 9 binary rules in priority order against login context. The
/// attempt counters and lockouts live only in the shared cache, so every
/// replica sees the same state; a cache that cannot answer fails the check
/// instead of reading as "no attempts".
pub struct AnomalyDetector {
    config: AnomalyConfig,
    /// Network policy from SecurityPolicy (country, Tor, datacenter restrictions).
    network_policy: NetworkPolicy,
    /// Shared attempt counters and lockouts.
    cache: Arc<dyn CacheBackend>,
}

fn lockout_key(identity: &str) -> String {
    format!("rate:brute:lockout:{identity}")
}

fn attempts_key(identity: &str) -> String {
    format!("rate:brute:{identity}")
}

fn ip_key(ip: IpAddr) -> String {
    format!("rate:ip:{ip}")
}

/// Haversine distance between two (lat, lon) points in kilometers.
///
/// Standard great-circle distance on Earth (mean radius 6371 km).
fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;

    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();

    let a =
        (dlat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();

    EARTH_RADIUS_KM * c
}

/// Map NetworkViolationReaction to RuleReaction.
fn violation_reaction_to_rule(reaction: &NetworkViolationReaction) -> RuleReaction {
    match reaction {
        NetworkViolationReaction::Block => RuleReaction::Block,
        NetworkViolationReaction::StepUp => RuleReaction::StepUp,
        NetworkViolationReaction::Alert => RuleReaction::Allow, // Alert = allow but notify
    }
}

impl AnomalyDetector {
    /// Create a new anomaly detector with the given configuration.
    pub fn new(
        config: AnomalyConfig,
        network_policy: NetworkPolicy,
        cache: Arc<dyn CacheBackend>,
    ) -> Self {
        Self {
            config,
            network_policy,
            cache,
        }
    }

    /// The brute-force and stuffing limits this detector enforces.
    pub fn config(&self) -> &AnomalyConfig {
        &self.config
    }

    /// The value of a shared counter (0 when absent).
    async fn counter(&self, key: &str) -> CacheResult<u64> {
        match self.cache.get(key).await? {
            None => Ok(0),
            Some(data) => std::str::from_utf8(&data)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| CacheError::Serialization(format!("counter {key}"))),
        }
    }

    /// Create with default CE configuration.
    pub fn ce_default(cache: Arc<dyn CacheBackend>) -> Self {
        Self::new(AnomalyConfig::default(), NetworkPolicy::default(), cache)
    }

    /// Update network policy (e.g., when admin changes SecurityPolicy).
    pub fn set_network_policy(&mut self, policy: NetworkPolicy) {
        self.network_policy = policy;
    }

    /// Evaluate all rules against the login context.
    ///
    /// Returns `Allow` if no rules matched, or the reaction from the
    /// highest-priority matching rule.
    ///
    /// Priority order:
    /// 1. IP blocklist (known attack IPs → HardNo)
    /// 2. Brute force lockout (active lockout → Block)
    /// 3. Country restriction (NetworkPolicy allow/block list → per policy)
    /// 4. Tor exit node (NetworkPolicy.block_tor → per policy)
    /// 5. Brute force detection (max attempts → RequireCaptcha/Block)
    /// 6. Datacenter IP (NetworkPolicy.block_datacenter_ips → per policy)
    /// 7. Credential stuffing (IP rate limit → RequireCaptcha)
    /// 8. New device + new IP (both new, for a profile that signed in before → StepUp)
    /// 9. None matched → Allow
    pub async fn evaluate(&self, ctx: &LoginContext) -> CacheResult<RuleMatch> {
        // 1. IP blocklist (absolute deny, no override)
        if ctx.is_blocklisted {
            return Ok(RuleMatch {
                rule: "ip_blocklist",
                reaction: RuleReaction::HardNo,
                reason: "IP address appears on threat blocklist".to_string(),
            });
        }

        // 2. Check active lockout (highest priority after blocklist)
        if let Some(m) = self.check_brute_force_lockout(ctx).await? {
            return Ok(m);
        }

        // 3. Country restriction
        if let Some(m) = self.check_country_restriction(ctx) {
            return Ok(m);
        }

        // 4. Tor exit node
        if let Some(m) = self.check_tor_exit(ctx) {
            return Ok(m);
        }

        // 5. Brute force threshold
        if let Some(m) = self.check_brute_force(ctx).await? {
            return Ok(m);
        }

        // 6. Impossible travel (haversine distance + speed check)
        if let Some(m) = self.check_impossible_travel(ctx) {
            return Ok(m);
        }

        // 7. Datacenter IP
        if let Some(m) = self.check_datacenter_ip(ctx) {
            return Ok(m);
        }

        // 8. Credential stuffing (IP-based rate limit)
        if let Some(m) = self.check_credential_stuffing(ctx).await? {
            return Ok(m);
        }

        // 9. New device + new IP: a change from the profile's history. A first
        // sign-in has no familiar device or address to differ from.
        if ctx.prev_login_at.is_some() && ctx.new_device && ctx.new_ip {
            return Ok(RuleMatch {
                rule: "new_device_ip",
                reaction: RuleReaction::StepUp,
                reason: "login from new device and new IP address".to_string(),
            });
        }

        Ok(RuleMatch {
            rule: "none",
            reaction: RuleReaction::Allow,
            reason: "no anomalies detected".to_string(),
        })
    }

    /// Count a failed attempt for `identity`; the attempt that reaches the
    /// limit starts the lockout. An error means the attempt was not counted.
    pub async fn record_failed_attempt(&self, identity: &str) -> CacheResult<()> {
        let window = Duration::from_secs(self.config.brute_force_window_secs);
        let count = self.cache.incr(&attempts_key(identity), window).await?;
        if count >= u64::from(self.config.brute_force_max_attempts) {
            let lockout_ttl = Duration::from_secs(self.config.brute_force_lockout_secs);
            self.cache
                .set(&lockout_key(identity), b"1", lockout_ttl)
                .await?;
        }
        Ok(())
    }

    /// Count a login attempt from `ip` (credential stuffing).
    pub async fn record_ip_attempt(&self, ip: IpAddr) -> CacheResult<()> {
        self.cache.incr(&ip_key(ip), IP_WINDOW).await.map(|_| ())
    }

    /// How long a lockout lasts from its start: the most a locked-out client
    /// waits before retrying.
    pub fn lockout_duration(&self) -> Duration {
        Duration::from_secs(self.config.brute_force_lockout_secs)
    }

    /// Whether `identity` is locked out after repeated failed attempts, on
    /// any replica. A cache failure is an error, not "unlocked".
    pub async fn lockout_active(&self, identity: &str) -> CacheResult<bool> {
        self.cache.exists(&lockout_key(identity)).await
    }

    /// Lift the lockout of `identity` and forget its failed attempts.
    pub async fn clear_lockout(&self, identity: &str) -> CacheResult<()> {
        self.cache.delete(&lockout_key(identity)).await?;
        self.cache.delete(&attempts_key(identity)).await
    }

    /// Check country restriction rule.
    ///
    /// Uses NetworkPolicy from SecurityPolicy:
    /// - AllowList: only listed countries allowed
    /// - BlockList: listed countries blocked
    /// - None: no country restrictions
    fn check_country_restriction(&self, ctx: &LoginContext) -> Option<RuleMatch> {
        let country = ctx.country.as_deref()?;
        if country.is_empty() {
            return None;
        }

        let reaction = violation_reaction_to_rule(&self.network_policy.violation_reaction);
        let country_upper = country.to_ascii_uppercase();

        match self.network_policy.country_mode {
            CountryMode::None => None,
            CountryMode::AllowList => {
                let allowed = self
                    .network_policy
                    .countries
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&country_upper));
                if allowed {
                    None
                } else {
                    Some(RuleMatch {
                        rule: "country_restriction",
                        reaction,
                        reason: format!("country '{}' is not in the allow list", country_upper),
                    })
                }
            }
            CountryMode::BlockList => {
                let blocked = self
                    .network_policy
                    .countries
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&country_upper));
                if blocked {
                    Some(RuleMatch {
                        rule: "country_restriction",
                        reaction,
                        reason: format!("country '{}' is in the block list", country_upper),
                    })
                } else {
                    None
                }
            }
        }
    }

    /// Check Tor exit node rule.
    ///
    /// Reads `block_tor` from NetworkPolicy. The `is_tor_exit` flag
    /// on LoginContext is set by the caller (GeoIP/blocklist lookup).
    fn check_tor_exit(&self, ctx: &LoginContext) -> Option<RuleMatch> {
        if !self.network_policy.block_tor || !ctx.is_tor_exit {
            return None;
        }
        Some(RuleMatch {
            rule: "tor_exit_node",
            reaction: violation_reaction_to_rule(&self.network_policy.violation_reaction),
            reason: "login from known Tor exit node".to_string(),
        })
    }

    /// Check impossible travel rule.
    ///
    /// Computes haversine distance between current and previous login locations.
    /// If the required speed exceeds the threshold AND the distance exceeds
    /// the minimum, triggers StepUp — UNLESS both locations are designated
    /// (known locations for this user, e.g. roaming between WiFi and mobile data).
    ///
    /// Requires both current and previous lat/lon to be available.
    /// When either geo is None, the rule is skipped (cannot evaluate).
    fn check_impossible_travel(&self, ctx: &LoginContext) -> Option<RuleMatch> {
        let lat1 = ctx.prev_latitude?;
        let lon1 = ctx.prev_longitude?;
        let lat2 = ctx.latitude?;
        let lon2 = ctx.longitude?;
        let prev_at = ctx.prev_login_at?;

        let distance_km = haversine_km(lat1, lon1, lat2, lon2);
        if distance_km < self.config.impossible_travel_min_distance_km {
            return None;
        }

        let elapsed = chrono::Utc::now() - prev_at;
        let elapsed_hours = elapsed.num_seconds() as f64 / 3600.0;
        if elapsed_hours <= 0.0 {
            return None; // Same timestamp or clock skew — skip.
        }

        let speed_kmh = distance_km / elapsed_hours;
        if speed_kmh <= self.config.impossible_travel_min_speed_kmh {
            return None;
        }

        // Designated location suppression: if both current and previous
        // countries are designated (user regularly logs in from both), suppress
        // the impossible travel alert. This handles roaming scenarios where
        // switching between WiFi and mobile data changes the GeoIP country.
        if let (Some(current_country), Some(prev_country)) = (&ctx.country, &ctx.prev_country) {
            let current_designated = ctx
                .designated_countries
                .iter()
                .any(|c| c == current_country);
            let prev_designated = ctx.designated_countries.iter().any(|c| c == prev_country);
            if current_designated && prev_designated {
                return Some(RuleMatch {
                    rule: "location_switch",
                    reaction: RuleReaction::Allow,
                    reason: format!(
                        "impossible travel suppressed: both {} and {} are designated locations \
                         (distance {:.0}km in {:.0}min, likely network switch)",
                        prev_country,
                        current_country,
                        distance_km,
                        elapsed_hours * 60.0,
                    ),
                });
            }
        }

        Some(RuleMatch {
            rule: "impossible_travel",
            reaction: RuleReaction::StepUp,
            reason: format!(
                "login from {:.0}km away in {:.0}min (speed {:.0}km/h exceeds {:.0}km/h threshold)",
                distance_km,
                elapsed_hours * 60.0,
                speed_kmh,
                self.config.impossible_travel_min_speed_kmh,
            ),
        })
    }

    /// Check datacenter/hosting IP rule.
    ///
    /// Reads `block_datacenter_ips` from NetworkPolicy. The `is_datacenter_ip`
    /// flag on LoginContext is set by the caller (MaxMind ASN lookup).
    fn check_datacenter_ip(&self, ctx: &LoginContext) -> Option<RuleMatch> {
        if !self.network_policy.block_datacenter_ips || !ctx.is_datacenter_ip {
            return None;
        }
        Some(RuleMatch {
            rule: "datacenter_ip",
            reaction: violation_reaction_to_rule(&self.network_policy.violation_reaction),
            reason: "login from datacenter/hosting provider IP".to_string(),
        })
    }

    async fn check_brute_force_lockout(
        &self,
        ctx: &LoginContext,
    ) -> CacheResult<Option<RuleMatch>> {
        if !self.lockout_active(&ctx.identity).await? {
            return Ok(None);
        }
        Ok(Some(RuleMatch {
            rule: "brute_force",
            reaction: RuleReaction::Block,
            reason: "account temporarily locked due to repeated failed attempts".to_string(),
        }))
    }

    async fn check_brute_force(&self, ctx: &LoginContext) -> CacheResult<Option<RuleMatch>> {
        if !ctx.failed {
            return Ok(None);
        }
        // Warn at 80% of the limit: the attempts before the lockout need a CAPTCHA.
        let warn_threshold = u64::from(self.config.brute_force_max_attempts) * 4 / 5;
        let count = self.counter(&attempts_key(&ctx.identity)).await?;
        if count < warn_threshold {
            return Ok(None);
        }
        Ok(Some(RuleMatch {
            rule: "brute_force",
            reaction: RuleReaction::RequireCaptcha,
            reason: format!(
                "{} failed attempts in window (threshold: {})",
                count, self.config.brute_force_max_attempts
            ),
        }))
    }

    async fn check_credential_stuffing(
        &self,
        ctx: &LoginContext,
    ) -> CacheResult<Option<RuleMatch>> {
        let Some(ip) = ctx.ip else {
            return Ok(None);
        };
        let count = self.counter(&ip_key(ip)).await?;
        if count < u64::from(self.config.credential_stuffing_threshold) {
            return Ok(None);
        }
        Ok(Some(RuleMatch {
            rule: "credential_stuffing",
            reaction: RuleReaction::RequireCaptcha,
            reason: format!(
                "{} login attempts from {} in 60s (threshold: {})",
                count, ip, self.config.credential_stuffing_threshold
            ),
        }))
    }
}

#[cfg(test)]
mod tests;
