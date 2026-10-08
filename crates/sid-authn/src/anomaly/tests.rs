use super::*;
use sid_plugin::cache::InMemoryCacheBackend;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

fn test_cache() -> Arc<dyn CacheBackend> {
    Arc::new(InMemoryCacheBackend::new())
}

/// A cache that answers nothing: every operation fails.
struct DownCache;

#[async_trait::async_trait]
impl CacheBackend for DownCache {
    async fn get(&self, _key: &str) -> CacheResult<Option<Vec<u8>>> {
        Err(CacheError::Timeout)
    }
    async fn set(&self, _key: &str, _value: &[u8], _ttl: Duration) -> CacheResult<()> {
        Err(CacheError::Timeout)
    }
    async fn delete(&self, _key: &str) -> CacheResult<()> {
        Err(CacheError::Timeout)
    }
    async fn take(&self, _key: &str) -> CacheResult<Option<Vec<u8>>> {
        Err(CacheError::Timeout)
    }
    async fn exists(&self, _key: &str) -> CacheResult<bool> {
        Err(CacheError::Timeout)
    }
    async fn incr(&self, _key: &str, _ttl: Duration) -> CacheResult<u64> {
        Err(CacheError::Timeout)
    }
    async fn publish(&self, _channel: &str, _message: &[u8]) -> CacheResult<()> {
        Err(CacheError::Timeout)
    }
    async fn subscribe(&self, _channel: &str) -> CacheResult<mpsc::UnboundedReceiver<Vec<u8>>> {
        Err(CacheError::Timeout)
    }
    async fn health_check(&self) -> CacheResult<()> {
        Err(CacheError::Timeout)
    }
}

fn default_context() -> LoginContext {
    LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: false,
        is_datacenter_ip: false,
        is_blocklisted: false,
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    }
}

// ── New device and address ──

// The rule compares a sign-in with the profile's history. A first sign-in
// (right after registration or a reset) has no familiar device or address
// yet, so nothing about it is new; the next sign-in from elsewhere is.
#[tokio::test]
async fn test_new_device_ip_needs_a_previous_sign_in() {
    let detector = AnomalyDetector::ce_default(test_cache());
    let first = LoginContext {
        new_device: true,
        new_ip: true,
        prev_login_at: None,
        ..default_context()
    };
    let m = detector.evaluate(&first).await.unwrap();
    assert_eq!(m.reaction, RuleReaction::Allow, "{}", m.reason);

    let later = LoginContext {
        prev_login_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        ..first
    };
    let m = detector.evaluate(&later).await.unwrap();
    assert_eq!(m.reaction, RuleReaction::StepUp);
    assert_eq!(m.rule, "new_device_ip");
}

// ── Shared state and failure (multi-instance) ──

/// A lockout reached on one replica holds on every replica sharing the
/// cache; the lockout used to live in each process's own memory.
#[tokio::test]
async fn test_lockout_holds_on_every_replica() {
    let cache = test_cache();
    let config = AnomalyConfig {
        brute_force_max_attempts: 3,
        ..AnomalyConfig::default()
    };
    let a = AnomalyDetector::new(config.clone(), NetworkPolicy::default(), cache.clone());
    let b = AnomalyDetector::new(config, NetworkPolicy::default(), cache);

    a.record_failed_attempt("shared@sid.example.com")
        .await
        .unwrap();
    b.record_failed_attempt("shared@sid.example.com")
        .await
        .unwrap();
    a.record_failed_attempt("shared@sid.example.com")
        .await
        .unwrap();

    let mut ctx = default_context();
    ctx.identity = "shared@sid.example.com".into();
    assert_eq!(
        b.evaluate(&ctx).await.unwrap().reaction,
        RuleReaction::Block
    );
    assert!(b.lockout_active("shared@sid.example.com").await.unwrap());
}

/// A cache that cannot answer fails the check and the count instead of
/// reading as "no attempts" and admitting a guessing attacker.
#[tokio::test]
async fn test_cache_failure_fails_closed() {
    let detector = AnomalyDetector::ce_default(Arc::new(DownCache));
    let mut ctx = default_context();
    ctx.failed = true;
    assert!(detector.evaluate(&ctx).await.is_err());
    assert!(
        detector
            .record_failed_attempt("alice@sid.example.com")
            .await
            .is_err()
    );
    assert!(
        detector
            .lockout_active("alice@sid.example.com")
            .await
            .is_err()
    );
    assert!(
        detector
            .record_ip_attempt(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .is_err()
    );
}

/// A counter that is not a number is a fault, not zero attempts.
#[tokio::test]
async fn test_unreadable_counter_is_an_error() {
    let cache = test_cache();
    cache
        .set(
            "rate:brute:garbled@sid.example.com",
            b"lots",
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let detector = AnomalyDetector::ce_default(cache);
    let mut ctx = default_context();
    ctx.identity = "garbled@sid.example.com".into();
    ctx.failed = true;
    assert!(detector.evaluate(&ctx).await.is_err());
}

#[tokio::test]
async fn test_no_anomalies_allows() {
    let detector = AnomalyDetector::ce_default(test_cache());
    let result = detector.evaluate(&default_context()).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
    assert_eq!(result.rule, "none");
}

#[tokio::test]
async fn test_new_device_and_ip_triggers_step_up() {
    let detector = AnomalyDetector::ce_default(test_cache());
    // A profile that has signed in before, now from a new device and address.
    let mut ctx = default_context();
    ctx.prev_login_at = Some(chrono::Utc::now() - chrono::Duration::days(1));
    ctx.new_device = true;
    ctx.new_ip = true;

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::StepUp);
    assert_eq!(result.rule, "new_device_ip");
}

#[tokio::test]
async fn test_new_device_only_allows() {
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.new_device = true;
    ctx.new_ip = false;

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_brute_force_lockout() {
    let config = AnomalyConfig {
        brute_force_max_attempts: 3,
        brute_force_window_secs: 300,
        brute_force_lockout_secs: 60,
        credential_stuffing_threshold: 10,
        ..Default::default()
    };
    let detector = AnomalyDetector::new(config, NetworkPolicy::default(), test_cache());

    for _ in 0..3 {
        detector
            .record_failed_attempt("alice@sid.example.com")
            .await
            .unwrap();
    }

    let mut ctx = default_context();
    ctx.failed = true;
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Block);
    assert_eq!(result.rule, "brute_force");
}

/// The retry delay a locked-out client is told is the configured lockout.
#[test]
fn test_lockout_duration_is_the_configured_lockout() {
    let config = AnomalyConfig {
        brute_force_lockout_secs: 60,
        ..Default::default()
    };
    let detector = AnomalyDetector::new(config, NetworkPolicy::default(), test_cache());
    assert_eq!(detector.lockout_duration(), Duration::from_secs(60));
}

#[tokio::test]
async fn test_brute_force_clear_lockout() {
    let config = AnomalyConfig {
        brute_force_max_attempts: 3,
        brute_force_window_secs: 300,
        brute_force_lockout_secs: 60,
        credential_stuffing_threshold: 10,
        ..Default::default()
    };
    let detector = AnomalyDetector::new(config, NetworkPolicy::default(), test_cache());

    for _ in 0..3 {
        detector
            .record_failed_attempt("alice@sid.example.com")
            .await
            .unwrap();
    }

    detector
        .clear_lockout("alice@sid.example.com")
        .await
        .unwrap();

    let ctx = default_context();
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_credential_stuffing_captcha() {
    let config = AnomalyConfig {
        brute_force_max_attempts: 5,
        brute_force_window_secs: 300,
        brute_force_lockout_secs: 60,
        credential_stuffing_threshold: 3,
        ..Default::default()
    };
    let detector = AnomalyDetector::new(config, NetworkPolicy::default(), test_cache());

    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    for _ in 0..3 {
        detector.record_ip_attempt(ip).await.unwrap();
    }

    let mut ctx = default_context();
    ctx.ip = Some(ip);
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::RequireCaptcha);
    assert_eq!(result.rule, "credential_stuffing");
}

#[tokio::test]
async fn test_credential_stuffing_below_threshold() {
    let detector = AnomalyDetector::ce_default(test_cache());
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    detector.record_ip_attempt(ip).await.unwrap();

    let mut ctx = default_context();
    ctx.ip = Some(ip);
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_no_ip_skips_credential_stuffing() {
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.ip = None;
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_lockout_takes_priority_over_new_device() {
    let config = AnomalyConfig {
        brute_force_max_attempts: 2,
        brute_force_window_secs: 300,
        brute_force_lockout_secs: 60,
        credential_stuffing_threshold: 10,
        ..Default::default()
    };
    let detector = AnomalyDetector::new(config, NetworkPolicy::default(), test_cache());

    for _ in 0..2 {
        detector
            .record_failed_attempt("alice@sid.example.com")
            .await
            .unwrap();
    }

    let mut ctx = default_context();
    ctx.new_device = true;
    ctx.new_ip = true;
    ctx.failed = true;

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Block);
    assert_eq!(result.rule, "brute_force");
}

#[test]
fn test_rule_reaction_as_str() {
    assert_eq!(RuleReaction::Allow.as_str(), "allow");
    assert_eq!(RuleReaction::StepUp.as_str(), "step_up");
    assert_eq!(RuleReaction::RequireCaptcha.as_str(), "require_captcha");
    assert_eq!(RuleReaction::Block.as_str(), "block");
    assert_eq!(RuleReaction::HardNo.as_str(), "hard_no");
}

#[test]
fn test_default_config_values() {
    let config = AnomalyConfig::default();
    assert_eq!(config.brute_force_max_attempts, 5);
    assert_eq!(config.brute_force_window_secs, 300);
    assert_eq!(config.brute_force_lockout_secs, 900);
    assert_eq!(config.credential_stuffing_threshold, 10);
}

#[tokio::test]
async fn test_multiple_identities_independent() {
    let config = AnomalyConfig {
        brute_force_max_attempts: 2,
        brute_force_window_secs: 300,
        brute_force_lockout_secs: 60,
        credential_stuffing_threshold: 10,
        ..Default::default()
    };
    let detector = AnomalyDetector::new(config, NetworkPolicy::default(), test_cache());

    for _ in 0..2 {
        detector
            .record_failed_attempt("alice@sid.example.com")
            .await
            .unwrap();
    }

    let ctx = LoginContext {
        identity: "bob@sid.example.com".to_string(),
        ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: false,
        is_blocklisted: false,
        is_datacenter_ip: false,
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

// ── Country restriction tests ──

#[tokio::test]
async fn test_country_allow_list_permits_listed() {
    let policy = NetworkPolicy {
        country_mode: CountryMode::AllowList,
        countries: vec!["US".into(), "DE".into()],
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.country = Some("US".into());
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_country_allow_list_blocks_unlisted() {
    let policy = NetworkPolicy {
        country_mode: CountryMode::AllowList,
        countries: vec!["US".into(), "DE".into()],
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.country = Some("RU".into());
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Block);
    assert_eq!(result.rule, "country_restriction");
}

#[tokio::test]
async fn test_country_block_list_blocks_listed() {
    let policy = NetworkPolicy {
        country_mode: CountryMode::BlockList,
        countries: vec!["CN".into(), "KP".into()],
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.country = Some("CN".into());
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Block);
    assert_eq!(result.rule, "country_restriction");
}

#[tokio::test]
async fn test_country_block_list_allows_unlisted() {
    let policy = NetworkPolicy {
        country_mode: CountryMode::BlockList,
        countries: vec!["CN".into(), "KP".into()],
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.country = Some("US".into());
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_country_mode_none_allows_all() {
    let policy = NetworkPolicy {
        country_mode: CountryMode::None,
        countries: vec!["CN".into()],
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.country = Some("CN".into());
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_country_case_insensitive() {
    let policy = NetworkPolicy {
        country_mode: CountryMode::AllowList,
        countries: vec!["us".into()],
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.country = Some("US".into());
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_country_no_country_skips_rule() {
    let policy = NetworkPolicy {
        country_mode: CountryMode::AllowList,
        countries: vec!["US".into()],
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let ctx = default_context(); // country = None
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_country_violation_reaction_step_up() {
    let policy = NetworkPolicy {
        country_mode: CountryMode::BlockList,
        countries: vec!["CN".into()],
        violation_reaction: NetworkViolationReaction::StepUp,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.country = Some("CN".into());
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::StepUp);
    assert_eq!(result.rule, "country_restriction");
}

// ── Tor exit node tests ──

#[tokio::test]
async fn test_tor_exit_blocks_when_enabled() {
    let policy = NetworkPolicy {
        block_tor: true,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.is_tor_exit = true;
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Block);
    assert_eq!(result.rule, "tor_exit_node");
}

#[tokio::test]
async fn test_tor_exit_allows_when_disabled() {
    let policy = NetworkPolicy {
        block_tor: false,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.is_tor_exit = true;
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_tor_exit_allows_non_tor() {
    let policy = NetworkPolicy {
        block_tor: true,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let ctx = default_context(); // is_tor_exit = false
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

// ── Datacenter IP tests ──

#[tokio::test]
async fn test_datacenter_ip_blocks_when_enabled() {
    let policy = NetworkPolicy {
        block_datacenter_ips: true,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.is_datacenter_ip = true;
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Block);
    assert_eq!(result.rule, "datacenter_ip");
}

#[tokio::test]
async fn test_datacenter_ip_allows_when_disabled() {
    let policy = NetworkPolicy {
        block_datacenter_ips: false,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.is_datacenter_ip = true;
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_datacenter_ip_allows_non_datacenter() {
    let policy = NetworkPolicy {
        block_datacenter_ips: true,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let ctx = default_context(); // is_datacenter_ip = false
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

// ── Priority tests ──

#[tokio::test]
async fn test_country_takes_priority_over_tor() {
    let policy = NetworkPolicy {
        country_mode: CountryMode::BlockList,
        countries: vec!["CN".into()],
        block_tor: true,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.country = Some("CN".into());
    ctx.is_tor_exit = true;
    let result = detector.evaluate(&ctx).await.unwrap();
    // Country restriction has higher priority than Tor
    assert_eq!(result.rule, "country_restriction");
}

#[tokio::test]
async fn test_tor_takes_priority_over_datacenter() {
    let policy = NetworkPolicy {
        block_tor: true,
        block_datacenter_ips: true,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.is_tor_exit = true;
    ctx.is_datacenter_ip = true;
    let result = detector.evaluate(&ctx).await.unwrap();
    // Tor has higher priority than datacenter
    assert_eq!(result.rule, "tor_exit_node");
}

// ── IP blocklist tests ──

#[tokio::test]
async fn test_blocklisted_ip_hard_no() {
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.is_blocklisted = true;
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::HardNo);
    assert_eq!(result.rule, "ip_blocklist");
}

#[tokio::test]
async fn test_blocklist_takes_priority_over_everything() {
    // Blocklist should win even when brute force lockout is active.
    let config = AnomalyConfig {
        brute_force_max_attempts: 2,
        brute_force_window_secs: 300,
        brute_force_lockout_secs: 60,
        credential_stuffing_threshold: 10,
        ..Default::default()
    };
    let policy = NetworkPolicy {
        block_tor: true,
        block_datacenter_ips: true,
        country_mode: CountryMode::BlockList,
        countries: vec!["CN".into()],
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(config, policy, test_cache());

    for _ in 0..2 {
        detector
            .record_failed_attempt("alice@sid.example.com")
            .await
            .unwrap();
    }

    let mut ctx = default_context();
    ctx.is_blocklisted = true;
    ctx.is_tor_exit = true;
    ctx.is_datacenter_ip = true;
    ctx.country = Some("CN".into());
    ctx.failed = true;

    let result = detector.evaluate(&ctx).await.unwrap();
    // Blocklist = highest priority = HardNo
    assert_eq!(result.rule, "ip_blocklist");
    assert_eq!(result.reaction, RuleReaction::HardNo);
}

#[tokio::test]
async fn test_non_blocklisted_allows() {
    let detector = AnomalyDetector::ce_default(test_cache());
    let ctx = default_context(); // is_blocklisted = false
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

// ── Haversine tests ──

#[test]
fn test_haversine_known_distance() {
    // Berlin (52.52, 13.40) → New York (40.71, -74.01) ≈ 6385 km
    let d = haversine_km(52.52, 13.40, 40.71, -74.01);
    assert!(
        (d - 6385.0).abs() < 50.0,
        "Berlin→NYC should be ~6385km, got {d:.0}"
    );
}

#[test]
fn test_haversine_same_point_is_zero() {
    let d = haversine_km(52.52, 13.40, 52.52, 13.40);
    assert!(d < 0.01, "same point should be 0km, got {d}");
}

#[test]
fn test_haversine_short_distance() {
    // London (51.51, -0.13) → Paris (48.86, 2.35) ≈ 344 km
    let d = haversine_km(51.51, -0.13, 48.86, 2.35);
    assert!(
        (d - 344.0).abs() < 10.0,
        "London→Paris should be ~344km, got {d:.0}"
    );
}

#[test]
fn test_haversine_antipodal() {
    // North pole → South pole ≈ 20015 km (half circumference)
    let d = haversine_km(90.0, 0.0, -90.0, 0.0);
    assert!(
        (d - 20015.0).abs() < 100.0,
        "poles should be ~20015km, got {d:.0}"
    );
}

// ── Impossible travel tests ──

#[tokio::test]
async fn test_impossible_travel_triggers_step_up() {
    // Berlin → New York in 45 min = ~8533 km/h (> 900 km/h threshold)
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.latitude = Some(40.71); // New York (current)
    ctx.longitude = Some(-74.01);
    ctx.prev_latitude = Some(52.52); // Berlin (previous)
    ctx.prev_longitude = Some(13.40);
    ctx.prev_login_at = Some(chrono::Utc::now() - chrono::Duration::minutes(45));

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "impossible_travel");
    assert_eq!(result.reaction, RuleReaction::StepUp);
    assert!(
        result.reason.contains("km/h"),
        "reason should mention speed: {}",
        result.reason
    );
}

#[tokio::test]
async fn test_impossible_travel_allows_slow_travel() {
    // Berlin → Paris (344 km) in 2 hours = 172 km/h (< 900 threshold)
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.latitude = Some(48.86); // Paris (current)
    ctx.longitude = Some(2.35);
    ctx.prev_latitude = Some(52.52); // Berlin (previous)
    ctx.prev_longitude = Some(13.40);
    ctx.prev_login_at = Some(chrono::Utc::now() - chrono::Duration::hours(2));

    let result = detector.evaluate(&ctx).await.unwrap();
    // 344 km < 500 km min_distance → rule skipped
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_impossible_travel_allows_long_time() {
    // Berlin → New York (6385 km) in 10 hours = 639 km/h (< 900 threshold)
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.latitude = Some(40.71);
    ctx.longitude = Some(-74.01);
    ctx.prev_latitude = Some(52.52);
    ctx.prev_longitude = Some(13.40);
    ctx.prev_login_at = Some(chrono::Utc::now() - chrono::Duration::hours(10));

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_impossible_travel_skipped_when_no_geo() {
    // No current geo → rule skipped.
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.prev_latitude = Some(52.52);
    ctx.prev_longitude = Some(13.40);
    ctx.prev_login_at = Some(chrono::Utc::now() - chrono::Duration::minutes(30));
    // latitude/longitude = None (default)

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_impossible_travel_skipped_when_no_previous() {
    // No previous session → rule skipped (first login).
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.latitude = Some(40.71);
    ctx.longitude = Some(-74.01);
    // prev_* = None (default)

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_impossible_travel_priority_below_country() {
    // Country block should fire before impossible travel.
    let policy = NetworkPolicy {
        country_mode: CountryMode::BlockList,
        countries: vec!["US".into()],
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.country = Some("US".into());
    ctx.latitude = Some(40.71);
    ctx.longitude = Some(-74.01);
    ctx.prev_latitude = Some(52.52);
    ctx.prev_longitude = Some(13.40);
    ctx.prev_login_at = Some(chrono::Utc::now() - chrono::Duration::minutes(10));

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(
        result.rule, "country_restriction",
        "country should fire before impossible_travel"
    );
}

// ── Designated location suppression ──

#[tokio::test]
async fn test_impossible_travel_suppressed_when_both_designated() {
    // Roaming scenario: Kyiv (UA) → Bucharest (RO) in 5 seconds.
    // Both countries are designated → location_switch (Allow), not StepUp.
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.latitude = Some(44.43); // Bucharest (current)
    ctx.longitude = Some(26.10);
    ctx.country = Some("RO".to_string());
    ctx.prev_latitude = Some(50.45); // Kyiv (previous)
    ctx.prev_longitude = Some(30.52);
    ctx.prev_login_at = Some(chrono::Utc::now() - chrono::Duration::seconds(5));
    ctx.prev_country = Some("UA".to_string());
    ctx.designated_countries = vec!["UA".to_string(), "RO".to_string()];

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(
        result.rule, "location_switch",
        "Both designated → should be location_switch, not impossible_travel"
    );
    assert_eq!(
        result.reaction,
        RuleReaction::Allow,
        "Designated location switch should Allow"
    );
    assert!(
        result.reason.contains("suppressed"),
        "Reason should mention suppression: {}",
        result.reason
    );
    assert!(
        result.reason.contains("designated"),
        "Reason should mention designated: {}",
        result.reason
    );
}

#[tokio::test]
async fn test_impossible_travel_not_suppressed_when_current_not_designated() {
    // Kyiv (UA, designated) → São Paulo (BR, NOT designated) in 5 seconds.
    // Only one is designated → StepUp.
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.latitude = Some(-23.55); // São Paulo (current)
    ctx.longitude = Some(-46.63);
    ctx.country = Some("BR".to_string());
    ctx.prev_latitude = Some(50.45); // Kyiv (previous)
    ctx.prev_longitude = Some(30.52);
    ctx.prev_login_at = Some(chrono::Utc::now() - chrono::Duration::seconds(5));
    ctx.prev_country = Some("UA".to_string());
    ctx.designated_countries = vec!["UA".to_string(), "RO".to_string()]; // BR not designated

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(
        result.rule, "impossible_travel",
        "Non-designated destination → impossible_travel StepUp"
    );
    assert_eq!(result.reaction, RuleReaction::StepUp);
}

#[tokio::test]
async fn test_impossible_travel_not_suppressed_when_no_designated() {
    // No designated locations at all → standard impossible travel.
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.latitude = Some(44.43);
    ctx.longitude = Some(26.10);
    ctx.country = Some("RO".to_string());
    ctx.prev_latitude = Some(50.45);
    ctx.prev_longitude = Some(30.52);
    ctx.prev_login_at = Some(chrono::Utc::now() - chrono::Duration::seconds(5));
    ctx.prev_country = Some("UA".to_string());
    ctx.designated_countries = vec![]; // empty

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "impossible_travel");
    assert_eq!(result.reaction, RuleReaction::StepUp);
}

#[tokio::test]
async fn test_impossible_travel_not_suppressed_when_no_country() {
    // Country not resolved (GeoIP failed) → no suppression, standard impossible travel.
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.latitude = Some(44.43);
    ctx.longitude = Some(26.10);
    ctx.country = None; // GeoIP country resolution failed
    ctx.prev_latitude = Some(50.45);
    ctx.prev_longitude = Some(30.52);
    ctx.prev_login_at = Some(chrono::Utc::now() - chrono::Duration::seconds(5));
    ctx.prev_country = Some("UA".to_string());
    ctx.designated_countries = vec!["UA".to_string(), "RO".to_string()];

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(
        result.rule, "impossible_travel",
        "No current country → can't check designated → standard StepUp"
    );
    assert_eq!(result.reaction, RuleReaction::StepUp);
}

// ── Brute force CAPTCHA threshold (80% of max_attempts) ──

#[tokio::test]
async fn test_brute_force_captcha_at_threshold() {
    let config = AnomalyConfig {
        brute_force_max_attempts: 5,
        brute_force_window_secs: 300,
        brute_force_lockout_secs: 900,
        ..AnomalyConfig::default()
    };
    let detector = AnomalyDetector::new(config, NetworkPolicy::default(), test_cache());

    // Record 3 failed attempts (below 80% threshold of 5 = 4).
    for _ in 0..3 {
        detector
            .record_failed_attempt("threshold-user")
            .await
            .unwrap();
    }

    let mut ctx = default_context();
    ctx.identity = "threshold-user".into();
    ctx.failed = true;

    // 3 attempts = below threshold → no CAPTCHA.
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_ne!(
        result.reaction,
        RuleReaction::RequireCaptcha,
        "3/5 should not trigger CAPTCHA"
    );

    // Record 4th attempt (hits 80% = 4/5).
    detector
        .record_failed_attempt("threshold-user")
        .await
        .unwrap();

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::RequireCaptcha);
    assert_eq!(result.rule, "brute_force");
}

#[tokio::test]
async fn test_brute_force_captcha_not_for_successful_login() {
    let detector = AnomalyDetector::ce_default(test_cache());

    // Record 4 failed attempts (above threshold).
    for _ in 0..4 {
        detector
            .record_failed_attempt("success-user")
            .await
            .unwrap();
    }

    let mut ctx = default_context();
    ctx.identity = "success-user".into();
    ctx.failed = false; // Successful login — should not trigger CAPTCHA.

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_ne!(
        result.reaction,
        RuleReaction::RequireCaptcha,
        "successful login should not get CAPTCHA even with prior failures"
    );
}

// ── Shared cache behavior ──

#[tokio::test]
async fn test_distributed_brute_force_lockout() {
    let cache = Arc::new(InMemoryCacheBackend::new());
    let config = AnomalyConfig {
        brute_force_max_attempts: 3,
        brute_force_window_secs: 300,
        brute_force_lockout_secs: 900,
        ..AnomalyConfig::default()
    };
    let detector = AnomalyDetector::new(config, NetworkPolicy::default(), cache.clone());

    // Record failures → triggers lockout.
    for _ in 0..3 {
        detector
            .record_failed_attempt("dist-lockout-user")
            .await
            .unwrap();
    }

    // Lockout should be visible via distributed cache.
    let lockout_key = "rate:brute:lockout:dist-lockout-user";
    let exists = cache.exists(lockout_key).await.unwrap();
    assert!(exists, "lockout should be written to distributed cache");

    // Evaluate should return Block from distributed lockout.
    let mut ctx = default_context();
    ctx.identity = "dist-lockout-user".into();
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Block);
    assert_eq!(result.rule, "brute_force");
}

#[tokio::test]
async fn test_distributed_brute_force_captcha_threshold() {
    let cache = Arc::new(InMemoryCacheBackend::new());
    let config = AnomalyConfig {
        brute_force_max_attempts: 5,
        brute_force_window_secs: 300,
        brute_force_lockout_secs: 900,
        ..AnomalyConfig::default()
    };

    // Simulate: another instance recorded 3 failures in cache.
    cache
        .set(
            "rate:brute:dist-captcha-user",
            b"3",
            Duration::from_secs(300),
        )
        .await
        .unwrap();

    let detector = AnomalyDetector::new(config, NetworkPolicy::default(), cache.clone());

    let mut ctx = default_context();
    ctx.identity = "dist-captcha-user".into();
    ctx.failed = true;

    // 3 < 4 (80% of 5) → no CAPTCHA.
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_ne!(result.reaction, RuleReaction::RequireCaptcha);

    // Set cache to 4 (threshold hit).
    cache
        .set(
            "rate:brute:dist-captcha-user",
            b"4",
            Duration::from_secs(300),
        )
        .await
        .unwrap();

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::RequireCaptcha);
    assert!(result.reason.contains("failed attempts"));
}

#[tokio::test]
async fn test_distributed_lockout_clear() {
    let cache = Arc::new(InMemoryCacheBackend::new());
    let config = AnomalyConfig {
        brute_force_max_attempts: 3,
        brute_force_window_secs: 300,
        brute_force_lockout_secs: 900,
        ..AnomalyConfig::default()
    };
    let detector = AnomalyDetector::new(config, NetworkPolicy::default(), cache.clone());

    // Create lockout.
    for _ in 0..3 {
        detector.record_failed_attempt("clear-user").await.unwrap();
    }

    // Verify locked.
    let mut ctx = default_context();
    ctx.identity = "clear-user".into();
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Block);

    // Clear lockout.
    detector.clear_lockout("clear-user").await.unwrap();

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
    assert!(!cache.exists("rate:brute:lockout:clear-user").await.unwrap());
}

// ── Alert reaction variant ──

#[tokio::test]
async fn test_country_violation_alert_allows() {
    let policy = NetworkPolicy {
        country_mode: CountryMode::BlockList,
        countries: vec!["CN".into()],
        violation_reaction: NetworkViolationReaction::Alert,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.country = Some("CN".into());

    let result = detector.evaluate(&ctx).await.unwrap();
    // Alert → Allow (notification sent separately), not Block.
    assert_eq!(result.reaction, RuleReaction::Allow);
    assert_eq!(result.rule, "country_restriction");
}

#[tokio::test]
async fn test_tor_violation_alert_allows() {
    let policy = NetworkPolicy {
        block_tor: true,
        violation_reaction: NetworkViolationReaction::Alert,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, test_cache());
    let mut ctx = default_context();
    ctx.is_tor_exit = true;

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
    assert_eq!(result.rule, "tor_exit_node");
}

// ── New IP only (without new device) → Allow ──

#[tokio::test]
async fn test_new_ip_only_without_device_allows() {
    let detector = AnomalyDetector::ce_default(test_cache());
    let mut ctx = default_context();
    ctx.new_ip = true;
    ctx.new_device = false;

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(
        result.reaction,
        RuleReaction::Allow,
        "new IP alone should not trigger step-up"
    );
}

// ── Credential stuffing via shared cache ──

#[tokio::test]
async fn test_distributed_credential_stuffing() {
    let cache = Arc::new(InMemoryCacheBackend::new());
    let config = AnomalyConfig {
        credential_stuffing_threshold: 10,
        ..AnomalyConfig::default()
    };

    // Simulate: another instance recorded 9 attempts for this IP.
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    cache
        .set(&format!("rate:ip:{ip}"), b"9", Duration::from_secs(60))
        .await
        .unwrap();

    let detector = AnomalyDetector::new(config, NetworkPolicy::default(), cache.clone());
    let mut ctx = default_context();
    ctx.ip = Some(ip);
    ctx.failed = true;

    // 9 < 10 → no CAPTCHA yet.
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_ne!(result.reaction, RuleReaction::RequireCaptcha);

    // Set to 10 → threshold hit.
    cache
        .set(&format!("rate:ip:{ip}"), b"10", Duration::from_secs(60))
        .await
        .unwrap();

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::RequireCaptcha);
    assert_eq!(result.rule, "credential_stuffing");
}
