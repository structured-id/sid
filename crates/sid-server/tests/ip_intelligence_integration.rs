// SPDX-License-Identifier: AGPL-3.0-only
//! IP Intelligence integration tests.
//!
//! End-to-end tests verifying the full pipeline:
//! IpIntelligenceProvider → Aggregator → LoginContext enrichment → AnomalyDetector reaction.
//!
//! Uses real (in-memory) provider data — no mocks for IP classification logic.

use sid_authn::anomaly::{AnomalyConfig, AnomalyDetector, LoginContext, RuleReaction};
use sid_authn::ip_intelligence::{
    CloudRangeProvider, FireholProvider, IpClassification, IpIntelError, IpIntelligenceAggregator,
    IpIntelligenceProvider, IpLabel, TorExitProvider,
};
use sid_core::models::security_policy::{CountryMode, NetworkPolicy, NetworkViolationReaction};
use sid_plugin::cache::NoCacheBackend;

use async_trait::async_trait;
use chrono::Utc;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

fn no_cache() -> Arc<dyn sid_plugin::cache::CacheBackend> {
    Arc::new(NoCacheBackend)
}

// ═══════════════════════════════════════════════════════════════════
// End-to-end: TorExitProvider → Aggregator → AnomalyDetector
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_tor_exit_ip_triggers_block() {
    // Setup: TorExitProvider with known exit nodes.
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("198.51.100.1\n198.51.100.2\n203.0.113.5\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![tor as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    ));

    // NetworkPolicy: block_tor = true.
    let policy = NetworkPolicy {
        block_tor: true,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, no_cache());

    // Test: Tor exit IP → classify → enrich LoginContext → evaluate.
    let tor_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let classification = aggregator.classify(tor_ip).await.unwrap();

    assert!(
        classification.is_tor_exit(),
        "IP should be classified as Tor exit"
    );
    assert!(
        !classification.is_datacenter(),
        "IP should NOT be classified as datacenter"
    );
    assert!(
        !classification.is_blocklisted(),
        "IP should NOT be classified as blocklisted"
    );

    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(tor_ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: classification.is_tor_exit(),
        is_datacenter_ip: classification.is_datacenter(),
        is_blocklisted: classification.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "tor_exit_node");
    assert_eq!(result.reaction, RuleReaction::Block);
}

#[tokio::test]
async fn test_e2e_normal_ip_allows() {
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("198.51.100.1\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![tor as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    ));

    let policy = NetworkPolicy {
        block_tor: true,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, no_cache());

    // Non-Tor IP.
    let normal_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let classification = aggregator.classify(normal_ip).await.unwrap();

    assert!(!classification.is_tor_exit());

    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(normal_ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: classification.is_tor_exit(),
        is_datacenter_ip: classification.is_datacenter(),
        is_blocklisted: classification.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "none");
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_e2e_tor_exit_allows_when_policy_disabled() {
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("198.51.100.1\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![tor as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    ));

    // block_tor = false (default) — Tor detection active but not enforced.
    let detector = AnomalyDetector::ce_default(no_cache());

    let tor_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let classification = aggregator.classify(tor_ip).await.unwrap();

    assert!(classification.is_tor_exit());

    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(tor_ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: classification.is_tor_exit(),
        is_datacenter_ip: classification.is_datacenter(),
        is_blocklisted: classification.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    // block_tor=false → Tor rule skipped → Allow.
    assert_eq!(result.reaction, RuleReaction::Allow);
}

// ═══════════════════════════════════════════════════════════════════
// Blocklist priority: HardNo overrides everything
// ═══════════════════════════════════════════════════════════════════

/// Stub provider that marks all IPs as blocklisted.
struct BlocklistStubProvider;

#[async_trait]
impl IpIntelligenceProvider for BlocklistStubProvider {
    async fn classify(&self, _ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
        Ok(Some(IpClassification {
            labels: vec![IpLabel::Blocklisted],
            risk_score: Some(1.0),
            source: "test_blocklist".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }))
    }

    async fn refresh(&self) -> Result<(), IpIntelError> {
        Ok(())
    }

    fn source_name(&self) -> &str {
        "test_blocklist"
    }
}

#[tokio::test]
async fn test_e2e_blocklisted_ip_hard_no_overrides_all() {
    // Blocklisted IP should get HardNo even with brute force lockout active.
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("198.51.100.1\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![
            tor as Arc<dyn IpIntelligenceProvider>,
            Arc::new(BlocklistStubProvider),
        ],
        no_cache(),
        Duration::from_secs(60),
    ));

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
    // The lockout lives in the shared cache only, so it must keep the attempts.
    let detector = AnomalyDetector::new(
        config,
        policy,
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
    );

    // Trigger brute force lockout.
    for _ in 0..2 {
        detector
            .record_failed_attempt("victim@sid.example.com")
            .await
            .unwrap();
    }

    // IP is BOTH tor_exit AND blocklisted.
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let classification = aggregator.classify(ip).await.unwrap();

    assert!(classification.is_tor_exit());
    assert!(classification.is_blocklisted());

    let ctx = LoginContext {
        identity: "victim@sid.example.com".to_string(),
        ip: Some(ip),
        country: Some("CN".into()), // also in block list
        failed: true,
        new_device: true,
        new_ip: true,
        is_tor_exit: classification.is_tor_exit(),
        is_datacenter_ip: classification.is_datacenter(),
        is_blocklisted: classification.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    // Blocklist = priority 1 = HardNo, overrides brute force (Block),
    // country (Block), Tor (Block), new_device_ip (StepUp).
    assert_eq!(result.rule, "ip_blocklist");
    assert_eq!(result.reaction, RuleReaction::HardNo);
}

// ═══════════════════════════════════════════════════════════════════
// Multi-provider label merging
// ═══════════════════════════════════════════════════════════════════

/// Stub provider that marks IPs as datacenter.
struct DatacenterStubProvider;

#[async_trait]
impl IpIntelligenceProvider for DatacenterStubProvider {
    async fn classify(&self, _ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
        Ok(Some(IpClassification {
            labels: vec![IpLabel::Datacenter],
            risk_score: Some(0.4),
            source: "test_datacenter".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }))
    }

    async fn refresh(&self) -> Result<(), IpIntelError> {
        Ok(())
    }

    fn source_name(&self) -> &str {
        "test_datacenter"
    }
}

#[tokio::test]
async fn test_e2e_multi_provider_label_merge() {
    // IP is classified as Tor by one provider and Datacenter by another.
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("198.51.100.1\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![
            tor as Arc<dyn IpIntelligenceProvider>,
            Arc::new(DatacenterStubProvider),
        ],
        no_cache(),
        Duration::from_secs(60),
    ));

    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let classification = aggregator.classify(ip).await.unwrap();

    // Both labels present (merge).
    assert!(classification.is_tor_exit());
    assert!(classification.is_datacenter());
    // Risk score = max(0.8 from Tor, 0.4 from Datacenter).
    assert_eq!(classification.risk_score, Some(0.8));
    // Both sources tracked.
    assert_eq!(classification.sources.len(), 2);
}

#[tokio::test]
async fn test_e2e_tor_higher_priority_than_datacenter_in_anomaly() {
    // When IP is both Tor and Datacenter, Tor rule fires first (higher priority).
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("198.51.100.1\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![
            tor as Arc<dyn IpIntelligenceProvider>,
            Arc::new(DatacenterStubProvider),
        ],
        no_cache(),
        Duration::from_secs(60),
    ));

    let policy = NetworkPolicy {
        block_tor: true,
        block_datacenter_ips: true,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, no_cache());

    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let classification = aggregator.classify(ip).await.unwrap();

    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: classification.is_tor_exit(),
        is_datacenter_ip: classification.is_datacenter(),
        is_blocklisted: classification.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    // Tor exit = priority 4, datacenter = priority 6 → Tor wins.
    assert_eq!(result.rule, "tor_exit_node");
    assert_eq!(result.reaction, RuleReaction::Block);
}

// ═══════════════════════════════════════════════════════════════════
// Provider refresh + data swap
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_tor_provider_load_from_text_updates_classify() {
    let provider = TorExitProvider::new(no_cache());

    // Initially empty.
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    assert!(provider.classify(ip).await.unwrap().is_none());

    // Load data.
    provider.load_from_text("198.51.100.1\n198.51.100.2\n");
    assert!(provider.classify(ip).await.unwrap().is_some());
    assert_eq!(provider.node_count(), 2);

    // Reload with different data — old entry removed.
    provider.load_from_text("203.0.113.1\n");
    assert!(
        provider.classify(ip).await.unwrap().is_none(),
        "old IP should be gone after reload"
    );
    assert!(
        provider
            .classify(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))
            .await
            .unwrap()
            .is_some(),
        "new IP should be present"
    );
    assert_eq!(provider.node_count(), 1);
}

#[tokio::test]
async fn test_aggregator_refresh_all_reports_results() {
    // Use an unreachable URL to ensure refresh fails predictably.
    let tor = Arc::new(TorExitProvider::with_url(
        no_cache(),
        "http://192.0.2.1:1/nonexistent".to_string(), // TEST-NET, unreachable
    ));

    let aggregator = IpIntelligenceAggregator::new(
        vec![tor as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    );

    let results = aggregator.refresh_all().await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "tor_exit");
    // Refresh should fail (unreachable endpoint).
    assert!(results[0].1.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// IPv6 support
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_ipv6_tor_exit() {
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("2001:db8::dead:beef\n198.51.100.1\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![tor as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    ));

    let ipv6: IpAddr = "2001:db8::dead:beef".parse().unwrap();
    let classification = aggregator.classify(ipv6).await.unwrap();
    assert!(classification.is_tor_exit());

    let non_tor_v6: IpAddr = "2001:db8::1".parse().unwrap();
    let classification = aggregator.classify(non_tor_v6).await.unwrap();
    assert!(!classification.is_tor_exit());
}

// ═══════════════════════════════════════════════════════════════════
// Allowlist always wins — overrides all negative labels
// ═══════════════════════════════════════════════════════════════════

/// Stub provider that allowlists all IPs.
struct AllowlistStubProvider;

#[async_trait]
impl IpIntelligenceProvider for AllowlistStubProvider {
    async fn classify(&self, _ip: IpAddr) -> Result<Option<IpClassification>, IpIntelError> {
        Ok(Some(IpClassification {
            labels: vec![IpLabel::Allowed],
            risk_score: Some(0.0),
            source: "test_allowlist".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }))
    }
    async fn refresh(&self) -> Result<(), IpIntelError> {
        Ok(())
    }
    fn source_name(&self) -> &str {
        "test_allowlist"
    }
}

#[tokio::test]
async fn test_e2e_allowlist_overrides_tor_and_blocklist() {
    // IP is Tor exit + Blocklisted + Allowlisted.
    // Allowlist must win → all negative labels cleared → anomaly allows.
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("198.51.100.1\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![
            tor as Arc<dyn IpIntelligenceProvider>,
            Arc::new(BlocklistStubProvider),
            Arc::new(AllowlistStubProvider),
        ],
        no_cache(),
        Duration::from_secs(60),
    ));

    let policy = NetworkPolicy {
        block_tor: true,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, no_cache());

    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let classification = aggregator.classify(ip).await.unwrap();

    // Allowlist cleared all negative labels.
    assert!(
        !classification.is_tor_exit(),
        "tor_exit should be cleared by allowlist"
    );
    assert!(
        !classification.is_blocklisted(),
        "blocklisted should be cleared by allowlist"
    );
    assert!(classification.has_label(IpLabel::Allowed));
    assert_eq!(classification.risk_score, Some(0.0));

    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: classification.is_tor_exit(),
        is_datacenter_ip: classification.is_datacenter(),
        is_blocklisted: classification.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    // Allowlist won → no negative labels → Allow.
    assert_eq!(result.rule, "none");
    assert_eq!(result.reaction, RuleReaction::Allow);
}

// ═══════════════════════════════════════════════════════════════════
// CloudRangeProvider: datacenter IP → StepUp
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_cloud_range_ip_triggers_step_up() {
    // AWS IP range.
    let cloud = Arc::new(CloudRangeProvider::new(no_cache()));
    cloud.load_from_text("3.5.0.0/15\n52.0.0.0/11\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![cloud as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    ));

    // violation_reaction: StepUp (arch default for datacenter_ip).
    // NetworkPolicy default is Block; datacenter_ip rule delegates to violation_reaction.
    let policy = NetworkPolicy {
        block_datacenter_ips: true,
        violation_reaction: NetworkViolationReaction::StepUp,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, no_cache());

    // IP in AWS range.
    let ip = "3.5.1.1".parse::<IpAddr>().unwrap();
    let classification = aggregator.classify(ip).await.unwrap();

    assert!(
        classification.is_datacenter(),
        "IP should be classified as datacenter"
    );
    assert!(!classification.is_tor_exit());
    assert!(!classification.is_blocklisted());

    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: classification.is_tor_exit(),
        is_datacenter_ip: classification.is_datacenter(),
        is_blocklisted: classification.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "datacenter_ip");
    assert_eq!(result.reaction, RuleReaction::StepUp);
}

#[tokio::test]
async fn test_e2e_cloud_range_allows_when_policy_disabled() {
    let cloud = Arc::new(CloudRangeProvider::new(no_cache()));
    cloud.load_from_text("3.5.0.0/15\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![cloud as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    ));

    // block_datacenter_ips = false (default).
    let detector = AnomalyDetector::ce_default(no_cache());

    let ip = "3.5.1.1".parse::<IpAddr>().unwrap();
    let classification = aggregator.classify(ip).await.unwrap();
    assert!(classification.is_datacenter());

    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: classification.is_tor_exit(),
        is_datacenter_ip: classification.is_datacenter(),
        is_blocklisted: classification.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    // block_datacenter_ips=false → datacenter rule skipped → Allow.
    assert_eq!(result.reaction, RuleReaction::Allow);
}

// ═══════════════════════════════════════════════════════════════════
// FireholProvider: blocklisted IP → HardNo
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_firehol_blocklisted_ip_hard_no() {
    let firehol = Arc::new(FireholProvider::new(no_cache()));
    firehol.load_from_text("# FireHOL Level 1\n45.95.147.0/24\n185.220.100.0/24\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![firehol as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    ));

    let detector = AnomalyDetector::ce_default(no_cache());

    // IP in FireHOL blocklist.
    let ip = "45.95.147.10".parse::<IpAddr>().unwrap();
    let classification = aggregator.classify(ip).await.unwrap();

    assert!(classification.is_blocklisted(), "IP should be blocklisted");
    assert!(!classification.is_datacenter());

    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: classification.is_tor_exit(),
        is_datacenter_ip: classification.is_datacenter(),
        is_blocklisted: classification.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    // Blocklisted → HardNo (priority 1, absolute deny).
    assert_eq!(result.rule, "ip_blocklist");
    assert_eq!(result.reaction, RuleReaction::HardNo);
}

// ═══════════════════════════════════════════════════════════════════
// Full pipeline: Tor + Cloud + FireHOL together
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_full_pipeline_all_three_providers() {
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("198.51.100.1\n");

    let cloud = Arc::new(CloudRangeProvider::new(no_cache()));
    cloud.load_from_text("3.5.0.0/15\n");

    let firehol = Arc::new(FireholProvider::new(no_cache()));
    firehol.load_from_text("45.95.147.0/24\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![
            tor as Arc<dyn IpIntelligenceProvider>,
            cloud as Arc<dyn IpIntelligenceProvider>,
            firehol as Arc<dyn IpIntelligenceProvider>,
        ],
        no_cache(),
        Duration::from_secs(60),
    ));

    let policy = NetworkPolicy {
        block_tor: true,
        block_datacenter_ips: true,
        violation_reaction: NetworkViolationReaction::StepUp,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, no_cache());

    // Tor IP → StepUp (shares violation_reaction with datacenter).
    let tor_ip = "198.51.100.1".parse::<IpAddr>().unwrap();
    let class = aggregator.classify(tor_ip).await.unwrap();
    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(tor_ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: class.is_tor_exit(),
        is_datacenter_ip: class.is_datacenter(),
        is_blocklisted: class.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "tor_exit_node");
    assert_eq!(result.reaction, RuleReaction::StepUp);

    // Cloud IP → StepUp (priority 6).
    let cloud_ip = "3.5.1.1".parse::<IpAddr>().unwrap();
    let class = aggregator.classify(cloud_ip).await.unwrap();
    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(cloud_ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: class.is_tor_exit(),
        is_datacenter_ip: class.is_datacenter(),
        is_blocklisted: class.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "datacenter_ip");
    assert_eq!(result.reaction, RuleReaction::StepUp);

    // Firehol IP → HardNo (priority 1).
    let firehol_ip = "45.95.147.10".parse::<IpAddr>().unwrap();
    let class = aggregator.classify(firehol_ip).await.unwrap();
    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(firehol_ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: class.is_tor_exit(),
        is_datacenter_ip: class.is_datacenter(),
        is_blocklisted: class.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "ip_blocklist");
    assert_eq!(result.reaction, RuleReaction::HardNo);

    // Normal IP → Allow.
    let normal_ip = "192.168.1.1".parse::<IpAddr>().unwrap();
    let class = aggregator.classify(normal_ip).await.unwrap();
    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(normal_ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: class.is_tor_exit(),
        is_datacenter_ip: class.is_datacenter(),
        is_blocklisted: class.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };
    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "none");
    assert_eq!(result.reaction, RuleReaction::Allow);
}

// ═══════════════════════════════════════════════════════════════════
// IPv6 CIDR ranges: cloud provider classifies IPv6 datacenter IPs
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_cloud_range_ipv6_triggers_step_up() {
    let cloud = Arc::new(CloudRangeProvider::new(no_cache()));
    // GCP IPv6 range.
    cloud.load_from_text("2600:1900::/32\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![cloud as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    ));

    let policy = NetworkPolicy {
        block_datacenter_ips: true,
        violation_reaction: NetworkViolationReaction::StepUp,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, no_cache());

    // IPv6 inside GCP range.
    let ip: IpAddr = "2600:1900::1".parse().unwrap();
    let classification = aggregator.classify(ip).await.unwrap();
    assert!(
        classification.is_datacenter(),
        "IPv6 should be classified as datacenter"
    );

    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: classification.is_tor_exit(),
        is_datacenter_ip: classification.is_datacenter(),
        is_blocklisted: classification.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "datacenter_ip");
    assert_eq!(result.reaction, RuleReaction::StepUp);

    // IPv6 outside range → no classification.
    let outside: IpAddr = "2001:db8::1".parse().unwrap();
    let class = aggregator.classify(outside).await.unwrap();
    assert!(!class.is_datacenter());
}

// ═══════════════════════════════════════════════════════════════════
// Priority: blocklist (HardNo, P1) beats datacenter (StepUp, P6)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_blocklist_beats_datacenter_priority() {
    // Same CIDR in both cloud and firehol → IP is both Datacenter AND Blocklisted.
    let cloud = Arc::new(CloudRangeProvider::new(no_cache()));
    cloud.load_from_text("45.95.147.0/24\n");

    let firehol = Arc::new(FireholProvider::new(no_cache()));
    firehol.load_from_text("45.95.147.0/24\n");

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![
            cloud as Arc<dyn IpIntelligenceProvider>,
            firehol as Arc<dyn IpIntelligenceProvider>,
        ],
        no_cache(),
        Duration::from_secs(60),
    ));

    let policy = NetworkPolicy {
        block_datacenter_ips: true,
        violation_reaction: NetworkViolationReaction::StepUp,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, no_cache());

    let ip = "45.95.147.10".parse::<IpAddr>().unwrap();
    let classification = aggregator.classify(ip).await.unwrap();

    // Both labels present from aggregator.
    assert!(classification.is_datacenter());
    assert!(classification.is_blocklisted());

    let ctx = LoginContext {
        identity: "alice@sid.example.com".to_string(),
        ip: Some(ip),
        country: None,
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: classification.is_tor_exit(),
        is_datacenter_ip: classification.is_datacenter(),
        is_blocklisted: classification.is_blocklisted(),
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: None,
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    // Blocklist = priority 1 → HardNo. Beats datacenter = priority 6 → StepUp.
    assert_eq!(result.rule, "ip_blocklist");
    assert_eq!(result.reaction, RuleReaction::HardNo);
}

// ═══════════════════════════════════════════════════════════════════
// Empty providers: no data loaded → all IPs allowed (no false positives)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_empty_providers_allow_all() {
    // Providers registered but no data loaded (first start, no cache, no internet).
    let cloud = Arc::new(CloudRangeProvider::new(no_cache()));
    let firehol = Arc::new(FireholProvider::new(no_cache()));
    let tor = Arc::new(TorExitProvider::new(no_cache()));

    assert_eq!(cloud.range_count(), 0);
    assert_eq!(firehol.range_count(), 0);
    assert_eq!(tor.node_count(), 0);

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![
            tor as Arc<dyn IpIntelligenceProvider>,
            cloud as Arc<dyn IpIntelligenceProvider>,
            firehol as Arc<dyn IpIntelligenceProvider>,
        ],
        no_cache(),
        Duration::from_secs(60),
    ));

    let policy = NetworkPolicy {
        block_tor: true,
        block_datacenter_ips: true,
        ..NetworkPolicy::default()
    };
    let detector = AnomalyDetector::new(AnomalyConfig::default(), policy, no_cache());

    // Any IP should be allowed — empty providers have no opinion.
    for ip_str in &["198.51.100.1", "3.5.1.1", "45.95.147.10", "8.8.8.8"] {
        let ip: IpAddr = ip_str.parse().unwrap();
        let class = aggregator.classify(ip).await.unwrap();
        assert!(
            !class.is_tor_exit(),
            "empty provider should not classify {ip_str}"
        );
        assert!(
            !class.is_datacenter(),
            "empty provider should not classify {ip_str}"
        );
        assert!(
            !class.is_blocklisted(),
            "empty provider should not classify {ip_str}"
        );

        let ctx = LoginContext {
            identity: "test@sid.example.com".to_string(),
            ip: Some(ip),
            country: None,
            failed: false,
            new_device: false,
            new_ip: false,
            is_tor_exit: class.is_tor_exit(),
            is_datacenter_ip: class.is_datacenter(),
            is_blocklisted: class.is_blocklisted(),
            latitude: None,
            longitude: None,
            prev_latitude: None,
            prev_longitude: None,
            prev_login_at: None,
            prev_country: None,
            designated_countries: vec![],
        };
        let result = detector.evaluate(&ctx).await.unwrap();
        assert_eq!(
            result.reaction,
            RuleReaction::Allow,
            "empty providers should allow {ip_str}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// FireHOL refresh failure: unreachable URL → error, no crash
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_firehol_refresh_failure_reports_error() {
    let firehol = Arc::new(FireholProvider::with_url(
        no_cache(),
        "http://192.0.2.1:1/nonexistent".to_string(), // TEST-NET, unreachable
    ));

    let aggregator = IpIntelligenceAggregator::new(
        vec![firehol as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    );

    let results = aggregator.refresh_all().await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "firehol_level1");
    assert!(
        results[0].1.is_err(),
        "refresh should fail on unreachable URL"
    );
}
