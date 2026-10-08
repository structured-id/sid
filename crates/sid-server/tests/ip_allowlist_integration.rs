// SPDX-License-Identifier: AGPL-3.0-only
//! IP Allowlist integration tests.
//!
//! Tests AllowlistProvider with real PostgreSQL and admin gRPC handlers.
//! Requires PostgreSQL on port 54399 (sid-test-postgres).

use sid_authn::anomaly::{AnomalyDetector, LoginContext, RuleReaction};
use sid_authn::ip_intelligence::{
    AllowlistProvider, IpIntelligenceAggregator, IpIntelligenceProvider, TorExitProvider,
};
use sid_plugin::cache::NoCacheBackend;
use sid_plugin::storage::StorageBackend;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

fn no_cache() -> Arc<dyn sid_plugin::cache::CacheBackend> {
    Arc::new(NoCacheBackend)
}

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

async fn create_storage() -> Arc<dyn StorageBackend> {
    let backend = sid_storage::PostgresBackend::new(&database_url(), None)
        .await
        .expect("PostgreSQL on port 54399 (docker-compose.test.yml)");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");

    // No global DELETE — tests use unique CIDRs to avoid parallel interference.
    Arc::new(backend)
}

/// Two random octets, so concurrently running tests pick different networks
/// (the leading bytes of a UUIDv7 are a timestamp every test shares).
fn random_octets() -> (u8, u8) {
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    (bytes[0], bytes[1])
}

// ═══════════════════════════════════════════════════════════════════
// StorageBackend CRUD
// ═══════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_allowlist_add_and_list() {
    let storage = create_storage().await;

    // Add entries (unique CIDRs per run to avoid parallel test interference).
    let (a, b) = random_octets();
    let cidr1 = format!("10.{a}.{b}.0/24");
    let cidr2 = format!("10.{a}.{b}.128/25");
    storage
        .add_ip_allowlist_entry(&cidr1, "Office VPN")
        .await
        .unwrap();
    storage
        .add_ip_allowlist_entry(&cidr2, "Home network")
        .await
        .unwrap();

    // List — check our entries exist (other parallel tests may add more).
    let entries = storage.list_ip_allowlist_entries().await.unwrap();
    assert!(
        entries.len() >= 2,
        "expected at least 2 entries, got {}",
        entries.len()
    );
    assert!(
        entries
            .iter()
            .any(|(c, d, _)| c == &cidr1 && d == "Office VPN")
    );
    assert!(
        entries
            .iter()
            .any(|(c, d, _)| c == &cidr2 && d == "Home network")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_allowlist_upsert_updates_description() {
    let storage = create_storage().await;

    // Use unique CIDR to avoid parallel test interference
    let cidr = "192.168.200.0/24";
    storage
        .add_ip_allowlist_entry(cidr, "Old description")
        .await
        .unwrap();
    storage
        .add_ip_allowlist_entry(cidr, "New description")
        .await
        .unwrap();

    let entries = storage.list_ip_allowlist_entries().await.unwrap();
    let found = entries.iter().find(|(c, _, _)| c == cidr);
    assert!(found.is_some(), "upserted entry not found");
    assert_eq!(found.unwrap().1, "New description");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_allowlist_remove() {
    let storage = create_storage().await;

    // Use unique CIDRs to avoid parallel test interference
    let keep = "192.168.201.0/24";
    let remove = "192.168.202.0/24";
    storage.add_ip_allowlist_entry(remove, "VPN").await.unwrap();
    storage
        .add_ip_allowlist_entry(keep, "Internal")
        .await
        .unwrap();

    storage.remove_ip_allowlist_entry(remove).await.unwrap();

    let entries = storage.list_ip_allowlist_entries().await.unwrap();
    assert!(
        entries.iter().any(|(c, _, _)| c == keep),
        "kept entry missing"
    );
    assert!(
        !entries.iter().any(|(c, _, _)| c == remove),
        "removed entry still present"
    );
}

// ═══════════════════════════════════════════════════════════════════
// AllowlistProvider: refresh from DB → classify
// ═══════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_allowlist_provider_refresh_and_classify() {
    let storage = create_storage().await;

    // Use unique CIDRs per run.
    let (a, b) = random_octets();
    let cidr = format!("172.{}.{b}.0/24", 16 + a % 16);
    let single_ip = format!("198.51.{a}.{b}");

    storage
        .add_ip_allowlist_entry(&cidr, "Office")
        .await
        .unwrap();
    storage
        .add_ip_allowlist_entry(&single_ip, "Admin workstation")
        .await
        .unwrap();

    // Create provider and refresh.
    let provider = AllowlistProvider::new(storage.clone());
    provider.refresh().await.unwrap();
    assert!(provider.entry_count() > 0);

    // Classify: in allowlist → Allowed.
    let test_ip: IpAddr = format!("172.{}.{b}.1", 16 + a % 16).parse().unwrap();
    let c = provider.classify(test_ip).await.unwrap().unwrap();
    assert_eq!(c.source, "admin_allowlist");
    assert_eq!(c.risk_score, Some(0.0));

    // Single IP entry.
    assert!(
        provider
            .classify(single_ip.parse::<IpAddr>().unwrap())
            .await
            .unwrap()
            .is_some()
    );

    // Not in allowlist → None.
    assert!(
        provider
            .classify("8.8.8.8".parse::<IpAddr>().unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

// ═══════════════════════════════════════════════════════════════════
// Full pipeline: allowlist overrides Tor in anomaly detection
// ═══════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_allowlist_overrides_tor_in_pipeline() {
    let storage = create_storage().await;

    // IP is both a Tor exit AND allowlisted.
    let tor = Arc::new(TorExitProvider::new(no_cache()));
    tor.load_from_text("10.0.0.1\n");

    storage
        .add_ip_allowlist_entry("10.0.0.0/8", "Trusted VPN")
        .await
        .unwrap();
    let allowlist = Arc::new(AllowlistProvider::new(storage.clone()));
    allowlist.refresh().await.unwrap();

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![
            tor as Arc<dyn IpIntelligenceProvider>,
            allowlist as Arc<dyn IpIntelligenceProvider>,
        ],
        no_cache(),
        Duration::from_secs(60),
    ));

    let policy = sid_core::models::security_policy::NetworkPolicy {
        block_tor: true,
        ..Default::default()
    };
    let detector = AnomalyDetector::new(
        sid_authn::anomaly::AnomalyConfig::default(),
        policy,
        no_cache(),
    );

    // Classify: allowlist wins over Tor.
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let classification = aggregator.classify(ip).await.unwrap();
    assert!(
        !classification.is_tor_exit(),
        "allowlist should clear tor_exit"
    );
    assert!(classification.has_label(sid_authn::ip_intelligence::IpLabel::Allowed));

    // AnomalyDetector: should Allow (not Block for Tor).
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
    assert_eq!(
        result.reaction,
        RuleReaction::Allow,
        "allowlisted IP should be allowed"
    );
}
