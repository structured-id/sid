// SPDX-License-Identifier: AGPL-3.0-only
//! IP Reputation integration tests.
//!
//! Tests the full pipeline: record events → refresh provider → classify IPs.
//! Requires PostgreSQL on port 54399 (sid-test-postgres).

use sid_authn::anomaly::{AnomalyDetector, LoginContext, RuleReaction};
use sid_authn::ip_intelligence::{
    IpIntelligenceAggregator, IpIntelligenceProvider, SelfLearnedReputationProvider,
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

/// The test database; an unreachable one fails the test instead of skipping it.
async fn create_storage() -> Option<Arc<dyn StorageBackend>> {
    let backend = sid_storage::PostgresBackend::new(&database_url(), None)
        .await
        .expect("test PostgreSQL on port 54399 (docker-compose.test.yml)");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");

    // No global DELETE: each test uses its own address, so tests running in
    // parallel never clear each other's rows.
    Some(Arc::new(backend))
}

// ═══════════════════════════════════════════════════════════════════
// record → list pipeline (StorageBackend methods)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_record_failures_builds_reputation() {
    let storage = match create_storage().await {
        Some(s) => s,
        None => return,
    };

    // Use unique IP per run to avoid leftover data.
    let run_id = uuid::Uuid::now_v7();
    let octet = run_id.as_bytes()[0] % 200 + 1;
    let ip = format!("198.51.{octet}.99");

    // Record 10 failures and 1 success.
    for _ in 0..10 {
        storage
            .record_ip_reputation_event(&ip, false)
            .await
            .unwrap();
    }
    storage.record_ip_reputation_event(&ip, true).await.unwrap();

    // Score should be ~ 10 / (10 + 1 + 1) = 0.833
    let suspicious = storage.list_suspicious_ips(0.5, 100).await.unwrap();
    let found = suspicious.iter().find(|(s, _)| s == &ip);
    assert!(found.is_some(), "IP should be in suspicious list");
    let score = found.unwrap().1;
    assert!(
        score > 0.7,
        "score {score} should be > 0.7 with 10 failures vs 1 success"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_successes_reduce_score() {
    let storage = match create_storage().await {
        Some(s) => s,
        None => return,
    };

    let ip = "198.51.100.100";
    // Some failures first.
    for _ in 0..5 {
        storage.record_ip_reputation_event(ip, false).await.unwrap();
    }
    // Many successes.
    for _ in 0..20 {
        storage.record_ip_reputation_event(ip, true).await.unwrap();
    }

    // Score should be low: 5 / (5 + 20 + 1) ≈ 0.19
    let suspicious = storage.list_suspicious_ips(0.5, 100).await.unwrap();
    let found = suspicious.iter().find(|(s, _)| s == ip);
    assert!(
        found.is_none(),
        "IP with mostly successes should not be in suspicious list at 0.5 threshold"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_provider_refresh_loads_suspicious_ips() {
    let storage = match create_storage().await {
        Some(s) => s,
        None => return,
    };

    // Record failures to make IP suspicious.
    let ip = "198.51.100.101";
    for _ in 0..10 {
        storage.record_ip_reputation_event(ip, false).await.unwrap();
    }

    // Create provider and refresh.
    let provider = SelfLearnedReputationProvider::new(storage.clone(), 0.7);
    assert_eq!(provider.suspicious_count(), 0, "should start empty");

    provider.refresh().await.unwrap();
    assert!(
        provider.suspicious_count() > 0,
        "should have loaded suspicious IPs"
    );

    // Classify the suspicious IP.
    let classification = provider
        .classify(ip.parse::<IpAddr>().unwrap())
        .await
        .unwrap();
    assert!(
        classification.is_some(),
        "suspicious IP should be classified"
    );
    let c = classification.unwrap();
    assert_eq!(c.source, "self_learned");
    assert!(c.risk_score.unwrap() > 0.7);

    // Normal IP → not classified.
    assert!(
        provider
            .classify("8.8.8.8".parse::<IpAddr>().unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_provider_pipeline_to_anomaly_detector() {
    let storage = match create_storage().await {
        Some(s) => s,
        None => return,
    };

    // Record 15 failures.
    let ip = "198.51.100.102";
    for _ in 0..15 {
        storage.record_ip_reputation_event(ip, false).await.unwrap();
    }

    let provider = Arc::new(SelfLearnedReputationProvider::new(storage.clone(), 0.7));
    provider.refresh().await.unwrap();

    let aggregator = Arc::new(IpIntelligenceAggregator::new(
        vec![provider as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    ));

    let detector = AnomalyDetector::ce_default(no_cache());

    // Suspicious IP → classify → LoginContext → HardNo (ip_blocklist rule).
    let parsed_ip: IpAddr = ip.parse().unwrap();
    let classification = aggregator.classify(parsed_ip).await.unwrap();
    assert!(classification.is_blocklisted());

    let ctx = LoginContext {
        identity: "test@sid.example.com".to_string(),
        ip: Some(parsed_ip),
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
    assert_eq!(result.rule, "ip_blocklist");
    assert_eq!(result.reaction, RuleReaction::HardNo);
}

/// A reputation store that cannot be read fails the classification instead
/// of reading as "no score": the blocklist once let every IP through while
/// its store was down.
#[tokio::test]
async fn test_unreadable_reputation_store_fails_classification() {
    let backend = sid_storage::sqlite::SqliteBackend::new_in_memory()
        .await
        .unwrap();
    sqlx::query("DROP TABLE ip_reputation")
        .execute(backend.pool())
        .await
        .unwrap();
    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    let provider = Arc::new(SelfLearnedReputationProvider::new(storage, 0.7));
    let ip: IpAddr = "198.51.100.250".parse().unwrap();

    assert!(provider.classify(ip).await.is_err());
    let aggregator = IpIntelligenceAggregator::new(
        vec![provider as Arc<dyn IpIntelligenceProvider>],
        no_cache(),
        Duration::from_secs(60),
    );
    assert!(aggregator.classify(ip).await.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// Per-call DB query (async classify())
// ═══════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_classify_without_refresh_uses_per_call_db_query() {
    let storage = match create_storage().await {
        Some(s) => s,
        None => return,
    };

    // Record 10 failures for an IP.
    let ip = "198.51.100.200";
    for _ in 0..10 {
        storage.record_ip_reputation_event(ip, false).await.unwrap();
    }

    // Create provider but DO NOT call refresh().
    // In-memory cache is empty — classify must use per-call DB query.
    let provider = SelfLearnedReputationProvider::new(storage.clone(), 0.7);
    assert_eq!(
        provider.suspicious_count(),
        0,
        "in-memory cache should be empty (no refresh)"
    );

    // classify() should still find the IP via per-call DB query.
    let classification = provider
        .classify(ip.parse::<IpAddr>().unwrap())
        .await
        .unwrap();
    assert!(
        classification.is_some(),
        "classify() should find IP via per-call DB query without refresh()"
    );

    let c = classification.unwrap();
    assert_eq!(c.source, "self_learned");
    assert!(c.risk_score.unwrap() > 0.7, "score should exceed threshold");
    assert_eq!(
        c.labels,
        vec![sid_authn::ip_intelligence::IpLabel::Blocklisted]
    );

    // Unknown IP → None even via DB query.
    assert!(
        provider
            .classify("8.8.8.8".parse::<IpAddr>().unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_classify_below_threshold_returns_none() {
    let storage = match create_storage().await {
        Some(s) => s,
        None => return,
    };

    // Record mostly successes — score will be below threshold.
    let ip = "198.51.100.201";
    for _ in 0..2 {
        storage.record_ip_reputation_event(ip, false).await.unwrap();
    }
    for _ in 0..20 {
        storage.record_ip_reputation_event(ip, true).await.unwrap();
    }
    // Score ≈ 2 / (2 + 20 + 1) ≈ 0.087 — below 0.7 threshold.

    let provider = SelfLearnedReputationProvider::new(storage.clone(), 0.7);

    // classify() queries DB but score is below threshold → None.
    let classification = provider
        .classify(ip.parse::<IpAddr>().unwrap())
        .await
        .unwrap();
    assert!(
        classification.is_none(),
        "IP with low score should not be classified as suspicious"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_get_ip_reputation_score() {
    let storage = match create_storage().await {
        Some(s) => s,
        None => return,
    };

    // Unknown IP → None (unique IP per run to avoid leftover DB data).
    let run_id = uuid::Uuid::now_v7();
    let unknown_ip = format!("198.51.{}.250", run_id.as_bytes()[0] % 200 + 1);
    let score = storage.get_ip_reputation_score(&unknown_ip).await.unwrap();
    assert!(
        score.is_none(),
        "unknown IP should return None, got {:?}",
        score
    );

    // Record failures and check score (unique IP per run).
    let test_ip = format!("198.51.{}.251", run_id.as_bytes()[1] % 200 + 1);
    for _ in 0..10 {
        storage
            .record_ip_reputation_event(&test_ip, false)
            .await
            .unwrap();
    }

    let score = storage.get_ip_reputation_score(&test_ip).await.unwrap();
    assert!(score.is_some(), "IP with events should have a score");
    // Score = 10 / (10 + 0 + 1) ≈ 0.909
    assert!(
        score.unwrap() > 0.9,
        "10 failures, 0 successes → score > 0.9"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_decay_reduces_scores() {
    let backend = sid_storage::PostgresBackend::new(&database_url(), None)
        .await
        .expect("test PostgreSQL on port 54399 (docker-compose.test.yml)");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");
    // Use fully unique IP: all 16 UUID bytes, to avoid collision with stale DB data.
    let run_id = uuid::Uuid::now_v7();
    let bytes = run_id.as_bytes();
    let ip = format!("203.0.{}.{}", bytes[14], bytes[15]);
    // The harness ages rows directly: no operation backdates them.
    let pool = backend.pool().clone();
    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    let backdate = || async {
        sqlx::query(
            "UPDATE ip_reputation SET updated_at = NOW() - INTERVAL '1 hour' WHERE ip = $1",
        )
        .bind(&ip)
        .execute(&pool)
        .await
        .unwrap();
    };

    sqlx::query("DELETE FROM ip_reputation WHERE ip = $1")
        .bind(&ip)
        .execute(&pool)
        .await
        .unwrap();

    // Record failures.
    for _ in 0..10 {
        storage
            .record_ip_reputation_event(&ip, false)
            .await
            .unwrap();
    }

    // Verify suspicious.
    let suspicious = storage.list_suspicious_ips(0.7, 100).await.unwrap();
    assert!(
        suspicious.iter().any(|(s, _)| s == &ip),
        "should be suspicious before decay"
    );

    // Backdate updated_at so decay considers these records stale.
    backdate().await;

    // Multiple decay cycles (older_than=1s, records are 1h old → captured).
    for i in 0..4u32 {
        storage
            .decay_ip_reputation(Duration::from_secs(1))
            .await
            .unwrap();
        // Backdate again so next decay captures the updated record.
        if i < 3 {
            backdate().await;
        }
    }
    // After 4 decays: 10→5→2→1→0, score = 0/(0+0+1) = 0.0, then DELETE.

    let suspicious = storage.list_suspicious_ips(0.7, 100).await.unwrap();
    let found = suspicious.iter().find(|(s, _)| s == &ip);
    assert!(
        found.is_none(),
        "IP should drop below threshold after decay"
    );
}
