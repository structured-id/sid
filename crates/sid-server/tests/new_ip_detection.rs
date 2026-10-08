// SPDX-License-Identifier: AGPL-3.0-only
//! new_ip detection integration tests (#588).
//!
//! Tests has_recent_session_from_ip() with real PostgreSQL (port 54399)
//! and the full pipeline: session history → LoginContext.new_ip → anomaly rule.

mod common;

use sid_authn::anomaly::{AnomalyDetector, LoginContext, RuleReaction};
use sid_core::models::session::Session;
use sid_core::models::{AuditEntry, ProfileId};
use sid_plugin::cache::NoCacheBackend;
use sid_plugin::storage::StorageBackend;
use std::sync::Arc;
use std::time::Duration;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

async fn setup_pg_storage() -> Arc<dyn StorageBackend> {
    let backend = sid_storage::PostgresBackend::new(&database_url(), None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("Failed to run migrations");
    Arc::new(backend)
}

fn test_profile_id() -> ProfileId {
    ProfileId::generate()
}

fn create_test_session(profile_id: ProfileId, ip: &str) -> Session {
    Session::new(
        profile_id,
        ip.to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
}

// ═══════════════════════════════════════════════════════════════════
// PostgreSQL integration tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_has_recent_session_from_ip_no_sessions() {
    let storage = setup_pg_storage().await;

    let profile_id = test_profile_id();
    let window = Duration::from_secs(90 * 24 * 3600); // 90 days

    // No sessions at all → IP is new.
    let result = storage
        .has_recent_session_from_ip(profile_id, "192.168.1.1", window)
        .await
        .unwrap();
    assert!(!result, "no sessions → IP should be new");
}

#[tokio::test]
async fn test_has_recent_session_from_ip_found() {
    let storage = setup_pg_storage().await;

    let profile_id = test_profile_id();
    let window = Duration::from_secs(90 * 24 * 3600);

    // Create a profile + session with this IP.
    // The whole id: a UUIDv7 prefix is a timestamp and repeats across tests.
    let mut profile =
        sid_core::models::profile::Profile::new(Some(format!("newip-found-{profile_id}")));
    profile.id = profile_id;
    storage
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let session = create_test_session(profile_id, "10.0.0.42");
    storage
        .create_session_atomic(&session, 100, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Same IP → should be found (not new).
    let result = storage
        .has_recent_session_from_ip(profile_id, "10.0.0.42", window)
        .await
        .unwrap();
    assert!(result, "same IP should be found in session history");

    // Different IP → should NOT be found (new).
    let result = storage
        .has_recent_session_from_ip(profile_id, "10.0.0.99", window)
        .await
        .unwrap();
    assert!(!result, "different IP should not be found");
}

#[tokio::test]
async fn test_has_recent_session_different_profiles_independent() {
    let storage = setup_pg_storage().await;

    let window = Duration::from_secs(90 * 24 * 3600);

    // Profile A has a session from 10.0.0.1.
    let profile_a = test_profile_id();
    let mut pa = sid_core::models::profile::Profile::new(Some(format!("newip-a-{profile_a}")));
    pa.id = profile_a;
    storage
        .create_profile(&pa, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let sa = create_test_session(profile_a, "10.0.0.1");
    storage
        .create_session_atomic(&sa, 100, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Profile B should NOT see profile A's IP.
    let profile_b = test_profile_id();
    let result = storage
        .has_recent_session_from_ip(profile_b, "10.0.0.1", window)
        .await
        .unwrap();
    assert!(!result, "profile B should not see profile A's sessions");
}

// ═══════════════════════════════════════════════════════════════════
// Pipeline test: new_ip → anomaly rule
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_new_ip_true_triggers_step_up_with_new_device() {
    // new_device_ip rule requires BOTH new_device=true AND new_ip=true, for a
    // profile that has signed in before (prev_login_at).
    let cache = Arc::new(NoCacheBackend);
    let detector = AnomalyDetector::ce_default(cache);

    let ctx = LoginContext {
        identity: "test-user".to_string(),
        ip: Some("10.0.0.1".parse().unwrap()),
        country: None,
        failed: false,
        new_device: true,
        new_ip: true, // <-- now populated from has_recent_session_from_ip
        is_tor_exit: false,
        is_datacenter_ip: false,
        is_blocklisted: false,
        latitude: None,
        longitude: None,
        prev_latitude: None,
        prev_longitude: None,
        prev_login_at: Some(chrono::Utc::now() - chrono::Duration::days(1)),
        prev_country: None,
        designated_countries: vec![],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "new_device_ip");
    assert_eq!(result.reaction, RuleReaction::StepUp);
}

#[tokio::test]
async fn test_new_ip_true_but_known_device_allows() {
    // new_device=false, new_ip=true → rule does NOT fire (needs both).
    let cache = Arc::new(NoCacheBackend);
    let detector = AnomalyDetector::ce_default(cache);

    let ctx = LoginContext {
        identity: "test-user".to_string(),
        ip: Some("10.0.0.1".parse().unwrap()),
        country: None,
        failed: false,
        new_device: false, // Known device
        new_ip: true,      // New IP
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
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_known_ip_allows() {
    // Both false → no anomaly.
    let cache = Arc::new(NoCacheBackend);
    let detector = AnomalyDetector::ce_default(cache);

    let ctx = LoginContext {
        identity: "test-user".to_string(),
        ip: Some("10.0.0.1".parse().unwrap()),
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
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.reaction, RuleReaction::Allow);
}
