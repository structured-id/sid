// SPDX-License-Identifier: AGPL-3.0-only
//! Device fingerprint + designated location integration tests (#589).
//!
//! Tests has_recent_session_from_device(), record_login_location(),
//! get_designated_countries() with real PostgreSQL (port 54399)
//! and the full pipeline: designated locations → impossible travel suppression.

mod common;

use sid_authn::anomaly::{AnomalyDetector, LoginContext, RuleReaction};
use sid_core::models::session::Session;
use sid_core::models::{AuditEntry, Profile, ProfileId};
use sid_plugin::cache::NoCacheBackend;
use sid_plugin::storage::StorageBackend;
use std::sync::Arc;
use std::time::Duration;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

/// The test database; an unreachable one fails the test instead of skipping it.
async fn setup_pg_storage() -> Option<Arc<dyn StorageBackend>> {
    let backend = sid_storage::PostgresBackend::new(&database_url(), None)
        .await
        .expect("test PostgreSQL on port 54399 (docker-compose.test.yml)");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("Failed to run migrations");
    Some(Arc::new(backend))
}

fn test_profile_id() -> ProfileId {
    ProfileId::generate()
}

/// Create a profile in DB and return its ID.
async fn create_test_profile(storage: &dyn StorageBackend) -> ProfileId {
    storage
        .ensure_system_project(AuditEntry::system("test", "setup").into())
        .await
        .expect("system project");
    let username = format!("testuser-{}", uuid::Uuid::now_v7());
    let profile = Profile::new(Some(&username));
    storage
        .create_profile(
            &profile,
            AuditEntry::system("test", "create_profile").into(),
        )
        .await
        .expect("save profile");
    profile.id
}

fn create_test_session_with_device(
    profile_id: ProfileId,
    ip: &str,
    device_id: Option<uuid::Uuid>,
) -> Session {
    let mut session = Session::new(
        profile_id,
        ip.to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.device_id = device_id;
    session
}

// ═══════════════════════════════════════════════════════════════════
// Device fingerprint: has_recent_session_from_device
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_pg_has_recent_session_from_device_no_sessions() {
    let storage = match setup_pg_storage().await {
        Some(s) => s,
        None => return,
    };
    let profile_id = test_profile_id();
    let device_id = uuid::Uuid::now_v7();
    let window = Duration::from_secs(90 * 24 * 3600);

    let found = storage
        .has_recent_session_from_device(profile_id, device_id, window)
        .await
        .expect("query should succeed");
    assert!(!found, "No sessions → device not found");
}

#[tokio::test]
async fn test_pg_has_recent_session_from_device_found() {
    let storage = match setup_pg_storage().await {
        Some(s) => s,
        None => return,
    };
    let profile_id = create_test_profile(storage.as_ref()).await;
    let device_id = uuid::Uuid::now_v7();

    // Create session with this device_id.
    let session = create_test_session_with_device(profile_id, "10.0.0.1", Some(device_id));
    storage
        .create_session_atomic(
            &session,
            0,
            AuditEntry::system("test", "create_session").into(),
        )
        .await
        .expect("session creation should succeed");

    let window = Duration::from_secs(90 * 24 * 3600);
    let found = storage
        .has_recent_session_from_device(profile_id, device_id, window)
        .await
        .expect("query should succeed");
    assert!(found, "Session with device_id exists → found");
}

#[tokio::test]
async fn test_pg_has_recent_session_from_device_different_profile() {
    let storage = match setup_pg_storage().await {
        Some(s) => s,
        None => return,
    };
    let profile_a = create_test_profile(storage.as_ref()).await;
    let profile_b = create_test_profile(storage.as_ref()).await;
    let device_id = uuid::Uuid::now_v7();

    // Create session for profile_a.
    let session = create_test_session_with_device(profile_a, "10.0.0.1", Some(device_id));
    storage
        .create_session_atomic(
            &session,
            0,
            AuditEntry::system("test", "create_session").into(),
        )
        .await
        .expect("session creation should succeed");

    // Check for profile_b → should NOT find it.
    let window = Duration::from_secs(90 * 24 * 3600);
    let found = storage
        .has_recent_session_from_device(profile_b, device_id, window)
        .await
        .expect("query should succeed");
    assert!(
        !found,
        "Different profile → device not found even with same device_id"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Designated locations: record_login_location + get_designated_countries
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_pg_record_login_location_builds_designation() {
    let storage = match setup_pg_storage().await {
        Some(s) => s,
        None => return,
    };
    let profile_id = create_test_profile(storage.as_ref()).await;

    // First login from RO → not designated yet (threshold=3).
    storage
        .record_login_location(profile_id, "RO", 44.43, 26.10, 3)
        .await
        .expect("record location should succeed");

    let designated = storage
        .get_designated_countries(profile_id)
        .await
        .expect("query should succeed");
    assert!(designated.is_empty(), "1 login → not designated yet");

    // Second login.
    storage
        .record_login_location(profile_id, "RO", 44.43, 26.10, 3)
        .await
        .expect("record location should succeed");

    let designated = storage
        .get_designated_countries(profile_id)
        .await
        .expect("query should succeed");
    assert!(designated.is_empty(), "2 logins → not designated yet");

    // Third login → designated!
    storage
        .record_login_location(profile_id, "RO", 44.43, 26.10, 3)
        .await
        .expect("record location should succeed");

    let designated = storage
        .get_designated_countries(profile_id)
        .await
        .expect("query should succeed");
    assert_eq!(designated, vec!["RO"], "3 logins → designated");
}

#[tokio::test]
async fn test_pg_designated_locations_per_profile_isolation() {
    let storage = match setup_pg_storage().await {
        Some(s) => s,
        None => return,
    };
    let profile_a = create_test_profile(storage.as_ref()).await;
    let profile_b = create_test_profile(storage.as_ref()).await;

    // Profile A: 3 logins from UA → designated.
    for _ in 0..3 {
        storage
            .record_login_location(profile_a, "UA", 50.45, 30.52, 3)
            .await
            .unwrap();
    }

    // Profile B: 1 login from UA → not designated.
    storage
        .record_login_location(profile_b, "UA", 50.45, 30.52, 3)
        .await
        .unwrap();

    let a_designated = storage.get_designated_countries(profile_a).await.unwrap();
    let b_designated = storage.get_designated_countries(profile_b).await.unwrap();

    assert_eq!(a_designated, vec!["UA"], "Profile A has UA designated");
    assert!(
        b_designated.is_empty(),
        "Profile B has no designated countries"
    );
}

#[tokio::test]
async fn test_pg_multiple_designated_countries() {
    let storage = match setup_pg_storage().await {
        Some(s) => s,
        None => return,
    };
    let profile_id = create_test_profile(storage.as_ref()).await;

    // 3 logins from UA and 3 from RO.
    for _ in 0..3 {
        storage
            .record_login_location(profile_id, "UA", 50.45, 30.52, 3)
            .await
            .unwrap();
        storage
            .record_login_location(profile_id, "RO", 44.43, 26.10, 3)
            .await
            .unwrap();
    }

    let mut designated = storage.get_designated_countries(profile_id).await.unwrap();
    designated.sort();
    assert_eq!(designated, vec!["RO", "UA"], "Both countries designated");
}

// ═══════════════════════════════════════════════════════════════════
// Full pipeline: designated locations → impossible travel suppression
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_pipeline_roaming_suppression() {
    // Simulate roaming: Kyiv (UA) → Bucharest (RO) in 5 seconds.
    // Both designated → location_switch (Allow).
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> = Arc::new(NoCacheBackend);
    let detector = AnomalyDetector::ce_default(cache);

    let ctx = LoginContext {
        identity: "roaming-user".to_string(),
        ip: Some("10.0.0.1".parse().unwrap()),
        country: Some("RO".to_string()),
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: false,
        is_datacenter_ip: false,
        is_blocklisted: false,
        latitude: Some(44.43), // Bucharest
        longitude: Some(26.10),
        prev_latitude: Some(50.45), // Kyiv
        prev_longitude: Some(30.52),
        prev_login_at: Some(chrono::Utc::now() - chrono::Duration::seconds(5)),
        prev_country: Some("UA".to_string()),
        designated_countries: vec!["UA".to_string(), "RO".to_string()],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "location_switch");
    assert_eq!(result.reaction, RuleReaction::Allow);
}

#[tokio::test]
async fn test_pipeline_new_country_not_suppressed() {
    // Same speed but destination is NOT designated → StepUp.
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> = Arc::new(NoCacheBackend);
    let detector = AnomalyDetector::ce_default(cache);

    let ctx = LoginContext {
        identity: "traveler".to_string(),
        ip: Some("10.0.0.2".parse().unwrap()),
        country: Some("BR".to_string()), // NOT designated
        failed: false,
        new_device: false,
        new_ip: false,
        is_tor_exit: false,
        is_datacenter_ip: false,
        is_blocklisted: false,
        latitude: Some(-23.55), // São Paulo
        longitude: Some(-46.63),
        prev_latitude: Some(50.45), // Kyiv
        prev_longitude: Some(30.52),
        prev_login_at: Some(chrono::Utc::now() - chrono::Duration::seconds(5)),
        prev_country: Some("UA".to_string()),
        designated_countries: vec!["UA".to_string(), "RO".to_string()],
    };

    let result = detector.evaluate(&ctx).await.unwrap();
    assert_eq!(result.rule, "impossible_travel");
    assert_eq!(result.reaction, RuleReaction::StepUp);
}
