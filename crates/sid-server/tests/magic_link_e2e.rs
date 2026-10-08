// SPDX-License-Identifier: AGPL-3.0-only
//! Magic link end-to-end tests with real PostgreSQL.
//!
//! Tests the full magic link lifecycle: generation → storage → redemption
//! → single-use enforcement → expiry → rate limiting → cleanup.
//!
//! Requires sid-test-postgres on port 54399.

mod common;

use sid_authn::magic_link::{MagicLinkService, MagicLinkVerifyResult};
use sid_core::models::{AuditEntry, MagicLinkSession};
use sid_plugin::StorageBackend;
use sid_storage::PostgresBackend;
use std::sync::Arc;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

/// An address no other run has used: the test database outlives a run, and an
/// unconsumed link from an earlier run counts against the per-address limit.
fn unique_email(tag: &str) -> String {
    format!("{tag}-{}@sid.example.com", uuid::Uuid::now_v7().simple())
}

async fn setup() -> (MagicLinkService, Arc<dyn StorageBackend>) {
    let backend = PostgresBackend::new(&database_url(), None)
        .await
        .expect("Failed to connect to PostgreSQL. Is sid-test-postgres running?");

    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("Failed to run migrations");

    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    let service = MagicLinkService::new(storage.clone());
    (service, storage)
}

#[tokio::test]
async fn test_magic_link_happy_path() {
    let (service, _storage) = setup().await;
    let email = unique_email("alice-ml-test");

    // Generate magic link.
    let (result, token) = service
        .request_magic_link(&email)
        .await
        .expect("request_magic_link should succeed");

    assert!(!token.is_empty(), "token should be non-empty");
    assert!(
        result.expires_in_seconds > 0,
        "expires_in should be positive"
    );

    // Verify with correct token.
    let verify_result = service
        .verify_magic_link(result.session_id, &token)
        .await
        .unwrap();

    match verify_result {
        MagicLinkVerifyResult::Success { email: verified } => {
            assert_eq!(verified, email);
        }
        other => panic!("expected Success, got {:?}", other),
    }
}

#[tokio::test]
async fn test_magic_link_single_use_enforcement() {
    let (service, _storage) = setup().await;

    let (result, token) = service
        .request_magic_link(&unique_email("bob-ml-single"))
        .await
        .unwrap();

    // First verify succeeds.
    let first = service
        .verify_magic_link(result.session_id, &token)
        .await
        .unwrap();
    assert!(
        matches!(first, MagicLinkVerifyResult::Success { .. }),
        "first verify should succeed"
    );

    // Second verify with same token → AlreadyConsumed.
    let second = service
        .verify_magic_link(result.session_id, &token)
        .await
        .unwrap();
    assert!(
        matches!(second, MagicLinkVerifyResult::AlreadyConsumed),
        "second verify should be AlreadyConsumed, got {:?}",
        second
    );
}

#[tokio::test]
async fn test_magic_link_invalid_token() {
    let (service, _storage) = setup().await;

    let (result, _token) = service
        .request_magic_link(&unique_email("carol-ml-invalid"))
        .await
        .unwrap();

    // Verify with wrong token.
    let verify = service
        .verify_magic_link(result.session_id, "wrong-token-value")
        .await
        .unwrap();

    assert!(
        matches!(verify, MagicLinkVerifyResult::InvalidToken),
        "wrong token should be InvalidToken, got {:?}",
        verify
    );
}

#[tokio::test]
async fn test_magic_link_session_not_found() {
    let (service, _storage) = setup().await;

    let verify = service
        .verify_magic_link(uuid::Uuid::now_v7(), "any-token")
        .await
        .unwrap();

    assert!(
        matches!(verify, MagicLinkVerifyResult::SessionNotFound),
        "random UUID should be SessionNotFound, got {:?}",
        verify
    );
}

#[tokio::test]
async fn test_magic_link_expired() {
    let (_service, storage) = setup().await;

    // Create a session that's already expired (manually, bypassing service).
    let expired_session = MagicLinkSession {
        id: uuid::Uuid::now_v7(),
        email: "dave-ml-expired@sid.example.com".to_string(),
        token_hash: "$argon2id$v=19$m=19456,t=2,p=1$fake$fakehash".to_string(),
        consumed: false,
        created_at: chrono::Utc::now() - chrono::Duration::hours(1),
        expires_at: chrono::Utc::now() - chrono::Duration::minutes(1), // expired 1 min ago
    };

    storage
        .create_magic_link_session(&expired_session, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    // Create a fresh service and verify.
    let service = MagicLinkService::new(storage.clone());
    let verify = service
        .verify_magic_link(expired_session.id, "any-token")
        .await
        .unwrap();

    assert!(
        matches!(verify, MagicLinkVerifyResult::Expired),
        "expired session should be Expired, got {:?}",
        verify
    );
}

#[tokio::test]
async fn test_magic_link_rate_limiting() {
    let (service, _storage) = setup().await;
    // Use unique email per run to avoid leftover sessions from previous test runs
    // (test DB persists within container lifetime).
    let email = unique_email("eve-ml-rate");

    // Request 3 magic links (should succeed — rate limit is 3).
    for i in 0..3 {
        let result = service.request_magic_link(&email).await;
        assert!(
            result.is_ok(),
            "request {} should succeed, got {:?}",
            i + 1,
            result.err()
        );
    }

    // 4th request should be rate-limited.
    let fourth = service.request_magic_link(&email).await;
    assert!(
        fourth.is_err(),
        "4th request should be rate-limited, got Ok"
    );

    let err = fourth.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("rate") || err_str.contains("Rate") || err_str.contains("limit"),
        "error should mention rate limit, got: {}",
        err_str
    );
}

#[tokio::test]
async fn test_magic_link_cleanup_removes_expired() {
    let (_service, storage) = setup().await;

    // Create an expired session.
    let expired = MagicLinkSession {
        id: uuid::Uuid::now_v7(),
        email: "frank-ml-cleanup@sid.example.com".to_string(),
        token_hash: "hash".to_string(),
        consumed: false,
        created_at: chrono::Utc::now() - chrono::Duration::hours(2),
        expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
    };
    storage
        .create_magic_link_session(&expired, AuditEntry::system("test", "test").into())
        .await
        .unwrap();

    // Verify it exists.
    let found = storage.get_magic_link_session(expired.id).await.unwrap();
    assert!(found.is_some(), "session should exist before cleanup");

    // Run cleanup.
    let service = MagicLinkService::new(storage.clone());
    let cleaned = service.cleanup().await.unwrap();
    assert!(cleaned >= 1, "should clean at least 1 expired session");

    // Verify it's gone.
    let after = storage.get_magic_link_session(expired.id).await.unwrap();
    assert!(
        after.is_none(),
        "expired session should be removed after cleanup"
    );
}

#[tokio::test]
async fn test_magic_link_token_uniqueness() {
    let (service, _storage) = setup().await;

    let (_, token1) = service
        .request_magic_link(&unique_email("grace-ml-unique1"))
        .await
        .unwrap();
    let (_, token2) = service
        .request_magic_link(&unique_email("grace-ml-unique2"))
        .await
        .unwrap();

    assert_ne!(token1, token2, "each magic link should have a unique token");
}
