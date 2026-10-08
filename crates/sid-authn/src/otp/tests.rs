// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_plugin::cache::{CacheError, CacheResult, InMemoryCacheBackend};
use tokio::sync::mpsc;

fn shared() -> Arc<dyn CacheBackend> {
    Arc::new(InMemoryCacheBackend::new())
}

fn service() -> OtpService {
    OtpService::new(shared())
}

/// A cache that cannot answer anything.
struct DownCache;

#[async_trait::async_trait]
impl CacheBackend for DownCache {
    async fn get(&self, _: &str) -> CacheResult<Option<Vec<u8>>> {
        Err(CacheError::Connection("down".into()))
    }
    async fn set(&self, _: &str, _: &[u8], _: Duration) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
    async fn delete(&self, _: &str) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
    async fn take(&self, _: &str) -> CacheResult<Option<Vec<u8>>> {
        Err(CacheError::Connection("down".into()))
    }
    async fn incr(&self, _: &str, _: Duration) -> CacheResult<u64> {
        Err(CacheError::Connection("down".into()))
    }
    async fn publish(&self, _: &str, _: &[u8]) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
    async fn subscribe(&self, _: &str) -> CacheResult<mpsc::UnboundedReceiver<Vec<u8>>> {
        Err(CacheError::Connection("down".into()))
    }
    async fn health_check(&self) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
}

#[test]
fn test_generate_otp_code_length() {
    let code = generate_otp_code();
    assert_eq!(code.len(), OTP_CODE_LENGTH as usize);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn test_generate_otp_code_randomness() {
    let c1 = generate_otp_code();
    let c2 = generate_otp_code();
    // Extremely unlikely to be equal
    assert_ne!(c1, c2);
}

#[test]
fn test_hash_and_verify_code() {
    let code = "12345678";
    let hash = hash_code(code).unwrap();
    assert!(verify_code(code, &hash));
    assert!(!verify_code("87654321", &hash));
}

#[test]
fn test_otp_code_zero_padded() {
    // Verify that codes are always 8 digits even if numeric value is small
    for _ in 0..20 {
        let code = generate_otp_code();
        assert_eq!(code.len(), 8, "code '{}' is not 8 digits", code);
    }
}

#[tokio::test]
async fn test_request_otp_returns_code_and_session() {
    let service = service();
    let (result, code) = service.request_otp("alice@example.com").await.unwrap();

    assert_eq!(code.len(), 8);
    assert_eq!(result.code_length, 8);
    assert_eq!(result.expires_in_seconds, 600);
    assert_eq!(result.resend_available_in, 120);
}

#[tokio::test]
async fn test_verify_otp_success_consumes_the_code() {
    let service = service();
    let (result, code) = service.request_otp("alice@example.com").await.unwrap();

    match service.verify_otp(&result.session_id, &code).await.unwrap() {
        OtpVerifyResult::Success { target } => assert_eq!(target, "alice@example.com"),
        other => panic!("expected Success, got {other:?}"),
    }
    assert!(matches!(
        service.verify_otp(&result.session_id, &code).await.unwrap(),
        OtpVerifyResult::SessionNotFound
    ));
}

#[tokio::test]
async fn test_verify_otp_wrong_code_then_limit() {
    let service = service();
    let (result, code) = service.request_otp("alice@example.com").await.unwrap();

    for expected in (1..=4).rev() {
        match service
            .verify_otp(&result.session_id, "00000000")
            .await
            .unwrap()
        {
            OtpVerifyResult::InvalidCode { remaining_attempts } => {
                assert_eq!(remaining_attempts, expected)
            }
            other => panic!("expected InvalidCode, got {other:?}"),
        }
    }
    assert!(matches!(
        service
            .verify_otp(&result.session_id, "00000000")
            .await
            .unwrap(),
        OtpVerifyResult::MaxAttempts
    ));
    // The session is gone: not even the right code works now.
    assert!(matches!(
        service.verify_otp(&result.session_id, &code).await.unwrap(),
        OtpVerifyResult::SessionNotFound
    ));
}

#[tokio::test]
async fn test_verify_otp_session_not_found() {
    assert!(matches!(
        service()
            .verify_otp(&Uuid::now_v7(), "12345678")
            .await
            .unwrap(),
        OtpVerifyResult::SessionNotFound
    ));
}

/// Two replicas share one attempt count: guesses spread across them stop at
/// the limit, and a later right guess on the first replica is refused (each
/// replica once kept its own count, allowing five guesses per replica).
#[tokio::test]
async fn attempt_limit_holds_across_replicas() {
    let cache = shared();
    let a = OtpService::new(cache.clone());
    let b = OtpService::new(cache);
    let (result, code) = a.request_otp("x@example.com").await.unwrap();
    for _ in 0..4 {
        a.verify_otp(&result.session_id, "00000000").await.unwrap();
    }
    assert!(matches!(
        b.verify_otp(&result.session_id, "00000000").await.unwrap(),
        OtpVerifyResult::MaxAttempts
    ));
    assert!(
        !matches!(
            a.verify_otp(&result.session_id, &code).await.unwrap(),
            OtpVerifyResult::Success { .. }
        ),
        "a sixth guess was accepted after the limit"
    );
}

/// A code requested on one replica is verified on another.
#[tokio::test]
async fn code_verifies_on_another_replica() {
    let cache = shared();
    let a = OtpService::new(cache.clone());
    let b = OtpService::new(cache);
    let (result, code) = a.request_otp("y@example.com").await.unwrap();
    assert_eq!(
        b.get_session_target(&result.session_id).await.unwrap(),
        Some("y@example.com".to_string())
    );
    assert!(matches!(
        b.verify_otp(&result.session_id, &code).await.unwrap(),
        OtpVerifyResult::Success { .. }
    ));
}

/// Of concurrent verifications of the right code, exactly one signs in.
#[tokio::test]
async fn right_code_signs_in_once_under_concurrency() {
    let cache = shared();
    let a = Arc::new(OtpService::new(cache.clone()));
    let b = Arc::new(OtpService::new(cache));
    let (result, code) = a.request_otp("z@example.com").await.unwrap();
    let (ra, rb) = tokio::join!(
        a.verify_otp(&result.session_id, &code),
        b.verify_otp(&result.session_id, &code)
    );
    let successes = [ra.unwrap(), rb.unwrap()]
        .iter()
        .filter(|r| matches!(r, OtpVerifyResult::Success { .. }))
        .count();
    assert_eq!(successes, 1);
}

/// An expired code is reported as expired and ends its session.
#[tokio::test]
async fn expired_code_is_refused() {
    let cache = shared();
    let service = OtpService::new(cache.clone());
    let (result, code) = service.request_otp("old@example.com").await.unwrap();
    // Age the stored session past its expiry.
    let key = session_key(&result.session_id);
    let mut session: CachedOtpSession =
        serde_json::from_slice(&cache.get(&key).await.unwrap().unwrap()).unwrap();
    session.expires_at = Utc::now() - chrono::Duration::seconds(1);
    cache
        .set(&key, &serde_json::to_vec(&session).unwrap(), OTP_RETENTION)
        .await
        .unwrap();

    assert!(matches!(
        service.verify_otp(&result.session_id, &code).await.unwrap(),
        OtpVerifyResult::Expired
    ));
    assert!(matches!(
        service.verify_otp(&result.session_id, &code).await.unwrap(),
        OtpVerifyResult::SessionNotFound
    ));
}

/// Without a cache nothing passes: requests and verifications are errors, so
/// neither the request limit nor the attempt limit can fail open.
#[tokio::test]
async fn unreachable_cache_fails_closed() {
    let service = OtpService::new(Arc::new(DownCache));
    assert!(matches!(
        service.request_otp("down@example.com").await,
        Err(OtpError::Internal(_))
    ));
    assert!(matches!(
        service.verify_otp(&Uuid::now_v7(), "12345678").await,
        Err(OtpError::Internal(_))
    ));
}

#[tokio::test]
async fn test_rate_limiting() {
    let service = service();
    let target = "ratelimit@example.com";
    for _ in 0..3 {
        assert!(service.request_otp(target).await.is_ok());
    }
    match service.request_otp(target).await {
        Err(OtpError::RateLimited { wait_seconds }) => {
            assert!(wait_seconds > 0);
            assert!(wait_seconds <= 900);
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

/// The request limit is shared too: requests spread over replicas count
/// together.
#[tokio::test]
async fn rate_limit_holds_across_replicas() {
    let cache = shared();
    let a = OtpService::new(cache.clone());
    let b = OtpService::new(cache);
    let target = "spread@example.com";
    a.request_otp(target).await.unwrap();
    b.request_otp(target).await.unwrap();
    a.request_otp(target).await.unwrap();
    assert!(matches!(
        b.request_otp(target).await,
        Err(OtpError::RateLimited { .. })
    ));
}

#[tokio::test]
async fn test_different_targets_independent_rate_limits() {
    let service = service();
    for _ in 0..3 {
        assert!(service.request_otp("a@example.com").await.is_ok());
    }
    assert!(service.request_otp("b@example.com").await.is_ok());
}

#[tokio::test]
async fn test_get_session_target_not_found() {
    assert_eq!(
        service().get_session_target(&Uuid::now_v7()).await.unwrap(),
        None
    );
}
