use super::*;
use sid_plugin::cache::{CacheResult, InMemoryCacheBackend};

fn cache(max_token_lifetime: Duration) -> RevocationCache {
    RevocationCache::new(max_token_lifetime, Arc::new(InMemoryCacheBackend::new()))
}

async fn revoked(cache: &RevocationCache, jti: &str, session_id: &str) -> bool {
    cache.is_revoked(jti, session_id).await.unwrap()
}

/// Wait until `check` holds (the other process applies a revocation after
/// the pub/sub delivers it).
async fn eventually(check: impl Fn() -> bool) -> bool {
    for _ in 0..100 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    false
}

#[tokio::test]
async fn test_revoke_jti_and_check() {
    let cache = cache(Duration::from_secs(900));

    cache
        .revoke_jti("jti-123".to_string(), Duration::from_secs(60))
        .await
        .unwrap();

    assert!(revoked(&cache, "jti-123", "session-any").await);
    assert!(!revoked(&cache, "jti-other", "session-any").await);
}

#[tokio::test]
async fn test_revoke_session_and_check() {
    let cache = cache(Duration::from_secs(900));

    cache
        .revoke_session("session-abc".to_string())
        .await
        .unwrap();

    assert!(revoked(&cache, "any-jti", "session-abc").await);
    assert!(!revoked(&cache, "any-jti", "session-other").await);
}

/// A revocation made in one process is applied to the local map of every
/// other process sharing the cache (every replica, every service verifying
/// SID tokens), so they answer without a round trip.
#[tokio::test]
async fn test_revocation_reaches_other_processes() {
    let shared: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let a = Arc::new(RevocationCache::new(
        Duration::from_secs(900),
        shared.clone(),
    ));
    let b = Arc::new(RevocationCache::new(Duration::from_secs(900), shared));
    b.listen().await.unwrap();

    a.revoke_session("session-x".to_string()).await.unwrap();
    a.revoke_jti("jti-x".to_string(), Duration::from_secs(60))
        .await
        .unwrap();

    assert!(eventually(|| b.len() == 2).await);
    assert!(revoked(&b, "any", "session-x").await);
    assert!(revoked(&b, "jti-x", "any").await);
}

/// A process started after a revocation (a new replica, a restart) still
/// refuses the revoked tokens: pub/sub only carries what happens after it
/// subscribed.
#[tokio::test]
async fn test_revocation_before_start_is_seen() {
    let shared: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let a = RevocationCache::new(Duration::from_secs(900), shared.clone());
    a.revoke_session("session-early".to_string()).await.unwrap();
    a.revoke_jti("jti-early".to_string(), Duration::from_secs(60))
        .await
        .unwrap();

    let late = Arc::new(RevocationCache::new(Duration::from_secs(900), shared));
    late.listen().await.unwrap();

    assert!(revoked(&late, "any", "session-early").await);
    assert!(revoked(&late, "jti-early", "any").await);
    assert!(!revoked(&late, "jti-other", "session-other").await);
}

/// Once subscribed for a full token lifetime the local map is complete and
/// answers alone: a key present only in the shared cache (which no process
/// writes without publishing) is not looked up.
#[tokio::test]
async fn test_warm_process_answers_locally() {
    let shared: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let cache = Arc::new(RevocationCache::new(
        Duration::from_millis(20),
        shared.clone(),
    ));
    cache.listen().await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;

    shared
        .set(
            &format!("{SESSION_KEY}unpublished"),
            &[],
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    assert!(!revoked(&cache, "any", "unpublished").await);
}

/// While a local miss must be confirmed, an unreachable shared cache is an
/// error (the caller refuses the token), never "not revoked".
#[tokio::test]
async fn test_unreachable_cache_while_cold_is_an_error() {
    struct Down;
    #[async_trait::async_trait]
    impl CacheBackend for Down {
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
        async fn publish(&self, _: &str, _: &[u8]) -> CacheResult<()> {
            Err(CacheError::Connection("down".into()))
        }
        async fn subscribe(
            &self,
            _: &str,
        ) -> CacheResult<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
            Err(CacheError::Connection("down".into()))
        }
        async fn health_check(&self) -> CacheResult<()> {
            Err(CacheError::Connection("down".into()))
        }
    }
    let cache = RevocationCache::new(Duration::from_secs(900), Arc::new(Down));

    assert!(cache.is_revoked("jti", "session").await.is_err());
    // A revocation this process made is still known locally.
    assert!(cache.revoke_session("session".to_string()).await.is_err());
    assert!(cache.is_revoked("jti", "session").await.unwrap());
}

#[tokio::test]
async fn test_both_jti_and_session_revoked() {
    let cache = cache(Duration::from_secs(900));

    cache
        .revoke_jti("jti-1".to_string(), Duration::from_secs(60))
        .await
        .unwrap();
    cache.revoke_session("session-1".to_string()).await.unwrap();

    // Either match triggers revocation
    assert!(revoked(&cache, "jti-1", "session-other").await);
    assert!(revoked(&cache, "jti-other", "session-1").await);
    assert!(revoked(&cache, "jti-1", "session-1").await);
}

#[tokio::test]
async fn test_expired_jti_not_revoked() {
    let cache = cache(Duration::from_secs(900));

    cache
        .revoke_jti("jti-expired".to_string(), Duration::from_millis(1))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!revoked(&cache, "jti-expired", "session-any").await);
}

#[tokio::test]
async fn test_expired_session_not_revoked() {
    let cache = cache(Duration::from_millis(1));

    cache
        .revoke_session("session-expired".to_string())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!revoked(&cache, "any-jti", "session-expired").await);
}

#[tokio::test]
async fn test_cleanup_removes_expired() {
    let cache = cache(Duration::from_millis(1));

    cache
        .revoke_jti("jti-1".to_string(), Duration::from_millis(1))
        .await
        .unwrap();
    cache
        .revoke_jti("jti-2".to_string(), Duration::from_millis(1))
        .await
        .unwrap();
    cache.revoke_session("session-1".to_string()).await.unwrap();

    assert_eq!(cache.len(), 3);

    tokio::time::sleep(Duration::from_millis(10)).await;
    cache.cleanup();

    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

#[tokio::test]
async fn test_cleanup_keeps_valid_entries() {
    let cache = cache(Duration::from_secs(60));

    cache
        .revoke_jti("jti-short".to_string(), Duration::from_millis(1))
        .await
        .unwrap();
    cache
        .revoke_jti("jti-long".to_string(), Duration::from_secs(60))
        .await
        .unwrap();
    cache
        .revoke_session("session-long".to_string())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(10)).await;
    cache.cleanup();

    // Short JTI expired, long JTI and session still valid
    assert_eq!(cache.len(), 2);
    assert!(!revoked(&cache, "jti-short", "session-any").await);
    assert!(revoked(&cache, "jti-long", "session-any").await);
    assert!(revoked(&cache, "any-jti", "session-long").await);
}
