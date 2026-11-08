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
    let _listening = b.listen().await;

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
    let _listening = late.listen().await;

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
    let _listening = cache.listen().await;
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
    let cache = RevocationCache::new(Duration::from_secs(900), Arc::new(DownCache));

    assert!(cache.is_revoked("jti", "session").await.is_err());
    // A revocation this process made is still known locally.
    assert!(cache.revoke_session("session".to_string()).await.is_err());
    assert!(cache.is_revoked("jti", "session").await.unwrap());
}

/// A cache whose every operation fails.
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

/// A shared cache that carries everything but this process's publications.
struct MutePublisher(Arc<dyn CacheBackend>);

#[async_trait::async_trait]
impl CacheBackend for MutePublisher {
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        self.0.get(key).await
    }
    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<()> {
        self.0.set(key, value, ttl).await
    }
    async fn delete(&self, key: &str) -> CacheResult<()> {
        self.0.delete(key).await
    }
    async fn take(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        self.0.take(key).await
    }
    async fn publish(&self, _: &str, _: &[u8]) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
    async fn subscribe(
        &self,
        channel: &str,
    ) -> CacheResult<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
        self.0.subscribe(channel).await
    }
    async fn health_check(&self) -> CacheResult<()> {
        self.0.health_check().await
    }
}

fn recorded_in(
    store: &Arc<sid_plugin::InProcessCeremonyState>,
    lifetime: Duration,
    shared: Arc<dyn CacheBackend>,
) -> Arc<RevocationCache> {
    let store: Arc<dyn sid_plugin::CeremonyStateStore> = store.clone();
    Arc::new(RevocationCache::recorded_in(lifetime, shared, store))
}

/// A warm process whose listener stopped, or was dropped, no longer learns of
/// revocations: from then on a local miss is confirmed in the shared cache,
/// so a token another process revokes afterwards is refused.
#[tokio::test]
async fn test_a_stopped_listener_turns_the_cache_cold() {
    for stop in [true, false] {
        let shared: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
        let a = RevocationCache::new(Duration::from_millis(20), shared.clone());
        let b = Arc::new(RevocationCache::new(Duration::from_millis(20), shared));
        let listener = b.listen().await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!revoked(&b, "jti-late", "any").await, "warm and clean");
        if stop {
            listener.stop().await;
        } else {
            drop(listener);
        }
        a.revoke_jti("jti-late".to_string(), Duration::from_millis(20))
            .await
            .unwrap();
        assert!(
            revoked(&b, "jti-late", "any").await,
            "a revocation after the listener {} is refused",
            if stop { "stopped" } else { "was dropped" }
        );
    }
}

/// A shared cache whose first subscription succeeds and every later one
/// fails, as a broker lost after a process started.
struct LostAfterFirst {
    inner: Arc<dyn CacheBackend>,
    subscribed: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl CacheBackend for LostAfterFirst {
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        self.inner.get(key).await
    }
    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<()> {
        self.inner.set(key, value, ttl).await
    }
    async fn delete(&self, key: &str) -> CacheResult<()> {
        self.inner.delete(key).await
    }
    async fn take(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        self.inner.take(key).await
    }
    async fn publish(&self, channel: &str, payload: &[u8]) -> CacheResult<()> {
        self.inner.publish(channel, payload).await
    }
    async fn subscribe(
        &self,
        channel: &str,
    ) -> CacheResult<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
        if self
            .subscribed
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(CacheError::Connection("lost".into()));
        }
        self.inner.subscribe(channel).await
    }
    async fn health_check(&self) -> CacheResult<()> {
        self.inner.health_check().await
    }
}

/// A warm listener replaced by one whose subscription fails leaves no right
/// to answer from the local maps: the new listener starts cold, and the old
/// one's stop cannot restore it, so a later revocation is still refused.
#[tokio::test]
async fn test_a_replacing_listener_without_a_subscription_is_cold() {
    let shared: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let a = RevocationCache::new(Duration::from_millis(20), shared.clone());
    let b = Arc::new(RevocationCache::new(
        Duration::from_millis(20),
        Arc::new(LostAfterFirst {
            inner: shared,
            subscribed: std::sync::atomic::AtomicBool::new(false),
        }),
    ));
    let first = b.listen().await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!revoked(&b, "jti-replaced", "any").await, "warm and clean");
    let second = b.listen().await;
    first.stop().await;
    a.revoke_jti("jti-replaced".to_string(), Duration::from_millis(20))
        .await
        .unwrap();
    assert!(
        revoked(&b, "jti-replaced", "any").await,
        "a revocation without a live subscription is refused"
    );
    second.stop().await;
}

/// A stop interrupted at its first wait leaves no task running: every task
/// was aborted before the wait, and the listener still owns the rest.
#[tokio::test]
async fn test_an_interrupted_stop_leaves_no_task() {
    let store = Arc::new(sid_plugin::InProcessCeremonyState::new());
    let cache = recorded_in(
        &store,
        Duration::from_secs(900),
        Arc::new(InMemoryCacheBackend::new()),
    );
    let listener = cache.listen().await;
    // The stop is polled once, then dropped wherever its wait stood.
    let mut stop = Box::pin(listener.stop());
    std::future::poll_fn(|cx| {
        let polled = stop.as_mut().poll(cx);
        std::task::Poll::Ready(polled.is_ready())
    })
    .await;
    drop(stop);
    drop(cache);
    // The heartbeat holds the store until it ends: it must have been aborted
    // with the rest, not left for its next beat.
    assert!(
        eventually(|| Arc::strong_count(&store) == 1).await,
        "every task ended and released the store"
    );
}

/// A stopped listener holds nothing: the cache and the store it read are
/// released, so a host can close its database after its installation.
#[tokio::test]
async fn test_a_stopped_listener_releases_the_store() {
    let store = Arc::new(sid_plugin::InProcessCeremonyState::new());
    let cache = recorded_in(
        &store,
        Duration::from_secs(900),
        Arc::new(InMemoryCacheBackend::new()),
    );
    let listener = cache.listen().await;
    listener.stop().await;
    assert_eq!(Arc::strong_count(&cache), 1, "the cache is released");
    drop(cache);
    assert_eq!(Arc::strong_count(&store), 1, "the store is released");
}

/// An issuer's revocation is committed in its store: replicas that cannot
/// reach the shared cache start, revoke and refuse revoked tokens, each
/// confirming a local miss against the store.
#[tokio::test]
async fn test_store_revocation_holds_without_the_cache() {
    let store = Arc::new(sid_plugin::InProcessCeremonyState::new());
    let a = recorded_in(&store, Duration::from_secs(900), Arc::new(DownCache));
    let b = recorded_in(&store, Duration::from_secs(900), Arc::new(DownCache));
    let _a = a.listen().await;
    let _b = b.listen().await;

    a.revoke_session("session-x".to_string()).await.unwrap();
    a.revoke_jti("jti-x".to_string(), Duration::from_secs(60))
        .await
        .unwrap();

    assert!(revoked(&b, "any", "session-x").await);
    assert!(revoked(&b, "jti-x", "any").await);
    assert!(!revoked(&b, "jti-other", "session-other").await);
}

/// A shared cache that restarts empty revives no revoked token: the
/// revocation lives in the store, not in the cache's keys.
#[tokio::test]
async fn test_store_revocation_survives_an_empty_cache() {
    let store = Arc::new(sid_plugin::InProcessCeremonyState::new());
    let a = recorded_in(
        &store,
        Duration::from_secs(900),
        Arc::new(InMemoryCacheBackend::new()),
    );
    a.revoke_jti("jti-early".to_string(), Duration::from_secs(60))
        .await
        .unwrap();

    let late = recorded_in(
        &store,
        Duration::from_secs(900),
        Arc::new(InMemoryCacheBackend::new()),
    );
    let _listening = late.listen().await;
    assert!(revoked(&late, "jti-early", "any").await);
}

/// A revocation whose publication failed still reaches a replica that
/// trusted its own map: the failure is recorded in the store, and every
/// replica confirms its misses there until the revoked tokens have expired.
#[tokio::test]
async fn test_a_lost_publication_makes_replicas_confirm() {
    let store = Arc::new(sid_plugin::InProcessCeremonyState::new());
    let shared: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    // Longer than the heartbeat, as every real token lifetime is.
    let lifetime = HEARTBEAT * 3;
    let warm = recorded_in(&store, lifetime, shared.clone());
    let _listening = warm.listen().await;
    tokio::time::sleep(lifetime + Duration::from_millis(100)).await;
    assert!(!revoked(&warm, "jti-x", "any").await, "warm and clean");

    let mute = recorded_in(&store, lifetime, Arc::new(MutePublisher(shared)));
    mute.revoke_jti("jti-x".to_string(), lifetime)
        .await
        .expect("committed in the store although not published");

    assert!(
        eventually_async(|| async { revoked(&warm, "jti-x", "any").await }).await,
        "the warm replica sees the revocation it never received"
    );
}

/// Wait until the asynchronous `check` holds, within two heartbeats.
async fn eventually_async<F, Fut>(check: F) -> bool
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + HEARTBEAT * 2;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
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
