// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_plugin::cache::{CacheError, InMemoryCacheBackend};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

fn shared() -> Arc<dyn CacheBackend> {
    Arc::new(InMemoryCacheBackend::new())
}

/// Start of some window, in milliseconds.
const T0: i64 = 1_700_000_040_000;

/// A cache whose reads can be switched off, over a working store.
struct FlakyReads {
    inner: InMemoryCacheBackend,
    reads_fail: AtomicBool,
}

impl FlakyReads {
    fn new() -> Self {
        Self {
            inner: InMemoryCacheBackend::new(),
            reads_fail: AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl CacheBackend for FlakyReads {
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        if self.reads_fail.load(Ordering::SeqCst) {
            return Err(CacheError::Connection("down".into()));
        }
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
    async fn incr(&self, key: &str, ttl: Duration) -> CacheResult<u64> {
        if self.reads_fail.load(Ordering::SeqCst) {
            return Err(CacheError::Connection("down".into()));
        }
        self.inner.incr(key, ttl).await
    }
    async fn publish(&self, channel: &str, message: &[u8]) -> CacheResult<()> {
        self.inner.publish(channel, message).await
    }
    async fn subscribe(&self, channel: &str) -> CacheResult<mpsc::UnboundedReceiver<Vec<u8>>> {
        self.inner.subscribe(channel).await
    }
    async fn health_check(&self) -> CacheResult<()> {
        self.inner.health_check().await
    }
}

#[tokio::test]
async fn allows_within_limit() {
    let rl = RateLimiter::new(shared());
    for _ in 0..5 {
        assert!(rl.check_and_record("client-1", 10).await.unwrap());
    }
}

#[tokio::test]
async fn blocks_over_limit() {
    let rl = RateLimiter::new(shared());
    for _ in 0..3 {
        assert!(rl.check_at("client-1", 3, T0).await.unwrap());
    }
    assert!(!rl.check_at("client-1", 3, T0).await.unwrap());
}

#[tokio::test]
async fn zero_means_unlimited() {
    let rl = RateLimiter::new(shared());
    for _ in 0..1000 {
        assert!(rl.check_and_record("client-1", 0).await.unwrap());
    }
}

#[tokio::test]
async fn independent_clients() {
    let rl = RateLimiter::new(shared());
    for _ in 0..3 {
        assert!(rl.check_at("client-1", 3, T0).await.unwrap());
    }
    assert!(!rl.check_at("client-1", 3, T0).await.unwrap());
    // Different client is not affected.
    assert!(rl.check_at("client-2", 3, T0).await.unwrap());
}

/// Two replicas count into one window: requests spread over them stop at the
/// limit (each replica once kept its own window, multiplying the limit by the
/// number of replicas).
#[tokio::test]
async fn limit_holds_across_replicas() {
    let cache = shared();
    let a = RateLimiter::new(cache.clone());
    let b = RateLimiter::new(cache);
    assert!(a.check_at("c", 3, T0).await.unwrap());
    assert!(b.check_at("c", 3, T0).await.unwrap());
    assert!(a.check_at("c", 3, T0).await.unwrap());
    assert!(
        !b.check_at("c", 3, T0).await.unwrap(),
        "a fourth request passed a 3 rpm limit"
    );
}

/// Just past a window edge the previous window still counts, so a client
/// that used its limit at the end of one window cannot use it again at the
/// start of the next (the double burst a fixed window allows).
#[tokio::test]
async fn no_double_burst_at_the_window_edge() {
    let rl = RateLimiter::new(shared());
    let end_of_window = T0 + 59_000;
    for _ in 0..3 {
        assert!(rl.check_at("c", 3, end_of_window).await.unwrap());
    }
    let start_of_next = T0 + 61_000;
    assert!(!rl.check_at("c", 3, start_of_next).await.unwrap());
}

/// The previous window's weight falls as the current window runs: late in the
/// next window most of the old count has aged out.
#[tokio::test]
async fn previous_window_ages_out() {
    let rl = RateLimiter::new(shared());
    for _ in 0..3 {
        assert!(rl.check_at("c", 3, T0 + 1_000).await.unwrap());
    }
    // 90% into the next window: 3 * 0.1 = 0 whole requests remain counted.
    assert!(rl.check_at("c", 3, T0 + 114_000).await.unwrap());
    assert!(rl.check_at("c", 3, T0 + 114_000).await.unwrap());
}

/// Without a cache the limiter reports an error instead of letting requests
/// through.
#[tokio::test]
async fn unreachable_cache_is_an_error() {
    let cache = Arc::new(FlakyReads::new());
    cache.reads_fail.store(true, Ordering::SeqCst);
    let rl = RateLimiter::new(cache);
    assert!(rl.check_and_record("c", 3).await.is_err());
}

#[tokio::test]
async fn dashboard_counts_blocks() {
    let stats = RateLimitStats::new(shared());
    stats.record_block(Some("192.0.2.1"), "login").await;
    stats.record_block(Some("192.0.2.1"), "login").await;
    stats.record_block(Some("192.0.2.2"), "token").await;

    let data = stats.get_dashboard().await.unwrap();
    assert_eq!(data.total_blocked_last_hour, 3);
    assert_eq!(data.total_blocked_last_day, 3);
    assert_eq!(data.top_blocked_ips[0], ("192.0.2.1".to_string(), 2));
    assert_eq!(data.top_blocked_endpoints.len(), 2);
}

/// A dashboard over a cache that cannot answer is an error, not zeros.
#[tokio::test]
async fn dashboard_over_unreachable_cache_is_an_error() {
    let cache = Arc::new(FlakyReads::new());
    cache.reads_fail.store(true, Ordering::SeqCst);
    let stats = RateLimitStats::new(cache);
    assert!(stats.get_dashboard().await.is_err());
}

/// A block recorded while the tracked set cannot be read leaves the set as
/// it was (it was once replaced by a set holding only the new entry).
#[tokio::test]
async fn failed_read_does_not_replace_the_set() {
    let cache = Arc::new(FlakyReads::new());
    let stats = RateLimitStats::new(cache.clone());
    stats.record_block(Some("192.0.2.1"), "login").await;

    cache.reads_fail.store(true, Ordering::SeqCst);
    stats.add_to_set(KEY_IP_SET, "192.0.2.9").await;
    cache.reads_fail.store(false, Ordering::SeqCst);

    assert_eq!(
        stats.get_set(KEY_IP_SET).await.unwrap(),
        vec!["192.0.2.1".to_string()]
    );
}
