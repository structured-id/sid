// SPDX-License-Identifier: AGPL-3.0-only
//! Cache backend abstraction.
//!
//! Pluggable cache layer for distributed session/policy caching
//! and cross-instance invalidation via pub/sub.
//!
//! Three backends available:
//! - `NoCacheBackend` — pass-through, no caching (CE small, single instance)
//! - Redis — standard distributed cache (CE medium)
//! - Dragonfly — high-performance distributed cache (EE/SaaS)

use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;

/// Errors from cache operations.
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("connection error: {0}")]
    Connection(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("key not found: {0}")]
    NotFound(String),

    #[error("cache operation timed out")]
    Timeout,

    #[error("cache error: {0}")]
    Other(String),
}

pub type CacheResult<T> = Result<T, CacheError>;

/// Pluggable cache backend trait.
///
/// Services use this trait for distributed caching and pub/sub invalidation.
/// All implementations must be safe for concurrent access from multiple tasks.
#[async_trait]
pub trait CacheBackend: Send + Sync {
    /// Get a value by key. Returns `None` if key doesn't exist or has expired.
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>>;

    /// Set a key-value pair with a time-to-live duration.
    /// Overwrites any existing value for the same key.
    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<()>;

    /// Delete a key. No-op if key doesn't exist.
    async fn delete(&self, key: &str) -> CacheResult<()>;

    /// Atomically read and delete a key (`GETDEL`): of any number of
    /// concurrent callers, across every process sharing the cache, exactly
    /// one gets the value. Returns `None` if the key is absent or expired.
    ///
    /// Required, with no check-then-delete default: that would hand the same
    /// single-use value to two callers.
    async fn take(&self, key: &str) -> CacheResult<Option<Vec<u8>>>;

    /// Check if a key exists (without fetching the value).
    async fn exists(&self, key: &str) -> CacheResult<bool> {
        Ok(self.get(key).await?.is_some())
    }

    /// Atomically set a key only if it does not already exist (SETNX + TTL).
    ///
    /// Returns `true` if the key was set (did not exist before),
    /// `false` if the key already existed (replay / duplicate detected).
    ///
    /// Used for distributed replay prevention (JTI caches, nonce checks).
    /// Implementations backed by Redis/Dragonfly should use `SET key value NX EX ttl`.
    async fn set_nx(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<bool> {
        // Default non-atomic fallback: check + set. Override for atomic backends.
        if self.exists(key).await? {
            Ok(false)
        } else {
            self.set(key, value, ttl).await?;
            Ok(true)
        }
    }

    /// Atomically increment a counter and return the new value.
    ///
    /// If the key does not exist, creates it with value 1 and sets TTL.
    /// If the key exists, increments it (TTL unchanged).
    ///
    /// Used for distributed rate limiting (INCR + EXPIRE pattern).
    /// Implementations backed by Redis/Dragonfly should use `INCR key` + `EXPIRE key ttl`.
    async fn incr(&self, key: &str, ttl: Duration) -> CacheResult<u64> {
        // Default non-atomic fallback: get + set. Override for atomic backends.
        let current = match self.get(key).await? {
            Some(data) => {
                let s = String::from_utf8_lossy(&data);
                s.parse::<u64>().unwrap_or(0)
            }
            None => 0,
        };
        let new_val = current + 1;
        self.set(key, new_val.to_string().as_bytes(), ttl).await?;
        Ok(new_val)
    }

    /// Publish a message to a channel (for cross-instance invalidation).
    async fn publish(&self, channel: &str, message: &[u8]) -> CacheResult<()>;

    /// Subscribe to a channel. Returns a receiver for incoming messages.
    /// The subscription remains active until the receiver is dropped.
    async fn subscribe(&self, channel: &str) -> CacheResult<mpsc::UnboundedReceiver<Vec<u8>>>;

    /// Check if the cache backend is healthy and connected.
    async fn health_check(&self) -> CacheResult<()>;
}

/// No-op cache backend — all reads miss, all writes succeed silently.
///
/// Used for CE small deployments (single instance, no distributed cache needed).
/// RevocationCache and ChallengeStore still work in-memory; this only affects
/// the distributed cache layer.
pub struct NoCacheBackend;

#[async_trait]
impl CacheBackend for NoCacheBackend {
    async fn get(&self, _key: &str) -> CacheResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn set(&self, _key: &str, _value: &[u8], _ttl: Duration) -> CacheResult<()> {
        Ok(())
    }

    async fn delete(&self, _key: &str) -> CacheResult<()> {
        Ok(())
    }

    async fn take(&self, _key: &str) -> CacheResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn exists(&self, _key: &str) -> CacheResult<bool> {
        Ok(false)
    }

    async fn publish(&self, _channel: &str, _message: &[u8]) -> CacheResult<()> {
        Ok(())
    }

    async fn subscribe(&self, _channel: &str) -> CacheResult<mpsc::UnboundedReceiver<Vec<u8>>> {
        let (_tx, rx) = mpsc::unbounded_channel();
        Ok(rx)
    }

    async fn health_check(&self) -> CacheResult<()> {
        Ok(())
    }
}

/// In-memory cache backend with real TTL, atomic set_nx/incr, and pub/sub.
///
/// For testing code that uses CacheBackend without requiring Redis.
/// Stores values with expiration timestamps, supports publish/subscribe
/// via tokio broadcast channels.
///
/// NOT for production — no persistence, no distributed coordination.
pub struct InMemoryCacheBackend {
    store: std::sync::Mutex<std::collections::HashMap<String, (Vec<u8>, std::time::Instant)>>,
    ttls: std::sync::Mutex<std::collections::HashMap<String, Duration>>,
    channels: std::sync::Mutex<
        std::collections::HashMap<String, tokio::sync::broadcast::Sender<Vec<u8>>>,
    >,
}

impl InMemoryCacheBackend {
    pub fn new() -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
            ttls: std::sync::Mutex::new(std::collections::HashMap::new()),
            channels: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn is_expired(created: std::time::Instant, ttl: Duration) -> bool {
        created.elapsed() >= ttl
    }

    fn cleanup_expired(&self) {
        let mut store = self.store.lock().unwrap();
        let ttls = self.ttls.lock().unwrap();
        store.retain(|key, (_, created)| {
            if let Some(ttl) = ttls.get(key) {
                !Self::is_expired(*created, *ttl)
            } else {
                true
            }
        });
    }
}

impl Default for InMemoryCacheBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheBackend for InMemoryCacheBackend {
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        let store = self.store.lock().unwrap();
        let ttls = self.ttls.lock().unwrap();
        match store.get(key) {
            Some((value, created)) => {
                if let Some(ttl) = ttls.get(key)
                    && Self::is_expired(*created, *ttl)
                {
                    return Ok(None);
                }
                Ok(Some(value.clone()))
            }
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<()> {
        let mut store = self.store.lock().unwrap();
        let mut ttls = self.ttls.lock().unwrap();
        store.insert(key.to_string(), (value.to_vec(), std::time::Instant::now()));
        ttls.insert(key.to_string(), ttl);
        Ok(())
    }

    async fn delete(&self, key: &str) -> CacheResult<()> {
        let mut store = self.store.lock().unwrap();
        let mut ttls = self.ttls.lock().unwrap();
        store.remove(key);
        ttls.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> CacheResult<bool> {
        Ok(self.get(key).await?.is_some())
    }

    async fn take(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        // Atomic: single lock scope.
        let mut store = self.store.lock().unwrap();
        let mut ttls = self.ttls.lock().unwrap();
        let Some((value, created)) = store.remove(key) else {
            return Ok(None);
        };
        let ttl = ttls.remove(key);
        if ttl.is_some_and(|ttl| Self::is_expired(created, ttl)) {
            return Ok(None);
        }
        Ok(Some(value))
    }

    async fn set_nx(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<bool> {
        // Atomic: single lock scope.
        let mut store = self.store.lock().unwrap();
        let mut ttls = self.ttls.lock().unwrap();

        // Check if key exists and not expired.
        if let Some((_, created)) = store.get(key)
            && let Some(existing_ttl) = ttls.get(key)
            && !Self::is_expired(*created, *existing_ttl)
        {
            return Ok(false); // Key exists and is alive.
        }

        store.insert(key.to_string(), (value.to_vec(), std::time::Instant::now()));
        ttls.insert(key.to_string(), ttl);
        Ok(true)
    }

    async fn incr(&self, key: &str, ttl: Duration) -> CacheResult<u64> {
        // Atomic: single lock scope.
        let mut store = self.store.lock().unwrap();
        let mut ttls = self.ttls.lock().unwrap();

        let current = match store.get(key) {
            Some((data, created)) => {
                if let Some(existing_ttl) = ttls.get(key) {
                    if Self::is_expired(*created, *existing_ttl) {
                        0 // Expired — start fresh.
                    } else {
                        let s = String::from_utf8_lossy(data);
                        s.parse::<u64>().unwrap_or(0)
                    }
                } else {
                    let s = String::from_utf8_lossy(data);
                    s.parse::<u64>().unwrap_or(0)
                }
            }
            None => 0,
        };

        let new_val = current + 1;
        let now = std::time::Instant::now();
        if current == 0 {
            // New key — set TTL.
            ttls.insert(key.to_string(), ttl);
            store.insert(key.to_string(), (new_val.to_string().into_bytes(), now));
        } else {
            // Existing key — keep original created time for TTL calculation.
            // Only update the value, not the timestamp.
            if let Some(entry) = store.get_mut(key) {
                entry.0 = new_val.to_string().into_bytes();
            }
        }
        Ok(new_val)
    }

    async fn publish(&self, channel: &str, message: &[u8]) -> CacheResult<()> {
        let channels = self.channels.lock().unwrap();
        if let Some(tx) = channels.get(channel) {
            let _ = tx.send(message.to_vec()); // Ignore if no subscribers.
        }
        Ok(())
    }

    async fn subscribe(&self, channel: &str) -> CacheResult<mpsc::UnboundedReceiver<Vec<u8>>> {
        let mut channels = self.channels.lock().unwrap();
        let tx = channels
            .entry(channel.to_string())
            .or_insert_with(|| tokio::sync::broadcast::channel(64).0);
        let mut broadcast_rx = tx.subscribe();

        let (mpsc_tx, mpsc_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok(msg) = broadcast_rx.recv().await {
                if mpsc_tx.send(msg).is_err() {
                    break; // Receiver dropped.
                }
            }
        });

        Ok(mpsc_rx)
    }

    async fn health_check(&self) -> CacheResult<()> {
        self.cleanup_expired();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_no_cache_get_returns_none() {
        let cache = NoCacheBackend;
        let result = cache.get("any_key").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_no_cache_set_succeeds() {
        let cache = NoCacheBackend;
        cache
            .set("key", b"value", Duration::from_secs(60))
            .await
            .unwrap();
        // Value is not stored — get still returns None
        assert!(cache.get("key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_no_cache_delete_succeeds() {
        let cache = NoCacheBackend;
        cache.delete("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn test_no_cache_exists_returns_false() {
        let cache = NoCacheBackend;
        assert!(!cache.exists("any_key").await.unwrap());
    }

    #[tokio::test]
    async fn test_no_cache_publish_succeeds() {
        let cache = NoCacheBackend;
        cache.publish("channel", b"message").await.unwrap();
    }

    #[tokio::test]
    async fn test_no_cache_subscribe_returns_empty_receiver() {
        let cache = NoCacheBackend;
        let mut rx = cache.subscribe("channel").await.unwrap();
        // Receiver should be empty (sender dropped immediately)
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_no_cache_health_check_succeeds() {
        let cache = NoCacheBackend;
        cache.health_check().await.unwrap();
    }

    #[tokio::test]
    async fn test_no_cache_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoCacheBackend>();
    }

    #[tokio::test]
    async fn test_cache_backend_object_safety() {
        // Verify CacheBackend can be used as trait object (dyn dispatch)
        let cache: Box<dyn CacheBackend> = Box::new(NoCacheBackend);
        assert!(cache.get("test").await.unwrap().is_none());
        cache
            .set("test", b"val", Duration::from_secs(1))
            .await
            .unwrap();
        cache.health_check().await.unwrap();
    }

    #[tokio::test]
    async fn test_no_cache_set_nx_always_succeeds() {
        let cache = NoCacheBackend;
        // NoCacheBackend: set_nx always returns true (no distributed state).
        assert!(
            cache
                .set_nx("key", b"1", Duration::from_secs(60))
                .await
                .unwrap()
        );
        // Second call also returns true — no state kept.
        assert!(
            cache
                .set_nx("key", b"1", Duration::from_secs(60))
                .await
                .unwrap()
        );
    }

    // ── InMemoryCacheBackend tests ──

    #[tokio::test]
    async fn test_inmem_get_set_basic() {
        let cache = InMemoryCacheBackend::new();
        assert!(cache.get("key1").await.unwrap().is_none());

        cache
            .set("key1", b"hello", Duration::from_secs(60))
            .await
            .unwrap();
        let val = cache.get("key1").await.unwrap().unwrap();
        assert_eq!(val, b"hello");
    }

    #[tokio::test]
    async fn test_inmem_set_overwrites() {
        let cache = InMemoryCacheBackend::new();
        cache
            .set("key", b"v1", Duration::from_secs(60))
            .await
            .unwrap();
        cache
            .set("key", b"v2", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(cache.get("key").await.unwrap().unwrap(), b"v2");
    }

    #[tokio::test]
    async fn test_inmem_delete() {
        let cache = InMemoryCacheBackend::new();
        cache
            .set("key", b"val", Duration::from_secs(60))
            .await
            .unwrap();
        cache.delete("key").await.unwrap();
        assert!(cache.get("key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_inmem_delete_nonexistent() {
        let cache = InMemoryCacheBackend::new();
        cache.delete("nope").await.unwrap(); // No error.
    }

    #[tokio::test]
    async fn test_inmem_exists() {
        let cache = InMemoryCacheBackend::new();
        assert!(!cache.exists("key").await.unwrap());
        cache
            .set("key", b"val", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(cache.exists("key").await.unwrap());
    }

    #[tokio::test]
    async fn test_inmem_ttl_expiry() {
        let cache = InMemoryCacheBackend::new();
        cache
            .set("short", b"val", Duration::from_millis(50))
            .await
            .unwrap();
        assert!(cache.get("short").await.unwrap().is_some());

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            cache.get("short").await.unwrap().is_none(),
            "key should expire after TTL"
        );
    }

    #[tokio::test]
    async fn test_inmem_ttl_not_expired_within_window() {
        let cache = InMemoryCacheBackend::new();
        cache
            .set("alive", b"val", Duration::from_secs(10))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(cache.get("alive").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_inmem_set_nx_first_wins() {
        let cache = InMemoryCacheBackend::new();
        assert!(
            cache
                .set_nx("lock", b"1", Duration::from_secs(60))
                .await
                .unwrap()
        );
        assert!(
            !cache
                .set_nx("lock", b"2", Duration::from_secs(60))
                .await
                .unwrap()
        );
        // Value is still from first set.
        assert_eq!(cache.get("lock").await.unwrap().unwrap(), b"1");
    }

    #[tokio::test]
    async fn test_inmem_set_nx_after_expiry() {
        let cache = InMemoryCacheBackend::new();
        assert!(
            cache
                .set_nx("lock", b"1", Duration::from_millis(50))
                .await
                .unwrap()
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        // Expired — set_nx should succeed again.
        assert!(
            cache
                .set_nx("lock", b"2", Duration::from_secs(60))
                .await
                .unwrap()
        );
        assert_eq!(cache.get("lock").await.unwrap().unwrap(), b"2");
    }

    #[tokio::test]
    async fn test_inmem_incr_from_zero() {
        let cache = InMemoryCacheBackend::new();
        let val = cache
            .incr("counter", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(val, 1);
    }

    #[tokio::test]
    async fn test_inmem_incr_sequential() {
        let cache = InMemoryCacheBackend::new();
        assert_eq!(cache.incr("c", Duration::from_secs(60)).await.unwrap(), 1);
        assert_eq!(cache.incr("c", Duration::from_secs(60)).await.unwrap(), 2);
        assert_eq!(cache.incr("c", Duration::from_secs(60)).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_inmem_incr_after_expiry_resets() {
        let cache = InMemoryCacheBackend::new();
        assert_eq!(cache.incr("c", Duration::from_millis(50)).await.unwrap(), 1);
        assert_eq!(cache.incr("c", Duration::from_millis(50)).await.unwrap(), 2);
        tokio::time::sleep(Duration::from_millis(80)).await;
        // Expired — counter resets.
        assert_eq!(cache.incr("c", Duration::from_secs(60)).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_inmem_key_prefix_isolation() {
        let cache = InMemoryCacheBackend::new();
        cache
            .set("jti:abc", b"1", Duration::from_secs(60))
            .await
            .unwrap();
        cache
            .set("rate:abc", b"2", Duration::from_secs(60))
            .await
            .unwrap();

        assert_eq!(cache.get("jti:abc").await.unwrap().unwrap(), b"1");
        assert_eq!(cache.get("rate:abc").await.unwrap().unwrap(), b"2");
        assert!(cache.get("other:abc").await.unwrap().is_none());

        cache.delete("jti:abc").await.unwrap();
        assert!(cache.get("jti:abc").await.unwrap().is_none());
        assert!(cache.get("rate:abc").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_inmem_pubsub_delivery() {
        let cache = InMemoryCacheBackend::new();
        let mut rx = cache.subscribe("invalidate").await.unwrap();

        cache.publish("invalidate", b"profile:123").await.unwrap();

        // Give the spawned task a moment to forward the message.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg, b"profile:123");
    }

    #[tokio::test]
    async fn test_inmem_pubsub_no_cross_channel() {
        let cache = InMemoryCacheBackend::new();
        let mut rx_a = cache.subscribe("channel_a").await.unwrap();

        cache.publish("channel_b", b"msg").await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert!(
            rx_a.try_recv().is_err(),
            "channel_a should not receive channel_b messages"
        );
    }

    #[tokio::test]
    async fn test_inmem_pubsub_multiple_subscribers() {
        let cache = InMemoryCacheBackend::new();
        let mut rx1 = cache.subscribe("events").await.unwrap();
        let mut rx2 = cache.subscribe("events").await.unwrap();

        cache.publish("events", b"hello").await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(rx1.try_recv().unwrap(), b"hello");
        assert_eq!(rx2.try_recv().unwrap(), b"hello");
    }

    #[tokio::test]
    async fn test_inmem_publish_no_subscribers() {
        let cache = InMemoryCacheBackend::new();
        // No subscribers — publish should not error.
        cache.publish("nobody", b"msg").await.unwrap();
    }

    #[tokio::test]
    async fn test_inmem_health_check() {
        let cache = InMemoryCacheBackend::new();
        cache.health_check().await.unwrap();
    }

    #[tokio::test]
    async fn test_inmem_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryCacheBackend>();
    }

    #[tokio::test]
    async fn test_inmem_as_trait_object() {
        let cache: std::sync::Arc<dyn CacheBackend> =
            std::sync::Arc::new(InMemoryCacheBackend::new());
        cache.set("k", b"v", Duration::from_secs(60)).await.unwrap();
        assert_eq!(cache.get("k").await.unwrap().unwrap(), b"v");
    }
}
