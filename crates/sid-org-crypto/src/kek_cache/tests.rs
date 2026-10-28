// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;

use super::*;
use crate::kek_source::EnvVarKekSource;

#[tokio::test]
async fn cache_hit_within_ttl() {
    let kek = [7u8; 32];
    let source: Arc<dyn KekSource> = Arc::new(EnvVarKekSource::new(kek, 1));
    let cache = KekCache::new(source, Duration::from_secs(60));

    let (v1, _) = cache.current().await.unwrap();
    let (v2, _) = cache.current().await.unwrap();
    assert_eq!(v1, v2);
}

#[tokio::test]
async fn cache_expires_after_ttl() {
    let kek = [9u8; 32];
    let source: Arc<dyn KekSource> = Arc::new(EnvVarKekSource::new(kek, 1));
    let cache = KekCache::new(source, Duration::from_millis(10));

    let _ = cache.current().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Force a re-fetch path; correctness check is that no panic, value matches.
    let (_, fetched) = cache.current().await.unwrap();
    assert_eq!(fetched.expose_secret()[0], 9);
}

#[tokio::test]
async fn wipe_clears() {
    let source: Arc<dyn KekSource> = Arc::new(EnvVarKekSource::new([1u8; 32], 1));
    let cache = KekCache::new(source, Duration::from_secs(60));
    let _ = cache.current().await.unwrap();
    cache.wipe().await;
    let guard = cache.state.lock().await;
    assert!(guard.is_none());
}

/// A source whose KEK can stop being available.
struct Switchable {
    available: AtomicBool,
}

#[async_trait]
impl KekSource for Switchable {
    async fn fetch_kek(&self, _version: u32) -> Result<SecretBox<[u8; 32]>, OrgCryptoError> {
        if self.available.load(Ordering::SeqCst) {
            Ok(SecretBox::new(Box::new([3u8; 32])))
        } else {
            Err(OrgCryptoError::KekUnavailable("switched off".into()))
        }
    }

    async fn current_version(&self) -> Result<u32, OrgCryptoError> {
        Ok(1)
    }

    fn kind(&self) -> &'static str {
        "switchable"
    }
}

const TTL: Duration = Duration::from_millis(20);

// An expired KEK is erased at its TTL even when nothing asks for it again:
// the cache holds no KEK past the TTL it promises.
#[tokio::test]
async fn an_expired_kek_is_erased_without_another_access() {
    let source: Arc<dyn KekSource> = Arc::new(EnvVarKekSource::new([5u8; 32], 1));
    let cache = KekCache::new(source, TTL);
    let _ = cache.current().await.unwrap();
    tokio::time::sleep(TTL * 5).await;
    assert!(cache.state.lock().await.is_none(), "erased at its TTL");
}

// A source that fails after the TTL leaves no expired KEK behind, through
// either read.
#[tokio::test]
async fn an_expired_kek_is_erased_when_the_source_fails() {
    let source = Arc::new(Switchable {
        available: AtomicBool::new(true),
    });
    let cache = KekCache::new(source.clone(), Duration::from_secs(3600));
    let _ = cache.current().await.unwrap();
    // Expire it in place, as an elapsed TTL would.
    cache.state.lock().await.as_mut().unwrap().expires_at = Instant::now();
    source.available.store(false, Ordering::SeqCst);
    assert!(cache.current().await.is_err());
    assert!(cache.state.lock().await.is_none(), "current() erases it");

    source.available.store(true, Ordering::SeqCst);
    let _ = cache.current().await.unwrap();
    cache.state.lock().await.as_mut().unwrap().expires_at = Instant::now();
    source.available.store(false, Ordering::SeqCst);
    assert!(cache.fetch(1).await.is_err());
    assert!(cache.state.lock().await.is_none(), "fetch() erases it");
}
