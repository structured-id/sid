// SPDX-License-Identifier: AGPL-3.0-only
//! In-memory TTL cache for fetched KEK.
//!
//! Used by `K8sSecretKekSource` and similar lazy sources. The cached value
//! lives in a `SecretBox` that zeroizes on drop. After TTL expiry, the value
//! is wiped on next access and re-fetched.
//!
//! Concurrency: an in-flight fetch is single-flight via `tokio::sync::Mutex`.
//! Multiple readers within the TTL window share the cached value (cheap clone
//! of the inner `[u8; 32]`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretBox};
use tokio::sync::Mutex;

use crate::error::OrgCryptoError;
use crate::kek_source::KekSource;

struct CachedKek {
    version: u32,
    /// Raw bytes; wrapped in our own struct because SecretBox is single-owner
    /// and we need shared read access. We accept the lifetime risk: the cache
    /// is wiped on TTL or `wipe()` call.
    bytes: [u8; 32],
    expires_at: Instant,
}

impl Drop for CachedKek {
    fn drop(&mut self) {
        // Best-effort zeroize: zeroize crate guarantees this through `Zeroize`
        // when applied; here we explicitly overwrite.
        for b in self.bytes.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

pub struct KekCache {
    source: Arc<dyn KekSource>,
    ttl: Duration,
    state: Mutex<Option<CachedKek>>,
}

impl KekCache {
    /// New cache wrapping a KEK source with the given TTL.
    pub fn new(source: Arc<dyn KekSource>, ttl: Duration) -> Self {
        Self {
            source,
            ttl,
            state: Mutex::new(None),
        }
    }

    /// Fetch current KEK (cache hit if not expired, otherwise reads source).
    ///
    /// Returns `(version, kek_secret)`. Caller treats the secret as ephemeral.
    pub async fn current(&self) -> Result<(u32, SecretBox<[u8; 32]>), OrgCryptoError> {
        let now = Instant::now();
        let mut guard = self.state.lock().await;

        // An expired entry falls through and is replaced; Drop runs on overwrite.
        if let Some(cached) = guard.as_ref()
            && now < cached.expires_at
        {
            return Ok((cached.version, SecretBox::new(Box::new(cached.bytes))));
        }

        // Cache miss or expired: fetch fresh.
        let version = self.source.current_version().await?;
        let secret = self.source.fetch_kek(version).await?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret.expose_secret());

        *guard = Some(CachedKek {
            version,
            bytes,
            expires_at: now + self.ttl,
        });

        Ok((version, SecretBox::new(Box::new(bytes))))
    }

    /// Fetch a specific KEK version (bypasses cache for non-current).
    pub async fn fetch(&self, version: u32) -> Result<SecretBox<[u8; 32]>, OrgCryptoError> {
        let guard = self.state.lock().await;
        if let Some(cached) = guard.as_ref()
            && cached.version == version
            && Instant::now() < cached.expires_at
        {
            return Ok(SecretBox::new(Box::new(cached.bytes)));
        }
        drop(guard);
        self.source.fetch_kek(version).await
    }

    /// Force-wipe cache (e.g., before pod shutdown or after suspected leak).
    pub async fn wipe(&self) {
        let mut guard = self.state.lock().await;
        *guard = None; // Drop runs the zeroize
    }
}

#[cfg(test)]
mod tests {
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
}
