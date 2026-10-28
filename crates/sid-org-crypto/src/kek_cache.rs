// SPDX-License-Identifier: AGPL-3.0-only
//! In-memory TTL cache for fetched KEK.
//!
//! Used by `FileKekSource` and similar lazy sources. The cached value is
//! overwritten with zeros when it leaves the cache: at its TTL, whether or not
//! anything asks for it again (an eraser task the insert schedules), on an
//! access after it, whatever the source then answers, and on `wipe()`. The
//! source's own copy (a mounted file) is outside this cache.
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
    state: Arc<Mutex<Option<CachedKek>>>,
}

/// Drop `slot`'s entry if it expired by `now`; Drop zeroes it.
fn erase_expired(slot: &mut Option<CachedKek>, now: Instant) {
    if slot.as_ref().is_some_and(|c| now >= c.expires_at) {
        *slot = None;
    }
}

impl KekCache {
    /// New cache wrapping a KEK source with the given TTL.
    pub fn new(source: Arc<dyn KekSource>, ttl: Duration) -> Self {
        Self {
            source,
            ttl,
            state: Arc::new(Mutex::new(None)),
        }
    }

    /// Fetch current KEK (cache hit if not expired, otherwise reads source).
    ///
    /// Returns `(version, kek_secret)`. Caller treats the secret as ephemeral.
    pub async fn current(&self) -> Result<(u32, SecretBox<[u8; 32]>), OrgCryptoError> {
        let now = Instant::now();
        let mut guard = self.state.lock().await;
        // An expired entry is erased before the source is asked, so a source
        // that fails now leaves none behind.
        erase_expired(&mut guard, now);
        if let Some(cached) = guard.as_ref() {
            return Ok((cached.version, SecretBox::new(Box::new(cached.bytes))));
        }

        let version = self.source.current_version().await?;
        let secret = self.source.fetch_kek(version).await?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret.expose_secret());
        let expires_at = now + self.ttl;
        *guard = Some(CachedKek {
            version,
            bytes,
            expires_at,
        });
        drop(guard);
        self.erase_at(expires_at);
        Ok((version, SecretBox::new(Box::new(bytes))))
    }

    /// Fetch a specific KEK version (bypasses cache for non-current).
    pub async fn fetch(&self, version: u32) -> Result<SecretBox<[u8; 32]>, OrgCryptoError> {
        let mut guard = self.state.lock().await;
        erase_expired(&mut guard, Instant::now());
        if let Some(cached) = guard.as_ref()
            && cached.version == version
        {
            return Ok(SecretBox::new(Box::new(cached.bytes)));
        }
        drop(guard);
        self.source.fetch_kek(version).await
    }

    /// Erase the entry cached until `expires_at` at that instant, unless the
    /// cache dropped it or holds a newer one by then. The task holds no
    /// strong reference: a dropped cache zeroes its entry itself.
    fn erase_at(&self, expires_at: Instant) {
        let state = Arc::downgrade(&self.state);
        tokio::spawn(async move {
            tokio::time::sleep_until(expires_at.into()).await;
            if let Some(state) = state.upgrade() {
                let mut slot = state.lock().await;
                if slot.as_ref().is_some_and(|c| c.expires_at == expires_at) {
                    *slot = None;
                }
            }
        });
    }

    /// Force-wipe cache (e.g., before pod shutdown or after suspected leak).
    pub async fn wipe(&self) {
        let mut guard = self.state.lock().await;
        *guard = None; // Drop runs the zeroize
    }
}

#[cfg(test)]
mod tests;
