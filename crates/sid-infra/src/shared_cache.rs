// SPDX-License-Identifier: AGPL-3.0-only
//! The cache every replica of a service shares.

use std::sync::Arc;

use sid_plugin::cache::{CacheBackend, CacheResult, InMemoryCacheBackend};

use crate::RedisCacheBackend;

/// The configured shared cache URL: `SID_CACHE_URL`, else `SID_REDIS_URL`.
pub fn cache_url_from_env() -> Option<String> {
    std::env::var("SID_CACHE_URL")
        .or_else(|_| std::env::var("SID_REDIS_URL"))
        .ok()
        .filter(|url| !url.trim().is_empty())
}

/// Connect the shared cache at `url`. Without one, the cache lives in this
/// process, which is correct only while the service runs as a single process:
/// a second replica neither sees its ceremonies, sessions and revocations nor
/// counts against its limits.
pub async fn shared_cache(url: Option<&str>) -> CacheResult<Arc<dyn CacheBackend>> {
    match url {
        Some(url) => {
            let backend = RedisCacheBackend::connect(url).await?;
            tracing::info!("state shared across replicas through the configured cache");
            Ok(Arc::new(backend))
        }
        None => {
            tracing::warn!(
                "no shared cache configured (SID_CACHE_URL / SID_REDIS_URL): ceremony state, \
                 sessions, revocations and rate limits are per process, so run a single replica"
            );
            Ok(Arc::new(InMemoryCacheBackend::new()))
        }
    }
}
