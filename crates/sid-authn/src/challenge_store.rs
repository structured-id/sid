// SPDX-License-Identifier: AGPL-3.0-only
//! Ceremony state shared by every replica.
//!
//! A ceremony started on one replica is finished on whichever one the next
//! request reaches, so its state lives in the shared cache, not in the
//! process. Each state is taken exactly once across the deployment, expires
//! with its TTL, and is sealed under the key manager: the cache holds OPAQUE
//! server state, WebAuthn challenges and pending TOTP seeds, none of which
//! may be readable to whoever can read the cache.

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use sid_keys::KeyManager;
use sid_plugin::cache::{CacheBackend, CacheError};

use crate::sealed_secret::{self, SealedSecretError};

/// Why ceremony state could not be stored or read back. Every case fails the
/// ceremony closed: missing state is never read as success.
#[derive(Debug, thiserror::Error)]
pub enum ChallengeStoreError {
    #[error("ceremony state store unavailable: {0}")]
    Cache(#[from] CacheError),
    #[error("ceremony state could not be sealed or opened: {0}")]
    Seal(#[from] SealedSecretError),
    #[error("ceremony state is malformed: {0}")]
    Encoding(#[from] serde_json::Error),
}

impl From<ChallengeStoreError> for sid_core::Error {
    fn from(e: ChallengeStoreError) -> Self {
        sid_core::Error::Internal(e.to_string())
    }
}

/// An internal error to the client; the cause stays in the log.
#[cfg(feature = "grpc")]
impl From<ChallengeStoreError> for tonic::Status {
    fn from(e: ChallengeStoreError) -> Self {
        tracing::error!(error = %e, "ceremony state store failed");
        sid_core::grpc_error::ApiError::internal().into()
    }
}

/// Short-lived state of one ceremony kind, keyed by the state key handed to
/// the client when the ceremony starts.
pub struct ChallengeStore<V> {
    cache: Arc<dyn CacheBackend>,
    keys: Arc<dyn KeyManager>,
    namespace: &'static str,
    ttl: Duration,
    _value: PhantomData<fn() -> V>,
}

impl<V: Serialize + DeserializeOwned> ChallengeStore<V> {
    /// A store for one ceremony kind; `namespace` keeps kinds apart in the cache.
    pub fn new(
        cache: Arc<dyn CacheBackend>,
        keys: Arc<dyn KeyManager>,
        namespace: &'static str,
        ttl: Duration,
    ) -> Self {
        Self {
            cache,
            keys,
            namespace,
            ttl,
            _value: PhantomData,
        }
    }

    /// Store `value` under `key` for the store's TTL.
    pub async fn insert(&self, key: &str, value: &V) -> Result<(), ChallengeStoreError> {
        let context = self.context(key);
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
        let sealed = sealed_secret::seal(self.keys.as_ref(), &context, &plain).await?;
        self.cache.set(&context, &sealed, self.ttl).await?;
        Ok(())
    }

    /// Take the value under `key`: of any number of concurrent callers on any
    /// replica, one gets it; absent or expired state is `None`.
    pub async fn take(&self, key: &str) -> Result<Option<V>, ChallengeStoreError> {
        let context = self.context(key);
        let Some(sealed) = self.cache.take(&context).await? else {
            return Ok(None);
        };
        let opened = sealed_secret::open(self.keys.as_ref(), &context, &sealed).await?;
        Ok(Some(serde_json::from_slice(&opened.secret)?))
    }

    /// The cache key and sealing context of `key`: binds a sealed value to the
    /// ceremony kind and state key it was stored under.
    fn context(&self, key: &str) -> String {
        format!("ceremony:{}:{key}", self.namespace)
    }
}

#[cfg(test)]
mod tests;
