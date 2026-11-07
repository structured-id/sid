// SPDX-License-Identifier: AGPL-3.0-only
//! Ceremony state shared by every replica.
//!
//! A ceremony started on one replica is finished on whichever one the next
//! request reaches, so its state lives in the authoritative store, not in
//! the process or a cache that may be absent. Each state is taken exactly
//! once across the deployment, expires with its TTL, and is sealed under the
//! key manager: the store holds OPAQUE server state, WebAuthn challenges and
//! pending TOTP seeds, none of which may be readable to whoever can read it.

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use sid_keys::KeyManager;
use sid_plugin::CeremonyStateStore;

use crate::sealed_secret::{self, SealedSecretError};

/// Why ceremony state could not be stored or read back. Every case fails the
/// ceremony closed: missing state is never read as success.
#[derive(Debug, thiserror::Error)]
pub enum ChallengeStoreError {
    #[error("ceremony state store unavailable: {0}")]
    Store(#[from] sid_core::Error),
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

/// A value read together with the form it is stored in, so a replacement
/// applies only to exactly what was read.
pub struct Versioned<V> {
    pub value: V,
    stored: Vec<u8>,
}

/// Short-lived state of one ceremony kind, keyed by the state key handed to
/// the client when the ceremony starts.
pub struct ChallengeStore<V> {
    store: Arc<dyn CeremonyStateStore>,
    keys: Arc<dyn KeyManager>,
    namespace: &'static str,
    ttl: Duration,
    _value: PhantomData<fn() -> V>,
}

impl<V: Serialize + DeserializeOwned> ChallengeStore<V> {
    /// A store for one ceremony kind; `namespace` keeps kinds apart.
    pub fn new(
        store: Arc<dyn CeremonyStateStore>,
        keys: Arc<dyn KeyManager>,
        namespace: &'static str,
        ttl: Duration,
    ) -> Self {
        Self {
            store,
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
        self.store
            .put_ceremony_state(self.namespace, key, &sealed, self.ttl)
            .await?;
        Ok(())
    }

    /// Store `value` under `key` until `deadline`, the absolute end of a
    /// ceremony that is stored again at each of its steps. Returns `false`,
    /// storing nothing, once the deadline has passed.
    pub async fn insert_until(
        &self,
        key: &str,
        value: &V,
        deadline: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, ChallengeStoreError> {
        let Ok(left) = (deadline - chrono::Utc::now()).to_std() else {
            return Ok(false);
        };
        if left.is_zero() {
            return Ok(false);
        }
        let context = self.context(key);
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
        let sealed = sealed_secret::seal(self.keys.as_ref(), &context, &plain).await?;
        self.store
            .put_ceremony_state(self.namespace, key, &sealed, left)
            .await?;
        Ok(true)
    }

    /// Take the value under `key`: of any number of concurrent callers on any
    /// replica, one gets it; absent or expired state is `None`.
    pub async fn take(&self, key: &str) -> Result<Option<V>, ChallengeStoreError> {
        let context = self.context(key);
        let Some(sealed) = self.store.take_ceremony_state(self.namespace, key).await? else {
            return Ok(None);
        };
        let opened = sealed_secret::open(self.keys.as_ref(), &context, &sealed).await?;
        Ok(Some(serde_json::from_slice(&opened.secret)?))
    }

    /// The value under `key`, left in place for its taker: for a page showing
    /// state it must not consume. Absent or expired state is `None`.
    pub async fn read(&self, key: &str) -> Result<Option<V>, ChallengeStoreError> {
        let context = self.context(key);
        let Some(sealed) = self.store.read_ceremony_state(self.namespace, key).await? else {
            return Ok(None);
        };
        let opened = sealed_secret::open(self.keys.as_ref(), &context, &sealed).await?;
        Ok(Some(serde_json::from_slice(&opened.secret)?))
    }

    /// The value under `key` with its stored form, for a later
    /// [`ChallengeStore::replace`] that applies only while nobody changed it.
    pub async fn read_versioned(
        &self,
        key: &str,
    ) -> Result<Option<Versioned<V>>, ChallengeStoreError> {
        let context = self.context(key);
        let Some(sealed) = self.store.read_ceremony_state(self.namespace, key).await? else {
            return Ok(None);
        };
        let opened = sealed_secret::open(self.keys.as_ref(), &context, &sealed).await?;
        Ok(Some(Versioned {
            value: serde_json::from_slice(&opened.secret)?,
            stored: sealed,
        }))
    }

    /// Replace the value under `key` with `value` until `deadline`, only while
    /// it is still `read` (atomic across replicas). Returns the replacement as
    /// read, for the writer's next replacement, so the writer never adopts a
    /// state another writer stored after it; `None`, changing nothing, when
    /// another writer changed or removed it first, or once the deadline has
    /// passed.
    pub async fn replace(
        &self,
        key: &str,
        read: &Versioned<V>,
        value: &V,
        deadline: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<Versioned<V>>, ChallengeStoreError>
    where
        V: Clone,
    {
        let Ok(left) = (deadline - chrono::Utc::now()).to_std() else {
            return Ok(None);
        };
        if left.is_zero() {
            return Ok(None);
        }
        let context = self.context(key);
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
        let sealed = sealed_secret::seal(self.keys.as_ref(), &context, &plain).await?;
        if !self
            .store
            .replace_ceremony_state(self.namespace, key, &read.stored, &sealed, left)
            .await?
        {
            return Ok(None);
        }
        Ok(Some(Versioned {
            value: value.clone(),
            stored: sealed,
        }))
    }

    /// What a mutation completing the ceremony `read` under `key` consumes
    /// in its own transaction (`MutationContext::consuming`): exactly the
    /// state as read, so a ceremony changed or completed meanwhile completes
    /// nothing.
    pub fn consumption(
        &self,
        key: &str,
        read: &Versioned<V>,
    ) -> sid_core::models::CeremonyConsumption {
        sid_core::models::CeremonyConsumption {
            namespace: self.namespace,
            key: key.to_owned(),
            stored: read.stored.clone(),
        }
    }

    /// The sealing context of `key`: binds a sealed value to the ceremony
    /// kind and state key it was stored under.
    fn context(&self, key: &str) -> String {
        format!("ceremony:{}:{key}", self.namespace)
    }
}

#[cfg(test)]
mod tests;
