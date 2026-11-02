// SPDX-License-Identifier: AGPL-3.0-only
//! Ceremony state capability: short-lived protocol state that a step of a
//! ceremony leaves for the next one, and single-use admissions, held by the
//! authoritative store so every replica sees one owner of each.
//!
//! The store is the only owner: a cache in front of it never holds this
//! state, so its absence loses nothing and a lost reply is never repeated
//! against a second store. Every deadline is evaluated on the store's clock
//! at the moment of the operation, so replicas with skewed clocks agree and
//! expired state is refused at use, not merely removed later.

use std::time::Duration;

use async_trait::async_trait;
use sid_core::Result;

#[async_trait]
pub trait CeremonyStateStore: Send + Sync {
    /// Hold `value` under `key` in `namespace` for `ttl` from now, replacing
    /// whatever it held.
    async fn put_ceremony_state(
        &self,
        namespace: &str,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> Result<()>;

    /// Remove and return the live value under `key`: of any number of
    /// concurrent callers on any replica, exactly one gets it. Absent or
    /// expired state is `None`.
    async fn take_ceremony_state(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>>;

    /// The live value under `key`, left in place.
    async fn read_ceremony_state(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>>;

    /// Replace the value under `key` with `value` for `ttl` from now, only
    /// while it is live and exactly `expected`: `false`, changing nothing,
    /// when it is absent, expired or holds anything else.
    async fn replace_ceremony_state(
        &self,
        namespace: &str,
        key: &str,
        expected: &[u8],
        value: &[u8],
        ttl: Duration,
    ) -> Result<bool>;

    /// Admit `key` once for `ttl` from now: `true` for the one caller that
    /// holds it, `false` while a live admission of it exists. An expired
    /// admission no longer holds the key.
    async fn admit_once(&self, namespace: &str, key: &str, ttl: Duration) -> Result<bool>;

    /// Drop every state and admission expired by now. Returns how many.
    async fn purge_expired_ceremony_state(&self) -> Result<u64>;
}
