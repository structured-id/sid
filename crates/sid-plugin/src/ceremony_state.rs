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

    /// Count one more event under `key` and return the count in its window:
    /// the first event opens a window of `window` from now, events within it
    /// add to it, and the first event after it ends opens a new one at 1.
    /// Concurrent events on any replica are each counted exactly once.
    async fn count_in_window(&self, namespace: &str, key: &str, window: Duration) -> Result<u64>;

    /// Drop every state and admission expired by now. Returns how many.
    async fn purge_expired_ceremony_state(&self) -> Result<u64>;
}

/// A state or admission by (namespace, key): its value and its deadline.
type Entries = std::collections::HashMap<(String, String), (Vec<u8>, std::time::Instant)>;

/// A count by (namespace, key): the count and its window's end.
type Counts = std::collections::HashMap<(String, String), (u64, std::time::Instant)>;

/// Ceremony state of one process: the authority only where that process is
/// the only one finishing its ceremonies (a single-process embedded host,
/// tests). Every operation runs under one lock.
#[derive(Default)]
pub struct InProcessCeremonyState {
    entries: std::sync::Mutex<Entries>,
    counts: std::sync::Mutex<Counts>,
}

impl InProcessCeremonyState {
    pub fn new() -> Self {
        Self::default()
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, Entries> {
        // A panic while holding the lock leaves the map consistent: every
        // operation is one insert or remove.
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// The instant `ttl` from now; a lifetime past the clock's range is a caller
/// error, never a deadline in the past.
fn deadline(ttl: Duration) -> Result<std::time::Instant> {
    std::time::Instant::now()
        .checked_add(ttl)
        .ok_or_else(|| sid_core::Error::Internal(format!("ceremony state lifetime {ttl:?}")))
}

#[async_trait]
impl CeremonyStateStore for InProcessCeremonyState {
    async fn put_ceremony_state(
        &self,
        namespace: &str,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> Result<()> {
        let expires = deadline(ttl)?;
        self.entries()
            .insert((namespace.into(), key.into()), (value.to_vec(), expires));
        Ok(())
    }

    async fn take_ceremony_state(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let now = std::time::Instant::now();
        Ok(self
            .entries()
            .remove(&(namespace.into(), key.into()))
            .filter(|(_, expires)| *expires > now)
            .map(|(value, _)| value))
    }

    async fn read_ceremony_state(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let now = std::time::Instant::now();
        Ok(self
            .entries()
            .get(&(namespace.into(), key.into()))
            .filter(|(_, expires)| *expires > now)
            .map(|(value, _)| value.clone()))
    }

    async fn replace_ceremony_state(
        &self,
        namespace: &str,
        key: &str,
        expected: &[u8],
        value: &[u8],
        ttl: Duration,
    ) -> Result<bool> {
        let expires = deadline(ttl)?;
        let now = std::time::Instant::now();
        let mut entries = self.entries();
        match entries.get_mut(&(namespace.into(), key.into())) {
            Some(entry) if entry.1 > now && entry.0 == expected => {
                *entry = (value.to_vec(), expires);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn admit_once(&self, namespace: &str, key: &str, ttl: Duration) -> Result<bool> {
        let expires = deadline(ttl)?;
        let now = std::time::Instant::now();
        let mut entries = self.entries();
        let entry = entries
            .entry((namespace.into(), key.into()))
            .or_insert((Vec::new(), now));
        if entry.1 > now {
            return Ok(false);
        }
        *entry = (Vec::new(), expires);
        Ok(true)
    }

    async fn count_in_window(&self, namespace: &str, key: &str, window: Duration) -> Result<u64> {
        let ends = deadline(window)?;
        let now = std::time::Instant::now();
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let entry = counts
            .entry((namespace.into(), key.into()))
            .or_insert((0, now));
        if entry.1 <= now {
            *entry = (0, ends);
        }
        entry.0 = entry
            .0
            .checked_add(1)
            .ok_or_else(|| sid_core::Error::Internal(format!("count of {key} overflows")))?;
        Ok(entry.0)
    }

    async fn purge_expired_ceremony_state(&self) -> Result<u64> {
        let now = std::time::Instant::now();
        let mut entries = self.entries();
        let before = entries.len();
        entries.retain(|_, (_, expires)| *expires > now);
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let counted = counts.len();
        counts.retain(|_, (_, ends)| *ends > now);
        Ok(
            u64::try_from(before - entries.len() + counted - counts.len())
                .expect("map length fits u64"),
        )
    }
}

#[cfg(test)]
mod tests;
