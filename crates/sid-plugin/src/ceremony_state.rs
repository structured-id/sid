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
use sid_core::models::NewWork;

/// Single-use admissions: the atomic replay record a verifier needs to
/// accept a one-time value (a proof's `jti`) exactly once across every
/// replica sharing it. A host gives a verifier this alone, not its store.
#[async_trait]
pub trait SingleUseAdmissions: Send + Sync {
    /// Admit `key` once for `ttl` from now: `true` for the one caller that
    /// holds it, `false` while a live admission of it exists. An expired
    /// admission no longer holds the key.
    async fn admit_once(&self, namespace: &str, key: &str, ttl: Duration) -> Result<bool>;

    /// Admit `key` for `holder` for `ttl` from now, or confirm that `holder`
    /// already holds it: `true` when `holder` holds the live admission after
    /// the call, `false`, changing nothing, while another holder does. A
    /// confirmation keeps the admission's original deadline; an expired
    /// admission no longer holds the key for anyone.
    async fn admit_for(
        &self,
        namespace: &str,
        key: &str,
        holder: &[u8],
        ttl: Duration,
    ) -> Result<bool>;
}

#[async_trait]
pub trait CeremonyStateStore: SingleUseAdmissions {
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

    /// Hold `value` under `key` as [`Self::put_ceremony_state`] does, with the
    /// durable work `owed` in the same commit: both are stored or neither.
    /// Refuses `ResourceExhausted`, storing nothing, when `owed`'s kind is
    /// full. A store keeping no durable work beside its ceremony state
    /// refuses rather than store the state alone.
    async fn put_ceremony_state_owing(
        &self,
        _namespace: &str,
        _key: &str,
        _value: &[u8],
        _ttl: Duration,
        _owed: OwedWork<'_>,
    ) -> Result<()> {
        Err(sid_core::Error::Internal(
            "this ceremony state store keeps no durable work".into(),
        ))
    }

    /// [`Self::replace_ceremony_state`] with the durable work `owed` in the
    /// same commit: `false`, storing neither, when the state is no longer
    /// `expected`; `ResourceExhausted`, the state left as it was, when
    /// `owed`'s kind is full.
    async fn replace_ceremony_state_owing(
        &self,
        _namespace: &str,
        _key: &str,
        _expected: &[u8],
        _value: &[u8],
        _ttl: Duration,
        _owed: OwedWork<'_>,
    ) -> Result<bool> {
        Err(sid_core::Error::Internal(
            "this ceremony state store keeps no durable work".into(),
        ))
    }

    /// Count one more event under `key` and return the count in its window:
    /// the first event opens a window of `window` from now, events within it
    /// add to it, and the first event after it ends opens a new one at 1.
    /// Concurrent events on any replica are each counted exactly once.
    async fn count_in_window(&self, namespace: &str, key: &str, window: Duration) -> Result<u64>;

    /// The count under `key` in its current window, counting nothing: 0 when
    /// nothing was counted or its window has ended.
    async fn read_count(&self, namespace: &str, key: &str) -> Result<u64>;

    /// Forget the count under `key`: the next event opens a new window at 1.
    async fn clear_count(&self, namespace: &str, key: &str) -> Result<()>;

    /// Drop every state and admission expired by now. Returns how many.
    async fn purge_expired_ceremony_state(&self) -> Result<u64>;

    /// Every live state, admission and count with its deadline on the
    /// store's clock, for an instance transfer: a challenge in flight, a
    /// replay record or an attempt count keeps holding after the move.
    async fn export_ceremony_state(&self) -> Result<CeremonyRecords> {
        Err(sid_core::Error::Internal(
            "this ceremony state store does not transfer its records".into(),
        ))
    }

    /// Store exported records with their deadlines. A record already held
    /// exactly is skipped; another live one under its key is a `Conflict`,
    /// nothing written. Returns how many were stored.
    async fn import_ceremony_state(&self, _records: &CeremonyRecords) -> Result<u64> {
        Err(sid_core::Error::Internal(
            "this ceremony state store does not transfer its records".into(),
        ))
    }
}

/// Durable work a ceremony state write owes, admitted while its kind holds
/// fewer than `capacity` open items.
#[derive(Debug, Clone, Copy)]
pub struct OwedWork<'a> {
    pub work: &'a NewWork,
    pub capacity: u64,
}

/// Live ceremony records with their deadlines, as a transfer carries them.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CeremonyRecords {
    /// States and admissions: an admission holds its holder (empty for
    /// [`SingleUseAdmissions::admit_once`]) as its value.
    pub states: Vec<CeremonyEntry>,
    pub counts: Vec<CeremonyCount>,
}

impl CeremonyRecords {
    /// Keep only the records still live at `at`.
    pub fn retain_live_at(&mut self, at: chrono::DateTime<chrono::Utc>) {
        self.states.retain(|s| s.expires_at > at);
        self.counts.retain(|c| c.window_ends > at);
    }
}

/// A state or admission under `(namespace, key)` until `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CeremonyEntry {
    pub namespace: String,
    pub key: String,
    pub value: Vec<u8>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// A count under `(namespace, key)` in a window ending at `window_ends`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CeremonyCount {
    pub namespace: String,
    pub key: String,
    pub count: u64,
    pub window_ends: chrono::DateTime<chrono::Utc>,
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
impl SingleUseAdmissions for InProcessCeremonyState {
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

    async fn admit_for(
        &self,
        namespace: &str,
        key: &str,
        holder: &[u8],
        ttl: Duration,
    ) -> Result<bool> {
        let expires = deadline(ttl)?;
        let now = std::time::Instant::now();
        let mut entries = self.entries();
        let entry = entries
            .entry((namespace.into(), key.into()))
            .or_insert((Vec::new(), now));
        if entry.1 > now {
            return Ok(entry.0 == holder);
        }
        *entry = (holder.to_vec(), expires);
        Ok(true)
    }
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

    async fn read_count(&self, namespace: &str, key: &str) -> Result<u64> {
        let now = std::time::Instant::now();
        let counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        Ok(counts
            .get(&(namespace.into(), key.into()))
            .filter(|(_, ends)| *ends > now)
            .map_or(0, |(count, _)| *count))
    }

    async fn clear_count(&self, namespace: &str, key: &str) -> Result<()> {
        self.counts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&(namespace.into(), key.into()));
        Ok(())
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

    async fn export_ceremony_state(&self) -> Result<CeremonyRecords> {
        let (now, wall) = (std::time::Instant::now(), chrono::Utc::now());
        let at = |deadline: std::time::Instant| {
            chrono::Duration::from_std(deadline - now)
                .ok()
                .and_then(|left| wall.checked_add_signed(left))
                // Milliseconds, the precision every store keeps a deadline at.
                .and_then(|t| {
                    chrono::DurationRound::duration_trunc(t, chrono::Duration::milliseconds(1)).ok()
                })
                .ok_or_else(|| sid_core::Error::Internal("ceremony deadline out of range".into()))
        };
        let mut states = Vec::new();
        for ((namespace, key), (value, expires)) in self.entries().iter() {
            if *expires > now {
                states.push(CeremonyEntry {
                    namespace: namespace.clone(),
                    key: key.clone(),
                    value: value.clone(),
                    expires_at: at(*expires)?,
                });
            }
        }
        let mut counts = Vec::new();
        for ((namespace, key), (count, ends)) in
            self.counts.lock().unwrap_or_else(|p| p.into_inner()).iter()
        {
            if *ends > now {
                counts.push(CeremonyCount {
                    namespace: namespace.clone(),
                    key: key.clone(),
                    count: *count,
                    window_ends: at(*ends)?,
                });
            }
        }
        states.sort_by(|a, b| (&a.namespace, &a.key).cmp(&(&b.namespace, &b.key)));
        counts.sort_by(|a, b| (&a.namespace, &a.key).cmp(&(&b.namespace, &b.key)));
        Ok(CeremonyRecords { states, counts })
    }

    async fn import_ceremony_state(&self, records: &CeremonyRecords) -> Result<u64> {
        let (now, wall) = (std::time::Instant::now(), chrono::Utc::now());
        // A deadline already past on this clock holds nothing.
        let until =
            |at: chrono::DateTime<chrono::Utc>| (at - wall).to_std().ok().map(|left| now + left);
        let mut entries = self.entries();
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        // Checked before any write: a conflict stores nothing.
        for s in &records.states {
            if let Some((value, expires)) = entries.get(&(s.namespace.clone(), s.key.clone()))
                && *expires > now
                && *value != s.value
            {
                return Err(sid_core::Error::Conflict(
                    "another live ceremony state holds the key".into(),
                ));
            }
        }
        for c in &records.counts {
            if let Some((count, ends)) = counts.get(&(c.namespace.clone(), c.key.clone()))
                && *ends > now
                && *count != c.count
            {
                return Err(sid_core::Error::Conflict(
                    "another live count holds the key".into(),
                ));
            }
        }
        let mut stored = 0;
        for s in &records.states {
            let slot = (s.namespace.clone(), s.key.clone());
            let live = entries.get(&slot).is_some_and(|(_, e)| *e > now);
            if let (false, Some(expires)) = (live, until(s.expires_at)) {
                entries.insert(slot, (s.value.clone(), expires));
                stored += 1;
            }
        }
        for c in &records.counts {
            let slot = (c.namespace.clone(), c.key.clone());
            let live = counts.get(&slot).is_some_and(|(_, e)| *e > now);
            if let (false, Some(ends)) = (live, until(c.window_ends)) {
                counts.insert(slot, (c.count, ends));
                stored += 1;
            }
        }
        Ok(stored)
    }
}

#[cfg(test)]
mod tests;
