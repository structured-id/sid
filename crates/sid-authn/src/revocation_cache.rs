// SPDX-License-Identifier: AGPL-3.0-only
//! Token revocation cache shared by every replica and service.
//!
//! Every revocation is written to the shared cache as a key living as long as
//! the tokens it revokes, and published so that every process applies it to
//! its own map. A process answers "is this token revoked?" from that map
//! without a round trip once it has been subscribed for a full token
//! lifetime: every revocation older than that has expired with its tokens,
//! every newer one was delivered. Before that (just started, or resubscribing
//! after the subscription dropped) a local miss is confirmed against the
//! shared keys, so a new replica never accepts a token revoked before it
//! started.
//!
//! At the issuer, revocations are committed in its store
//! ([`RevocationCache::recorded_in`]): the shared cache only carries them to
//! the other replicas, so its outage or an empty restart loses none of them.
//! A publication that failed is recorded in the store too, and every replica
//! confirms its misses there until the tokens it may have missed expired.
//!
//! Two revocation scopes:
//! - **JTI**: single token revocation (e.g. `/oauth2/revoke` with access token)
//! - **Session**: all tokens for a session (e.g. session kill via gRPC)
//!
//! Entries auto-expire: JTI entries live until the token's `exp`, session
//! entries live for `max_token_lifetime` (the access token lifetime).

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sid_plugin::CeremonyStateStore;
use sid_plugin::cache::{CacheBackend, CacheError};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Pub/sub channel revocations travel on.
const REVOCATION_CHANNEL: &str = "sid:revocations";

/// Shared-cache key prefixes of the stored revocations.
const JTI_KEY: &str = "sid:revoked:jti:";
const SESSION_KEY: &str = "sid:revoked:session:";

/// Store namespaces of the committed revocations and of a lost publication.
const JTI_RECORD: &str = "revoked-jti";
const SESSION_RECORD: &str = "revoked-session";
const DELIVERY_RECORD: &str = "revocation-delivery";
const DELIVERY_GAP: &str = "gap";

/// Pause before resubscribing after the subscription ended.
const RESUBSCRIBE_DELAY: Duration = Duration::from_secs(1);

/// How often a store-backed process looks for a lost publication.
const HEARTBEAT: Duration = Duration::from_secs(1);

/// Where the revocations are committed.
enum Record {
    /// The issuer's store; the shared cache only propagates.
    Store(Arc<dyn CeremonyStateStore>),
    /// The shared cache's keys, for a verifier without the issuer's store.
    SharedCache,
}

/// `cold_until` value meaning "not subscribed": every local miss is confirmed.
const ALWAYS_COLD: u64 = u64::MAX;

/// One revocation as published to the other processes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Revocation {
    Jti { jti: String, ttl_ms: u64 },
    Session { session_id: String },
}

/// Revocation cache for JWT access tokens.
pub struct RevocationCache {
    /// Revoked JTIs → expiry instant.
    jtis: DashMap<String, Instant>,
    /// Revoked session IDs → expiry instant.
    sessions: DashMap<String, Instant>,
    /// Max access token lifetime (used as TTL for session-level revocations).
    max_token_lifetime: Duration,
    /// Where revocations are stored, published to and received from.
    shared: Arc<dyn CacheBackend>,
    /// Reference point of `cold_until`.
    origin: Instant,
    /// Milliseconds after `origin` until which the local maps may miss a
    /// revocation, or [`ALWAYS_COLD`] while not subscribed.
    cold_until: AtomicU64,
    /// Where revocations are committed and cold misses confirmed.
    record: Record,
    /// A publication was lost within a token lifetime (store-backed only):
    /// local misses are confirmed until it is no longer recorded.
    gap: AtomicBool,
}

impl std::fmt::Debug for RevocationCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationCache")
            .field("jtis", &self.jtis.len())
            .field("sessions", &self.sessions.len())
            .field("max_token_lifetime", &self.max_token_lifetime)
            .finish_non_exhaustive()
    }
}

impl RevocationCache {
    /// Create a revocation cache over `shared`; call [`listen`](Self::listen)
    /// to receive the other processes' revocations. Until then every local
    /// miss is confirmed against the shared cache.
    ///
    /// `max_token_lifetime` is the maximum access token TTL (e.g. 15 min).
    /// Session-level revocations expire after this duration (worst case:
    /// a token issued just before the session was killed).
    pub fn new(max_token_lifetime: Duration, shared: Arc<dyn CacheBackend>) -> Self {
        Self::with_record(max_token_lifetime, shared, Record::SharedCache)
    }

    /// The issuer's revocation cache: each revocation is committed in
    /// `store` and propagated over `shared`; cold misses are confirmed in
    /// `store`, so the shared cache is never needed for a correct answer.
    pub fn recorded_in(
        max_token_lifetime: Duration,
        shared: Arc<dyn CacheBackend>,
        store: Arc<dyn CeremonyStateStore>,
    ) -> Self {
        Self::with_record(max_token_lifetime, shared, Record::Store(store))
    }

    fn with_record(
        max_token_lifetime: Duration,
        shared: Arc<dyn CacheBackend>,
        record: Record,
    ) -> Self {
        Self {
            jtis: DashMap::new(),
            sessions: DashMap::new(),
            max_token_lifetime,
            shared,
            origin: Instant::now(),
            cold_until: AtomicU64::new(ALWAYS_COLD),
            record,
            gap: AtomicBool::new(false),
        }
    }

    /// Revoke a specific token by JTI, here and in every other process.
    ///
    /// `ttl` is the remaining lifetime of the access token (from now until
    /// `exp`), so at most `max_token_lifetime`. The revocation holds in this
    /// process even when it cannot be recorded; the error says it was not.
    /// Store-backed, a failed publication is no error: the store holds the
    /// revocation and records the lost delivery.
    pub async fn revoke_jti(&self, jti: String, ttl: Duration) -> Result<(), CacheError> {
        debug_assert!(
            ttl <= self.max_token_lifetime,
            "a revoked access token outlives the access token lifetime"
        );
        self.commit(JTI_RECORD, JTI_KEY, &jti, ttl).await?;
        self.propagate(Revocation::Jti {
            jti,
            ttl_ms: millis(ttl),
        })
        .await
    }

    /// Revoke all tokens for a session, here and in every other process.
    ///
    /// The entry is kept for `max_token_lifetime`: after that, all tokens
    /// for this session would have expired naturally anyway.
    pub async fn revoke_session(&self, session_id: String) -> Result<(), CacheError> {
        self.commit(
            SESSION_RECORD,
            SESSION_KEY,
            &session_id,
            self.max_token_lifetime,
        )
        .await?;
        self.propagate(Revocation::Session { session_id }).await
    }

    /// Record the revocation of `id` for `ttl` where revocations are
    /// committed. It applies here first, so this process refuses the token
    /// even when the record fails.
    async fn commit(
        &self,
        namespace: &str,
        prefix: &str,
        id: &str,
        ttl: Duration,
    ) -> Result<(), CacheError> {
        match &self.record {
            Record::Store(store) => {
                let committed = store.put_ceremony_state(namespace, id, &[], ttl).await;
                if committed.is_err() {
                    self.apply_now(namespace, id, ttl);
                }
                committed.map_err(|e| CacheError::Other(format!("revocation record: {e}")))
            }
            Record::SharedCache => {
                self.apply_now(namespace, id, ttl);
                self.shared.set(&format!("{prefix}{id}"), &[], ttl).await
            }
        }
    }

    fn apply_now(&self, namespace: &str, id: &str, ttl: Duration) {
        let expires = Instant::now() + ttl;
        if namespace == JTI_RECORD {
            self.jtis.insert(id.to_owned(), expires);
        } else {
            self.sessions.insert(id.to_owned(), expires);
        }
    }

    /// Apply `revocation` here and publish it to the other processes.
    async fn propagate(&self, revocation: Revocation) -> Result<(), CacheError> {
        self.apply(&revocation);
        let published = self.publish(&revocation).await;
        let Record::Store(store) = &self.record else {
            return published;
        };
        if let Err(e) = published {
            tracing::warn!(error = %e, "revocation not published, recording the lost delivery");
            // Every replica confirms its misses while this is live: no token
            // the lost message revoked outlives one token lifetime from now.
            store
                .put_ceremony_state(DELIVERY_RECORD, DELIVERY_GAP, &[], self.max_token_lifetime)
                .await
                .map_err(|e| CacheError::Other(format!("revocation delivery record: {e}")))?;
            self.gap.store(true, Ordering::Release);
        }
        Ok(())
    }

    /// Apply the revocations every process publishes, from now on, and keep
    /// doing so: when the subscription ends, or cannot be opened at all, a
    /// task subscribes again, and local misses are confirmed until the
    /// subscription has covered a full token lifetime. Store-backed, a
    /// heartbeat also watches for a lost publication.
    pub async fn listen(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let first = match self.shared.subscribe(REVOCATION_CHANNEL).await {
            Ok(received) => {
                self.warm_after_lifetime();
                Some(received)
            }
            Err(e) => {
                tracing::warn!(error = %e, "revocation subscription unavailable, confirming misses");
                None
            }
        };
        if let Record::Store(store) = &self.record {
            let cache = Arc::downgrade(self);
            let store = Arc::clone(store);
            tokio::spawn(async move {
                let mut beat = tokio::time::interval(HEARTBEAT);
                loop {
                    beat.tick().await;
                    let Some(cache) = cache.upgrade() else { return };
                    // An unreadable record counts as a gap: misses are then
                    // confirmed in the store, which answers or refuses.
                    let gap = !matches!(
                        store
                            .read_ceremony_state(DELIVERY_RECORD, DELIVERY_GAP)
                            .await,
                        Ok(None)
                    );
                    cache.gap.store(gap, Ordering::Release);
                }
            });
        }
        let cache = Arc::clone(self);
        tokio::spawn(async move {
            let mut received = first;
            loop {
                if let Some(mut stream) = received.take() {
                    while let Some(message) = stream.recv().await {
                        match serde_json::from_slice::<Revocation>(&message) {
                            Ok(revocation) => cache.apply(&revocation),
                            Err(e) => tracing::warn!(error = %e, "unreadable revocation message"),
                        }
                    }
                    cache.cold_until.store(ALWAYS_COLD, Ordering::Release);
                    tracing::warn!("revocation subscription ended, resubscribing");
                }
                tokio::time::sleep(RESUBSCRIBE_DELAY).await;
                match cache.shared.subscribe(REVOCATION_CHANNEL).await {
                    Ok(stream) => {
                        cache.warm_after_lifetime();
                        received = Some(stream);
                    }
                    Err(e) => tracing::warn!(error = %e, "revocation resubscribe failed"),
                }
            }
        })
    }

    /// Local answers become complete one token lifetime from now.
    fn warm_after_lifetime(&self) {
        let now = millis(self.origin.elapsed());
        let until = now
            .checked_add(millis(self.max_token_lifetime))
            .unwrap_or(ALWAYS_COLD);
        self.cold_until.store(until, Ordering::Release);
    }

    fn apply(&self, revocation: &Revocation) {
        let now = Instant::now();
        match revocation {
            Revocation::Jti { jti, ttl_ms } => {
                self.jtis
                    .insert(jti.clone(), now + Duration::from_millis(*ttl_ms));
            }
            Revocation::Session { session_id } => {
                self.sessions
                    .insert(session_id.clone(), now + self.max_token_lifetime);
            }
        }
    }

    async fn publish(&self, revocation: &Revocation) -> Result<(), CacheError> {
        let message =
            serde_json::to_vec(revocation).map_err(|e| CacheError::Serialization(e.to_string()))?;
        self.shared.publish(REVOCATION_CHANNEL, &message).await
    }

    /// Check if a token is revoked (by JTI or session ID).
    ///
    /// Returns `true` if the token should be rejected. Fails only while a
    /// local miss has to be confirmed and the record cannot answer; the
    /// caller must then refuse the token.
    pub async fn is_revoked(&self, jti: &str, session_id: &str) -> Result<bool, CacheError> {
        let now = Instant::now();
        if let Some(expires) = self.jtis.get(jti)
            && now < *expires
        {
            return Ok(true);
        }
        if let Some(expires) = self.sessions.get(session_id)
            && now < *expires
        {
            return Ok(true);
        }
        if millis(self.origin.elapsed()) >= self.cold_until.load(Ordering::Acquire)
            && !self.gap.load(Ordering::Acquire)
        {
            return Ok(false);
        }
        match &self.record {
            Record::Store(store) => {
                if recorded(store.as_ref(), JTI_RECORD, jti).await? {
                    return Ok(true);
                }
                recorded(store.as_ref(), SESSION_RECORD, session_id).await
            }
            Record::SharedCache => {
                if self.shared.exists(&format!("{JTI_KEY}{jti}")).await? {
                    return Ok(true);
                }
                self.shared
                    .exists(&format!("{SESSION_KEY}{session_id}"))
                    .await
            }
        }
    }

    /// Remove expired entries from both maps.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.jtis.retain(|_, expires| now < *expires);
        self.sessions.retain(|_, expires| now < *expires);
    }

    /// Total number of entries (JTIs + sessions).
    pub fn len(&self) -> usize {
        self.jtis.len() + self.sessions.len()
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.jtis.is_empty() && self.sessions.is_empty()
    }
}

/// Whether `store` holds a live revocation of `id` in `namespace`.
async fn recorded(
    store: &dyn CeremonyStateStore,
    namespace: &str,
    id: &str,
) -> Result<bool, CacheError> {
    store
        .read_ceremony_state(namespace, id)
        .await
        .map(|found| found.is_some())
        .map_err(|e| CacheError::Other(format!("revocation record: {e}")))
}

/// Whole milliseconds of `d`; token lifetimes and process uptimes are far
/// below the `u64` range.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).expect("duration fits u64 milliseconds")
}

#[cfg(test)]
mod tests;
