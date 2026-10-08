// SPDX-License-Identifier: AGPL-3.0-only
use std::sync::Arc;

use async_trait::async_trait;
use sid_plugin::cache::{CacheResult, InMemoryCacheBackend};
use tokio::sync::mpsc;

use super::*;

const LONG: Duration = Duration::from_secs(3600);

/// The shipped lifetime of a pending authorization. None of these tests is
/// about that number, so they all take the configured default and say so once
/// here rather than at every construction.
const PENDING: Duration = Duration::from_secs(300);

/// A store with the two session lifetimes a test cares about.
fn build(
    cache: Arc<dyn CacheBackend>,
    max_age: Duration,
    idle_timeout: Duration,
) -> BffSessionStore {
    BffSessionStore::new(cache, max_age, idle_timeout, PENDING)
}

fn store() -> BffSessionStore {
    build(Arc::new(InMemoryCacheBackend::new()), LONG, LONG)
}

/// Two stores over one cache: what a load balancer does to a BFF.
fn replica_pair() -> (BffSessionStore, BffSessionStore) {
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    (build(cache.clone(), LONG, LONG), build(cache, LONG, LONG))
}

fn test_claims() -> ForwardAuthClaims {
    ForwardAuthClaims {
        sub: "up_01HY000000000000000000".into(),
        iss: "https://sid.example.com".into(),
        exp: 0,
        iat: 0,
        auth_time: 0,
        acr: "standard".into(),
        scope: "openid".into(),
        roles: String::new(),
        sid: "sess_01HY000000000000000000".into(),
        jti: "tok_01HY000000000000000000".into(),
        email: Some("user@sid.example.com".into()),
        name: None,
        preferred_username: None,
        groups: None,
        cnf: None,
    }
}

/// A working cache that counts its writes, so a test can say how many round
/// trips a read costs.
struct CountingCache {
    inner: InMemoryCacheBackend,
    writes: std::sync::atomic::AtomicUsize,
}

impl CountingCache {
    fn new() -> Self {
        Self {
            inner: InMemoryCacheBackend::new(),
            writes: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn writes(&self) -> usize {
        self.writes.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[async_trait]
impl CacheBackend for CountingCache {
    async fn get(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        self.inner.get(key).await
    }
    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<()> {
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.set(key, value, ttl).await
    }
    async fn delete(&self, key: &str) -> CacheResult<()> {
        self.inner.delete(key).await
    }
    async fn take(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        self.inner.take(key).await
    }
    async fn set_nx(&self, key: &str, value: &[u8], ttl: Duration) -> CacheResult<bool> {
        self.inner.set_nx(key, value, ttl).await
    }
    async fn publish(&self, channel: &str, message: &[u8]) -> CacheResult<()> {
        self.inner.publish(channel, message).await
    }
    async fn subscribe(&self, channel: &str) -> CacheResult<mpsc::UnboundedReceiver<Vec<u8>>> {
        self.inner.subscribe(channel).await
    }
    async fn health_check(&self) -> CacheResult<()> {
        self.inner.health_check().await
    }
}

/// A backend whose every call fails, to prove the store reports the failure
/// instead of reporting an empty store.
struct BrokenCache;

#[async_trait]
impl CacheBackend for BrokenCache {
    async fn get(&self, _key: &str) -> CacheResult<Option<Vec<u8>>> {
        Err(CacheError::Connection("down".into()))
    }
    async fn set(&self, _key: &str, _value: &[u8], _ttl: Duration) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
    async fn delete(&self, _key: &str) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
    async fn take(&self, _key: &str) -> CacheResult<Option<Vec<u8>>> {
        Err(CacheError::Connection("down".into()))
    }
    async fn set_nx(&self, _key: &str, _value: &[u8], _ttl: Duration) -> CacheResult<bool> {
        Err(CacheError::Connection("down".into()))
    }
    async fn publish(&self, _channel: &str, _message: &[u8]) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
    async fn subscribe(&self, _channel: &str) -> CacheResult<mpsc::UnboundedReceiver<Vec<u8>>> {
        Err(CacheError::Connection("down".into()))
    }
    async fn health_check(&self) -> CacheResult<()> {
        Err(CacheError::Connection("down".into()))
    }
}

// ── Sessions ──

#[tokio::test]
async fn test_create_and_get_session() {
    let s = store();
    let (id, csrf) = s
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();

    let got = s.get_session(&id).await.unwrap().expect("session exists");
    assert_eq!(got.access_token, "access");
    assert_eq!(got.csrf_token, csrf);
    assert_eq!(got.claims.sub, "up_01HY000000000000000000");
}

#[tokio::test]
async fn test_create_session_with_refresh_token() {
    let s = store();
    let (id, _) = s
        .create_session("access".into(), Some("refresh".into()), test_claims())
        .await
        .unwrap();
    let got = s.get_session(&id).await.unwrap().unwrap();
    assert_eq!(got.refresh_token.as_deref(), Some("refresh"));
}

#[tokio::test]
async fn test_nonexistent_session() {
    let s = store();
    assert!(s.get_session("nope").await.unwrap().is_none());
}

#[tokio::test]
async fn test_destroy_session() {
    let s = store();
    let (id, _) = s
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    s.destroy_session(&id).await.unwrap();
    assert!(s.get_session(&id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_destroy_nonexistent_is_noop() {
    let s = store();
    s.destroy_session("nope").await.unwrap();
}

#[tokio::test]
async fn test_destroy_twice_is_idempotent() {
    let s = store();
    let (id, _) = s
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    s.destroy_session(&id).await.unwrap();
    s.destroy_session(&id).await.unwrap();
    assert!(s.get_session(&id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_get_session_updates_last_access() {
    let s = store();
    let (id, _) = s
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    let first = s.get_session(&id).await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    let second = s.get_session(&id).await.unwrap().unwrap();
    assert!(second.last_access > first.last_access);
    assert_eq!(
        second.created_at, first.created_at,
        "creation does not move"
    );
}

/// Reads are the common case, so a read inside the refresh threshold must not
/// cost a write to the shared store.
#[tokio::test]
async fn test_a_read_within_half_the_window_writes_nothing() {
    let cache = Arc::new(CountingCache::new());
    let s = build(cache.clone(), LONG, Duration::from_secs(3600));
    let (id, _) = s
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    let after_create = cache.writes();

    for _ in 0..5 {
        assert!(s.get_session(&id).await.unwrap().is_some());
    }
    assert_eq!(
        cache.writes(),
        after_create,
        "five reads inside the window cost no write"
    );
}

/// Past the threshold the window is pushed out, or a session in steady use
/// would expire mid-use.
#[tokio::test]
async fn test_a_read_past_half_the_window_refreshes_it() {
    let cache = Arc::new(CountingCache::new());
    let s = build(cache.clone(), LONG, Duration::from_millis(100));
    let (id, _) = s
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    let after_create = cache.writes();

    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(s.get_session(&id).await.unwrap().is_some());
    assert_eq!(
        cache.writes(),
        after_create + 1,
        "the window was pushed out"
    );

    // And the session outlives the original window because of it.
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(s.get_session(&id).await.unwrap().is_some());
}

#[tokio::test]
async fn test_create_multiple_sessions_unique_ids() {
    let s = store();
    let (a, _) = s
        .create_session("a".into(), None, test_claims())
        .await
        .unwrap();
    let (b, _) = s
        .create_session("b".into(), None, test_claims())
        .await
        .unwrap();
    assert_ne!(a, b);
    assert_eq!(s.get_session(&a).await.unwrap().unwrap().access_token, "a");
    assert_eq!(s.get_session(&b).await.unwrap().unwrap().access_token, "b");
}

#[tokio::test]
async fn test_session_id_is_hex_of_32_bytes() {
    let s = store();
    let (id, csrf) = s
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    for token in [&id, &csrf] {
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }
    assert_ne!(id, csrf, "the CSRF token is not the session id");
}

// ── Expiry ──

/// The idle window is the cache's TTL: an untouched session disappears.
#[tokio::test]
async fn test_session_expires_when_idle() {
    let s = build(
        Arc::new(InMemoryCacheBackend::new()),
        LONG,
        Duration::from_millis(50),
    );
    let (id, _) = s
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(s.get_session(&id).await.unwrap().is_none());
}

/// Use keeps a session alive against the idle window: five uses 150ms apart
/// span 750ms, well past a 400ms window, and each gap leaves 250ms of margin
/// for a loaded test host.
#[tokio::test]
async fn test_use_pushes_the_idle_window_out() {
    let s = build(
        Arc::new(InMemoryCacheBackend::new()),
        LONG,
        Duration::from_millis(400),
    );
    let (id, _) = s
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            s.get_session(&id).await.unwrap().is_some(),
            "a session used every 150ms must survive a 400ms idle window"
        );
    }
}

/// The absolute deadline is not the idle one: a session in constant use still
/// ends. Without this the idle refresh would keep a session alive forever.
#[tokio::test]
async fn test_session_expires_at_max_age_despite_use() {
    let s = build(
        Arc::new(InMemoryCacheBackend::new()),
        Duration::from_millis(60),
        LONG,
    );
    let (id, _) = s
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(s.get_session(&id).await.unwrap().is_some(), "still young");

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(s.get_session(&id).await.unwrap().is_none(), "past max_age");
}

/// A session refused for age is also removed, not left for the next reader.
#[tokio::test]
async fn test_expired_session_is_deleted_not_just_hidden() {
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let s = build(cache.clone(), Duration::from_millis(40), LONG);
    let (id, _) = s
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(s.get_session(&id).await.unwrap().is_none());
    assert!(
        cache.get(&session_key(&id)).await.unwrap().is_none(),
        "the entry is gone from the cache"
    );
}

// ── Pending authorizations ──

/// The configured lifetime is the one a half-finished login actually gets.
/// Deployments set this to fit their login path, so a value that were read
/// but not applied would be worse than none: it would read as enforced.
#[tokio::test]
async fn test_pending_expires_on_its_configured_ttl() {
    let s = BffSessionStore::new(
        Arc::new(InMemoryCacheBackend::new()),
        LONG,
        LONG,
        Duration::from_millis(50),
    );
    let state = s
        .store_pending("verifier".into(), "nonce".into(), "/dashboard".into())
        .await
        .unwrap();

    assert!(
        s.take_pending(&state).await.unwrap().is_some(),
        "still inside the window"
    );

    let state = s
        .store_pending("verifier".into(), "nonce".into(), "/dashboard".into())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        s.take_pending(&state).await.unwrap().is_none(),
        "a callback arriving after the configured window gets nothing"
    );
}

/// A longer configured window really does keep the authorization alive: the
/// test above would also pass if the TTL were hardcoded to something short.
#[tokio::test]
async fn test_a_longer_configured_ttl_outlives_the_old_default() {
    let s = BffSessionStore::new(Arc::new(InMemoryCacheBackend::new()), LONG, LONG, LONG);
    let state = s
        .store_pending("verifier".into(), "nonce".into(), "/dashboard".into())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(s.take_pending(&state).await.unwrap().is_some());
}

#[tokio::test]
async fn test_store_pending_returns_unique_state() {
    let s = store();
    let a = s
        .store_pending("v1".into(), "n1".into(), "/a".into())
        .await
        .unwrap();
    let b = s
        .store_pending("v2".into(), "n2".into(), "/b".into())
        .await
        .unwrap();
    assert_ne!(a, b);
}

#[tokio::test]
async fn test_take_pending_returns_what_was_stored() {
    let s = store();
    let state = s
        .store_pending("verifier".into(), "nonce".into(), "/after-login".into())
        .await
        .unwrap();
    let taken = s.take_pending(&state).await.unwrap().expect("pending");
    assert_eq!(taken.code_verifier, "verifier");
    assert_eq!(taken.nonce, "nonce");
    assert_eq!(taken.redirect_url, "/after-login");
}

#[tokio::test]
async fn test_take_pending_consumes_it() {
    let s = store();
    let state = s
        .store_pending("v".into(), "n".into(), "/".into())
        .await
        .unwrap();
    assert!(s.take_pending(&state).await.unwrap().is_some());
    assert!(
        s.take_pending(&state).await.unwrap().is_none(),
        "a second callback with the same state gets nothing"
    );
}

#[tokio::test]
async fn test_take_pending_nonexistent() {
    let s = store();
    assert!(s.take_pending("never-issued").await.unwrap().is_none());
}

/// The replay this protects against arrives at two replicas at once. Exactly
/// one of them may proceed.
#[tokio::test]
async fn test_take_pending_is_claimed_once_across_replicas() {
    let (a, b) = replica_pair();
    let state = a
        .store_pending("v".into(), "n".into(), "/".into())
        .await
        .unwrap();

    let (first, second) = tokio::join!(a.take_pending(&state), b.take_pending(&state));
    let winners = [first.unwrap().is_some(), second.unwrap().is_some()]
        .iter()
        .filter(|w| **w)
        .count();
    assert_eq!(winners, 1, "exactly one replica may consume the state");
}

// ── Across replicas ──

/// The gap itself: login lands on one replica, the callback on another.
#[tokio::test]
async fn test_session_created_on_one_replica_is_readable_on_another() {
    let (a, b) = replica_pair();
    let (id, csrf) = a
        .create_session("access".into(), Some("refresh".into()), test_claims())
        .await
        .unwrap();

    let got = b.get_session(&id).await.unwrap().expect("visible on B");
    assert_eq!(got.access_token, "access");
    assert_eq!(got.csrf_token, csrf);
}

#[tokio::test]
async fn test_pending_stored_on_one_replica_is_taken_on_another() {
    let (a, b) = replica_pair();
    let state = a
        .store_pending("verifier".into(), "nonce".into(), "/done".into())
        .await
        .unwrap();
    let taken = b.take_pending(&state).await.unwrap().expect("visible on B");
    assert_eq!(taken.code_verifier, "verifier");
}

/// Logout must end the session everywhere, not only where it was called.
#[tokio::test]
async fn test_logout_on_one_replica_ends_the_session_on_another() {
    let (a, b) = replica_pair();
    let (id, _) = a
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    a.destroy_session(&id).await.unwrap();
    assert!(b.get_session(&id).await.unwrap().is_none());
}

/// A replica that starts later serves sessions opened before it existed —
/// what a rolling update does.
#[tokio::test]
async fn test_a_replica_started_later_sees_existing_sessions() {
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let old = build(cache.clone(), LONG, LONG);
    let (id, _) = old
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    drop(old);

    let fresh = build(cache, LONG, LONG);
    assert!(fresh.get_session(&id).await.unwrap().is_some());
}

// ── Failure is reported, not disguised ──

/// An id of the shape the store issues, so the call reaches the backend
/// instead of stopping at the shape check.
fn plausible_id() -> String {
    "a".repeat(64)
}

#[tokio::test]
async fn test_unreachable_cache_is_an_error_not_an_empty_store() {
    let s = build(Arc::new(BrokenCache), LONG, LONG);
    assert!(matches!(
        s.get_session(&plausible_id()).await,
        Err(SessionStoreError::Backend(_))
    ));
    assert!(matches!(
        s.create_session("a".into(), None, test_claims()).await,
        Err(SessionStoreError::Backend(_))
    ));
    assert!(matches!(
        s.destroy_session(&plausible_id()).await,
        Err(SessionStoreError::Backend(_))
    ));
}

/// The dangerous one: a broken cache must not let a pending authorization look
/// freshly claimable.
#[tokio::test]
async fn test_unreachable_cache_does_not_hand_out_a_pending_authorization() {
    let s = build(Arc::new(BrokenCache), LONG, LONG);
    assert!(matches!(
        s.take_pending(&plausible_id()).await,
        Err(SessionStoreError::Backend(_))
    ));
    assert!(matches!(
        s.store_pending("v".into(), "n".into(), "/".into()).await,
        Err(SessionStoreError::Backend(_))
    ));
}

#[tokio::test]
async fn test_unreadable_value_is_an_error_not_a_missing_session() {
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let id = plausible_id();
    cache
        .set(&session_key(&id), b"not json", LONG)
        .await
        .unwrap();
    let s = build(cache, LONG, LONG);
    assert!(matches!(
        s.get_session(&id).await,
        Err(SessionStoreError::Corrupt(_))
    ));
}

// ── Keys and redaction ──

/// Sessions and pending authorizations share a cache with everything else that
/// uses one; their keys must not collide with each other or with a bare id.
#[tokio::test]
async fn test_a_pending_state_is_not_readable_as_a_session() {
    let (a, _b) = replica_pair();
    let state = a
        .store_pending("v".into(), "n".into(), "/".into())
        .await
        .unwrap();
    assert!(a.get_session(&state).await.unwrap().is_none());
}

/// The id comes from a cookie, so it is client input. Anything that is not
/// the shape we issue is refused before it reaches the shared cache.
#[tokio::test]
async fn test_a_client_supplied_id_of_the_wrong_shape_never_reaches_the_cache() {
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let s = build(cache.clone(), LONG, LONG);

    // Planted under the key such an id would produce, to show it is not read.
    cache
        .set(&session_key("../other"), b"{}", LONG)
        .await
        .unwrap();

    for bogus in ["", "short", "../other", &"g".repeat(64), &"a".repeat(65)] {
        assert!(
            s.get_session(bogus).await.unwrap().is_none(),
            "accepted {bogus:?}"
        );
        assert!(s.take_pending(bogus).await.unwrap().is_none());
    }
}

/// The check must not reject what the store itself issues.
#[tokio::test]
async fn test_issued_ids_pass_the_shape_check() {
    let s = store();
    let (id, _) = s
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    assert!(s.get_session(&id).await.unwrap().is_some());

    let state = s
        .store_pending("v".into(), "n".into(), "/".into())
        .await
        .unwrap();
    assert!(s.take_pending(&state).await.unwrap().is_some());
}

#[test]
fn test_debug_hides_the_tokens() {
    let session = BffSession {
        access_token: "super-secret-access".into(),
        refresh_token: Some("super-secret-refresh".into()),
        claims: test_claims(),
        csrf_token: "super-secret-csrf".into(),
        created_at: Utc::now(),
        last_access: Utc::now(),
    };
    let rendered = format!("{session:?}");
    assert!(!rendered.contains("super-secret"), "{rendered}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(
        rendered.contains("up_01HY000000000000000000"),
        "the subject stays, so a log still identifies the session"
    );
}
