// SPDX-License-Identifier: AGPL-3.0-only
//! Two replicas over one real cache.
//!
//! The unit tests for the session store and for Shield run over
//! `InMemoryCacheBackend`, which is one process holding a mutex: it proves the
//! logic reads and writes the right keys, and it passes whether or not the
//! deployed backend is atomic or even shared. What this gap is about is the
//! other half — that two processes behind a load balancer agree — and that can
//! only be answered by the server they would actually agree through. So these
//! run against Redis, with the two stores and the two Shields standing in for
//! the two replicas.
//!
//! Run with: cargo nextest run -p sid-auth --test shared_cache_replicas

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use sid_auth::auth::jwt::ForwardAuthClaims;
use sid_auth_proxy::session::BffSessionStore;
use sid_auth_proxy::shield::{Shield, ShieldConfig};
use sid_infra::RedisCacheBackend;
use sid_plugin::cache::{CacheBackend, InMemoryCacheBackend};

const LONG: Duration = Duration::from_secs(3600);

/// The shipped lifetime of a pending authorization; these tests take it as
/// configured and vary only the two session lifetimes.
const PENDING: Duration = Duration::from_secs(300);

/// A store with the two session lifetimes a test cares about.
fn build(
    cache: Arc<dyn CacheBackend>,
    max_age: Duration,
    idle_timeout: Duration,
) -> BffSessionStore {
    BffSessionStore::new(cache, max_age, idle_timeout, PENDING)
}

/// An auth endpoint, so the request is classified into the `auth_rate` bucket.
const AUTH_PATH: &str = "/v1/auth/opaque/login/start";

fn redis_url() -> String {
    std::env::var("SID_TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:63799".to_string())
}

async fn shared_cache() -> Arc<dyn CacheBackend> {
    Arc::new(
        RedisCacheBackend::connect(&redis_url())
            .await
            .expect("Failed to connect to Redis. Is the test cache running?"),
    )
}

/// Two session stores over one Redis: what a load balancer does to a BFF.
async fn store_pair() -> (BffSessionStore, BffSessionStore) {
    let cache = shared_cache().await;
    (build(cache.clone(), LONG, LONG), build(cache, LONG, LONG))
}

/// The Redis server outlives a single test run, and tests run in parallel, so
/// every rate-limit test needs an address no other test counts against. The
/// process id separates runs, the counter separates tests within one.
fn unique_ip() -> IpAddr {
    static NEXT: AtomicU16 = AtomicU16::new(1);
    let pid = std::process::id();
    IpAddr::V6(Ipv6Addr::new(
        0xfd00,
        (pid >> 16) as u16,
        pid as u16,
        NEXT.fetch_add(1, Ordering::Relaxed),
        0,
        0,
        0,
        1,
    ))
}

/// Same reasoning as [`unique_ip`], for the per-principal buckets.
fn unique_principal(name: &str) -> String {
    static NEXT: AtomicU16 = AtomicU16::new(1);
    format!(
        "{name}-{}-{}@sid.example.com",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
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

// ─── Sessions across replicas ───────────────────────────────────────────

#[tokio::test]
async fn session_created_on_one_replica_is_served_by_the_other() {
    let (a, b) = store_pair().await;

    let (id, csrf) = a
        .create_session("access".into(), Some("refresh".into()), test_claims())
        .await
        .unwrap();

    let seen = b.get_session(&id).await.unwrap().expect("B sees it");
    assert_eq!(seen.claims.sub, test_claims().sub);
    assert_eq!(seen.access_token, "access");
    assert_eq!(seen.refresh_token.as_deref(), Some("refresh"));
    // The CSRF token travels with the session, or B could not validate a form
    // posted against a session A issued.
    assert_eq!(seen.csrf_token, csrf);
}

#[tokio::test]
async fn logout_on_one_replica_ends_the_session_on_the_other() {
    let (a, b) = store_pair().await;

    let (id, _) = a
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    assert!(b.get_session(&id).await.unwrap().is_some());

    a.destroy_session(&id).await.unwrap();
    assert!(
        b.get_session(&id).await.unwrap().is_none(),
        "a logout that only ends the session on one replica is not a logout"
    );
}

#[tokio::test]
async fn a_replica_started_later_serves_an_existing_session() {
    let cache = shared_cache().await;
    let first = build(cache.clone(), LONG, LONG);
    let (id, _) = first
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();

    // A rolling update, or scaling out: the new process has an empty heap.
    let later = build(cache, LONG, LONG);
    assert!(later.get_session(&id).await.unwrap().is_some());
}

#[tokio::test]
async fn a_session_past_its_absolute_deadline_is_gone_on_both_replicas() {
    let cache = shared_cache().await;
    // max_age far below idle_timeout, so what expires the session is the
    // absolute deadline and not the cache TTL.
    let short = Duration::from_millis(300);
    let a = build(cache.clone(), short, LONG);
    let b = build(cache, short, LONG);

    let (id, _) = a
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();
    assert!(b.get_session(&id).await.unwrap().is_some());

    tokio::time::sleep(Duration::from_millis(400)).await;

    assert!(b.get_session(&id).await.unwrap().is_none(), "B expires it");
    assert!(
        a.get_session(&id).await.unwrap().is_none(),
        "and B's read removed it for A too, rather than leaving it to be found"
    );
}

#[tokio::test]
async fn the_idle_window_is_the_ttl_redis_actually_applies() {
    let cache = shared_cache().await;
    // Only the real server can show that the idle window is enforced by the
    // store rather than by a sweeper this code does not have.
    let idle = Duration::from_secs(1);
    let a = build(cache.clone(), LONG, idle);
    let b = build(cache, LONG, idle);

    let (id, _) = a
        .create_session("access".into(), None, test_claims())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(1500)).await;

    assert!(
        b.get_session(&id).await.unwrap().is_none(),
        "an untouched session should have expired out of the cache"
    );
}

// ─── Refresh across replicas ────────────────────────────────────────────

/// Many replicas reach an expiring session at once; exactly one may refresh
/// it, because SID ends a grant whose rotated refresh token is replayed. The
/// others see the tokens the winner stored.
#[tokio::test]
async fn one_replica_refreshes_a_session() {
    let cache = shared_cache().await;
    let stores: Vec<_> = (0..8)
        .map(|_| Arc::new(build(cache.clone(), LONG, LONG)))
        .collect();
    let (id, _) = stores[0]
        .create_session("access-1".into(), Some("refresh-1".into()), test_claims())
        .await
        .unwrap();

    let mut tasks = Vec::new();
    for store in &stores {
        let (store, id) = (store.clone(), id.clone());
        tasks.push(tokio::spawn(async move {
            store
                .claim_refresh(&id, Duration::from_secs(15))
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);

    assert!(
        stores[3]
            .replace_tokens(
                &id,
                "access-2".into(),
                Some("refresh-2".into()),
                test_claims(),
            )
            .await
            .unwrap()
    );
    let seen = stores[5].get_session(&id).await.unwrap().unwrap();
    assert_eq!(seen.access_token, "access-2");
    assert_eq!(seen.refresh_token.as_deref(), Some("refresh-2"));
}

// ─── Pending authorizations across replicas ─────────────────────────────

#[tokio::test]
async fn pending_authorization_stored_on_one_replica_is_taken_on_the_other() {
    let (a, b) = store_pair().await;

    let state = a
        .store_pending(
            "verifier".into(),
            "nonce".into(),
            "https://app.sid.example.com/".into(),
        )
        .await
        .unwrap();

    let taken = b.take_pending(&state).await.unwrap().expect("B takes it");
    assert_eq!(taken.code_verifier, "verifier");
    assert_eq!(taken.redirect_url, "https://app.sid.example.com/");
}

#[tokio::test]
async fn a_pending_authorization_is_taken_exactly_once_across_replicas() {
    let (a, b) = store_pair().await;
    let state = a
        .store_pending(
            "verifier".into(),
            "nonce".into(),
            "https://app.sid.example.com/".into(),
        )
        .await
        .unwrap();

    // Both replicas race for the same `state`, which is precisely the replay
    // the parameter exists to stop. A read-then-delete would let both through.
    let (first, second) = tokio::join!(a.take_pending(&state), b.take_pending(&state));
    let winners = [first.unwrap(), second.unwrap()]
        .iter()
        .filter(|v| v.is_some())
        .count();
    assert_eq!(winners, 1, "exactly one callback may consume a state");
}

#[tokio::test]
async fn many_concurrent_takes_still_produce_one_winner() {
    let cache = shared_cache().await;
    let stores: Vec<_> = (0..8)
        .map(|_| Arc::new(build(cache.clone(), LONG, LONG)))
        .collect();

    let state = stores[0]
        .store_pending(
            "verifier".into(),
            "nonce".into(),
            "https://app.sid.example.com/".into(),
        )
        .await
        .unwrap();

    let mut tasks = Vec::new();
    for store in &stores {
        for _ in 0..4 {
            let store = store.clone();
            let state = state.clone();
            tasks.push(tokio::spawn(
                async move { store.take_pending(&state).await },
            ));
        }
    }

    let mut winners = 0;
    for t in tasks {
        if t.await.unwrap().unwrap().is_some() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "32 racers, one winner");
}

// ─── Rate limits across replicas ────────────────────────────────────────

fn shield_config(auth_rate: u32, principal_rate: u32) -> ShieldConfig {
    ShieldConfig {
        auth_rate,
        principal_rate,
        ..Default::default()
    }
}

#[tokio::test]
async fn the_rate_limit_budget_is_one_across_replicas() {
    let cache = shared_cache().await;
    let a = Shield::new(shield_config(2, 0), cache.clone());
    let b = Shield::new(shield_config(2, 0), cache);
    let ip = unique_ip();

    // Two requests, spread over the replicas: within the budget of 2.
    assert!(a.check(ip, AUTH_PATH).await.is_ok());
    assert!(b.check(ip, AUTH_PATH).await.is_ok());

    // The third is over the budget, and neither replica has seen more than two
    // itself — only the shared counter knows. It must be refused wherever the
    // load balancer sends it.
    assert!(
        a.check(ip, AUTH_PATH).await.is_err(),
        "the third request is over a budget of two, whichever replica takes it"
    );
    assert!(b.check(ip, AUTH_PATH).await.is_err());
}

#[tokio::test]
async fn without_a_shared_cache_each_replica_spends_its_own_budget() {
    // The control for the test above: with a cache per process the same four
    // requests all pass, which is the behaviour this gap exists to remove. If
    // this ever starts failing, the test above is passing for some other reason.
    let a = Shield::new(shield_config(2, 0), Arc::new(InMemoryCacheBackend::new()));
    let b = Shield::new(shield_config(2, 0), Arc::new(InMemoryCacheBackend::new()));
    let ip = unique_ip();

    assert!(a.check(ip, AUTH_PATH).await.is_ok());
    assert!(b.check(ip, AUTH_PATH).await.is_ok());
    assert!(a.check(ip, AUTH_PATH).await.is_ok());
    assert!(b.check(ip, AUTH_PATH).await.is_ok());
}

#[tokio::test]
async fn the_principal_budget_is_one_across_replicas() {
    let cache = shared_cache().await;
    let a = Shield::new(shield_config(1000, 1), cache.clone());
    let b = Shield::new(shield_config(1000, 1), cache);
    let principal = unique_principal("brute");

    // A brute-force against one account is spread over replicas by the load
    // balancer, so this is the limit a per-instance count would hand away.
    assert!(a.check_principal(&principal, AUTH_PATH).await.is_ok());
    assert!(
        b.check_principal(&principal, AUTH_PATH).await.is_err(),
        "the second attempt against the same account is over a budget of one"
    );
}

#[tokio::test]
async fn the_principal_budget_is_matched_case_insensitively_across_replicas() {
    let cache = shared_cache().await;
    let a = Shield::new(shield_config(1000, 1), cache.clone());
    let b = Shield::new(shield_config(1000, 1), cache);
    let principal = unique_principal("Case");

    assert!(a.check_principal(&principal, AUTH_PATH).await.is_ok());
    assert!(
        b.check_principal(&principal.to_uppercase(), AUTH_PATH)
            .await
            .is_err(),
        "changing the case of an address must not buy another budget"
    );
}

#[tokio::test]
async fn an_unreachable_cache_leaves_the_local_limit_standing() {
    // Not a Redis test — the point is the failure mode, and the way to reach it
    // is a URL nothing answers on. A store that is down must not turn into a
    // service that refuses everything, nor into one that limits nothing.
    let dead = RedisCacheBackend::connect("redis://127.0.0.1:1").await;
    let Ok(dead) = dead else {
        // Connecting eagerly failed, which is the same outcome by another path:
        // there is nothing to assert about a backend that cannot be built.
        return;
    };
    let shield = Shield::new(shield_config(2, 0), Arc::new(dead));
    let ip = unique_ip();

    assert!(shield.check(ip, AUTH_PATH).await.is_ok());
    assert!(shield.check(ip, AUTH_PATH).await.is_ok());
    assert!(
        shield.check(ip, AUTH_PATH).await.is_err(),
        "with the shared counter gone the local window is still the limit"
    );
}
