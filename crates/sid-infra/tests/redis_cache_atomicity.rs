// SPDX-License-Identifier: AGPL-3.0-only
//! The atomic cache operations, against a real Redis.
//!
//! `InMemoryCacheBackend` takes a mutex, so every one of these passes there
//! whatever the Redis implementation does. They are the operations that decide
//! whether a replayed JTI is rejected and whether a rate limit counts, and the
//! thing that has to be atomic is the command Redis executes, so this is where
//! they are checked.
//!
//! Run with: cargo nextest run -p sid-infra --test redis_cache_atomicity

use std::sync::Arc;
use std::time::Duration;

use sid_infra::RedisCacheBackend;
use sid_plugin::cache::CacheBackend;

fn redis_url() -> String {
    std::env::var("SID_TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:63799".to_string())
}

async fn cache() -> RedisCacheBackend {
    RedisCacheBackend::connect(&redis_url())
        .await
        .expect("Failed to connect to Redis. Is the test cache running?")
}

/// A key of its own per test: the server is shared and tests run in parallel.
fn key(name: &str) -> String {
    format!("test:{name}:{}", uuid::Uuid::now_v7())
}

#[tokio::test]
async fn test_set_get_delete_round_trip() {
    let c = cache().await;
    let k = key("roundtrip");

    assert!(c.get(&k).await.unwrap().is_none());
    c.set(&k, b"value", Duration::from_secs(60)).await.unwrap();
    assert_eq!(c.get(&k).await.unwrap().unwrap(), b"value");
    c.delete(&k).await.unwrap();
    assert!(c.get(&k).await.unwrap().is_none());
}

#[tokio::test]
async fn test_set_honours_its_ttl() {
    let c = cache().await;
    let k = key("ttl");

    c.set(&k, b"v", Duration::from_millis(100)).await.unwrap();
    assert!(c.get(&k).await.unwrap().is_some());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(c.get(&k).await.unwrap().is_none());
}

// ── set_nx ──

#[tokio::test]
async fn test_set_nx_first_call_wins() {
    let c = cache().await;
    let k = key("nx");

    assert!(
        c.set_nx(&k, b"first", Duration::from_secs(60))
            .await
            .unwrap()
    );
    assert!(
        !c.set_nx(&k, b"second", Duration::from_secs(60))
            .await
            .unwrap()
    );
    assert_eq!(
        c.get(&k).await.unwrap().unwrap(),
        b"first",
        "the refused call must not overwrite the value"
    );
}

/// What a replayed JTI or a duplicated callback actually looks like: many
/// callers reaching the same key at once. A check-then-set implementation
/// lets several through here.
#[tokio::test]
async fn test_set_nx_admits_exactly_one_of_many_racers() {
    let c = Arc::new(cache().await);
    let k = key("nx-race");

    let mut tasks = Vec::new();
    for _ in 0..32 {
        let c = c.clone();
        let k = k.clone();
        tasks.push(tokio::spawn(async move {
            c.set_nx(&k, b"1", Duration::from_secs(60)).await.unwrap()
        }));
    }

    let mut winners = 0;
    for t in tasks {
        if t.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "exactly one caller may claim the key");
}

#[tokio::test]
async fn test_set_nx_sets_a_ttl_so_a_claim_is_not_permanent() {
    let c = cache().await;
    let k = key("nx-ttl");

    assert!(
        c.set_nx(&k, b"1", Duration::from_millis(100))
            .await
            .unwrap()
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        c.set_nx(&k, b"1", Duration::from_millis(100))
            .await
            .unwrap(),
        "an expired claim can be made again"
    );
}

// ── take ──

#[tokio::test]
async fn test_take_returns_the_value_once() {
    let c = cache().await;
    let k = key("take");

    c.set(&k, b"state", Duration::from_secs(60)).await.unwrap();
    assert_eq!(c.take(&k).await.unwrap().as_deref(), Some(&b"state"[..]));
    assert!(c.take(&k).await.unwrap().is_none());
    assert!(c.get(&k).await.unwrap().is_none());
}

/// A ceremony finished twice at once, on two replicas: a read-then-delete
/// implementation hands the single-use state to both.
#[tokio::test]
async fn test_take_gives_the_value_to_exactly_one_of_many_racers() {
    let c = Arc::new(cache().await);
    let k = key("take-race");
    c.set(&k, b"state", Duration::from_secs(60)).await.unwrap();

    let mut tasks = Vec::new();
    for _ in 0..32 {
        let c = c.clone();
        let k = k.clone();
        tasks.push(tokio::spawn(async move { c.take(&k).await.unwrap() }));
    }

    let mut winners = 0;
    for t in tasks {
        if t.await.unwrap().is_some() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "exactly one caller may take the value");
}

#[tokio::test]
async fn test_take_of_an_expired_key_returns_nothing() {
    let c = cache().await;
    let k = key("take-ttl");

    c.set(&k, b"state", Duration::from_millis(100))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(c.take(&k).await.unwrap().is_none());
}

// ── incr ──

#[tokio::test]
async fn test_incr_counts_from_zero() {
    let c = cache().await;
    let k = key("incr");

    assert_eq!(c.incr(&k, Duration::from_secs(60)).await.unwrap(), 1);
    assert_eq!(c.incr(&k, Duration::from_secs(60)).await.unwrap(), 2);
    assert_eq!(c.incr(&k, Duration::from_secs(60)).await.unwrap(), 3);
}

/// A rate limiter that loses increments under load stops limiting exactly when
/// it is needed. A read-modify-write implementation loses them here.
#[tokio::test]
async fn test_incr_loses_nothing_under_concurrency() {
    let c = Arc::new(cache().await);
    let k = key("incr-race");

    let mut tasks = Vec::new();
    for _ in 0..64 {
        let c = c.clone();
        let k = k.clone();
        tasks.push(tokio::spawn(async move {
            c.incr(&k, Duration::from_secs(60)).await.unwrap()
        }));
    }

    let mut seen = Vec::new();
    for t in tasks {
        seen.push(t.await.unwrap());
    }
    seen.sort_unstable();
    assert_eq!(
        seen,
        (1..=64).collect::<Vec<u64>>(),
        "every caller must get its own number, and 64 increments must reach 64"
    );
}

#[tokio::test]
async fn test_incr_window_expires() {
    let c = cache().await;
    let k = key("incr-ttl");

    assert_eq!(c.incr(&k, Duration::from_secs(1)).await.unwrap(), 1);
    assert_eq!(c.incr(&k, Duration::from_secs(1)).await.unwrap(), 2);
    tokio::time::sleep(Duration::from_millis(1400)).await;
    assert_eq!(
        c.incr(&k, Duration::from_secs(1)).await.unwrap(),
        1,
        "the counter restarts in the next window"
    );
}

/// A later increment must not push the window out, or a caller sending
/// steadily would never see it close.
#[tokio::test]
async fn test_incr_does_not_extend_the_window() {
    let c = cache().await;
    let k = key("incr-window");

    assert_eq!(c.incr(&k, Duration::from_secs(1)).await.unwrap(), 1);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(c.incr(&k, Duration::from_secs(1)).await.unwrap(), 2);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        c.incr(&k, Duration::from_secs(1)).await.unwrap(),
        1,
        "the window is measured from the first increment"
    );
}
