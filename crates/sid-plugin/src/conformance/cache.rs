// SPDX-License-Identifier: AGPL-3.0-only
//! What every [`CacheBackend`] that offers compare-and-set owes its caller.
//! Each scenario takes a key prefix of its own, since a real server is shared.

use std::time::Duration;

use crate::cache::CacheBackend;

const TTL: Duration = Duration::from_secs(60);

/// A value equal to the expected one is replaced, with the new TTL's life.
pub async fn compare_and_set_replaces_the_expected_value<B: CacheBackend + ?Sized>(
    cache: &B,
    prefix: &str,
) {
    let key = format!("{prefix}:replace");
    cache.set(&key, b"old", TTL).await.unwrap();
    assert!(
        cache
            .compare_and_set(&key, b"old", b"new", TTL)
            .await
            .unwrap()
    );
    assert_eq!(cache.get(&key).await.unwrap().as_deref(), Some(&b"new"[..]));
}

/// A value another caller wrote since the read is not overwritten.
pub async fn compare_and_set_keeps_a_newer_value<B: CacheBackend + ?Sized>(
    cache: &B,
    prefix: &str,
) {
    let key = format!("{prefix}:newer");
    cache.set(&key, b"newer", TTL).await.unwrap();
    assert!(
        !cache
            .compare_and_set(&key, b"old", b"stale", TTL)
            .await
            .unwrap()
    );
    assert_eq!(
        cache.get(&key).await.unwrap().as_deref(),
        Some(&b"newer"[..])
    );
}

/// A key deleted since the read is not brought back.
pub async fn compare_and_set_never_resurrects<B: CacheBackend + ?Sized>(cache: &B, prefix: &str) {
    let key = format!("{prefix}:deleted");
    cache.set(&key, b"old", TTL).await.unwrap();
    cache.delete(&key).await.unwrap();
    assert!(
        !cache
            .compare_and_set(&key, b"old", b"back", TTL)
            .await
            .unwrap()
    );
    assert!(cache.get(&key).await.unwrap().is_none());
}

/// Of concurrent writers that all read the same value, exactly one replaces
/// it; the others see their read was outdated.
pub async fn compare_and_set_has_one_winner<B: CacheBackend + ?Sized>(cache: &B, prefix: &str) {
    let key = format!("{prefix}:race");
    cache.set(&key, b"read", TTL).await.unwrap();
    let writers = (0..16u8).map(|n| {
        let key = key.clone();
        async move {
            cache
                .compare_and_set(&key, b"read", &[n], TTL)
                .await
                .unwrap()
        }
    });
    let won = futures::future::join_all(writers)
        .await
        .into_iter()
        .filter(|won| *won)
        .count();
    assert_eq!(won, 1);
}

/// Every scenario, in order.
pub async fn run_compare_and_set<B: CacheBackend + ?Sized>(cache: &B, prefix: &str) {
    compare_and_set_replaces_the_expected_value(cache, prefix).await;
    compare_and_set_keeps_a_newer_value(cache, prefix).await;
    compare_and_set_never_resurrects(cache, prefix).await;
    compare_and_set_has_one_winner(cache, prefix).await;
}
