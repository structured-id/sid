// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::test_support::key_manager as keys;
use sid_plugin::cache::InMemoryCacheBackend;

/// Two replicas: separate stores over one shared cache and one master key.
fn replicas(ttl: Duration) -> (ChallengeStore<String>, ChallengeStore<String>) {
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let keys = keys();
    (
        ChallengeStore::new(cache.clone(), keys.clone(), "test", ttl),
        ChallengeStore::new(cache, keys, "test", ttl),
    )
}

/// State stored on one replica is taken on another, once.
#[tokio::test]
async fn start_on_one_replica_finish_on_another() {
    let (a, b) = replicas(Duration::from_secs(60));
    a.insert("k1", &"state".to_string()).await.unwrap();

    assert_eq!(b.take("k1").await.unwrap().as_deref(), Some("state"));
    assert_eq!(a.take("k1").await.unwrap(), None);
}

/// Of many concurrent finishes, exactly one gets the state.
#[tokio::test]
async fn concurrent_takes_have_one_winner() {
    let (a, b) = replicas(Duration::from_secs(60));
    a.insert("k1", &"state".to_string()).await.unwrap();
    let b = Arc::new(b);

    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let b = b.clone();
            tokio::spawn(async move { b.take("k1").await.unwrap() })
        })
        .collect();
    let mut winners = 0;
    for t in tasks {
        winners += usize::from(t.await.unwrap().is_some());
    }
    assert_eq!(winners, 1);
}

/// Expired state is gone, not taken.
#[tokio::test]
async fn expired_state_is_not_taken() {
    let (a, b) = replicas(Duration::from_millis(20));
    a.insert("k1", &"state".to_string()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;

    assert_eq!(b.take("k1").await.unwrap(), None);
}

/// The cache holds only sealed state, bound to its ceremony kind and key: the
/// plaintext is not in it, and a value moved to another key is refused.
#[tokio::test]
async fn cached_state_is_sealed_and_bound_to_its_key() {
    let cache: Arc<dyn CacheBackend> = Arc::new(InMemoryCacheBackend::new());
    let store: ChallengeStore<String> =
        ChallengeStore::new(cache.clone(), keys(), "test", Duration::from_secs(60));
    store
        .insert("k1", &"totp-seed-plaintext".to_string())
        .await
        .unwrap();

    let raw = cache.get("ceremony:test:k1").await.unwrap().unwrap();
    assert!(!raw.windows(19).any(|w| w == b"totp-seed-plaintext"));

    cache
        .set("ceremony:test:k2", &raw, Duration::from_secs(60))
        .await
        .unwrap();
    assert!(matches!(
        store.take("k2").await,
        Err(ChallengeStoreError::Seal(
            SealedSecretError::ContextMismatch
        ))
    ));
}

/// An unreachable cache is an error, never "no state" that could be read as
/// a fresh start or as success.
#[tokio::test]
async fn unreachable_cache_is_an_error() {
    struct Down;
    #[async_trait::async_trait]
    impl CacheBackend for Down {
        async fn get(&self, _: &str) -> sid_plugin::cache::CacheResult<Option<Vec<u8>>> {
            Err(CacheError::Connection("down".into()))
        }
        async fn set(&self, _: &str, _: &[u8], _: Duration) -> sid_plugin::cache::CacheResult<()> {
            Err(CacheError::Connection("down".into()))
        }
        async fn delete(&self, _: &str) -> sid_plugin::cache::CacheResult<()> {
            Err(CacheError::Connection("down".into()))
        }
        async fn take(&self, _: &str) -> sid_plugin::cache::CacheResult<Option<Vec<u8>>> {
            Err(CacheError::Connection("down".into()))
        }
        async fn publish(&self, _: &str, _: &[u8]) -> sid_plugin::cache::CacheResult<()> {
            Err(CacheError::Connection("down".into()))
        }
        async fn subscribe(
            &self,
            _: &str,
        ) -> sid_plugin::cache::CacheResult<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
            Err(CacheError::Connection("down".into()))
        }
        async fn health_check(&self) -> sid_plugin::cache::CacheResult<()> {
            Err(CacheError::Connection("down".into()))
        }
    }
    let store: ChallengeStore<String> =
        ChallengeStore::new(Arc::new(Down), keys(), "test", Duration::from_secs(60));

    assert!(store.insert("k1", &"s".to_string()).await.is_err());
    assert!(store.take("k1").await.is_err());
}
