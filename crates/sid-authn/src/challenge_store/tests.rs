// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::test_support::key_manager as keys;
use sid_plugin::InProcessCeremonyState;

/// Two replicas: separate stores over one authoritative store and one
/// master key.
fn replicas(ttl: Duration) -> (ChallengeStore<String>, ChallengeStore<String>) {
    let store: Arc<dyn CeremonyStateStore> = Arc::new(InProcessCeremonyState::new());
    let keys = keys();
    (
        ChallengeStore::new(store.clone(), keys.clone(), "test", ttl),
        ChallengeStore::new(store, keys, "test", ttl),
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

/// A replacement applies only to exactly what was read: of two replicas that
/// read the same state, the first replaces it and the second, now stale,
/// changes nothing; a past deadline replaces nothing either.
#[tokio::test]
async fn a_replacement_applies_only_to_what_was_read() {
    let (a, b) = replicas(Duration::from_secs(60));
    a.insert("k1", &"one".to_string()).await.unwrap();
    let deadline = chrono::Utc::now() + chrono::Duration::seconds(60);
    let read_a = a.read_versioned("k1").await.unwrap().unwrap();
    let read_b = b.read_versioned("k1").await.unwrap().unwrap();
    assert_eq!(read_a.value, "one");

    let two = a
        .replace("k1", &read_a, &"two".to_string(), deadline)
        .await
        .unwrap()
        .expect("the first replacement applies");
    assert_eq!(two.value, "two");
    assert!(
        b.replace("k1", &read_b, &"three".to_string(), deadline)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(b.read("k1").await.unwrap().as_deref(), Some("two"));

    // The replacement it returned is the writer's next version: it replaces
    // exactly what that writer stored, and nothing stored after it.
    let three = a
        .replace("k1", &two, &"three".to_string(), deadline)
        .await
        .unwrap()
        .expect("the writer's own version");
    b.insert("k1", &"other".to_string()).await.unwrap();
    assert!(
        a.replace("k1", &three, &"four".to_string(), deadline)
            .await
            .unwrap()
            .is_none(),
        "a version another writer replaced admits nothing"
    );

    let read = a.read_versioned("k1").await.unwrap().unwrap();
    let past = chrono::Utc::now() - chrono::Duration::seconds(1);
    assert!(
        a.replace("k1", &read, &"late".to_string(), past)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(a.read("k1").await.unwrap().as_deref(), Some("other"));
}

/// Reading state leaves it in place: any replica reads it any number of
/// times, and the one taker still gets it afterwards. Absent state reads as
/// `None`.
#[tokio::test]
async fn a_read_leaves_the_state_for_its_taker() {
    let (a, b) = replicas(Duration::from_secs(60));
    a.insert("k1", &"state".to_string()).await.unwrap();

    assert_eq!(b.read("k1").await.unwrap().as_deref(), Some("state"));
    assert_eq!(a.read("k1").await.unwrap().as_deref(), Some("state"));
    assert_eq!(b.take("k1").await.unwrap().as_deref(), Some("state"));
    assert_eq!(a.read("k1").await.unwrap(), None);
}

/// Expired state is gone, not taken.
#[tokio::test]
async fn expired_state_is_not_taken() {
    let (a, b) = replicas(Duration::from_millis(20));
    a.insert("k1", &"state".to_string()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;

    assert_eq!(b.take("k1").await.unwrap(), None);
}

/// State stored again at a later step keeps its ceremony's deadline instead
/// of a fresh store TTL; past the deadline nothing is stored.
#[tokio::test]
async fn state_stored_until_a_deadline_ends_with_it() {
    let (a, b) = replicas(Duration::from_secs(60));
    let deadline = chrono::Utc::now() + chrono::Duration::milliseconds(40);
    assert!(
        a.insert_until("k1", &"state".to_string(), deadline)
            .await
            .unwrap()
    );
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(b.take("k1").await.unwrap(), None);

    let passed = chrono::Utc::now() - chrono::Duration::milliseconds(1);
    assert!(
        !a.insert_until("k2", &"state".to_string(), passed)
            .await
            .unwrap()
    );
    assert_eq!(b.take("k2").await.unwrap(), None);
}

/// The store holds only sealed state, bound to its ceremony kind and key:
/// the plaintext is not in it, and a value moved to another key is refused.
#[tokio::test]
async fn stored_state_is_sealed_and_bound_to_its_key() {
    let raw_store: Arc<dyn CeremonyStateStore> = Arc::new(InProcessCeremonyState::new());
    let store: ChallengeStore<String> =
        ChallengeStore::new(raw_store.clone(), keys(), "test", Duration::from_secs(60));
    store
        .insert("k1", &"totp-seed-plaintext".to_string())
        .await
        .unwrap();

    let raw = raw_store
        .read_ceremony_state("test", "k1")
        .await
        .unwrap()
        .unwrap();
    assert!(!raw.windows(19).any(|w| w == b"totp-seed-plaintext"));

    raw_store
        .put_ceremony_state("test", "k2", &raw, Duration::from_secs(60))
        .await
        .unwrap();
    assert!(matches!(
        store.take("k2").await,
        Err(ChallengeStoreError::Seal(
            SealedSecretError::ContextMismatch
        ))
    ));
}

/// A consumption names the state exactly as it was read, under its own
/// namespace and key, so a mutation consuming it removes only that state.
#[tokio::test]
async fn consumption_names_the_state_as_read() {
    let store: Arc<dyn CeremonyStateStore> = Arc::new(InProcessCeremonyState::new());
    let challenges: ChallengeStore<String> =
        ChallengeStore::new(store.clone(), keys(), "test", Duration::from_secs(60));
    challenges.insert("k1", &"state".to_string()).await.unwrap();
    let read = challenges.read_versioned("k1").await.unwrap().unwrap();

    let consumption = challenges.consumption("k1", &read);

    assert_eq!(consumption.namespace, "test");
    assert_eq!(consumption.key, "k1");
    assert_eq!(
        Some(consumption.stored),
        store.read_ceremony_state("test", "k1").await.unwrap()
    );
}

/// An unreachable store is an error, never "no state" that could be read as
/// a fresh start or as success.
#[tokio::test]
async fn unreachable_store_is_an_error() {
    let store: ChallengeStore<String> = ChallengeStore::new(
        Arc::new(crate::test_support::DownCeremonies),
        keys(),
        "test",
        Duration::from_secs(60),
    );

    assert!(store.insert("k1", &"s".to_string()).await.is_err());
    assert!(store.take("k1").await.is_err());
    assert!(store.read("k1").await.is_err());
}
