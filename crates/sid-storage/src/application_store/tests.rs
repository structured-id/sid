// SPDX-License-Identifier: AGPL-3.0-only
use std::time::Duration;

use super::*;

const LONG: Duration = Duration::from_secs(3600);

/// A URL naming neither engine is refused instead of falling back to one:
/// the store is chosen at composition, never guessed.
#[tokio::test]
async fn a_url_of_another_engine_is_refused() {
    for url in [
        "redis://localhost:6379",
        "mysql://db/app",
        "/var/lib/app.db",
        "",
    ] {
        assert!(
            matches!(ceremony_store(url).await, Err(SidError::Validation(_))),
            "accepted {url:?}"
        );
    }
}

/// What one process put in a SQLite file is there for the process opened on
/// it next: a restart loses no session.
#[cfg(feature = "storage-sqlite")]
#[tokio::test]
async fn a_sqlite_store_keeps_its_state_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}", dir.path().join("app.db").display());
    let first = ceremony_store(&url).await.unwrap();
    first
        .put_ceremony_state("app", "key", b"value", LONG)
        .await
        .unwrap();
    drop(first);

    let reopened = ceremony_store(&url).await.unwrap();
    assert_eq!(
        reopened.read_ceremony_state("app", "key").await.unwrap(),
        Some(b"value".to_vec())
    );
}

/// The application's purge removes expired rows on its own: after it ran,
/// nothing expired is left for another purge to find.
#[cfg(feature = "storage-sqlite")]
#[tokio::test]
async fn the_periodic_purge_reclaims_expired_records() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}", dir.path().join("app.db").display());
    let store = ceremony_store(&url).await.unwrap();
    store
        .put_ceremony_state("app", "gone", b"v", Duration::from_millis(10))
        .await
        .unwrap();
    store
        .put_ceremony_state("app", "kept", b"v", LONG)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    let purge = tokio::spawn(purge_expired(store.clone(), Duration::from_millis(20)));
    tokio::time::sleep(Duration::from_millis(200)).await;
    purge.abort();
    assert_eq!(store.purge_expired_ceremony_state().await.unwrap(), 0);
    assert!(
        store
            .read_ceremony_state("app", "kept")
            .await
            .unwrap()
            .is_some()
    );
}

fn database_url() -> String {
    std::env::var("SID_STORAGE_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid_storage_test".to_string())
}

/// Two stores opened on one PostgreSQL database are one authority: what one
/// replica puts, another takes, exactly once.
#[cfg(feature = "storage-pg")]
#[tokio::test]
async fn replicas_on_one_postgres_database_share_one_state() {
    let key = uuid::Uuid::now_v7().to_string();
    let a = ceremony_store(&database_url()).await.unwrap();
    let b = ceremony_store(&database_url()).await.unwrap();
    a.put_ceremony_state("app", &key, b"value", LONG)
        .await
        .unwrap();
    assert_eq!(
        b.take_ceremony_state("app", &key).await.unwrap(),
        Some(b"value".to_vec())
    );
    assert_eq!(a.take_ceremony_state("app", &key).await.unwrap(), None);
}
