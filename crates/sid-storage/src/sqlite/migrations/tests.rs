use super::*;
use crate::sqlite::schema::SCHEMA;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use std::str::FromStr;
use std::time::Duration;

/// A pool on the file at `path`, opened as the backend opens it.
async fn open(path: &std::path::Path) -> SqlitePool {
    let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
        .unwrap()
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .unwrap()
}

async fn version(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn has_table(pool: &SqlitePool, name: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sqlite_master WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
        == 1
}

async fn add_profile(pool: &SqlitePool, id: &str) {
    sqlx::query("INSERT INTO profiles (id, username) VALUES (?, ?)")
        .bind(id)
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}

async fn has_profile(pool: &SqlitePool, id: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM profiles WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
        == 1
}

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sid.db");
    (dir, path)
}

/// An empty file gets the schema and records its version.
#[tokio::test]
async fn an_empty_file_gets_the_schema() {
    let (_dir, path) = scratch();
    let pool = open(&path).await;
    prepare(&pool, SCHEMA).await.unwrap();
    assert_eq!(version(&pool).await, SCHEMA_VERSION);
    assert!(has_table(&pool, "history_key_epochs").await);
}

/// Reopening a current file keeps its data and changes nothing.
#[tokio::test]
async fn reopening_keeps_the_data() {
    let (_dir, path) = scratch();
    let pool = open(&path).await;
    prepare(&pool, SCHEMA).await.unwrap();
    add_profile(&pool, "p1").await;
    pool.close().await;

    let pool = open(&path).await;
    prepare(&pool, SCHEMA).await.unwrap();
    prepare(&pool, SCHEMA).await.unwrap();
    assert_eq!(version(&pool).await, SCHEMA_VERSION);
    assert!(has_profile(&pool, "p1").await);
}

/// An unversioned file of any shape is refused and left as it was: its data
/// stays and nothing is created in it.
#[tokio::test]
async fn an_unversioned_file_is_refused_unchanged() {
    let (_dir, path) = scratch();
    let pool = open(&path).await;
    sqlx::raw_sql("CREATE TABLE profiles (id TEXT PRIMARY KEY, username TEXT NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    add_profile(&pool, "p1").await;

    let err = prepare(&pool, SCHEMA).await.unwrap_err();
    assert!(matches!(err, SidError::InvalidState(_)), "{err:?}");
    assert_eq!(version(&pool).await, 0);
    assert!(has_profile(&pool, "p1").await);
    assert!(!has_table(&pool, "sessions").await);
}

/// A file of another version, older or newer, is refused unchanged.
#[tokio::test]
async fn a_file_of_another_version_is_refused_unchanged() {
    for other in [1, SCHEMA_VERSION + 1] {
        let (_dir, path) = scratch();
        let pool = open(&path).await;
        prepare(&pool, SCHEMA).await.unwrap();
        add_profile(&pool, "p1").await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "PRAGMA user_version = {other}"
        )))
        .execute(&pool)
        .await
        .unwrap();

        let err = prepare(&pool, SCHEMA).await.unwrap_err();
        assert!(matches!(err, SidError::InvalidState(_)), "{err:?}");
        assert_eq!(version(&pool).await, other);
        assert!(has_profile(&pool, "p1").await);
    }
}

/// A schema that fails part way leaves the file empty and unversioned, and the
/// next open creates it.
#[tokio::test]
async fn an_interrupted_creation_leaves_the_file_and_resumes() {
    let (_dir, path) = scratch();
    let pool = open(&path).await;
    prepare(
        &pool,
        "CREATE TABLE extra (id INTEGER PRIMARY KEY); CREATE TABLE broken (",
    )
    .await
    .unwrap_err();
    assert_eq!(version(&pool).await, 0);
    assert!(!has_table(&pool, "extra").await, "the change rolled back");

    prepare(&pool, SCHEMA).await.unwrap();
    assert_eq!(version(&pool).await, SCHEMA_VERSION);
}

/// A row whose policy evidence disagrees is refused on insert and on update;
/// a complete verdict is stored.
#[tokio::test]
async fn disagreeing_policy_evidence_is_refused() {
    let (_dir, path) = scratch();
    let pool = open(&path).await;
    prepare(&pool, SCHEMA).await.unwrap();
    add_profile(&pool, "p-1").await;
    add_profile(&pool, "p-2").await;
    sqlx::query(
        "INSERT INTO credentials (id, profile_id, credential_type, data)
         VALUES ('c1', 'p-1', 'opaque', X'00')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let disagreeing = sqlx::query(
        "INSERT INTO credentials (id, profile_id, credential_type, data, zkpp_verified, policy_version)
         VALUES ('c2', 'p-2', 'opaque', X'00', 1, 1)",
    )
    .execute(&pool)
    .await;
    assert!(disagreeing.is_err(), "a verdict without its artifact");
    let disagreeing = sqlx::query("UPDATE credentials SET zkpp_verified = 1 WHERE id = 'c1'")
        .execute(&pool)
        .await;
    assert!(
        disagreeing.is_err(),
        "a verdict set without policy or artifact"
    );
    sqlx::query(
        "UPDATE credentials SET zkpp_verified = 1, policy_version = 1, zkpp_artifact = ?
         WHERE id = 'c1'",
    )
    .bind(vec![7u8; 32])
    .execute(&pool)
    .await
    .expect("a complete verdict is stored");
}

/// Processes opening one empty file at once: one creates it, the others wait
/// and find it current.
#[tokio::test]
async fn concurrent_starters_create_once() {
    let (_dir, path) = scratch();
    let (a, b, c) = (open(&path).await, open(&path).await, open(&path).await);
    let (ra, rb, rc) = tokio::join!(
        prepare(&a, SCHEMA),
        prepare(&b, SCHEMA),
        prepare(&c, SCHEMA),
    );
    ra.unwrap();
    rb.unwrap();
    rc.unwrap();
    assert_eq!(version(&a).await, SCHEMA_VERSION);
}
