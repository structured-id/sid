use super::*;
use crate::sqlite::schema::BASELINE;
use sqlx::sqlite::SqliteJournalMode;
use std::time::Duration;

/// Two changes above the baseline: a new table and a column on an existing one.
const TWO: &[Migration] = &[
    Migration {
        version: 2,
        sql: "CREATE TABLE extra (id INTEGER PRIMARY KEY);
              ALTER TABLE profiles ADD COLUMN nickname TEXT;",
    },
    Migration {
        version: 3,
        sql: "CREATE INDEX idx_extra ON extra (id);",
    },
];

/// The same first change, then one that fails half way.
const BROKEN: &[Migration] = &[
    Migration {
        version: 2,
        sql: "CREATE TABLE extra (id INTEGER PRIMARY KEY);
              ALTER TABLE profiles ADD COLUMN nickname TEXT;",
    },
    Migration {
        version: 3,
        sql: "CREATE INDEX idx_extra ON extra (id); CREATE TABLE broken (",
    },
];

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

/// An empty file gets the baseline and every migration, and records the
/// latest version.
#[tokio::test]
async fn an_empty_file_is_created_at_the_latest_version() {
    let (_dir, path) = scratch();
    let pool = open(&path).await;
    upgrade(&pool, BASELINE, TWO).await.unwrap();
    assert_eq!(version(&pool).await, 3);
    assert!(has_table(&pool, "extra").await);
    assert!(has_table(&pool, "idx_extra").await);
}

/// Reopening a current file keeps its data and changes nothing: a repeated
/// upgrade is a no-op.
#[tokio::test]
async fn reopening_keeps_the_data() {
    let (_dir, path) = scratch();
    let pool = open(&path).await;
    upgrade(&pool, BASELINE, TWO).await.unwrap();
    add_profile(&pool, "p1").await;
    pool.close().await;

    let pool = open(&path).await;
    upgrade(&pool, BASELINE, TWO).await.unwrap();
    upgrade(&pool, BASELINE, TWO).await.unwrap();
    assert_eq!(version(&pool).await, 3);
    assert!(has_profile(&pool, "p1").await);
}

/// Regression: a file written before versioning got only the missing tables
/// on reopen (`CREATE TABLE IF NOT EXISTS`), never a new column. A file that
/// is exactly the baseline is now upgraded, its data kept.
#[tokio::test]
async fn an_unversioned_baseline_file_is_upgraded_with_its_data() {
    let (_dir, path) = scratch();
    let pool = open(&path).await;
    sqlx::raw_sql(BASELINE).execute(&pool).await.unwrap();
    add_profile(&pool, "p1").await;
    assert_eq!(version(&pool).await, 0);

    upgrade(&pool, BASELINE, TWO).await.unwrap();
    assert_eq!(version(&pool).await, 3);
    assert!(has_profile(&pool, "p1").await);
    let nickname: Option<String> =
        sqlx::query_scalar("SELECT nickname FROM profiles WHERE id = 'p1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(nickname, None);
}

/// An unversioned file of any other shape is refused and left as it was:
/// its data stays and nothing is created in it.
#[tokio::test]
async fn an_unknown_unversioned_schema_is_refused_unchanged() {
    let (_dir, path) = scratch();
    let pool = open(&path).await;
    sqlx::raw_sql("CREATE TABLE profiles (id TEXT PRIMARY KEY, username TEXT NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    add_profile(&pool, "p1").await;

    let err = upgrade(&pool, BASELINE, TWO).await.unwrap_err();
    assert!(matches!(err, SidError::InvalidState(_)), "{err:?}");
    assert_eq!(version(&pool).await, 0);
    assert!(has_profile(&pool, "p1").await);
    assert!(!has_table(&pool, "sessions").await);
}

/// A file from a newer build is refused, not rolled back to this build's
/// schema.
#[tokio::test]
async fn a_newer_file_is_refused_unchanged() {
    let (_dir, path) = scratch();
    let pool = open(&path).await;
    upgrade(&pool, BASELINE, TWO).await.unwrap();

    let err = upgrade(&pool, BASELINE, &TWO[..1]).await.unwrap_err();
    assert!(matches!(err, SidError::InvalidState(_)), "{err:?}");
    assert_eq!(version(&pool).await, 3);
}

/// An upgrade that fails part way leaves the file at its old version with
/// none of the changes; the next open applies them all.
#[tokio::test]
async fn an_interrupted_upgrade_leaves_the_file_and_resumes() {
    let (_dir, path) = scratch();
    let pool = open(&path).await;
    upgrade(&pool, BASELINE, &[]).await.unwrap();
    add_profile(&pool, "p1").await;
    assert_eq!(version(&pool).await, 1);

    upgrade(&pool, BASELINE, BROKEN).await.unwrap_err();
    assert_eq!(version(&pool).await, 1);
    assert!(
        !has_table(&pool, "extra").await,
        "the first change rolled back"
    );
    assert!(has_profile(&pool, "p1").await);

    upgrade(&pool, BASELINE, TWO).await.unwrap();
    assert_eq!(version(&pool).await, 3);
    assert!(has_profile(&pool, "p1").await);
}

/// Verdicts stored before artifacts were named are demoted with their
/// provenance kept: the password reads as policy-unverified, the legacy
/// table holds what was claimed. Afterwards a row whose evidence columns
/// disagree is refused on insert and on update.
#[tokio::test]
async fn unattributed_policy_verdicts_are_demoted_with_provenance() {
    let (_dir, path) = scratch();
    let pool = open(&path).await;
    upgrade(&pool, BASELINE, &MIGRATIONS[..2]).await.unwrap();
    // One password per profile.
    for (id, verified, version) in [("c1", 1, Some(1)), ("c2", 0, None), ("c3", 0, Some(1))] {
        add_profile(&pool, &format!("p-{id}")).await;
        sqlx::query(
            "INSERT INTO credentials (id, profile_id, credential_type, data, zkpp_verified, policy_version)
             VALUES (?, ?, 'opaque', X'00', ?, ?)",
        )
        .bind(id)
        .bind(format!("p-{id}"))
        .bind(verified)
        .bind(version)
        .execute(&pool)
        .await
        .unwrap();
    }
    add_profile(&pool, "p-c4").await;

    upgrade(&pool, BASELINE, MIGRATIONS).await.unwrap();
    let rows: Vec<(String, i64, Option<i64>)> =
        sqlx::query_as("SELECT id, zkpp_verified, policy_version FROM credentials ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        rows,
        vec![
            ("c1".into(), 0, None),
            ("c2".into(), 0, None),
            ("c3".into(), 0, None)
        ]
    );
    let kept: Vec<(String, i64, Option<i64>)> = sqlx::query_as(
        "SELECT credential_id, zkpp_verified, policy_version
         FROM credential_policy_evidence_legacy ORDER BY credential_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        kept,
        vec![("c1".into(), 1, Some(1)), ("c3".into(), 0, Some(1))],
        "every claimed verdict keeps its provenance"
    );

    let disagreeing = sqlx::query(
        "INSERT INTO credentials (id, profile_id, credential_type, data, zkpp_verified, policy_version)
         VALUES ('c4', 'p-c4', 'opaque', X'00', 1, 1)",
    )
    .execute(&pool)
    .await;
    assert!(disagreeing.is_err(), "a verdict without its artifact");
    let disagreeing = sqlx::query("UPDATE credentials SET zkpp_verified = 1 WHERE id = 'c2'")
        .execute(&pool)
        .await;
    assert!(
        disagreeing.is_err(),
        "a verdict set without policy or artifact"
    );
    sqlx::query(
        "UPDATE credentials SET zkpp_verified = 1, policy_version = 1, zkpp_artifact = ?
         WHERE id = 'c2'",
    )
    .bind(vec![7u8; 32])
    .execute(&pool)
    .await
    .expect("a complete verdict is stored");
}

/// Processes opening one empty file at once: one creates and upgrades it,
/// the others wait and find it current.
#[tokio::test]
async fn concurrent_starters_upgrade_once() {
    let (_dir, path) = scratch();
    let (a, b, c) = (open(&path).await, open(&path).await, open(&path).await);
    let (ra, rb, rc) = tokio::join!(
        upgrade(&a, BASELINE, TWO),
        upgrade(&b, BASELINE, TWO),
        upgrade(&c, BASELINE, TWO),
    );
    ra.unwrap();
    rb.unwrap();
    rc.unwrap();
    assert_eq!(version(&a).await, 3);
}
