// SPDX-License-Identifier: AGPL-3.0-only
use chrono::Duration;
use sid_plugin::audit::AuditLog;

use super::*;

fn database_url() -> String {
    std::env::var("SID_STORAGE_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

/// A host audit store in a schema of its own, its pool seeing only it, and
/// the schema's name.
async fn store() -> (PgAuditStore, PgPool, String) {
    let schema = format!("audit_{}", uuid::Uuid::now_v7().simple());
    let admin = PgPool::connect(&database_url())
        .await
        .expect("Failed to connect to PostgreSQL. Is the database running?");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    let url = database_url();
    let separator = if url.contains('?') { '&' } else { '?' };
    let pool = PgPool::connect(&format!(
        "{url}{separator}options=-c%20search_path%3D{schema}"
    ))
    .await
    .unwrap();
    let store = PgAuditStore::new(pool.clone());
    store.ensure_schema().await.unwrap();
    (store, pool, schema)
}

async fn drop_schema(schema: &str) {
    let admin = PgPool::connect(&database_url()).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .unwrap();
}

/// Whether the monthly partition of the month starting at `month` exists.
async fn partition_exists(pool: &PgPool, month: chrono::NaiveDate) -> bool {
    use chrono::Datelike;
    let name = format!("audit_records_{:04}_{:02}", month.year(), month.month());
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A host's schema check prepares the partitions of this and the next
/// month, so its records never land in the default partition.
#[tokio::test]
async fn the_schema_prepares_this_and_next_month() {
    let (_store, pool, schema) = store().await;
    let this = audit_retention::month_start(Utc::now())
        .unwrap()
        .date_naive();
    let next = this.checked_add_months(Months::new(1)).unwrap();
    let prepared = (
        partition_exists(&pool, this).await,
        partition_exists(&pool, next).await,
    );
    pool.close().await;
    drop_schema(&schema).await;
    assert_eq!(prepared, (true, true));
}

/// A month past retention is removed whole: its records go, its chain keeps
/// a checkpoint it still verifies from, the later record stays, and the
/// removal is recorded on its own chain.
#[tokio::test]
async fn an_expired_month_leaves_a_verifiable_chain() {
    let (store, pool, schema) = store().await;
    let this = audit_retention::month_start(Utc::now()).unwrap();
    let old = this.checked_sub_months(Months::new(3)).unwrap();
    audit_retention::ensure_partition(&pool, old.date_naive())
        .await
        .unwrap();
    let chain = "org:expiry";
    let mut tx = pool.begin().await.unwrap();
    for i in 0..2 {
        PostgresAuditLog::append_at(
            &mut tx,
            chain,
            AuditEntry::system("test", format!("old {i}")),
            old + Duration::days(1),
        )
        .await
        .unwrap();
    }
    PostgresAuditLog::log_in_conn(&mut tx, chain, AuditEntry::system("test", "kept"))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let removed = store
        .drop_expired(
            this.checked_sub_months(Months::new(1)).unwrap(),
            "site:audit_retention",
            AuditEntry::system("audit_retention", "expired months removed"),
        )
        .await
        .unwrap();
    let left = store.log().query(chain, None, None).await.unwrap();
    let verified = store.log().verify_chain(chain).await.unwrap();
    let recorded = store
        .log()
        .query("site:audit_retention", None, None)
        .await
        .unwrap();
    pool.close().await;
    drop_schema(&schema).await;
    assert_eq!(removed, 2);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].sequence, 3);
    assert!(verified.valid, "{verified:?}");
    assert_eq!(recorded.len(), 1, "the removal is recorded");
}
