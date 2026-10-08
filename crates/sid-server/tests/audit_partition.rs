// SPDX-License-Identifier: AGPL-3.0-only
//! Audit storage maintenance on PostgreSQL: the current and next month get
//! their partitions ahead of time, and the default `archive` retention never
//! removes records. Removal itself is covered by the storage conformance
//! suite, on a month no other test writes to.

use sid_server::background_tasks::{AuditRetention, RetentionAction, manage_audit_partitions};

async fn setup() -> (sid_storage::PostgresBackend, sqlx::PgPool) {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string());
    let backend = sid_storage::PostgresBackend::new(&url, None)
        .await
        .expect("PostgreSQL on port 54399 (docker-compose.test.yml)");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");
    let pool = backend.pool().clone();
    (backend, pool)
}

async fn partition_exists(pool: &sqlx::PgPool, name: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A run prepares the month it runs in and the next one, and running again
/// changes nothing.
#[tokio::test]
async fn maintenance_prepares_this_and_next_month() {
    let (backend, pool) = setup().await;
    let now = "2031-12-10T12:00:00Z".parse().unwrap();
    let retention = AuditRetention {
        days: 365,
        action: RetentionAction::Archive,
    };

    for _ in 0..2 {
        assert_eq!(
            manage_audit_partitions(&backend, retention, now)
                .await
                .unwrap(),
            0
        );
    }
    assert!(partition_exists(&pool, "audit_records_2031_12").await);
    assert!(partition_exists(&pool, "audit_records_2032_01").await);
}

/// With `archive`, records past retention stay: nothing is removed before an
/// archive holds them. The record checked is this test's own, in a month no
/// other test writes to or drops, so tests sharing the database cannot move
/// the result.
#[tokio::test]
async fn archive_retention_removes_nothing() {
    let (backend, pool) = setup().await;
    sqlx::query("SELECT create_audit_partition(2031, 6)")
        .execute(&pool)
        .await
        .unwrap();
    let record_id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO audit_records (id, timestamp, chain_id, sequence, actor_id, actor_type,
         action, resource, outcome, prev_hash, hash)
         VALUES ($1, '2031-06-15'::timestamptz, $2, 1, 'system', 'system', 'test.retention',
                 'test-resource', 'success', 'genesis', $3)",
    )
    .bind(&record_id)
    .bind(format!("retention:{record_id}"))
    .bind(format!("hash_{record_id}"))
    .execute(&pool)
    .await
    .unwrap();

    let retention = AuditRetention {
        days: 1,
        action: RetentionAction::Archive,
    };
    let removed =
        manage_audit_partitions(&backend, retention, "2031-12-10T12:00:00Z".parse().unwrap())
            .await
            .unwrap();
    assert_eq!(removed, 0);
    let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_records WHERE id = $1")
        .bind(&record_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kept, 1, "archive retention removed a record past retention");
}
