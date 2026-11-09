// SPDX-License-Identifier: AGPL-3.0-only
//! The test PostgreSQL database of this service's own tables
//! (`SID_NOTIFY_TEST_DATABASE_URL`, default database `sid_notify_test` on
//! port 54399). An unreachable server fails the test.

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

fn database_url() -> String {
    std::env::var("SID_NOTIFY_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid_notify_test".into())
}

/// A pool on a schema no other test uses, so its tables start empty.
pub(crate) async fn pool() -> sqlx::PgPool {
    let url = database_url();
    let schema = format!("t{}", uuid::Uuid::now_v7().simple());
    let admin = sqlx::PgPool::connect(&url)
        .await
        .expect("test PostgreSQL unreachable; start docker-compose.test.yml");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .expect("create the test schema");
    admin.close().await;
    let options: PgConnectOptions = url.parse().expect("test database URL");
    PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options.options([("search_path", schema.as_str())]))
        .await
        .expect("connect to the test schema")
}

/// The operation result store of `pool`, its tables created.
pub(crate) async fn operations(
    pool: &sqlx::PgPool,
) -> std::sync::Arc<sid_storage::PgOperationStore> {
    let store = sid_storage::PgOperationStore::new(pool.clone());
    store.ensure_schema().await.expect("operation tables");
    std::sync::Arc::new(store)
}
