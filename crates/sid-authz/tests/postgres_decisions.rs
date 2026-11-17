// SPDX-License-Identifier: AGPL-3.0-only
//! The CE engine's decisions over PostgreSQL (port 54399), in process. Each
//! scenario runs in a migrated schema of its own: installation-wide policies
//! would otherwise reach the tests sharing the database.

mod decisions;

use std::sync::Arc;

use sid_plugin::StorageBackend;
use sid_storage::PostgresBackend;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_owned())
}

async fn isolated() -> (Arc<PostgresBackend>, String) {
    let schema = format!("authz_{}", uuid::Uuid::now_v7().simple());
    let backend = PostgresBackend::new(&database_url(), Some(schema.clone()))
        .await
        .expect("PostgreSQL on port 54399 (docker-compose.test.yml)");
    sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
        .await
        .expect("migrations in an isolated schema");
    (Arc::new(backend), schema)
}

/// Drop `schema` over a connection of its own, then report the outcome.
async fn finish(schema: &str, outcome: Result<(), tokio::task::JoinError>) {
    let pool = sqlx::PgPool::connect(&database_url()).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&pool)
    .await
    .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}

async fn run<F, Fut>(scenario: F)
where
    F: FnOnce(Arc<dyn StorageBackend>) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (backend, schema) = isolated().await;
    let outcome = tokio::spawn(scenario(backend)).await;
    finish(&schema, outcome).await;
}

decision_scenarios!(run);

#[tokio::test]
async fn an_unreachable_store_never_allows() {
    let (backend, schema) = isolated().await;
    let pool = backend.pool().clone();
    let outcome = tokio::spawn(decisions::an_unreachable_store_never_allows(
        backend,
        async move { pool.close().await },
    ))
    .await;
    finish(&schema, outcome).await;
}
