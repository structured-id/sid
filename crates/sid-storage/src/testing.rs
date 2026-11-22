// SPDX-License-Identifier: AGPL-3.0-only
//! The shared PostgreSQL test databases, migrated once per test run.
//!
//! The run's setup script ([`prepare`], through the `prepare_test_database`
//! example) migrates both databases before any test that depends on this
//! crate starts and marks the run with [`PREPARED`]; each test only connects
//! ([`prepared_postgres`], [`prepared_storage_postgres`]). Tests never migrate
//! a shared database themselves: under a process-per-test runner that would
//! repeat the whole migration check, queued on the migrator's lock, in every
//! test.

use crate::PostgresBackend;

/// Set to `1` in a test's environment once the run prepared the databases.
pub const PREPARED: &str = "SID_TEST_DATABASE_PREPARED";

/// The engine's shared test database: `DATABASE_URL`, else the test compose
/// stack's `sid` database on port 54399.
pub fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

/// The test compose stack's database for the storage crate's own tests.
pub const COMPOSE_STORAGE_DATABASE_URL: &str =
    "postgres://sid:sid_dev@localhost:54399/sid_storage_test";

/// The storage crate's own test database: `SID_STORAGE_TEST_DATABASE_URL`,
/// else `DATABASE_URL`, else [`COMPOSE_STORAGE_DATABASE_URL`].
pub fn storage_database_url() -> String {
    std::env::var("SID_STORAGE_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| COMPOSE_STORAGE_DATABASE_URL.to_string())
}

/// Migrate both shared test databases; what the run's setup script does once.
pub async fn prepare() -> sid_core::Result<()> {
    let engine = database_url();
    let storage = storage_database_url();
    migrate(&engine).await?;
    if storage != engine {
        migrate(&storage).await?;
    }
    Ok(())
}

async fn migrate(url: &str) -> sid_core::Result<()> {
    let backend = PostgresBackend::new(url, None).await?;
    crate::migrator::run_migrations(backend.pool(), None).await
}

/// A backend on the engine's shared test database the run prepared.
///
/// # Panics
///
/// When the run did not prepare it (the test was started without the setup
/// script) or the database is unreachable.
pub async fn prepared_postgres() -> PostgresBackend {
    connect_prepared(&database_url()).await
}

/// A backend on the storage crate's test database the run prepared.
///
/// # Panics
///
/// As [`prepared_postgres`].
pub async fn prepared_storage_postgres() -> PostgresBackend {
    connect_prepared(&storage_database_url()).await
}

async fn connect_prepared(url: &str) -> PostgresBackend {
    assert_eq!(
        std::env::var(PREPARED).as_deref(),
        Ok("1"),
        "the shared test database is not prepared: run the tests through \
         `cargo nextest run`, whose setup script migrates it once"
    );
    PostgresBackend::new(url, None)
        .await
        .expect("PostgreSQL on port 54399 (docker-compose.test.yml) or the configured URL")
}
