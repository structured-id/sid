// SPDX-License-Identifier: AGPL-3.0-only
//! The shared PostgreSQL test database, migrated once per test run.
//!
//! The run's setup script ([`prepare`], through the `prepare_test_database`
//! example) migrates the database before any test that depends on this
//! crate starts and marks the run with [`PREPARED`]; each test only connects
//! ([`prepared_postgres`]). Tests never migrate the shared database
//! themselves: under a process-per-test runner that would repeat the whole
//! migration check, queued on the migrator's lock, in every test.

use crate::PostgresBackend;

/// Set to `1` in a test's environment once the run prepared the database.
pub const PREPARED: &str = "SID_TEST_DATABASE_PREPARED";

/// The shared test database: `DATABASE_URL`, else the test compose stack's
/// PostgreSQL on port 54399.
pub fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

/// Migrate the shared test database; what the run's setup script does once.
pub async fn prepare() -> sid_core::Result<()> {
    let backend = PostgresBackend::new(&database_url(), None).await?;
    crate::migrator::run_migrations(backend.pool(), None).await
}

/// A backend on the shared test database the run prepared.
///
/// # Panics
///
/// When the run did not prepare it (the test was started without the setup
/// script) or the database is unreachable.
pub async fn prepared_postgres() -> PostgresBackend {
    assert_eq!(
        std::env::var(PREPARED).as_deref(),
        Ok("1"),
        "the shared test database is not prepared: run the tests through \
         `cargo nextest run`, whose setup script migrates it once"
    );
    PostgresBackend::new(&database_url(), None)
        .await
        .expect("PostgreSQL on port 54399 (docker-compose.test.yml) or DATABASE_URL")
}
