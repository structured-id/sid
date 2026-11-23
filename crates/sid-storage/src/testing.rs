// SPDX-License-Identifier: AGPL-3.0-only
//! The shared PostgreSQL test databases, each migrated once per test run.
//!
//! A run's setup script ([`TestDatabase::prepare`], through the
//! `prepare_test_database` example) migrates one database before the tests
//! that use it start and marks the run with that database's
//! [`TestDatabase::marker`]; each test only connects ([`prepared_postgres`],
//! [`prepared_storage_postgres`]). Tests never migrate a shared database
//! themselves: under a process-per-test runner that would repeat the whole
//! migration check, queued on the migrator's lock, in every test. Each
//! database is prepared only for the tests that use it, so a run of one
//! crate's tests needs no other database.

use crate::PostgresBackend;

/// The test compose stack's database for the storage crate's own tests.
pub const COMPOSE_STORAGE_DATABASE_URL: &str =
    "postgres://sid:sid_dev@localhost:54399/sid_storage_test";

/// One shared test database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestDatabase {
    /// The engine's database, used by the tests of crates depending on this
    /// one.
    Engine,
    /// This crate's own database, used by its own tests.
    Storage,
}

impl TestDatabase {
    /// The database named on the setup script's command line.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "engine" => Some(Self::Engine),
            "storage" => Some(Self::Storage),
            _ => None,
        }
    }

    /// Its URL: `DATABASE_URL` (the storage database first
    /// `SID_STORAGE_TEST_DATABASE_URL`), else the compose stack's database.
    pub fn url(self) -> String {
        match self {
            Self::Engine => std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string()),
            Self::Storage => std::env::var("SID_STORAGE_TEST_DATABASE_URL")
                .or_else(|_| std::env::var("DATABASE_URL"))
                .unwrap_or_else(|_| COMPOSE_STORAGE_DATABASE_URL.to_string()),
        }
    }

    /// The variable set to `1` in a test's environment once the run prepared
    /// it.
    pub fn marker(self) -> &'static str {
        match self {
            Self::Engine => "SID_TEST_DATABASE_PREPARED",
            Self::Storage => "SID_STORAGE_TEST_DATABASE_PREPARED",
        }
    }

    /// Migrate it; what the run's setup script does once.
    pub async fn prepare(self) -> sid_core::Result<()> {
        let backend = PostgresBackend::new(&self.url(), None).await?;
        crate::migrator::run_migrations(backend.pool(), None).await
    }

    /// A backend on it, once the run prepared it.
    ///
    /// # Panics
    ///
    /// When the run did not prepare it (the test was started without its
    /// setup script) or the database is unreachable.
    pub async fn connect_prepared(self) -> PostgresBackend {
        assert_eq!(
            std::env::var(self.marker()).as_deref(),
            Ok("1"),
            "the shared test database is not prepared: run the tests through \
             `cargo nextest run`, whose setup script migrates it once"
        );
        PostgresBackend::new(&self.url(), None)
            .await
            .expect("PostgreSQL on port 54399 (docker-compose.test.yml) or the configured URL")
    }
}

/// The engine's shared test database URL.
pub fn database_url() -> String {
    TestDatabase::Engine.url()
}

/// The storage crate's own test database URL.
pub fn storage_database_url() -> String {
    TestDatabase::Storage.url()
}

/// A backend on the engine's shared test database the run prepared.
pub async fn prepared_postgres() -> PostgresBackend {
    TestDatabase::Engine.connect_prepared().await
}

/// A backend on the storage crate's test database the run prepared.
pub async fn prepared_storage_postgres() -> PostgresBackend {
    TestDatabase::Storage.connect_prepared().await
}
