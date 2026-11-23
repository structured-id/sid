// SPDX-License-Identifier: AGPL-3.0-only
//! The test stores, each prepared once per test run.
//!
//! A run's setup script ([`TestDatabase::prepare`], through the
//! `prepare_test_database` example) prepares one store before the tests
//! that use it start and marks the run with its [`TestDatabase::marker`].
//! Tests never migrate or declare a schema themselves: each test runs in its
//! own process, so that would repeat the whole schema setup in every test.
//! Each store is prepared only for the tests that use it, so a run of one
//! crate's tests needs no other store.
//!
//! - The shared databases ([`prepared_postgres`],
//!   [`prepared_storage_postgres`]) are used by many tests at once, each on
//!   rows of its own.
//! - A test about the installation as a whole (its first administrator, its
//!   policies, a cleanup of every expired row) gets an installation of its
//!   own: a copy of the prepared template ([`isolated_postgres`], and
//!   `isolated_coordinode` for CoordiNode), removed when the test ends.

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
    /// The migrated database each [`isolated_postgres`] installation is a
    /// copy of, on the engine's server. Nothing connects to it but its setup:
    /// PostgreSQL copies only a database no session uses.
    Template,
}

/// The template database's name.
const TEMPLATE_DATABASE: &str = "sid_test_template";

impl TestDatabase {
    /// The database named on the setup script's command line.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "engine" => Some(Self::Engine),
            "storage" => Some(Self::Storage),
            "template" => Some(Self::Template),
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
            Self::Template => with_database(&Self::Engine.url(), TEMPLATE_DATABASE),
        }
    }

    /// The variable set to `1` in a test's environment once the run prepared
    /// it.
    pub fn marker(self) -> &'static str {
        match self {
            Self::Engine => "SID_TEST_DATABASE_PREPARED",
            Self::Storage => "SID_STORAGE_TEST_DATABASE_PREPARED",
            Self::Template => "SID_TEMPLATE_TEST_DATABASE_PREPARED",
        }
    }

    /// Migrate it; what the run's setup script does once. The template is
    /// made anew from the current migrations, then left with no session.
    /// Copies an earlier run left behind (a test killed before its removal)
    /// go first; one test stack serves one run at a time.
    pub async fn prepare(self) -> sid_core::Result<()> {
        if self == Self::Template {
            let admin = admin_pool().await?;
            let left: Vec<String> = sqlx::query_scalar(
                "SELECT datname::text FROM pg_database WHERE datname LIKE 'sid\\_test\\_%'",
            )
            .fetch_all(&admin)
            .await
            .map_err(|e| sid_core::Error::Storage(e.to_string()))?;
            for name in left {
                execute(&admin, format!("DROP DATABASE \"{name}\" WITH (FORCE)")).await?;
            }
            execute(&admin, format!("CREATE DATABASE \"{TEMPLATE_DATABASE}\"")).await?;
            admin.close().await;
        }
        let backend = PostgresBackend::new(&self.url(), None).await?;
        crate::migrator::run_migrations(backend.pool(), None).await?;
        backend.pool().close().await;
        Ok(())
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

/// An installation of its own: a new database copied from the template the
/// run prepared, removed by [`drop_isolated_postgres`].
///
/// # Panics
///
/// When the run did not prepare the template or the server refuses the copy.
pub async fn isolated_postgres() -> PostgresBackend {
    assert_eq!(
        std::env::var(TestDatabase::Template.marker()).as_deref(),
        Ok("1"),
        "the template database is not prepared: run the tests through \
         `cargo nextest run`, whose setup script migrates it once"
    );
    let name = format!("sid_test_{}", uuid::Uuid::now_v7().simple());
    let admin = admin_pool().await.expect("the test PostgreSQL server");
    // A file copy of a database this small is cheaper than logging its pages.
    execute(
        &admin,
        format!("CREATE DATABASE \"{name}\" TEMPLATE \"{TEMPLATE_DATABASE}\" STRATEGY FILE_COPY"),
    )
    .await
    .expect("a copy of the template database");
    admin.close().await;
    PostgresBackend::new(&with_database(&TestDatabase::Engine.url(), &name), None)
        .await
        .expect("the copied database")
}

/// Remove an [`isolated_postgres`] installation, ending its sessions.
///
/// # Panics
///
/// When the server refuses the removal.
pub async fn drop_isolated_postgres(backend: &PostgresBackend) {
    let name = database_name(backend);
    backend.pool().close().await;
    remove_database(&name).await;
}

/// The isolated installation's database name, from the pool's options rather
/// than a query: the scenario may have closed the pool.
fn database_name(backend: &PostgresBackend) -> String {
    let name = backend
        .pool()
        .connect_options()
        .get_database()
        .expect("the copied database's name")
        .to_owned();
    assert!(
        name.starts_with("sid_test_") && name != TEMPLATE_DATABASE,
        "{name} is not an isolated installation"
    );
    name
}

/// Remove the database `name`, ending every session still on it.
async fn remove_database(name: &str) {
    let admin = admin_pool().await.expect("the test PostgreSQL server");
    execute(&admin, format!("DROP DATABASE \"{name}\" WITH (FORCE)"))
        .await
        .expect("the copied database removed");
    admin.close().await;
}

/// An [`isolated_postgres`] installation removed when this is dropped, the
/// test's end or its panic alike, for a test that holds it for its whole
/// body rather than handing a scenario to [`in_isolated_postgres`].
pub struct IsolatedPostgres {
    backend: PostgresBackend,
}

impl IsolatedPostgres {
    /// A new installation of its own.
    pub async fn new() -> Self {
        Self {
            backend: isolated_postgres().await,
        }
    }

    /// The backend on it; clones share its pool.
    pub fn backend(&self) -> &PostgresBackend {
        &self.backend
    }

    /// Its URL, for a pool of its own (another replica on the same
    /// installation).
    pub fn url(&self) -> String {
        with_database(&TestDatabase::Engine.url(), &database_name(&self.backend))
    }
}

impl Drop for IsolatedPostgres {
    fn drop(&mut self) {
        // Drop cannot await; the removal runs on a runtime of its own, on a
        // thread of its own, so it works inside or outside the test's runtime.
        // The test's pool is left to the server's forced removal: closing it
        // needs the test's runtime, which waits here for the removal.
        let name = database_name(&self.backend);
        let removed = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime for the removal")
                .block_on(remove_database(&name));
        })
        .join();
        if removed.is_err() && !std::thread::panicking() {
            panic!("the isolated installation was not removed");
        }
    }
}

/// Run `scenario` on an [`isolated_postgres`] installation, remove it, then
/// report the scenario's outcome.
pub async fn in_isolated_postgres<F, Fut>(scenario: F)
where
    F: FnOnce(PostgresBackend) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let backend = isolated_postgres().await;
    let outcome = tokio::spawn(scenario(backend.clone())).await;
    drop_isolated_postgres(&backend).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}

/// One connection to the engine's server, for creating and dropping
/// databases.
async fn admin_pool() -> sid_core::Result<sqlx::PgPool> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&TestDatabase::Engine.url())
        .await
        .map_err(|e| sid_core::Error::Storage(format!("the test PostgreSQL server: {e}")))
}

async fn execute(pool: &sqlx::PgPool, statement: String) -> sid_core::Result<()> {
    sqlx::query(sqlx::AssertSqlSafe(statement))
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|e| sid_core::Error::Storage(e.to_string()))
}

/// `url` naming the database `name` on the same server.
fn with_database(url: &str, name: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (url, None),
    };
    let authority = base.find("://").map_or(0, |i| i + 3);
    let path = base[authority..]
        .find('/')
        .map_or(base.len(), |i| authority + i);
    match query {
        Some(query) => format!("{}/{name}?{query}", &base[..path]),
        None => format!("{}/{name}", &base[..path]),
    }
}

#[cfg(all(feature = "test-support", feature = "storage-coordinode"))]
pub use self::coordinode::{
    COORDINODE_TEMPLATE, IsolatedCoordinode, coordinode_copy, isolated_coordinode,
    prepare_coordinode_template, release_coordinode_copies,
};

/// The CoordiNode store each test opens a copy of.
#[cfg(all(feature = "test-support", feature = "storage-coordinode"))]
mod coordinode {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, Weak};

    use coordinode_embed::Database;

    use crate::coordinode::CoordinodeBackend;

    /// The variable naming the directory of the template the run prepared.
    pub const COORDINODE_TEMPLATE: &str = "SID_COORDINODE_TEST_TEMPLATE";

    /// Make SID's schema in a new CoordiNode store under `root`, in a
    /// directory of this run's own, and close it; returns its directory.
    /// Declaring the schema (its constraints and every index) is what made
    /// each test's store slow to open; a copy of a declared store opens in
    /// milliseconds. Templates of runs that started over a day ago are
    /// removed; a run still going beside this one keeps its own.
    pub async fn prepare_coordinode_template(root: &Path, run: &str) -> sid_core::Result<PathBuf> {
        std::fs::create_dir_all(root).map_err(io)?;
        let day = std::time::Duration::from_secs(24 * 60 * 60);
        for entry in std::fs::read_dir(root).map_err(io)? {
            let entry = entry.map_err(io)?;
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|at| at.elapsed().ok())
                .is_some_and(|age| age > day);
            if stale {
                std::fs::remove_dir_all(entry.path()).map_err(io)?;
            }
        }
        let dir = root.join(run);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(io)?;
        }
        std::fs::create_dir_all(&dir).map_err(io)?;
        let backend = CoordinodeBackend::new(open(dir.clone()).await?).await?;
        drop(backend);
        Ok(dir)
    }

    /// A store of a test's own, copied from the run's template, and the
    /// host's handle on it. The copy is removed when this is dropped.
    pub struct IsolatedCoordinode {
        /// SID's backend on the copy.
        pub backend: CoordinodeBackend,
        /// The host's handle on the same database.
        pub db: Arc<Database>,
        // Dropped last: the files outlive both handles.
        _dir: tempfile::TempDir,
    }

    /// A copy of the template the run prepared, opened.
    ///
    /// # Panics
    ///
    /// When the run did not prepare the template or the copy fails.
    pub async fn isolated_coordinode() -> IsolatedCoordinode {
        let template = std::env::var(COORDINODE_TEMPLATE).expect(
            "the CoordiNode template is not prepared: run the tests through \
             `cargo nextest run`, whose setup script makes it once",
        );
        let dir = tempfile::tempdir().expect("a directory for the copy");
        copy_dir(Path::new(&template), dir.path()).expect("a copy of the template store");
        let db = open(dir.path().to_path_buf())
            .await
            .expect("the copied store");
        let backend = CoordinodeBackend::new(db.clone())
            .await
            .expect("SID's schema in the copied store");
        IsolatedCoordinode {
            backend,
            db,
            _dir: dir,
        }
    }

    /// The copies [`coordinode_copy`] handed out as a bare backend, each kept
    /// until its database closes.
    static COPIES: Mutex<Vec<(Weak<Database>, tempfile::TempDir)>> = Mutex::new(Vec::new());

    /// A backend on a copy of the template, for a harness that can hold
    /// nothing but the backend; [`release_coordinode_copies`] removes the copy
    /// once every handle on it is gone.
    pub async fn coordinode_copy() -> CoordinodeBackend {
        let IsolatedCoordinode { backend, db, _dir } = isolated_coordinode().await;
        COPIES
            .lock()
            .expect("the copy registry")
            .push((Arc::downgrade(&db), _dir));
        backend
    }

    /// Remove every [`coordinode_copy`] whose database has closed.
    pub fn release_coordinode_copies() {
        COPIES
            .lock()
            .expect("the copy registry")
            .retain(|(db, _)| db.strong_count() > 0);
    }

    async fn open(path: PathBuf) -> sid_core::Result<Arc<Database>> {
        tokio::task::spawn_blocking(move || Database::open(path))
            .await
            .map_err(|e| sid_core::Error::Internal(format!("CoordiNode opening: {e}")))?
            .map(Arc::new)
            .map_err(|e| sid_core::Error::Storage(format!("CoordiNode store: {e:?}")))
    }

    fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            let target = to.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_dir(&entry.path(), &target)?;
            } else {
                std::fs::copy(entry.path(), target)?;
            }
        }
        Ok(())
    }

    fn io(e: std::io::Error) -> sid_core::Error {
        sid_core::Error::Internal(format!("the CoordiNode template directory: {e}"))
    }
}
