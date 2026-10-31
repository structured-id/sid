// SPDX-License-Identifier: AGPL-3.0-only
//! Embedded SQL migration runner.
//!
//! Executes SQL migrations in order, tracking applied state in a `_migrations` table.
//! Migrations are embedded at compile time via `include_str!`.
//!
//! Supports schema isolation: when `schema` is provided, all tables are created
//! within that PostgreSQL schema (for shared-database embedded deployments).
//!
//! Until the first stable release a schema change edits the migration that
//! created the table, as the SQLite baseline is edited: a database created
//! from an earlier set of files is recreated, not migrated, and the runner
//! keeps no forward migration for it.

use sid_core::{Error as SidError, Result as SidResult};
use sqlx::{AssertSqlSafe, PgPool};
use tracing::info;

/// A single migration with name and SQL content.
struct Migration {
    name: &'static str,
    sql: &'static str,
}

/// The engine's schema.
const MIGRATIONS: &[Migration] = &[Migration {
    name: "20260314_001_initial_schema",
    sql: include_str!("../../../migrations/20260314_001_initial_schema.sql"),
}];

/// The history evaluator's own store: applied by the evaluator under its own
/// credentials, tracked apart from [`MIGRATIONS`] so the store can live in a
/// database of its own.
const HISTORY_KEY_MIGRATIONS: &[Migration] = &[Migration {
    name: "20261010_001_history_keys",
    sql: include_str!("../../../migrations/history_keys/20261010_001_history_keys.sql"),
}];

/// Run the pending migrations of the history evaluator's store on `pool`:
/// each in its own transaction with its tracking row in
/// `_history_key_migrations`, serialized across replicas by an advisory lock
/// of its own.
pub async fn run_history_key_migrations(pool: &PgPool) -> SidResult<()> {
    use sqlx::Connection;

    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| SidError::Storage(format!("Failed to acquire a connection: {}", e)))?;
    // A key of its own: the small numbers are the engine's migration lock and
    // its background jobs' locks, which share the one advisory key space.
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('sid.history_key.migrations', 0))")
        .execute(&mut *conn)
        .await
        .map_err(|e| SidError::Storage(format!("Failed to acquire migration lock: {}", e)))?;
    let applied: SidResult<()> = async {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS _history_key_migrations (
                name TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&mut *conn)
        .await
        .map_err(|e| SidError::Storage(format!("history key migrations table: {e}")))?;
        let done: Vec<String> =
            sqlx::query_scalar("SELECT name FROM _history_key_migrations ORDER BY name")
                .fetch_all(&mut *conn)
                .await
                .map_err(|e| SidError::Storage(format!("history key migrations: {e}")))?;
        for migration in HISTORY_KEY_MIGRATIONS {
            if done.iter().any(|name| name == migration.name) {
                continue;
            }
            info!("Running history key migration: {}", migration.name);
            let fail = |e: sqlx::Error| {
                SidError::Storage(format!("Migration '{}' failed: {}", migration.name, e))
            };
            let mut tx = conn.begin().await.map_err(fail)?;
            sqlx::raw_sql(migration.sql)
                .execute(&mut *tx)
                .await
                .map_err(fail)?;
            sqlx::query("INSERT INTO _history_key_migrations (name) VALUES ($1)")
                .bind(migration.name)
                .execute(&mut *tx)
                .await
                .map_err(fail)?;
            tx.commit().await.map_err(fail)?;
        }
        Ok(())
    }
    .await;
    let unlocked =
        sqlx::query("SELECT pg_advisory_unlock(hashtextextended('sid.history_key.migrations', 0))")
            .execute(&mut *conn)
            .await;
    applied?;
    unlocked.map_err(|e| SidError::Storage(format!("Failed to release migration lock: {}", e)))?;
    Ok(())
}

/// Run all pending migrations against the database.
///
/// Creates the `_migrations` tracking table if it doesn't exist,
/// then executes each migration that hasn't been applied yet.
///
/// If `schema` is provided, creates the schema and sets `search_path`
/// so all tables land in that schema (shared-database isolation).
pub async fn run_migrations(pool: &PgPool, schema: Option<&str>) -> SidResult<()> {
    migrate(pool, schema).await
}

async fn migrate(pool: &PgPool, schema: Option<&str>) -> SidResult<()> {
    // Schema isolation: create schema and set search_path
    if let Some(schema_name) = schema {
        validate_schema_name(schema_name)?;

        // A schema name cannot be a bind parameter. `validate_schema_name`
        // above admits only ASCII alphanumerics, `_` and `-`, none of which
        // can end the quoted identifier this interpolates into.
        sqlx::query(AssertSqlSafe(format!(
            "CREATE SCHEMA IF NOT EXISTS \"{}\"",
            schema_name
        )))
        .execute(pool)
        .await
        .map_err(|e| {
            SidError::Storage(format!("Failed to create schema '{}': {}", schema_name, e))
        })?;

        // Same validated identifier, same reason.
        sqlx::query(AssertSqlSafe(format!(
            "SET search_path TO \"{}\", public",
            schema_name
        )))
        .execute(pool)
        .await
        .map_err(|e| {
            SidError::Storage(format!(
                "Failed to set search_path to '{}': {}",
                schema_name, e
            ))
        })?;

        info!("Using schema '{}' for SID tables", schema_name);
    }

    // An advisory lock belongs to the session that took it, so the lock, every
    // migration and the unlock run on one connection taken out of the pool.
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| SidError::Storage(format!("Failed to acquire a connection: {}", e)))?;
    sqlx::query("SELECT pg_advisory_lock(42)")
        .execute(&mut *conn)
        .await
        .map_err(|e| SidError::Storage(format!("Failed to acquire migration lock: {}", e)))?;
    let applied = apply_pending(&mut conn).await;
    let unlocked = sqlx::query("SELECT pg_advisory_unlock(42)")
        .execute(&mut *conn)
        .await;
    let applied_count = applied?;
    unlocked.map_err(|e| SidError::Storage(format!("Failed to release migration lock: {}", e)))?;

    if applied_count > 0 {
        info!("Applied {} migration(s)", applied_count);
    } else {
        info!("Database is up to date (all migrations applied)");
    }
    let quarantined: i64 = sqlx::query_scalar(crate::QUARANTINED_EMAIL_KEYS_SQL)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| SidError::Storage(format!("count quarantined email keys: {e}")))?;
    crate::warn_quarantined_email_keys(quarantined);

    // Schema isolation: create read-only reader role for application JOINs.
    if let Some(schema_name) = schema {
        let role_name = format!("{}_reader", schema_name.replace('-', "_"));
        // role_name is the validated schema name with `-` turned into `_`,
        // so it carries no quote that could close this string literal.
        let role_exists: bool = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = '{}')",
            role_name
        )))
        .fetch_one(pool)
        .await
        .map_err(|e| SidError::Storage(format!("Failed to look up reader role: {}", e)))?;

        if !role_exists {
            sqlx::query(AssertSqlSafe(format!(
                "CREATE ROLE \"{}\" NOLOGIN",
                role_name
            )))
            .execute(pool)
            .await
            .map_err(|e| {
                SidError::Storage(format!(
                    "Failed to create reader role '{}': {}",
                    role_name, e
                ))
            })?;
            info!("Created reader role '{}'", role_name);
        }

        sqlx::query(AssertSqlSafe(format!(
            "GRANT USAGE ON SCHEMA \"{}\" TO \"{}\"",
            schema_name, role_name
        )))
        .execute(pool)
        .await
        .map_err(|e| SidError::Storage(format!("Failed to grant schema usage: {}", e)))?;

        sqlx::query(AssertSqlSafe(format!(
            "GRANT SELECT ON \"{}\".profiles_view TO \"{}\"",
            schema_name, role_name
        )))
        .execute(pool)
        .await
        .map_err(|e| {
            SidError::Storage(format!("Failed to grant select on profiles_view: {}", e))
        })?;

        info!(
            "Schema isolation ready: reader role '{}' can SELECT from {}.profiles_view",
            role_name, schema_name
        );
    }

    Ok(())
}

/// Apply every migration not yet recorded, each in its own transaction with its `_migrations` row, so a crash leaves a
/// migration either applied and recorded or not applied at all. Returns how
/// many were applied.
async fn apply_pending(conn: &mut sqlx::PgConnection) -> SidResult<u32> {
    use sqlx::Connection;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS _migrations (
            name TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| SidError::Storage(format!("Failed to create _migrations table: {}", e)))?;

    let applied: Vec<String> =
        sqlx::query_scalar::<_, String>("SELECT name FROM _migrations ORDER BY name")
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| SidError::Storage(format!("Failed to query _migrations: {}", e)))?;

    let mut applied_count = 0u32;
    for migration in MIGRATIONS {
        if !applied.iter().any(|name| name == migration.name) {
            info!("Running migration: {}", migration.name);

            let fail = |e: sqlx::Error| {
                SidError::Storage(format!("Migration '{}' failed: {}", migration.name, e))
            };
            let mut tx = conn.begin().await.map_err(fail)?;
            sqlx::raw_sql(migration.sql)
                .execute(&mut *tx)
                .await
                .map_err(fail)?;
            sqlx::query("INSERT INTO _migrations (name) VALUES ($1)")
                .bind(migration.name)
                .execute(&mut *tx)
                .await
                .map_err(fail)?;
            tx.commit().await.map_err(fail)?;
            applied_count += 1;
        }
    }
    Ok(applied_count)
}

/// Validate schema name to prevent SQL injection.
/// Only allows alphanumeric characters, underscores, and hyphens.
pub fn validate_schema_name(name: &str) -> SidResult<()> {
    if name.is_empty() || name.len() > 63 {
        return Err(SidError::Validation(
            "Schema name must be 1-63 characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(SidError::Validation(
            "Schema name must contain only alphanumeric characters, underscores, or hyphens".into(),
        ));
    }
    Ok(())
}

/// Validate a PostgreSQL connection URL with the parser the backend connects
/// with, without connecting.
pub fn validate_database_url(url: &str) -> SidResult<()> {
    url.parse::<sqlx::postgres::PgConnectOptions>()
        .map(drop)
        .map_err(|e| SidError::Validation(format!("Invalid database URL: {e}")))
}

#[cfg(test)]
mod tests;
