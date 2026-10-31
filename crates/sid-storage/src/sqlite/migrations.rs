// SPDX-License-Identifier: AGPL-3.0-only
//! The schema of a SQLite database file.
//!
//! A file records its schema version in `PRAGMA user_version`. An empty file
//! gets the schema in one `BEGIN IMMEDIATE` transaction, so a second process
//! opening it waits for the first and finds it current. A file of any other
//! version or shape is refused unchanged, never recreated: before the first
//! release such a file is recreated by its owner, not migrated.

use sid_core::{Error as SidError, Result as SidResult};
use sqlx::{SqliteConnection, SqlitePool};

/// The version of [`super::schema::SCHEMA`]. Raised with every schema change.
pub(crate) const SCHEMA_VERSION: i64 = 14;

/// Give the empty file behind `pool` the schema, or check that it has it.
pub(crate) async fn prepare(pool: &SqlitePool, schema: &'static str) -> SidResult<()> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(storage("begin schema creation"))?;
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("read schema version"))?;
    match version {
        SCHEMA_VERSION => return Ok(()),
        0 if is_empty(&mut tx).await? => {}
        v => {
            return Err(SidError::InvalidState(format!(
                "the SQLite file has schema version {v}, this build serves {SCHEMA_VERSION}; \
                 it is left unchanged"
            )));
        }
    }
    sqlx::raw_sql(schema)
        .execute(&mut *tx)
        .await
        .map_err(storage("create schema"))?;
    // A PRAGMA takes no bound parameter; the version is an integer constant.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "PRAGMA user_version = {SCHEMA_VERSION}"
    )))
    .execute(&mut *tx)
    .await
    .map_err(storage("record schema version"))?;
    tx.commit().await.map_err(storage("commit schema creation"))
}

/// Whether the database holds no schema object.
async fn is_empty(conn: &mut SqliteConnection) -> SidResult<bool> {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
    )
    .fetch_one(conn)
    .await
    .map(|n| n == 0)
    .map_err(storage("read schema objects"))
}

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

#[cfg(test)]
mod tests;
