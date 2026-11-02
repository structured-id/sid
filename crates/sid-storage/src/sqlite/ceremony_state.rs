// SPDX-License-Identifier: AGPL-3.0-only
//! Ceremony state and single-use admissions. Each write is one statement in
//! a write transaction, which SQLite serializes; deadlines are wall-clock
//! milliseconds of the host, the one clock every process sharing the file
//! reads.

use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::{CeremonyStateStore, SingleUseAdmissions};

use super::SqliteBackend;

fn failure(what: &str) -> impl FnOnce(sqlx::Error) -> SidError + '_ {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// The deadline `ttl` from `now`; a lifetime past the millisecond range is
/// a caller error, never a deadline in the past.
fn deadline(now: i64, ttl: Duration) -> SidResult<i64> {
    i64::try_from(ttl.as_millis())
        .ok()
        .and_then(|ttl| now.checked_add(ttl))
        .ok_or_else(|| {
            SidError::Storage(format!("ceremony state lifetime {ttl:?} is out of range"))
        })
}

impl SqliteBackend {
    /// Run one write statement and commit; the number of rows it changed.
    async fn ceremony_write(
        &self,
        what: &str,
        query: sqlx::query::Query<'_, sqlx::Sqlite, sqlx::sqlite::SqliteArguments>,
    ) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        let changed = query
            .execute(&mut *tx)
            .await
            .map_err(failure(what))?
            .rows_affected();
        tx.commit().await.map_err(failure(what))?;
        Ok(changed)
    }
}

#[async_trait]
impl SingleUseAdmissions for SqliteBackend {
    async fn admit_once(&self, namespace: &str, key: &str, ttl: Duration) -> SidResult<bool> {
        let now = now_ms();
        let admitted = self
            .ceremony_write(
                "admit once",
                sqlx::query(
                    "INSERT INTO ceremony_states (namespace, state_key, value, expires_at_ms)
                     VALUES (?, ?, X'', ?)
                     ON CONFLICT (namespace, state_key) DO UPDATE SET
                         value = excluded.value, expires_at_ms = excluded.expires_at_ms
                     WHERE ceremony_states.expires_at_ms <= ?",
                )
                .bind(namespace)
                .bind(key)
                .bind(deadline(now, ttl)?)
                .bind(now),
            )
            .await?;
        Ok(admitted == 1)
    }

    async fn admit_for(
        &self,
        namespace: &str,
        key: &str,
        holder: &[u8],
        ttl: Duration,
    ) -> SidResult<bool> {
        let now = now_ms();
        let held = self
            .ceremony_write(
                "admit for holder",
                sqlx::query(
                    "INSERT INTO ceremony_states (namespace, state_key, value, expires_at_ms)
                     VALUES (?, ?, ?, ?)
                     ON CONFLICT (namespace, state_key) DO UPDATE SET
                         value = CASE WHEN ceremony_states.expires_at_ms <= ?
                                      THEN excluded.value ELSE ceremony_states.value END,
                         expires_at_ms = CASE WHEN ceremony_states.expires_at_ms <= ?
                                              THEN excluded.expires_at_ms
                                              ELSE ceremony_states.expires_at_ms END
                     WHERE ceremony_states.expires_at_ms <= ? OR ceremony_states.value = excluded.value",
                )
                .bind(namespace)
                .bind(key)
                .bind(holder)
                .bind(deadline(now, ttl)?)
                .bind(now)
                .bind(now)
                .bind(now),
            )
            .await?;
        Ok(held == 1)
    }
}

#[async_trait]
impl CeremonyStateStore for SqliteBackend {
    async fn put_ceremony_state(
        &self,
        namespace: &str,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> SidResult<()> {
        let expires = deadline(now_ms(), ttl)?;
        self.ceremony_write(
            "store ceremony state",
            sqlx::query(
                "INSERT INTO ceremony_states (namespace, state_key, value, expires_at_ms)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT (namespace, state_key) DO UPDATE SET
                     value = excluded.value, expires_at_ms = excluded.expires_at_ms",
            )
            .bind(namespace)
            .bind(key)
            .bind(value)
            .bind(expires),
        )
        .await?;
        Ok(())
    }

    async fn take_ceremony_state(&self, namespace: &str, key: &str) -> SidResult<Option<Vec<u8>>> {
        let mut tx = self.begin_write().await?;
        let value: Option<Vec<u8>> = sqlx::query_scalar(
            "DELETE FROM ceremony_states
             WHERE namespace = ? AND state_key = ? AND expires_at_ms > ?
             RETURNING value",
        )
        .bind(namespace)
        .bind(key)
        .bind(now_ms())
        .fetch_optional(&mut *tx)
        .await
        .map_err(failure("take ceremony state"))?;
        tx.commit().await.map_err(failure("take ceremony state"))?;
        Ok(value)
    }

    async fn read_ceremony_state(&self, namespace: &str, key: &str) -> SidResult<Option<Vec<u8>>> {
        sqlx::query_scalar(
            "SELECT value FROM ceremony_states
             WHERE namespace = ? AND state_key = ? AND expires_at_ms > ?",
        )
        .bind(namespace)
        .bind(key)
        .bind(now_ms())
        .fetch_optional(&self.pool)
        .await
        .map_err(failure("read ceremony state"))
    }

    async fn replace_ceremony_state(
        &self,
        namespace: &str,
        key: &str,
        expected: &[u8],
        value: &[u8],
        ttl: Duration,
    ) -> SidResult<bool> {
        let now = now_ms();
        let replaced = self
            .ceremony_write(
                "replace ceremony state",
                sqlx::query(
                    "UPDATE ceremony_states SET value = ?, expires_at_ms = ?
                     WHERE namespace = ? AND state_key = ? AND value = ? AND expires_at_ms > ?",
                )
                .bind(value)
                .bind(deadline(now, ttl)?)
                .bind(namespace)
                .bind(key)
                .bind(expected)
                .bind(now),
            )
            .await?;
        Ok(replaced == 1)
    }

    async fn count_in_window(
        &self,
        namespace: &str,
        key: &str,
        window: Duration,
    ) -> SidResult<u64> {
        let now = now_ms();
        let mut tx = self.begin_write().await?;
        let count: i64 = sqlx::query_scalar(
            "INSERT INTO ceremony_counts (namespace, count_key, count, window_ends_ms)
             VALUES (?, ?, 1, ?)
             ON CONFLICT (namespace, count_key) DO UPDATE SET
                 count = CASE WHEN ceremony_counts.window_ends_ms <= ? THEN 1
                              ELSE ceremony_counts.count + 1 END,
                 window_ends_ms = CASE WHEN ceremony_counts.window_ends_ms <= ?
                                       THEN excluded.window_ends_ms
                                       ELSE ceremony_counts.window_ends_ms END
             RETURNING count",
        )
        .bind(namespace)
        .bind(key)
        .bind(deadline(now, window)?)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(failure("count in window"))?;
        tx.commit().await.map_err(failure("count in window"))?;
        u64::try_from(count).map_err(|_| SidError::Storage(format!("count of {key} is {count}")))
    }

    async fn purge_expired_ceremony_state(&self) -> SidResult<u64> {
        let now = now_ms();
        let states = self
            .ceremony_write(
                "purge ceremony state",
                sqlx::query("DELETE FROM ceremony_states WHERE expires_at_ms <= ?").bind(now),
            )
            .await?;
        let counts = self
            .ceremony_write(
                "purge ceremony counts",
                sqlx::query("DELETE FROM ceremony_counts WHERE window_ends_ms <= ?").bind(now),
            )
            .await?;
        Ok(states + counts)
    }
}
