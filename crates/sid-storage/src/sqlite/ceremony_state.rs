// SPDX-License-Identifier: AGPL-3.0-only
//! Ceremony state and single-use admissions. Each write is one statement in
//! a write transaction, which SQLite serializes; deadlines are wall-clock
//! milliseconds of the host, the one clock every process sharing the file
//! reads.

use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::{
    CeremonyCount, CeremonyEntry, CeremonyRecords, CeremonyStateStore, SingleUseAdmissions,
};

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

/// Remove `ceremony` inside a mutation's write transaction, while it is live
/// and exactly as read; otherwise `Error::Expired`, and the mutation commits
/// nothing. The write transaction holds SQLite's write lock, so no other
/// consumer runs between the check and the removal.
pub(crate) async fn consume_in_tx(
    tx: &mut super::WriteTx,
    ceremony: &sid_core::models::CeremonyConsumption,
) -> SidResult<()> {
    let removed = sqlx::query(
        "DELETE FROM ceremony_states
         WHERE namespace = ? AND state_key = ? AND value = ? AND expires_at_ms > ?",
    )
    .bind(ceremony.namespace)
    .bind(&ceremony.key)
    .bind(&ceremony.stored)
    .bind(now_ms())
    .execute(&mut **tx)
    .await
    .map_err(failure("consume ceremony state"))?
    .rows_affected();
    if removed == 1 {
        Ok(())
    } else {
        Err(SidError::Expired(format!(
            "ceremony {}:{} is no longer pending",
            ceremony.namespace, ceremony.key
        )))
    }
}

type CeremonyQuery<'q> = sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments>;

impl SqliteBackend {
    /// Run the write statement `build` makes for the clock's `now` and
    /// commit; the number of rows it changed. The clock is read holding the
    /// write lock: a write that waited for another writer judges expiry when
    /// it applies, not when it was asked for.
    async fn ceremony_write<'q>(
        &self,
        what: &str,
        build: impl FnOnce(i64) -> SidResult<CeremonyQuery<'q>>,
    ) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        let changed = build(now_ms())?
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
        let admitted = self
            .ceremony_write("admit once", |now| {
                Ok(sqlx::query(
                    "INSERT INTO ceremony_states (namespace, state_key, value, expires_at_ms)
                     VALUES (?, ?, X'', ?)
                     ON CONFLICT (namespace, state_key) DO UPDATE SET
                         value = excluded.value, expires_at_ms = excluded.expires_at_ms
                     WHERE ceremony_states.expires_at_ms <= ?",
                )
                .bind(namespace)
                .bind(key)
                .bind(deadline(now, ttl)?)
                .bind(now))
            })
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
        let held = self
            .ceremony_write("admit for holder", |now| {
                Ok(sqlx::query(
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
                .bind(now))
            })
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
        self.ceremony_write("store ceremony state", |now| {
            Ok(sqlx::query(
                "INSERT INTO ceremony_states (namespace, state_key, value, expires_at_ms)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT (namespace, state_key) DO UPDATE SET
                     value = excluded.value, expires_at_ms = excluded.expires_at_ms",
            )
            .bind(namespace)
            .bind(key)
            .bind(value)
            .bind(deadline(now, ttl)?))
        })
        .await?;
        Ok(())
    }

    async fn put_ceremony_state_owing(
        &self,
        namespace: &str,
        key: &str,
        value: &[u8],
        ttl: Duration,
        owed: &sid_core::models::NewWork,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO ceremony_states (namespace, state_key, value, expires_at_ms)
             VALUES (?, ?, ?, ?)
             ON CONFLICT (namespace, state_key) DO UPDATE SET
                 value = excluded.value, expires_at_ms = excluded.expires_at_ms",
        )
        .bind(namespace)
        .bind(key)
        .bind(value)
        .bind(deadline(now_ms(), ttl)?)
        .execute(&mut *tx)
        .await
        .map_err(failure("store ceremony state"))?;
        super::work::insert_work_in_tx(&mut tx, owed).await?;
        tx.commit().await.map_err(failure("store ceremony state"))?;
        Ok(())
    }

    async fn replace_ceremony_state_owing(
        &self,
        namespace: &str,
        key: &str,
        expected: &[u8],
        value: &[u8],
        ttl: Duration,
        owed: &sid_core::models::NewWork,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        // Read holding the write lock, as `ceremony_write` does.
        let now = now_ms();
        let replaced = sqlx::query(
            "UPDATE ceremony_states SET value = ?, expires_at_ms = ?
             WHERE namespace = ? AND state_key = ? AND value = ? AND expires_at_ms > ?",
        )
        .bind(value)
        .bind(deadline(now, ttl)?)
        .bind(namespace)
        .bind(key)
        .bind(expected)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(failure("replace ceremony state"))?
        .rows_affected();
        if replaced != 1 {
            return Ok(false);
        }
        super::work::insert_work_in_tx(&mut tx, owed).await?;
        tx.commit()
            .await
            .map_err(failure("replace ceremony state"))?;
        Ok(true)
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
        let replaced = self
            .ceremony_write("replace ceremony state", |now| {
                Ok(sqlx::query(
                    "UPDATE ceremony_states SET value = ?, expires_at_ms = ?
                     WHERE namespace = ? AND state_key = ? AND value = ? AND expires_at_ms > ?",
                )
                .bind(value)
                .bind(deadline(now, ttl)?)
                .bind(namespace)
                .bind(key)
                .bind(expected)
                .bind(now))
            })
            .await?;
        Ok(replaced == 1)
    }

    async fn count_in_window(
        &self,
        namespace: &str,
        key: &str,
        window: Duration,
    ) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        // Read holding the write lock, as `ceremony_write` does.
        let now = now_ms();
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

    async fn read_count(&self, namespace: &str, key: &str) -> SidResult<u64> {
        let count: Option<i64> = sqlx::query_scalar(
            "SELECT count FROM ceremony_counts
             WHERE namespace = ? AND count_key = ? AND window_ends_ms > ?",
        )
        .bind(namespace)
        .bind(key)
        .bind(now_ms())
        .fetch_optional(&self.pool)
        .await
        .map_err(failure("read count"))?;
        let count = count.unwrap_or(0);
        u64::try_from(count).map_err(|_| SidError::Storage(format!("count of {key} is {count}")))
    }

    async fn clear_count(&self, namespace: &str, key: &str) -> SidResult<()> {
        self.ceremony_write("clear count", |_| {
            Ok(
                sqlx::query("DELETE FROM ceremony_counts WHERE namespace = ? AND count_key = ?")
                    .bind(namespace)
                    .bind(key),
            )
        })
        .await?;
        Ok(())
    }

    async fn purge_expired_ceremony_state(&self) -> SidResult<u64> {
        let states = self
            .ceremony_write("purge ceremony state", |now| {
                Ok(sqlx::query("DELETE FROM ceremony_states WHERE expires_at_ms <= ?").bind(now))
            })
            .await?;
        let counts = self
            .ceremony_write("purge ceremony counts", |now| {
                Ok(sqlx::query("DELETE FROM ceremony_counts WHERE window_ends_ms <= ?").bind(now))
            })
            .await?;
        Ok(states + counts)
    }

    async fn export_ceremony_state(&self) -> SidResult<CeremonyRecords> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(failure("export ceremony state"))?;
        let now = now_ms();
        let states: Vec<(String, String, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT namespace, state_key, value, expires_at_ms FROM ceremony_states
             WHERE expires_at_ms > ? ORDER BY namespace, state_key",
        )
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .map_err(failure("export ceremony state"))?;
        let counts: Vec<(String, String, i64, i64)> = sqlx::query_as(
            "SELECT namespace, count_key, count, window_ends_ms FROM ceremony_counts
             WHERE window_ends_ms > ? ORDER BY namespace, count_key",
        )
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .map_err(failure("export ceremony counts"))?;
        tx.commit()
            .await
            .map_err(failure("export ceremony state"))?;
        Ok(CeremonyRecords {
            states: states
                .into_iter()
                .map(|(namespace, key, value, ms)| {
                    Ok(CeremonyEntry {
                        namespace,
                        key,
                        value,
                        expires_at: instant(ms)?,
                    })
                })
                .collect::<SidResult<_>>()?,
            counts: counts
                .into_iter()
                .map(|(namespace, key, count, ms)| {
                    Ok(CeremonyCount {
                        namespace,
                        count: u64::try_from(count)
                            .map_err(|_| SidError::Storage(format!("count of {key} is {count}")))?,
                        key,
                        window_ends: instant(ms)?,
                    })
                })
                .collect::<SidResult<_>>()?,
        })
    }

    async fn import_ceremony_state(&self, records: &CeremonyRecords) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        let now = now_ms();
        let mut stored = 0;
        for entry in &records.states {
            let held: Option<(Vec<u8>, i64)> = sqlx::query_as(
                "SELECT value, expires_at_ms FROM ceremony_states
                 WHERE namespace = ? AND state_key = ? AND expires_at_ms > ?",
            )
            .bind(&entry.namespace)
            .bind(&entry.key)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await
            .map_err(failure("import ceremony state"))?;
            let wanted = (entry.value.clone(), entry.expires_at.timestamp_millis());
            if let Some(held) = held {
                crate::transfer_repeat(&held, &wanted, "ceremony state")?;
                continue;
            }
            sqlx::query(
                "INSERT INTO ceremony_states (namespace, state_key, value, expires_at_ms)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT (namespace, state_key) DO UPDATE SET
                     value = excluded.value, expires_at_ms = excluded.expires_at_ms",
            )
            .bind(&entry.namespace)
            .bind(&entry.key)
            .bind(&entry.value)
            .bind(wanted.1)
            .execute(&mut *tx)
            .await
            .map_err(failure("import ceremony state"))?;
            stored += 1;
        }
        for count in &records.counts {
            let held: Option<(i64, i64)> = sqlx::query_as(
                "SELECT count, window_ends_ms FROM ceremony_counts
                 WHERE namespace = ? AND count_key = ? AND window_ends_ms > ?",
            )
            .bind(&count.namespace)
            .bind(&count.key)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await
            .map_err(failure("import ceremony count"))?;
            let value = i64::try_from(count.count).map_err(|_| {
                SidError::Validation(format!("count of {} is too large", count.key))
            })?;
            let wanted = (value, count.window_ends.timestamp_millis());
            if let Some(held) = held {
                crate::transfer_repeat(&held, &wanted, "ceremony count")?;
                continue;
            }
            sqlx::query(
                "INSERT INTO ceremony_counts (namespace, count_key, count, window_ends_ms)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT (namespace, count_key) DO UPDATE SET
                     count = excluded.count, window_ends_ms = excluded.window_ends_ms",
            )
            .bind(&count.namespace)
            .bind(&count.key)
            .bind(value)
            .bind(wanted.1)
            .execute(&mut *tx)
            .await
            .map_err(failure("import ceremony count"))?;
            stored += 1;
        }
        tx.commit()
            .await
            .map_err(failure("import ceremony state"))?;
        Ok(stored)
    }
}

/// The instant of a stored millisecond deadline.
fn instant(ms: i64) -> SidResult<chrono::DateTime<Utc>> {
    chrono::DateTime::from_timestamp_millis(ms)
        .ok_or_else(|| SidError::Storage(format!("ceremony deadline {ms} is out of range")))
}
