// SPDX-License-Identifier: AGPL-3.0-only
//! Ceremony state and single-use admissions. Every statement is one atomic
//! step on its row, and every deadline is the server's `clock_timestamp()`:
//! `NOW()` is fixed when the transaction began, so a statement that waited
//! on a row lock past an expiry would still see the row live. The current
//! clock is read when the row is reached, its lock held, and a conflict
//! update computes its new deadline then, never from `EXCLUDED`, whose value
//! the insert computed before the wait.

use std::time::Duration;

use async_trait::async_trait;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::{
    CeremonyCount, CeremonyEntry, CeremonyRecords, CeremonyStateStore, SingleUseAdmissions,
};

use super::PostgresBackend;

fn failure(what: &str) -> impl FnOnce(sqlx::Error) -> SidError + '_ {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

impl PostgresBackend {
    /// A transaction holding the lock of the state row `key`, if it exists.
    /// A statement whose row lock merely waited is not re-evaluated by
    /// PostgreSQL when the row is unchanged, so its expiry check would rest
    /// on a read made before the wait; the check runs after this instead.
    async fn lock_state(
        &self,
        namespace: &str,
        key: &str,
        what: &str,
    ) -> SidResult<sqlx::Transaction<'static, sqlx::Postgres>> {
        let mut tx = self.pool.begin().await.map_err(failure(what))?;
        sqlx::query(
            "SELECT 1 FROM ceremony_states WHERE namespace = $1 AND state_key = $2 FOR UPDATE",
        )
        .bind(namespace)
        .bind(key)
        .execute(&mut *tx)
        .await
        .map_err(failure(what))?;
        Ok(tx)
    }
}

/// Remove `ceremony` inside a mutation's transaction, while it is live and
/// exactly as read; otherwise `Error::Expired`, and the mutation commits
/// nothing. The row is locked first, so the condition is evaluated on the
/// version a concurrent consumer left (see [`PostgresBackend::lock_state`]).
pub(crate) async fn consume_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ceremony: &sid_core::models::CeremonyConsumption,
) -> SidResult<()> {
    sqlx::query("SELECT 1 FROM ceremony_states WHERE namespace = $1 AND state_key = $2 FOR UPDATE")
        .bind(ceremony.namespace)
        .bind(&ceremony.key)
        .execute(&mut **tx)
        .await
        .map_err(failure("lock ceremony state"))?;
    let removed = sqlx::query(
        "DELETE FROM ceremony_states
         WHERE namespace = $1 AND state_key = $2 AND value = $3 AND expires_at > clock_timestamp()",
    )
    .bind(ceremony.namespace)
    .bind(&ceremony.key)
    .bind(&ceremony.stored)
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

/// `ttl` in seconds, as `make_interval` takes it.
fn seconds(ttl: Duration) -> f64 {
    ttl.as_secs_f64()
}

#[async_trait]
impl SingleUseAdmissions for PostgresBackend {
    async fn admit_once(&self, namespace: &str, key: &str, ttl: Duration) -> SidResult<bool> {
        // A concurrent insert of the key waits for this one; the conflict
        // then takes the key over only from an expired admission.
        let admitted = sqlx::query(
            "INSERT INTO ceremony_states (namespace, state_key, value, expires_at)
             VALUES ($1, $2, ''::bytea, clock_timestamp() + make_interval(secs => $3))
             ON CONFLICT (namespace, state_key) DO UPDATE SET
                 value = EXCLUDED.value,
                 expires_at = clock_timestamp() + make_interval(secs => $3)
             WHERE ceremony_states.expires_at <= clock_timestamp()",
        )
        .bind(namespace)
        .bind(key)
        .bind(seconds(ttl))
        .execute(&self.pool)
        .await
        .map_err(failure("admit once"))?
        .rows_affected();
        Ok(admitted == 1)
    }

    async fn admit_for(
        &self,
        namespace: &str,
        key: &str,
        holder: &[u8],
        ttl: Duration,
    ) -> SidResult<bool> {
        // One statement: an expired admission is taken over, the holder's own
        // live one is touched without a new deadline, another holder's live
        // one leaves the row unchanged and no row affected.
        let held = sqlx::query(
            "INSERT INTO ceremony_states (namespace, state_key, value, expires_at)
             VALUES ($1, $2, $3, clock_timestamp() + make_interval(secs => $4))
             ON CONFLICT (namespace, state_key) DO UPDATE SET
                 value = CASE WHEN ceremony_states.expires_at <= clock_timestamp()
                              THEN EXCLUDED.value ELSE ceremony_states.value END,
                 expires_at = CASE WHEN ceremony_states.expires_at <= clock_timestamp()
                                   THEN clock_timestamp() + make_interval(secs => $4)
                                   ELSE ceremony_states.expires_at END
             WHERE ceremony_states.expires_at <= clock_timestamp() OR ceremony_states.value = EXCLUDED.value",
        )
        .bind(namespace)
        .bind(key)
        .bind(holder)
        .bind(seconds(ttl))
        .execute(&self.pool)
        .await
        .map_err(failure("admit for holder"))?
        .rows_affected();
        Ok(held == 1)
    }
}

#[async_trait]
impl CeremonyStateStore for PostgresBackend {
    async fn put_ceremony_state(
        &self,
        namespace: &str,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> SidResult<()> {
        sqlx::query(
            "INSERT INTO ceremony_states (namespace, state_key, value, expires_at)
             VALUES ($1, $2, $3, clock_timestamp() + make_interval(secs => $4))
             ON CONFLICT (namespace, state_key) DO UPDATE SET
                 value = EXCLUDED.value,
                 expires_at = clock_timestamp() + make_interval(secs => $4)",
        )
        .bind(namespace)
        .bind(key)
        .bind(value)
        .bind(seconds(ttl))
        .execute(&self.pool)
        .await
        .map_err(failure("store ceremony state"))?;
        Ok(())
    }

    async fn take_ceremony_state(&self, namespace: &str, key: &str) -> SidResult<Option<Vec<u8>>> {
        // A concurrent delete of the same row waits for this one and then
        // finds nothing, so one taker gets the value.
        let mut tx = self
            .lock_state(namespace, key, "take ceremony state")
            .await?;
        let value = sqlx::query_scalar(
            "DELETE FROM ceremony_states
             WHERE namespace = $1 AND state_key = $2 AND expires_at > clock_timestamp()
             RETURNING value",
        )
        .bind(namespace)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(failure("take ceremony state"))?;
        tx.commit().await.map_err(failure("take ceremony state"))?;
        Ok(value)
    }

    async fn read_ceremony_state(&self, namespace: &str, key: &str) -> SidResult<Option<Vec<u8>>> {
        sqlx::query_scalar(
            "SELECT value FROM ceremony_states
             WHERE namespace = $1 AND state_key = $2 AND expires_at > clock_timestamp()",
        )
        .bind(namespace)
        .bind(key)
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
        // A concurrent update of the row waits on its lock, then evaluates
        // the condition on the version it left: only the first one applies.
        let mut tx = self
            .lock_state(namespace, key, "replace ceremony state")
            .await?;
        let replaced = sqlx::query(
            "UPDATE ceremony_states
             SET value = $4, expires_at = clock_timestamp() + make_interval(secs => $5)
             WHERE namespace = $1 AND state_key = $2 AND value = $3 AND expires_at > clock_timestamp()",
        )
        .bind(namespace)
        .bind(key)
        .bind(expected)
        .bind(value)
        .bind(seconds(ttl))
        .execute(&mut *tx)
        .await
        .map_err(failure("replace ceremony state"))?
        .rows_affected();
        tx.commit()
            .await
            .map_err(failure("replace ceremony state"))?;
        Ok(replaced == 1)
    }

    async fn count_in_window(
        &self,
        namespace: &str,
        key: &str,
        window: Duration,
    ) -> SidResult<u64> {
        // Concurrent upserts of the key serialize on its row, so each event
        // adds exactly one.
        let count: i64 = sqlx::query_scalar(
            "INSERT INTO ceremony_counts (namespace, count_key, count, window_ends)
             VALUES ($1, $2, 1, clock_timestamp() + make_interval(secs => $3))
             ON CONFLICT (namespace, count_key) DO UPDATE SET
                 count = CASE WHEN ceremony_counts.window_ends <= clock_timestamp() THEN 1
                              ELSE ceremony_counts.count + 1 END,
                 window_ends = CASE WHEN ceremony_counts.window_ends <= clock_timestamp()
                                    THEN clock_timestamp() + make_interval(secs => $3)
                                    ELSE ceremony_counts.window_ends END
             RETURNING count",
        )
        .bind(namespace)
        .bind(key)
        .bind(seconds(window))
        .fetch_one(&self.pool)
        .await
        .map_err(failure("count in window"))?;
        u64::try_from(count).map_err(|_| SidError::Storage(format!("count of {key} is {count}")))
    }

    async fn read_count(&self, namespace: &str, key: &str) -> SidResult<u64> {
        let count: Option<i64> = sqlx::query_scalar(
            "SELECT count FROM ceremony_counts
             WHERE namespace = $1 AND count_key = $2 AND window_ends > clock_timestamp()",
        )
        .bind(namespace)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(failure("read count"))?;
        let count = count.unwrap_or(0);
        u64::try_from(count).map_err(|_| SidError::Storage(format!("count of {key} is {count}")))
    }

    async fn clear_count(&self, namespace: &str, key: &str) -> SidResult<()> {
        sqlx::query("DELETE FROM ceremony_counts WHERE namespace = $1 AND count_key = $2")
            .bind(namespace)
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(failure("clear count"))?;
        Ok(())
    }

    // Use refuses expired rows already; the server's periodic task calls this
    // to reclaim them (`background_tasks::purge_ceremony_state`).
    async fn purge_expired_ceremony_state(&self) -> SidResult<u64> {
        let states =
            sqlx::query("DELETE FROM ceremony_states WHERE expires_at <= clock_timestamp()")
                .execute(&self.pool)
                .await
                .map_err(failure("purge ceremony state"))?
                .rows_affected();
        let counts =
            sqlx::query("DELETE FROM ceremony_counts WHERE window_ends <= clock_timestamp()")
                .execute(&self.pool)
                .await
                .map_err(failure("purge ceremony counts"))?
                .rows_affected();
        Ok(states + counts)
    }

    async fn export_ceremony_state(&self) -> SidResult<CeremonyRecords> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(failure("export ceremony state"))?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(failure("export ceremony state"))?;
        let states: Vec<(String, String, Vec<u8>, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            // Milliseconds: the precision every store keeps a deadline at.
            "SELECT namespace, state_key, value, date_trunc('milliseconds', expires_at)
             FROM ceremony_states
             WHERE expires_at > clock_timestamp() ORDER BY namespace, state_key",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(failure("export ceremony state"))?;
        let counts: Vec<(String, String, i64, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT namespace, count_key, count, date_trunc('milliseconds', window_ends)
             FROM ceremony_counts
             WHERE window_ends > clock_timestamp() ORDER BY namespace, count_key",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(failure("export ceremony counts"))?;
        tx.commit()
            .await
            .map_err(failure("export ceremony state"))?;
        Ok(CeremonyRecords {
            states: states
                .into_iter()
                .map(|(namespace, key, value, expires_at)| CeremonyEntry {
                    namespace,
                    key,
                    value,
                    expires_at,
                })
                .collect(),
            counts: counts
                .into_iter()
                .map(|(namespace, key, count, window_ends)| {
                    Ok(CeremonyCount {
                        namespace,
                        count: u64::try_from(count)
                            .map_err(|_| SidError::Storage(format!("count of {key} is {count}")))?,
                        key,
                        window_ends,
                    })
                })
                .collect::<SidResult<_>>()?,
        })
    }

    async fn import_ceremony_state(&self, records: &CeremonyRecords) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(failure("import ceremony state"))?;
        let mut stored = 0;
        for entry in &records.states {
            // The row lock orders this with a concurrent writer of the key.
            let held: Option<(Vec<u8>, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
                "SELECT value, date_trunc('milliseconds', expires_at) FROM ceremony_states
                 WHERE namespace = $1 AND state_key = $2 AND expires_at > clock_timestamp()
                 FOR UPDATE",
            )
            .bind(&entry.namespace)
            .bind(&entry.key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(failure("import ceremony state"))?;
            if let Some(held) = held {
                crate::transfer_repeat(
                    &held,
                    &(entry.value.clone(), entry.expires_at),
                    "ceremony state",
                )?;
                continue;
            }
            sqlx::query(
                "INSERT INTO ceremony_states (namespace, state_key, value, expires_at)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, state_key) DO UPDATE SET
                     value = EXCLUDED.value, expires_at = EXCLUDED.expires_at",
            )
            .bind(&entry.namespace)
            .bind(&entry.key)
            .bind(&entry.value)
            .bind(entry.expires_at)
            .execute(&mut *tx)
            .await
            .map_err(failure("import ceremony state"))?;
            stored += 1;
        }
        for count in &records.counts {
            let value = i64::try_from(count.count).map_err(|_| {
                SidError::Validation(format!("count of {} is too large", count.key))
            })?;
            let held: Option<(i64, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
                "SELECT count, date_trunc('milliseconds', window_ends) FROM ceremony_counts
                 WHERE namespace = $1 AND count_key = $2 AND window_ends > clock_timestamp()
                 FOR UPDATE",
            )
            .bind(&count.namespace)
            .bind(&count.key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(failure("import ceremony count"))?;
            if let Some(held) = held {
                crate::transfer_repeat(&held, &(value, count.window_ends), "ceremony count")?;
                continue;
            }
            sqlx::query(
                "INSERT INTO ceremony_counts (namespace, count_key, count, window_ends)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, count_key) DO UPDATE SET
                     count = EXCLUDED.count, window_ends = EXCLUDED.window_ends",
            )
            .bind(&count.namespace)
            .bind(&count.key)
            .bind(value)
            .bind(count.window_ends)
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
