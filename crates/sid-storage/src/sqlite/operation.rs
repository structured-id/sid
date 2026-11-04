// SPDX-License-Identifier: AGPL-3.0-only
//! Completions of keyed commands, committed with their effect, and the
//! periods they are admitted under.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sid_core::models::{
    IssuedOperationPeriod, MutationContext, OperationCompletion, OperationKey, OperationPeriod,
    OperationPeriodPolicy, OperationPeriodRecord, OperationPeriodRefusal, OperationPeriodState,
    OperationRecord,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::OperationResultStore;
use sqlx::SqlitePool;

use super::{SqliteBackend, WriteTx, fmt_dt};

/// Record `operation` in `tx`. When another transaction already committed
/// the key, this one must commit nothing: `OperationCompleted`; a completion
/// past its retention no longer holds the key and is replaced. A keyed
/// command's period is admitted first; the write transaction serializes it
/// with every retirement.
pub(super) async fn record_in_tx(
    tx: &mut WriteTx,
    operation: &OperationCompletion,
) -> SidResult<()> {
    let period = operation.period.map(column).transpose()?;
    if let Some(period) = period {
        admit(tx, period).await?;
    }
    let now = Utc::now();
    let inserted = sqlx::query(
        "INSERT INTO operation_results
             (namespace, op_key, method, fingerprint, result, completed_at, period,
              retain_until_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (namespace, op_key) DO UPDATE SET
             method = excluded.method, fingerprint = excluded.fingerprint,
             result = excluded.result, completed_at = excluded.completed_at,
             period = excluded.period, retain_until_ms = excluded.retain_until_ms
         WHERE operation_results.retain_until_ms <= ?",
    )
    .bind(&operation.namespace)
    .bind(operation.key.as_str())
    .bind(&operation.method)
    .bind(&operation.fingerprint)
    .bind(&operation.result)
    .bind(fmt_dt(&now))
    .bind(period)
    .bind(operation.retain_until.map(|t| t.timestamp_millis()))
    .bind(now.timestamp_millis())
    .execute(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("operation completion: {e}")))?
    .rows_affected();
    if inserted == 0 {
        return Err(SidError::OperationCompleted(operation.key.as_str().into()));
    }
    Ok(())
}

/// Admit `period` on `conn`: refused when it has no row, as retired when
/// its number was issued, else as never issued.
async fn admit(conn: &mut sqlx::SqliteConnection, period: i64) -> SidResult<()> {
    let admitted: Option<i64> =
        sqlx::query_scalar("SELECT period FROM operation_periods WHERE period = ?")
            .bind(period)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| SidError::Storage(format!("operation period: {e}")))?;
    if admitted.is_some() {
        return Ok(());
    }
    let refusal = if period <= issued_through(conn).await? {
        OperationPeriodRefusal::Retired
    } else {
        OperationPeriodRefusal::NotIssued
    };
    Err(SidError::OperationPeriodRefused(refusal))
}

/// `period` as its INTEGER column.
fn column(period: OperationPeriod) -> SidResult<i64> {
    i64::try_from(period.get())
        .map_err(|_| SidError::OperationPeriodRefused(OperationPeriodRefusal::NotIssued))
}

/// An INTEGER period column as the period.
fn period_of(value: i64) -> SidResult<OperationPeriod> {
    u64::try_from(value)
        .map(OperationPeriod::new)
        .map_err(|_| SidError::Storage(format!("column period: {value}")))
}

/// A stored instant in Unix milliseconds; a malformed one is an error, never
/// a substitute.
fn instant(column: &str, ms: i64) -> SidResult<DateTime<Utc>> {
    DateTime::from_timestamp_millis(ms)
        .ok_or_else(|| SidError::Storage(format!("column {column}: {ms} is no instant")))
}

/// A stored retention end.
fn retention(ms: Option<i64>) -> SidResult<Option<DateTime<Utc>>> {
    ms.map(|ms| instant("retain_until_ms", ms)).transpose()
}

/// method, fingerprint, result, completed_at, period, retain_until_ms
type RecordRow = (String, Vec<u8>, Vec<u8>, String, Option<i64>, Option<i64>);

pub(super) async fn get(
    pool: &SqlitePool,
    namespace: &str,
    key: &OperationKey,
) -> SidResult<Option<OperationRecord>> {
    let row: Option<RecordRow> = sqlx::query_as(
        "SELECT method, fingerprint, result, completed_at, period, retain_until_ms
         FROM operation_results
         WHERE namespace = ? AND op_key = ? AND (retain_until_ms IS NULL OR retain_until_ms > ?)",
    )
    .bind(namespace)
    .bind(key.as_str())
    .bind(Utc::now().timestamp_millis())
    .fetch_optional(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation result: {e}")))?;
    row.map(
        |(method, fingerprint, result, completed_at, period, retain_until)| {
            Ok(OperationRecord {
                completion: OperationCompletion {
                    namespace: namespace.to_string(),
                    key: key.clone(),
                    method,
                    fingerprint,
                    result,
                    period: period.map(period_of).transpose()?,
                    retain_until: retention(retain_until)?,
                },
                completed_at: time("completed_at", &completed_at)?,
            })
        },
    )
    .transpose()
}

/// A stored RFC 3339 time; a malformed one is an error, never a substitute.
fn time(column: &str, value: &str) -> SidResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| SidError::Storage(format!("column {column}: bad timestamp {value}: {e}")))
}

/// namespace, op_key, method, fingerprint, result, completed_at, period,
/// retain_until_ms
type FullRow = (
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    String,
    Option<i64>,
    Option<i64>,
);

pub(super) async fn export(pool: &SqlitePool) -> SidResult<Vec<OperationRecord>> {
    let rows: Vec<FullRow> = sqlx::query_as(
        "SELECT namespace, op_key, method, fingerprint, result, completed_at, period,
                retain_until_ms
         FROM operation_results WHERE retain_until_ms IS NULL OR retain_until_ms > ?
         ORDER BY completed_at, namespace, op_key",
    )
    .bind(Utc::now().timestamp_millis())
    .fetch_all(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation results: {e}")))?;
    rows.into_iter()
        .map(
            |(namespace, key, method, fingerprint, result, completed_at, period, retain_until)| {
                Ok(OperationRecord {
                    completion: OperationCompletion {
                        namespace,
                        key: OperationKey::parse(&key)
                            .map_err(|e| SidError::Storage(format!("column op_key: {e}")))?,
                        method,
                        fingerprint,
                        result,
                        period: period.map(period_of).transpose()?,
                        retain_until: retention(retain_until)?,
                    },
                    completed_at: time("completed_at", &completed_at)?,
                })
            },
        )
        .collect()
}

/// Store an exported completion; one named with a period this store does
/// not admit is not taken, as its command is refused here anyway.
pub(super) async fn import(pool: &SqlitePool, record: &OperationRecord) -> SidResult<bool> {
    let c = &record.completion;
    if let Some(period) = c.period {
        let mut conn = pool
            .acquire()
            .await
            .map_err(|e| SidError::Storage(format!("operation period: {e}")))?;
        match admit(&mut conn, column(period)?).await {
            Ok(()) => {}
            Err(SidError::OperationPeriodRefused(_)) => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    let inserted = sqlx::query(
        "INSERT INTO operation_results
             (namespace, op_key, method, fingerprint, result, completed_at, period,
              retain_until_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (namespace, op_key) DO NOTHING",
    )
    .bind(&c.namespace)
    .bind(c.key.as_str())
    .bind(&c.method)
    .bind(&c.fingerprint)
    .bind(&c.result)
    .bind(fmt_dt(&record.completed_at))
    .bind(c.period.map(column).transpose()?)
    .bind(c.retain_until.map(|t| t.timestamp_millis()))
    .execute(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation result import: {e}")))?
    .rows_affected();
    Ok(inserted == 1)
}

/// period, accepted_until_ms
type PeriodRow = (i64, i64);

fn issued((period, accepted_until): PeriodRow) -> SidResult<IssuedOperationPeriod> {
    Ok(IssuedOperationPeriod {
        period: period_of(period)?,
        accepted_until: instant("accepted_until_ms", accepted_until)?,
    })
}

/// period, issued_at_ms, accepted_until_ms
type PeriodRecordRow = (i64, i64, i64);

/// The last period issued; a store without the record has lost its period
/// state and admits nothing rather than starting over.
async fn issued_through(conn: &mut sqlx::SqliteConnection) -> SidResult<i64> {
    sqlx::query_scalar("SELECT issued_through FROM operation_period_state WHERE id = 1")
        .fetch_optional(conn)
        .await
        .map_err(|e| SidError::Storage(format!("operation period boundary: {e}")))?
        .ok_or_else(|| SidError::Storage("operation period boundary missing".into()))
}

/// Retire `period`: its completions and its row go together.
async fn retire(conn: &mut sqlx::SqliteConnection, period: i64) -> SidResult<()> {
    sqlx::query("DELETE FROM operation_results WHERE period = ?")
        .bind(period)
        .execute(&mut *conn)
        .await
        .map_err(|e| SidError::Storage(format!("retire operation results: {e}")))?;
    sqlx::query("DELETE FROM operation_periods WHERE period = ?")
        .bind(period)
        .execute(&mut *conn)
        .await
        .map_err(|e| SidError::Storage(format!("retire operation periods: {e}")))?;
    Ok(())
}

/// A stored policy duration; a negative or out-of-range one is an error.
fn seconds(column: &str, value: i64) -> SidResult<Duration> {
    Duration::try_seconds(value)
        .filter(|d| *d >= Duration::zero())
        .ok_or_else(|| SidError::Storage(format!("column {column}: {value}")))
}

#[async_trait]
impl OperationResultStore for SqliteBackend {
    async fn operation_period_policy(&self) -> SidResult<OperationPeriodPolicy> {
        let (acceptance, retention): (i64, i64) = sqlx::query_as(
            "SELECT acceptance_seconds, retention_seconds FROM operation_period_state WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("operation period policy: {e}")))?
        .ok_or_else(|| SidError::Storage("operation period state missing".into()))?;
        Ok(OperationPeriodPolicy {
            acceptance: seconds("acceptance_seconds", acceptance)?,
            retention: seconds("retention_seconds", retention)?,
        })
    }

    async fn current_operation_period(
        &self,
        now: DateTime<Utc>,
        acceptance: Duration,
    ) -> SidResult<IssuedOperationPeriod> {
        let until = now.checked_add_signed(acceptance).ok_or_else(|| {
            SidError::Validation("operation period acceptance out of range".into())
        })?;
        // One write transaction: no other writer issues a period meanwhile.
        let mut tx = self.begin_write().await?;
        let current: Option<PeriodRow> = sqlx::query_as(
            "SELECT period, accepted_until_ms FROM operation_periods
             WHERE issued_at_ms <= ?1 AND accepted_until_ms > ?1
             ORDER BY period DESC LIMIT 1",
        )
        .bind(now.timestamp_millis())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("operation period: {e}")))?;
        let row = match current {
            Some(current) => current,
            // The next period follows every one ever issued, so a retired
            // number is never admitted again.
            None => {
                let next = issued_through(&mut tx)
                    .await?
                    .checked_add(1)
                    .ok_or_else(|| SidError::Storage("operation periods exhausted".into()))?;
                sqlx::query("UPDATE operation_period_state SET issued_through = ? WHERE id = 1")
                    .bind(next)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| SidError::Storage(format!("operation period boundary: {e}")))?;
                sqlx::query_as(
                    "INSERT INTO operation_periods (period, issued_at_ms, accepted_until_ms)
                     VALUES (?, ?, ?)
                     RETURNING period, accepted_until_ms",
                )
                .bind(next)
                .bind(now.timestamp_millis())
                .bind(until.timestamp_millis())
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("issue operation period: {e}")))?
            }
        };
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
        issued(row)
    }

    async fn admit_operation_period(&self, period: OperationPeriod) -> SidResult<()> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| SidError::Storage(format!("operation period: {e}")))?;
        admit(&mut conn, column(period)?).await
    }

    async fn retire_operation_periods(&self, before: DateTime<Utc>) -> SidResult<u64> {
        // The write transaction serializes this with every admitted commit.
        let mut tx = self.begin_write().await?;
        let ended: Vec<i64> =
            sqlx::query_scalar("SELECT period FROM operation_periods WHERE accepted_until_ms < ?")
                .bind(before.timestamp_millis())
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("operation periods: {e}")))?;
        for &period in &ended {
            retire(&mut tx, period).await?;
        }
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
        Ok(ended.len() as u64)
    }

    async fn export_operation_periods(&self) -> SidResult<OperationPeriodState> {
        let mut tx = self.begin_write().await?;
        let last = issued_through(&mut tx).await?;
        let rows: Vec<PeriodRecordRow> = sqlx::query_as(
            "SELECT period, issued_at_ms, accepted_until_ms FROM operation_periods
             ORDER BY period",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("operation periods: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
        Ok(OperationPeriodState {
            issued_through: period_of(last)?,
            active: rows
                .into_iter()
                .map(|(period, issued_at, accepted_until)| {
                    Ok(OperationPeriodRecord {
                        issued: issued((period, accepted_until))?,
                        issued_at: instant("issued_at_ms", issued_at)?,
                    })
                })
                .collect::<SidResult<_>>()?,
        })
    }

    async fn import_operation_periods(&self, state: &OperationPeriodState) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        let last = issued_through(&mut tx).await?;
        let source_last = column(state.issued_through)?;
        let source_active = state
            .active
            .iter()
            .map(|p| column(p.issued.period))
            .collect::<SidResult<Vec<i64>>>()?;
        // Retired at the source: issued there, no longer admitted there.
        let local: Vec<i64> = sqlx::query_scalar("SELECT period FROM operation_periods")
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("operation periods: {e}")))?;
        for period in local {
            if period <= source_last && !source_active.contains(&period) {
                retire(&mut tx, period).await?;
            }
        }
        for (record, &period) in state.active.iter().zip(&source_active) {
            // A period this store issued and no longer holds is retired here.
            if period <= last {
                continue;
            }
            sqlx::query(
                "INSERT INTO operation_periods (period, issued_at_ms, accepted_until_ms)
                 VALUES (?, ?, ?)",
            )
            .bind(period)
            .bind(record.issued_at.timestamp_millis())
            .bind(record.issued.accepted_until.timestamp_millis())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("operation period import: {e}")))?;
        }
        sqlx::query(
            "UPDATE operation_period_state SET issued_through = MAX(issued_through, ?)
             WHERE id = 1",
        )
        .bind(source_last)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("operation period boundary: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
        Ok(())
    }

    async fn record_outcome(&self, ctx: MutationContext) -> SidResult<()> {
        let chain = ctx
            .operation
            .as_ref()
            .map(|o| format!("operation:{}", o.namespace))
            .unwrap_or_else(|| "operation".to_string());
        let tx = self.begin_write().await?;
        Self::commit_mutation(tx, &chain, ctx).await
    }

    async fn purge_operation_results(
        &self,
        namespace: &str,
        method: &str,
        before: DateTime<Utc>,
    ) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        // Compared as instants: stored timestamps do not all sort as text.
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT op_key, completed_at FROM operation_results WHERE namespace = ? AND method = ?",
        )
        .bind(namespace)
        .bind(method)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("purge operation results: {e}")))?;
        let mut dropped = 0;
        for (key, completed_at) in rows {
            let completed_at = DateTime::parse_from_rfc3339(&completed_at)
                .map_err(|e| SidError::Storage(format!("completed_at: {e}")))?;
            if completed_at < before {
                sqlx::query("DELETE FROM operation_results WHERE namespace = ? AND op_key = ?")
                    .bind(namespace)
                    .bind(&key)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| SidError::Storage(format!("purge operation results: {e}")))?;
                dropped += 1;
            }
        }
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
        Ok(dropped)
    }

    async fn purge_expired_operation_results(&self, now: DateTime<Utc>) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        let dropped = sqlx::query("DELETE FROM operation_results WHERE retain_until_ms <= ?")
            .bind(now.timestamp_millis())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("purge expired operation results: {e}")))?
            .rows_affected();
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
        Ok(dropped)
    }

    async fn get_operation_result(
        &self,
        namespace: &str,
        key: &OperationKey,
    ) -> SidResult<Option<OperationRecord>> {
        get(&self.pool, namespace, key).await
    }

    async fn export_operation_results(&self) -> SidResult<Vec<OperationRecord>> {
        export(&self.pool).await
    }

    async fn import_operation_result(&self, record: &OperationRecord) -> SidResult<bool> {
        import(&self.pool, record).await
    }
}
