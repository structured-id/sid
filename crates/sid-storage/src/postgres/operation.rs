// SPDX-License-Identifier: AGPL-3.0-only
//! Completions of keyed commands, committed with their effect.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sid_core::models::{
    IssuedOperationPeriod, MutationContext, OperationCompletion, OperationKey, OperationPeriod,
    OperationPeriodRecord, OperationPeriodRefusal, OperationRecord,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::OperationResultStore;
use sqlx::PgPool;

use super::PostgresBackend;

/// Record `operation` in `tx`. When another transaction already committed
/// the key, this one must commit nothing: `OperationCompleted`; a completion
/// past its retention no longer holds the key and is replaced. A concurrent
/// transaction holding the same key makes this insert wait for its outcome.
/// A keyed command's period is admitted first: its row is held shared until
/// the commit, so a retirement waits for this transaction or refuses it.
pub(super) async fn record_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    operation: &OperationCompletion,
) -> SidResult<()> {
    let period = operation.period.map(column).transpose()?;
    if let Some(period) = period {
        let retired: Option<bool> =
            sqlx::query_scalar("SELECT retired FROM operation_periods WHERE period = $1 FOR SHARE")
                .bind(period)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| SidError::Storage(format!("operation period: {e}")))?;
        match retired {
            None => {
                return Err(SidError::OperationPeriodRefused(
                    OperationPeriodRefusal::NotIssued,
                ));
            }
            Some(true) => {
                return Err(SidError::OperationPeriodRefused(
                    OperationPeriodRefusal::Retired,
                ));
            }
            Some(false) => {}
        }
    }
    let inserted = sqlx::query(
        "INSERT INTO operation_results
             (namespace, op_key, method, fingerprint, result, period, retain_until)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (namespace, op_key) DO UPDATE SET
             method = EXCLUDED.method, fingerprint = EXCLUDED.fingerprint,
             result = EXCLUDED.result, completed_at = NOW(),
             period = EXCLUDED.period, retain_until = EXCLUDED.retain_until
         WHERE operation_results.retain_until <= NOW()",
    )
    .bind(&operation.namespace)
    .bind(operation.key.as_str())
    .bind(&operation.method)
    .bind(&operation.fingerprint)
    .bind(&operation.result)
    .bind(period)
    .bind(operation.retain_until)
    .execute(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("operation completion: {e}")))?
    .rows_affected();
    if inserted == 0 {
        return Err(SidError::OperationCompleted(operation.key.as_str().into()));
    }
    Ok(())
}

/// `period` as its `bigint` column.
fn column(period: OperationPeriod) -> SidResult<i64> {
    i64::try_from(period.get())
        .map_err(|_| SidError::OperationPeriodRefused(OperationPeriodRefusal::NotIssued))
}

/// A `bigint` period column as the period.
fn period_of(value: i64) -> SidResult<OperationPeriod> {
    u64::try_from(value)
        .map(OperationPeriod::new)
        .map_err(|_| SidError::Storage(format!("column period: {value}")))
}

/// method, fingerprint, result, completed_at, period, retain_until
type RecordRow = (
    String,
    Vec<u8>,
    Vec<u8>,
    DateTime<Utc>,
    Option<i64>,
    Option<DateTime<Utc>>,
);

/// namespace, op_key, method, fingerprint, result, completed_at, period,
/// retain_until
type FullRow = (
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    DateTime<Utc>,
    Option<i64>,
    Option<DateTime<Utc>>,
);

pub(super) async fn export(pool: &PgPool) -> SidResult<Vec<OperationRecord>> {
    let rows: Vec<FullRow> = sqlx::query_as(
        "SELECT namespace, op_key, method, fingerprint, result, completed_at, period, retain_until
         FROM operation_results
         WHERE retain_until IS NULL OR retain_until > NOW()
         ORDER BY completed_at, namespace, op_key",
    )
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
                        retain_until,
                    },
                    completed_at,
                })
            },
        )
        .collect()
}

pub(super) async fn import(pool: &PgPool, record: &OperationRecord) -> SidResult<bool> {
    let c = &record.completion;
    let inserted = sqlx::query(
        "INSERT INTO operation_results
             (namespace, op_key, method, fingerprint, result, completed_at, period, retain_until)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (namespace, op_key) DO NOTHING",
    )
    .bind(&c.namespace)
    .bind(c.key.as_str())
    .bind(&c.method)
    .bind(&c.fingerprint)
    .bind(&c.result)
    .bind(record.completed_at)
    .bind(c.period.map(column).transpose()?)
    .bind(c.retain_until)
    .execute(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation result import: {e}")))?
    .rows_affected();
    Ok(inserted == 1)
}

pub(super) async fn get(
    pool: &PgPool,
    namespace: &str,
    key: &OperationKey,
) -> SidResult<Option<OperationRecord>> {
    let row: Option<RecordRow> = sqlx::query_as(
        "SELECT method, fingerprint, result, completed_at, period, retain_until
         FROM operation_results
         WHERE namespace = $1 AND op_key = $2
           AND (retain_until IS NULL OR retain_until > NOW())",
    )
    .bind(namespace)
    .bind(key.as_str())
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
                    retain_until,
                },
                completed_at,
            })
        },
    )
    .transpose()
}

/// How many times issuing a new period is tried while other replicas issue
/// one at the same time: each lost race finds the period they issued.
const ISSUE_ATTEMPTS: usize = 3;

/// period, accepted_until
type PeriodRow = (i64, DateTime<Utc>);

async fn current_period(
    pool: &PgPool,
    now: DateTime<Utc>,
    acceptance: Duration,
) -> SidResult<IssuedOperationPeriod> {
    let issued = |(period, accepted_until): PeriodRow| {
        Ok(IssuedOperationPeriod {
            period: period_of(period)?,
            accepted_until,
        })
    };
    let until = now
        .checked_add_signed(acceptance)
        .ok_or_else(|| SidError::Validation("operation period acceptance out of range".into()))?;
    for _ in 0..ISSUE_ATTEMPTS {
        let current: Option<PeriodRow> = sqlx::query_as(
            "SELECT period, accepted_until FROM operation_periods
             WHERE NOT retired AND issued_at <= $1 AND accepted_until > $1
             ORDER BY period DESC LIMIT 1",
        )
        .bind(now)
        .fetch_optional(pool)
        .await
        .map_err(|e| SidError::Storage(format!("operation period: {e}")))?;
        if let Some(current) = current {
            return issued(current);
        }
        // The next period follows every one ever issued, retired ones
        // included, so a retired number is never admitted again.
        let created: Option<PeriodRow> = sqlx::query_as(
            "INSERT INTO operation_periods (period, issued_at, accepted_until)
             SELECT COALESCE(MAX(period), 0) + 1, $1, $2 FROM operation_periods
             ON CONFLICT (period) DO NOTHING
             RETURNING period, accepted_until",
        )
        .bind(now)
        .bind(until)
        .fetch_optional(pool)
        .await
        .map_err(|e| SidError::Storage(format!("issue operation period: {e}")))?;
        if let Some(created) = created {
            return issued(created);
        }
    }
    Err(SidError::Unavailable(
        "operation period: issuing kept racing other replicas".into(),
    ))
}

async fn retire_periods(pool: &PgPool, before: DateTime<Utc>) -> SidResult<u64> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| SidError::Storage(format!("begin: {e}")))?;
    // Taking the rows exclusively waits for every commit admitted under them.
    let retired: Vec<i64> = sqlx::query_scalar(
        "UPDATE operation_periods SET retired = true
         WHERE NOT retired AND accepted_until < $1
         RETURNING period",
    )
    .bind(before)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| SidError::Storage(format!("retire operation periods: {e}")))?;
    if !retired.is_empty() {
        sqlx::query("DELETE FROM operation_results WHERE period = ANY($1)")
            .bind(&retired)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("retire operation results: {e}")))?;
    }
    tx.commit()
        .await
        .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
    Ok(retired.len() as u64)
}

/// period, issued_at, accepted_until, retired
type PeriodRecordRow = (i64, DateTime<Utc>, DateTime<Utc>, bool);

async fn export_periods(pool: &PgPool) -> SidResult<Vec<OperationPeriodRecord>> {
    let rows: Vec<PeriodRecordRow> = sqlx::query_as(
        "SELECT period, issued_at, accepted_until, retired FROM operation_periods ORDER BY period",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation periods: {e}")))?;
    rows.into_iter()
        .map(|(period, issued_at, accepted_until, retired)| {
            Ok(OperationPeriodRecord {
                issued: IssuedOperationPeriod {
                    period: period_of(period)?,
                    accepted_until,
                },
                issued_at,
                retired,
            })
        })
        .collect()
}

async fn import_period(pool: &PgPool, record: &OperationPeriodRecord) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO operation_periods (period, issued_at, accepted_until, retired)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (period) DO UPDATE SET retired = true
         WHERE EXCLUDED.retired AND NOT operation_periods.retired",
    )
    .bind(column(record.issued.period)?)
    .bind(record.issued_at)
    .bind(record.issued.accepted_until)
    .bind(record.retired)
    .execute(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation period import: {e}")))?;
    Ok(())
}

#[async_trait]
impl OperationResultStore for PostgresBackend {
    async fn current_operation_period(
        &self,
        now: DateTime<Utc>,
        acceptance: Duration,
    ) -> SidResult<IssuedOperationPeriod> {
        current_period(&self.pool, now, acceptance).await
    }

    async fn retire_operation_periods(&self, before: DateTime<Utc>) -> SidResult<u64> {
        retire_periods(&self.pool, before).await
    }

    async fn export_operation_periods(&self) -> SidResult<Vec<OperationPeriodRecord>> {
        export_periods(&self.pool).await
    }

    async fn import_operation_period(&self, record: &OperationPeriodRecord) -> SidResult<()> {
        import_period(&self.pool, record).await
    }

    async fn record_outcome(&self, ctx: MutationContext) -> SidResult<()> {
        let chain = ctx
            .operation
            .as_ref()
            .map(|o| format!("operation:{}", o.namespace))
            .unwrap_or_else(|| "operation".to_string());
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(format!("begin: {e}")))?;
        Self::audit_in_tx(&mut tx, &chain, ctx).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
        Ok(())
    }

    async fn purge_operation_results(
        &self,
        namespace: &str,
        method: &str,
        before: DateTime<Utc>,
    ) -> SidResult<u64> {
        sqlx::query(
            "DELETE FROM operation_results
             WHERE namespace = $1 AND method = $2 AND completed_at < $3",
        )
        .bind(namespace)
        .bind(method)
        .bind(before)
        .execute(&self.pool)
        .await
        .map(|done| done.rows_affected())
        .map_err(|e| SidError::Storage(format!("purge operation results: {e}")))
    }

    async fn purge_expired_operation_results(&self, now: DateTime<Utc>) -> SidResult<u64> {
        sqlx::query("DELETE FROM operation_results WHERE retain_until <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|done| done.rows_affected())
            .map_err(|e| SidError::Storage(format!("purge expired operation results: {e}")))
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
