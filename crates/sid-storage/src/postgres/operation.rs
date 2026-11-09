// SPDX-License-Identifier: AGPL-3.0-only
//! Completions of keyed commands, committed with their effect, and the
//! periods they are admitted under.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sid_core::models::{
    IssuedOperationPeriod, MutationContext, OperationCompletion, OperationKey, OperationPeriod,
    OperationPeriodPolicy, OperationPeriodRecord, OperationPeriodRefusal, OperationPeriodState,
    OperationRecord, OperationResourceBinding,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::OperationResultStore;
use sqlx::PgPool;
use uuid::Uuid;

use super::PostgresBackend;

/// The operation tables of a host keeping its own database; the engine's
/// schema holds the same tables.
const SCHEMA: &str = include_str!("operations.sql");

/// Keyed command completions and their periods in a PostgreSQL database of
/// a host apart from the engine backend, whose own tables live beside them
/// (the SaaS control plane): its mutations record their completion inside
/// their own transaction ([`Self::record_in_tx`]) and its operation service
/// issues the periods.
#[derive(Clone)]
pub struct PgOperationStore {
    pool: PgPool,
}

impl PgOperationStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create the operation tables if they do not exist. Replicas starting
    /// together take turns under a transaction-scoped advisory lock:
    /// concurrent `CREATE ... IF NOT EXISTS` of one name collides in the
    /// catalog.
    pub async fn ensure_schema(&self) -> SidResult<()> {
        let schema_error = |e: sqlx::Error| SidError::Storage(format!("operation schema: {e}"));
        let mut tx = self.pool.begin().await.map_err(schema_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('sid.operations.schema'))")
            .execute(&mut *tx)
            .await
            .map_err(schema_error)?;
        sqlx::raw_sql(SCHEMA)
            .execute(&mut *tx)
            .await
            .map_err(schema_error)?;
        tx.commit().await.map_err(schema_error)?;
        Ok(())
    }

    /// Record the completion of the keyed command a host's mutation runs, in
    /// that mutation's transaction `tx`: under an admitted period, and
    /// `OperationCompleted` when another commit already completed the key,
    /// which must then commit nothing.
    pub async fn record_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        operation: &OperationCompletion,
    ) -> SidResult<()> {
        record_in_tx(tx, operation).await
    }
}

/// Record `operation` in `tx`. When another transaction already committed
/// the key, this one must commit nothing: `OperationCompleted`; a completion
/// past its retention no longer holds the key and is consumed with its
/// binding. A key a creation bound completes only that creation's command:
/// another is refused as `OperationKeyReused`. A keyed command takes its
/// place in its period first ([`take_place`]); a result larger than the
/// policy keeps, or a full period, is `ResourceExhausted`.
pub(super) async fn record_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    operation: &OperationCompletion,
) -> SidResult<()> {
    let period = operation.period.map(column).transpose()?;
    let size = i64::try_from(operation.result.len()).unwrap_or(i64::MAX);
    match period {
        Some(period) => {
            if let Err(e) = take_place(tx, period, size).await {
                // A completed key answers as completed, full period or not.
                return Err(
                    if matches!(e, SidError::ResourceExhausted(_))
                        && completed(tx, operation).await?
                    {
                        SidError::OperationCompleted(operation.key.as_str().into())
                    } else {
                        e
                    },
                );
            }
        }
        None => {
            let limit: i64 = sqlx::query_scalar("SELECT result_bytes FROM operation_period_state")
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| SidError::Storage(format!("operation result limit: {e}")))?;
            if size > limit {
                return Err(too_large(limit));
            }
        }
    }
    lock_key(tx, &operation.namespace, &operation.key).await?;
    consume_expired(tx, &operation.namespace, &operation.key).await?;
    let held: Option<(String, Vec<u8>, Option<i64>)> = sqlx::query_as(
        "SELECT method, fingerprint, period FROM operation_resources
         WHERE namespace = $1 AND op_key = $2",
    )
    .bind(&operation.namespace)
    .bind(operation.key.as_str())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("operation resource: {e}")))?;
    if let Some((method, fingerprint, held_in)) = held
        && (method != operation.method || fingerprint != operation.fingerprint || held_in != period)
    {
        return Err(SidError::OperationKeyReused(operation.key.as_str().into()));
    }
    let inserted = sqlx::query(
        "INSERT INTO operation_results
             (namespace, op_key, method, fingerprint, result, period, retain_until)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (namespace, op_key) DO NOTHING",
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

/// Count a completion of `size` bytes into admitted `period` on `tx`. The
/// period's row stays locked until the commit, so commits under one period
/// take their places in turn, a retirement waits for them or refuses them,
/// and the count never passes the policy's capacity on any replica.
async fn take_place(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    period: i64,
    size: i64,
) -> SidResult<()> {
    let placed: Option<i64> = sqlx::query_scalar(
        "UPDATE operation_periods p SET recorded = p.recorded + 1
         FROM operation_period_state s
         WHERE p.period = $1 AND p.recorded < s.capacity AND $2 <= s.result_bytes
         RETURNING p.period",
    )
    .bind(period)
    .bind(size)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("operation period: {e}")))?;
    if placed.is_some() {
        return Ok(());
    }
    // Why not, read once the commit is refused anyway.
    let (recorded, capacity, limit): (Option<i64>, i64, i64) = sqlx::query_as(
        "SELECT p.recorded, s.capacity, s.result_bytes
         FROM operation_period_state s
         LEFT JOIN operation_periods p ON p.period = $1",
    )
    .bind(period)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("operation period: {e}")))?;
    if recorded.is_none() {
        return admit(tx, period, false).await;
    }
    if size > limit {
        return Err(too_large(limit));
    }
    Err(SidError::ResourceExhausted(format!(
        "operation period full ({capacity} completions)"
    )))
}

/// Whether `operation`'s key holds a completion still kept.
async fn completed(
    conn: &mut sqlx::PgConnection,
    operation: &OperationCompletion,
) -> SidResult<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM operation_results
             WHERE namespace = $1 AND op_key = $2
               AND (retain_until IS NULL OR retain_until > NOW()))",
    )
    .bind(&operation.namespace)
    .bind(operation.key.as_str())
    .fetch_one(conn)
    .await
    .map_err(|e| SidError::Storage(format!("operation result: {e}")))
}

fn too_large(limit: i64) -> SidError {
    SidError::ResourceExhausted(format!("operation result larger than {limit} bytes"))
}

/// Serialize the transactions that decide who holds `key` in `namespace`: a
/// creation's binding and a command's completion each check the other's row
/// before writing their own, so two of them on one key must not interleave.
/// The lock ends with the transaction; a hash collision only serializes two
/// unrelated keys.
async fn lock_key(
    conn: &mut sqlx::PgConnection,
    namespace: &str,
    key: &OperationKey,
) -> SidResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 0))")
        .bind(namespace)
        .bind(key.as_str())
        .execute(&mut *conn)
        .await
        .map_err(|e| SidError::Storage(format!("operation key lock: {e}")))?;
    Ok(())
}

/// Release `key` in `namespace` when its completion's retention ended: the
/// expired completion and its binding are deleted, so whatever is written
/// next stands for every later attempt.
async fn consume_expired(
    conn: &mut sqlx::PgConnection,
    namespace: &str,
    key: &OperationKey,
) -> SidResult<()> {
    sqlx::query(
        "WITH gone AS (
             DELETE FROM operation_results
             WHERE namespace = $1 AND op_key = $2 AND retain_until <= NOW()
             RETURNING namespace, op_key)
         DELETE FROM operation_resources r USING gone g
         WHERE r.namespace = g.namespace AND r.op_key = g.op_key",
    )
    .bind(namespace)
    .bind(key.as_str())
    .execute(&mut *conn)
    .await
    .map_err(|e| SidError::Storage(format!("operation resource: {e}")))?;
    Ok(())
}

/// Admit `period` on `conn`: refused when it has no row, as retired when
/// its number was issued, else as never issued. A commit under it holds its
/// row shared (`for_commit`) until its transaction ends.
async fn admit(conn: &mut sqlx::PgConnection, period: i64, for_commit: bool) -> SidResult<()> {
    let sql = if for_commit {
        "SELECT period FROM operation_periods WHERE period = $1 FOR SHARE"
    } else {
        "SELECT period FROM operation_periods WHERE period = $1"
    };
    let admitted: Option<i64> = sqlx::query_scalar(sql)
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

/// Store an exported completion; one named with a period this store does
/// not admit is not taken, as its command is refused here anyway.
pub(super) async fn import(pool: &PgPool, record: &OperationRecord) -> SidResult<bool> {
    let c = &record.completion;
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| SidError::Storage(format!("begin: {e}")))?;
    if let Some(period) = c.period {
        match admit(&mut tx, column(period)?, true).await {
            Ok(()) => {}
            Err(SidError::OperationPeriodRefused(_)) => return Ok(false),
            Err(e) => return Err(e),
        }
    }
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
    .execute(&mut *tx)
    .await
    .map_err(|e| SidError::Storage(format!("operation result import: {e}")))?
    .rows_affected();
    // A carried completion counts toward its period's capacity here too.
    if inserted == 1
        && let Some(period) = c.period
    {
        sqlx::query("UPDATE operation_periods SET recorded = recorded + 1 WHERE period = $1")
            .bind(column(period)?)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("operation period: {e}")))?;
    }
    tx.commit()
        .await
        .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
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

/// period, accepted_until
type PeriodRow = (i64, DateTime<Utc>);

fn issued((period, accepted_until): PeriodRow) -> SidResult<IssuedOperationPeriod> {
    Ok(IssuedOperationPeriod {
        period: period_of(period)?,
        accepted_until,
    })
}

/// The last period issued; a store without the record has lost its period
/// state and admits nothing rather than starting over.
async fn issued_through(conn: &mut sqlx::PgConnection) -> SidResult<i64> {
    sqlx::query_scalar("SELECT issued_through FROM operation_period_state")
        .fetch_optional(conn)
        .await
        .map_err(|e| SidError::Storage(format!("operation period boundary: {e}")))?
        .ok_or_else(|| SidError::Storage("operation period boundary missing".into()))
}

/// The same, held until `tx` ends: issuing, retiring and importing periods
/// take it first, so they never interleave.
async fn lock_issued_through(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> SidResult<i64> {
    sqlx::query_scalar("SELECT issued_through FROM operation_period_state FOR UPDATE")
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| SidError::Storage(format!("operation period boundary: {e}")))?
        .ok_or_else(|| SidError::Storage("operation period boundary missing".into()))
}

/// Retire `periods` in `tx`: their completions and rows go together. Their
/// rows are taken exclusively first, which waits for every commit admitted
/// under them.
async fn retire(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, periods: &[i64]) -> SidResult<()> {
    if periods.is_empty() {
        return Ok(());
    }
    sqlx::query("SELECT period FROM operation_periods WHERE period = ANY($1) FOR UPDATE")
        .bind(periods)
        .execute(&mut **tx)
        .await
        .map_err(|e| SidError::Storage(format!("operation periods: {e}")))?;
    // A completed creation's binding goes with its completion; one that never
    // completed is kept to reconcile what it began.
    sqlx::query(
        "DELETE FROM operation_resources r WHERE r.period = ANY($1) AND EXISTS (
             SELECT 1 FROM operation_results o
             WHERE o.namespace = r.namespace AND o.op_key = r.op_key)",
    )
    .bind(periods)
    .execute(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("retire operation resources: {e}")))?;
    sqlx::query("DELETE FROM operation_results WHERE period = ANY($1)")
        .bind(periods)
        .execute(&mut **tx)
        .await
        .map_err(|e| SidError::Storage(format!("retire operation results: {e}")))?;
    sqlx::query("DELETE FROM operation_periods WHERE period = ANY($1)")
        .bind(periods)
        .execute(&mut **tx)
        .await
        .map_err(|e| SidError::Storage(format!("retire operation periods: {e}")))?;
    Ok(())
}

async fn current_period(
    pool: &PgPool,
    now: DateTime<Utc>,
    acceptance: Duration,
) -> SidResult<IssuedOperationPeriod> {
    let until = now
        .checked_add_signed(acceptance)
        .ok_or_else(|| SidError::Validation("operation period acceptance out of range".into()))?;
    let current = || {
        sqlx::query_as::<_, PeriodRow>(
            "SELECT period, accepted_until FROM operation_periods
             WHERE issued_at <= $1 AND accepted_until > $1
             ORDER BY period DESC LIMIT 1",
        )
        .bind(now)
    };
    if let Some(row) = current()
        .fetch_optional(pool)
        .await
        .map_err(|e| SidError::Storage(format!("operation period: {e}")))?
    {
        return issued(row);
    }
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| SidError::Storage(format!("begin: {e}")))?;
    let last = lock_issued_through(&mut tx).await?;
    // Another replica may have issued one while this waited for the lock.
    let row = match current()
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("operation period: {e}")))?
    {
        Some(row) => row,
        None => {
            let next = last
                .checked_add(1)
                .ok_or_else(|| SidError::Storage("operation periods exhausted".into()))?;
            sqlx::query("UPDATE operation_period_state SET issued_through = $1")
                .bind(next)
                .execute(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("operation period boundary: {e}")))?;
            sqlx::query_as(
                "INSERT INTO operation_periods (period, issued_at, accepted_until)
                 VALUES ($1, $2, $3)
                 RETURNING period, accepted_until",
            )
            .bind(next)
            .bind(now)
            .bind(until)
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

async fn retire_periods(pool: &PgPool, before: DateTime<Utc>) -> SidResult<u64> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| SidError::Storage(format!("begin: {e}")))?;
    lock_issued_through(&mut tx).await?;
    let ended: Vec<i64> =
        sqlx::query_scalar("SELECT period FROM operation_periods WHERE accepted_until < $1")
            .bind(before)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("operation periods: {e}")))?;
    retire(&mut tx, &ended).await?;
    tx.commit()
        .await
        .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
    Ok(ended.len() as u64)
}

/// period, issued_at, accepted_until
type PeriodRecordRow = (i64, DateTime<Utc>, DateTime<Utc>);

async fn export_periods(pool: &PgPool) -> SidResult<OperationPeriodState> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| SidError::Storage(format!("begin: {e}")))?;
    let last = lock_issued_through(&mut tx).await?;
    let rows: Vec<PeriodRecordRow> = sqlx::query_as(
        "SELECT period, issued_at, accepted_until FROM operation_periods ORDER BY period",
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
                    issued_at,
                })
            })
            .collect::<SidResult<_>>()?,
    })
}

async fn import_periods(pool: &PgPool, state: &OperationPeriodState) -> SidResult<()> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| SidError::Storage(format!("begin: {e}")))?;
    let last = lock_issued_through(&mut tx).await?;
    let source_last = column(state.issued_through)?;
    let source_active = state
        .active
        .iter()
        .map(|p| column(p.issued.period))
        .collect::<SidResult<Vec<i64>>>()?;
    // Retired at the source: issued there, no longer admitted there.
    let retired: Vec<i64> = sqlx::query_scalar(
        "SELECT period FROM operation_periods WHERE period <= $1 AND NOT (period = ANY($2))",
    )
    .bind(source_last)
    .bind(&source_active)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| SidError::Storage(format!("operation periods: {e}")))?;
    retire(&mut tx, &retired).await?;
    for (record, &period) in state.active.iter().zip(&source_active) {
        // A period this store issued and no longer holds is retired here.
        if period <= last {
            continue;
        }
        sqlx::query(
            "INSERT INTO operation_periods (period, issued_at, accepted_until)
             VALUES ($1, $2, $3)",
        )
        .bind(period)
        .bind(record.issued_at)
        .bind(record.issued.accepted_until)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("operation period import: {e}")))?;
    }
    sqlx::query("UPDATE operation_period_state SET issued_through = GREATEST(issued_through, $1)")
        .bind(source_last)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("operation period boundary: {e}")))?;
    tx.commit()
        .await
        .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
    Ok(())
}

/// A stored policy duration; a negative or out-of-range one is an error.
fn seconds(column: &str, value: i64) -> SidResult<Duration> {
    Duration::try_seconds(value)
        .filter(|d| *d >= Duration::zero())
        .ok_or_else(|| SidError::Storage(format!("column {column}: {value}")))
}

/// A stored positive bound.
fn bound(column: &str, value: i64) -> SidResult<u64> {
    u64::try_from(value)
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| SidError::Storage(format!("column {column}: {value}")))
}

async fn period_policy(pool: &PgPool) -> SidResult<OperationPeriodPolicy> {
    let (acceptance, retention, capacity, result_bytes): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT acceptance_seconds, retention_seconds, capacity, result_bytes
         FROM operation_period_state",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation period policy: {e}")))?
    .ok_or_else(|| SidError::Storage("operation period state missing".into()))?;
    Ok(OperationPeriodPolicy {
        acceptance: seconds("acceptance_seconds", acceptance)?,
        retention: seconds("retention_seconds", retention)?,
        capacity: bound("capacity", capacity)?,
        result_bytes: bound("result_bytes", result_bytes)?,
    })
}

async fn admit_period(pool: &PgPool, period: OperationPeriod) -> SidResult<()> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| SidError::Storage(format!("operation period: {e}")))?;
    admit(&mut conn, column(period)?, false).await
}

async fn purge(
    pool: &PgPool,
    namespace: &str,
    method: &str,
    before: DateTime<Utc>,
) -> SidResult<u64> {
    // The bindings of the dropped completions go in the same statement.
    let dropped: i64 = sqlx::query_scalar(
        "WITH gone AS (
             DELETE FROM operation_results
             WHERE namespace = $1 AND method = $2 AND completed_at < $3
             RETURNING namespace, op_key),
         freed AS (
             DELETE FROM operation_resources r USING gone g
             WHERE r.namespace = g.namespace AND r.op_key = g.op_key)
         SELECT count(*) FROM gone",
    )
    .bind(namespace)
    .bind(method)
    .bind(before)
    .fetch_one(pool)
    .await
    .map_err(|e| SidError::Storage(format!("purge operation results: {e}")))?;
    Ok(dropped as u64)
}

async fn purge_expired(pool: &PgPool, now: DateTime<Utc>) -> SidResult<u64> {
    let dropped: i64 = sqlx::query_scalar(
        "WITH gone AS (
             DELETE FROM operation_results WHERE retain_until <= $1
             RETURNING namespace, op_key),
         freed AS (
             DELETE FROM operation_resources r USING gone g
             WHERE r.namespace = g.namespace AND r.op_key = g.op_key)
         SELECT count(*) FROM gone",
    )
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(|e| SidError::Storage(format!("purge expired operation results: {e}")))?;
    Ok(dropped as u64)
}

/// method, fingerprint, period, resource
type BindingRow = (String, Vec<u8>, Option<i64>, Uuid);

/// The binding `row` holds for `namespace`/`key`.
fn binding_of(
    namespace: String,
    key: OperationKey,
    (method, fingerprint, period, resource): BindingRow,
) -> SidResult<OperationResourceBinding> {
    Ok(OperationResourceBinding {
        namespace,
        key,
        method,
        fingerprint,
        period: period.map(period_of).transpose()?,
        resource,
    })
}

async fn bind(pool: &PgPool, proposal: &OperationResourceBinding) -> SidResult<Uuid> {
    let reused = || SidError::OperationKeyReused(proposal.key.as_str().into());
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| SidError::Storage(format!("begin: {e}")))?;
    let period = proposal.period.map(column).transpose()?;
    if let Some(period) = period {
        admit(&mut tx, period, true).await?;
    }
    lock_key(&mut tx, &proposal.namespace, &proposal.key).await?;
    // A key completed for another command binds nothing.
    let completed: Option<(String, Vec<u8>, Option<i64>)> = sqlx::query_as(
        "SELECT method, fingerprint, period FROM operation_results
         WHERE namespace = $1 AND op_key = $2
           AND (retain_until IS NULL OR retain_until > NOW())",
    )
    .bind(&proposal.namespace)
    .bind(proposal.key.as_str())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| SidError::Storage(format!("operation result: {e}")))?;
    if let Some((method, fingerprint, done_in)) = completed
        && (method != proposal.method || fingerprint != proposal.fingerprint || done_in != period)
    {
        return Err(reused());
    }
    // A key whose completion's retention ended is free again.
    consume_expired(&mut tx, &proposal.namespace, &proposal.key).await?;
    // The first attempt binds; the key's lock orders concurrent attempts.
    let bound: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO operation_resources
             (namespace, op_key, method, fingerprint, period, resource)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (namespace, op_key) DO NOTHING
         RETURNING resource",
    )
    .bind(&proposal.namespace)
    .bind(proposal.key.as_str())
    .bind(&proposal.method)
    .bind(&proposal.fingerprint)
    .bind(period)
    .bind(proposal.resource)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| SidError::Storage(format!("operation resource: {e}")))?;
    let resource = match bound {
        Some(resource) => resource,
        None => {
            let row: BindingRow = sqlx::query_as(
                "SELECT method, fingerprint, period, resource FROM operation_resources
                 WHERE namespace = $1 AND op_key = $2",
            )
            .bind(&proposal.namespace)
            .bind(proposal.key.as_str())
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("operation resource: {e}")))?;
            let held = binding_of(proposal.namespace.clone(), proposal.key.clone(), row)?;
            if !held.same_command(proposal) {
                return Err(reused());
            }
            held.resource
        }
    };
    tx.commit()
        .await
        .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
    Ok(resource)
}

/// namespace, op_key, then a [`BindingRow`]
type FullBindingRow = (String, String, String, Vec<u8>, Option<i64>, Uuid);

async fn export_resources(pool: &PgPool) -> SidResult<Vec<OperationResourceBinding>> {
    // A binding whose completion expired holds a key already released: it
    // stays here until the purge, and is not carried elsewhere.
    let rows: Vec<FullBindingRow> = sqlx::query_as(
        "SELECT namespace, op_key, method, fingerprint, period, resource
         FROM operation_resources r
         WHERE NOT EXISTS (
             SELECT 1 FROM operation_results o
             WHERE o.namespace = r.namespace AND o.op_key = r.op_key
               AND o.retain_until <= NOW())
         ORDER BY bound_at, namespace, op_key",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation resources: {e}")))?;
    rows.into_iter()
        .map(|(namespace, key, method, fingerprint, period, resource)| {
            let key = OperationKey::parse(&key)
                .map_err(|e| SidError::Storage(format!("column op_key: {e}")))?;
            binding_of(namespace, key, (method, fingerprint, period, resource))
        })
        .collect()
}

async fn import_resource(pool: &PgPool, binding: &OperationResourceBinding) -> SidResult<bool> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| SidError::Storage(format!("begin: {e}")))?;
    // A binding under a retired period is an unfinished creation's, kept to
    // reconcile it: it is carried and holds its key, though nothing runs
    // under that period any more. One under a period never issued here is
    // not taken.
    if let Some(period) = binding.period {
        match admit(&mut tx, column(period)?, true).await {
            Ok(()) | Err(SidError::OperationPeriodRefused(OperationPeriodRefusal::Retired)) => {}
            Err(SidError::OperationPeriodRefused(_)) => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    let inserted = sqlx::query(
        "INSERT INTO operation_resources
             (namespace, op_key, method, fingerprint, period, resource)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (namespace, op_key) DO NOTHING",
    )
    .bind(&binding.namespace)
    .bind(binding.key.as_str())
    .bind(&binding.method)
    .bind(&binding.fingerprint)
    .bind(binding.period.map(column).transpose()?)
    .bind(binding.resource)
    .execute(&mut *tx)
    .await
    .map_err(|e| SidError::Storage(format!("operation resource import: {e}")))?
    .rows_affected();
    tx.commit()
        .await
        .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
    Ok(inserted == 1)
}

#[async_trait]
impl OperationResultStore for PgOperationStore {
    async fn operation_period_policy(&self) -> SidResult<OperationPeriodPolicy> {
        period_policy(&self.pool).await
    }

    async fn current_operation_period(
        &self,
        now: DateTime<Utc>,
        acceptance: Duration,
    ) -> SidResult<IssuedOperationPeriod> {
        current_period(&self.pool, now, acceptance).await
    }

    async fn admit_operation_period(&self, period: OperationPeriod) -> SidResult<()> {
        admit_period(&self.pool, period).await
    }

    async fn retire_operation_periods(&self, before: DateTime<Utc>) -> SidResult<u64> {
        retire_periods(&self.pool, before).await
    }

    async fn export_operation_periods(&self) -> SidResult<OperationPeriodState> {
        export_periods(&self.pool).await
    }

    async fn import_operation_periods(&self, state: &OperationPeriodState) -> SidResult<()> {
        import_periods(&self.pool, state).await
    }

    /// The completion and the work it owes (beside the host's durable work
    /// table); the host's own audit records its changes.
    async fn record_outcome(&self, ctx: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(format!("begin: {e}")))?;
        if let Some(operation) = &ctx.operation {
            record_in_tx(&mut tx, operation).await?;
        }
        if !ctx.work.is_empty() {
            super::work::PgWorkStore::owe_in_tx(&mut tx, &ctx.work).await?;
        }
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(format!("commit: {e}")))
    }

    async fn purge_operation_results(
        &self,
        namespace: &str,
        method: &str,
        before: DateTime<Utc>,
    ) -> SidResult<u64> {
        purge(&self.pool, namespace, method, before).await
    }

    async fn purge_expired_operation_results(&self, now: DateTime<Utc>) -> SidResult<u64> {
        purge_expired(&self.pool, now).await
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

    async fn bind_operation_resource(
        &self,
        proposal: &OperationResourceBinding,
    ) -> SidResult<Uuid> {
        bind(&self.pool, proposal).await
    }

    async fn export_operation_resources(&self) -> SidResult<Vec<OperationResourceBinding>> {
        export_resources(&self.pool).await
    }

    async fn import_operation_resource(
        &self,
        binding: &OperationResourceBinding,
    ) -> SidResult<bool> {
        import_resource(&self.pool, binding).await
    }
}

#[async_trait]
impl OperationResultStore for PostgresBackend {
    async fn operation_period_policy(&self) -> SidResult<OperationPeriodPolicy> {
        period_policy(&self.pool).await
    }

    async fn current_operation_period(
        &self,
        now: DateTime<Utc>,
        acceptance: Duration,
    ) -> SidResult<IssuedOperationPeriod> {
        current_period(&self.pool, now, acceptance).await
    }

    async fn admit_operation_period(&self, period: OperationPeriod) -> SidResult<()> {
        admit_period(&self.pool, period).await
    }

    async fn retire_operation_periods(&self, before: DateTime<Utc>) -> SidResult<u64> {
        retire_periods(&self.pool, before).await
    }

    async fn export_operation_periods(&self) -> SidResult<OperationPeriodState> {
        export_periods(&self.pool).await
    }

    async fn import_operation_periods(&self, state: &OperationPeriodState) -> SidResult<()> {
        import_periods(&self.pool, state).await
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
        purge(&self.pool, namespace, method, before).await
    }

    async fn purge_expired_operation_results(&self, now: DateTime<Utc>) -> SidResult<u64> {
        purge_expired(&self.pool, now).await
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

    async fn bind_operation_resource(
        &self,
        proposal: &OperationResourceBinding,
    ) -> SidResult<Uuid> {
        bind(&self.pool, proposal).await
    }

    async fn export_operation_resources(&self) -> SidResult<Vec<OperationResourceBinding>> {
        export_resources(&self.pool).await
    }

    async fn import_operation_resource(
        &self,
        binding: &OperationResourceBinding,
    ) -> SidResult<bool> {
        import_resource(&self.pool, binding).await
    }
}
