// SPDX-License-Identifier: AGPL-3.0-only
//! Completions of keyed commands, committed with their effect.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sid_core::models::{MutationContext, OperationCompletion, OperationKey, OperationRecord};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::OperationResultStore;
use sqlx::SqlitePool;

use super::{SqliteBackend, WriteTx, fmt_dt};

/// Record `operation` in `tx`. When another transaction already committed
/// the key, this one must commit nothing: `OperationCompleted`; a completion
/// past its retention no longer holds the key and is replaced.
pub(super) async fn record_in_tx(
    tx: &mut WriteTx,
    operation: &OperationCompletion,
) -> SidResult<()> {
    let now = Utc::now();
    let inserted = sqlx::query(
        "INSERT INTO operation_results
             (namespace, op_key, method, fingerprint, result, completed_at, retain_until_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (namespace, op_key) DO UPDATE SET
             method = excluded.method, fingerprint = excluded.fingerprint,
             result = excluded.result, completed_at = excluded.completed_at,
             retain_until_ms = excluded.retain_until_ms
         WHERE operation_results.retain_until_ms <= ?",
    )
    .bind(&operation.namespace)
    .bind(operation.key.as_str())
    .bind(&operation.method)
    .bind(&operation.fingerprint)
    .bind(&operation.result)
    .bind(fmt_dt(&now))
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

/// A stored retention end; a malformed one is an error, never a substitute.
fn retention(ms: Option<i64>) -> SidResult<Option<DateTime<Utc>>> {
    ms.map(|ms| {
        DateTime::from_timestamp_millis(ms)
            .ok_or_else(|| SidError::Storage(format!("column retain_until_ms: {ms} is no instant")))
    })
    .transpose()
}

/// method, fingerprint, result, completed_at, retain_until_ms
type RecordRow = (String, Vec<u8>, Vec<u8>, String, Option<i64>);

pub(super) async fn get(
    pool: &SqlitePool,
    namespace: &str,
    key: &OperationKey,
) -> SidResult<Option<OperationRecord>> {
    let row: Option<RecordRow> = sqlx::query_as(
        "SELECT method, fingerprint, result, completed_at, retain_until_ms FROM operation_results
         WHERE namespace = ? AND op_key = ? AND (retain_until_ms IS NULL OR retain_until_ms > ?)",
    )
    .bind(namespace)
    .bind(key.as_str())
    .bind(Utc::now().timestamp_millis())
    .fetch_optional(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation result: {e}")))?;
    row.map(
        |(method, fingerprint, result, completed_at, retain_until)| {
            Ok(OperationRecord {
                completion: OperationCompletion {
                    namespace: namespace.to_string(),
                    key: key.clone(),
                    method,
                    fingerprint,
                    result,
                    retain_until: retention(retain_until)?,
                },
                completed_at: time(&completed_at)?,
            })
        },
    )
    .transpose()
}

/// A stored completion time; a malformed one is an error, never a substitute.
fn time(value: &str) -> SidResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| SidError::Storage(format!("column completed_at: bad timestamp {value}: {e}")))
}

/// namespace, op_key, method, fingerprint, result, completed_at, retain_until_ms
type FullRow = (
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    String,
    Option<i64>,
);

pub(super) async fn export(pool: &SqlitePool) -> SidResult<Vec<OperationRecord>> {
    let rows: Vec<FullRow> = sqlx::query_as(
        "SELECT namespace, op_key, method, fingerprint, result, completed_at, retain_until_ms
         FROM operation_results WHERE retain_until_ms IS NULL OR retain_until_ms > ?
         ORDER BY completed_at, namespace, op_key",
    )
    .bind(Utc::now().timestamp_millis())
    .fetch_all(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation results: {e}")))?;
    rows.into_iter()
        .map(
            |(namespace, key, method, fingerprint, result, completed_at, retain_until)| {
                Ok(OperationRecord {
                    completion: OperationCompletion {
                        namespace,
                        key: OperationKey::parse(&key)
                            .map_err(|e| SidError::Storage(format!("column op_key: {e}")))?,
                        method,
                        fingerprint,
                        result,
                        retain_until: retention(retain_until)?,
                    },
                    completed_at: time(&completed_at)?,
                })
            },
        )
        .collect()
}

pub(super) async fn import(pool: &SqlitePool, record: &OperationRecord) -> SidResult<bool> {
    let c = &record.completion;
    let inserted = sqlx::query(
        "INSERT INTO operation_results
             (namespace, op_key, method, fingerprint, result, completed_at, retain_until_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (namespace, op_key) DO NOTHING",
    )
    .bind(&c.namespace)
    .bind(c.key.as_str())
    .bind(&c.method)
    .bind(&c.fingerprint)
    .bind(&c.result)
    .bind(fmt_dt(&record.completed_at))
    .bind(c.retain_until.map(|t| t.timestamp_millis()))
    .execute(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation result import: {e}")))?
    .rows_affected();
    Ok(inserted == 1)
}

#[async_trait]
impl OperationResultStore for SqliteBackend {
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
