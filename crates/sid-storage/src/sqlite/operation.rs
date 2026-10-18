// SPDX-License-Identifier: AGPL-3.0-only
//! Completions of keyed commands, committed with their effect.

use async_trait::async_trait;
use sid_core::models::{MutationContext, OperationCompletion, OperationKey, OperationRecord};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::OperationResultStore;
use sqlx::SqlitePool;

use super::{SqliteBackend, WriteTx, fmt_dt};

/// Record `operation` in `tx`. When another transaction already committed
/// the key, this one must commit nothing: `OperationCompleted`.
pub(super) async fn record_in_tx(
    tx: &mut WriteTx,
    operation: &OperationCompletion,
) -> SidResult<()> {
    let inserted = sqlx::query(
        "INSERT INTO operation_results (namespace, op_key, method, fingerprint, result, completed_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (namespace, op_key) DO NOTHING",
    )
    .bind(&operation.namespace)
    .bind(operation.key.as_str())
    .bind(&operation.method)
    .bind(&operation.fingerprint)
    .bind(&operation.result)
    .bind(fmt_dt(&chrono::Utc::now()))
    .execute(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("operation completion: {e}")))?
    .rows_affected();
    if inserted == 0 {
        return Err(SidError::OperationCompleted(operation.key.as_str().into()));
    }
    Ok(())
}

/// method, fingerprint, result, completed_at
type RecordRow = (String, Vec<u8>, Vec<u8>, String);

pub(super) async fn get(
    pool: &SqlitePool,
    namespace: &str,
    key: &OperationKey,
) -> SidResult<Option<OperationRecord>> {
    let row: Option<RecordRow> = sqlx::query_as(
        "SELECT method, fingerprint, result, completed_at FROM operation_results
         WHERE namespace = ? AND op_key = ?",
    )
    .bind(namespace)
    .bind(key.as_str())
    .fetch_optional(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation result: {e}")))?;
    row.map(|(method, fingerprint, result, completed_at)| {
        Ok(OperationRecord {
            completion: OperationCompletion {
                namespace: namespace.to_string(),
                key: key.clone(),
                method,
                fingerprint,
                result,
            },
            completed_at: time(&completed_at)?,
        })
    })
    .transpose()
}

/// A stored completion time; a malformed one is an error, never a substitute.
fn time(value: &str) -> SidResult<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|e| SidError::Storage(format!("column completed_at: bad timestamp {value}: {e}")))
}

/// namespace, op_key, method, fingerprint, result, completed_at
type FullRow = (String, String, String, Vec<u8>, Vec<u8>, String);

pub(super) async fn export(pool: &SqlitePool) -> SidResult<Vec<OperationRecord>> {
    let rows: Vec<FullRow> = sqlx::query_as(
        "SELECT namespace, op_key, method, fingerprint, result, completed_at
         FROM operation_results ORDER BY completed_at, namespace, op_key",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation results: {e}")))?;
    rows.into_iter()
        .map(
            |(namespace, key, method, fingerprint, result, completed_at)| {
                Ok(OperationRecord {
                    completion: OperationCompletion {
                        namespace,
                        key: OperationKey::parse(&key)
                            .map_err(|e| SidError::Storage(format!("column op_key: {e}")))?,
                        method,
                        fingerprint,
                        result,
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
        "INSERT INTO operation_results (namespace, op_key, method, fingerprint, result, completed_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (namespace, op_key) DO NOTHING",
    )
    .bind(&c.namespace)
    .bind(c.key.as_str())
    .bind(&c.method)
    .bind(&c.fingerprint)
    .bind(&c.result)
    .bind(fmt_dt(&record.completed_at))
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
        before: chrono::DateTime<chrono::Utc>,
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
            let completed_at = chrono::DateTime::parse_from_rfc3339(&completed_at)
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
