// SPDX-License-Identifier: AGPL-3.0-only
//! Completions of keyed commands, committed with their effect.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sid_core::models::{MutationContext, OperationCompletion, OperationKey, OperationRecord};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::OperationResultStore;
use sqlx::PgPool;

use super::PostgresBackend;

/// Record `operation` in `tx`. When another transaction already committed
/// the key, this one must commit nothing: `OperationCompleted`; a completion
/// past its retention no longer holds the key and is replaced. A concurrent
/// transaction holding the same key makes this insert wait for its outcome.
pub(super) async fn record_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    operation: &OperationCompletion,
) -> SidResult<()> {
    let inserted = sqlx::query(
        "INSERT INTO operation_results (namespace, op_key, method, fingerprint, result, retain_until)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (namespace, op_key) DO UPDATE SET
             method = EXCLUDED.method, fingerprint = EXCLUDED.fingerprint,
             result = EXCLUDED.result, completed_at = NOW(),
             retain_until = EXCLUDED.retain_until
         WHERE operation_results.retain_until <= NOW()",
    )
    .bind(&operation.namespace)
    .bind(operation.key.as_str())
    .bind(&operation.method)
    .bind(&operation.fingerprint)
    .bind(&operation.result)
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

/// method, fingerprint, result, completed_at, retain_until
type RecordRow = (
    String,
    Vec<u8>,
    Vec<u8>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

/// namespace, op_key, method, fingerprint, result, completed_at, retain_until
type FullRow = (
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

pub(super) async fn export(pool: &PgPool) -> SidResult<Vec<OperationRecord>> {
    let rows: Vec<FullRow> = sqlx::query_as(
        "SELECT namespace, op_key, method, fingerprint, result, completed_at, retain_until
         FROM operation_results
         WHERE retain_until IS NULL OR retain_until > NOW()
         ORDER BY completed_at, namespace, op_key",
    )
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
             (namespace, op_key, method, fingerprint, result, completed_at, retain_until)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (namespace, op_key) DO NOTHING",
    )
    .bind(&c.namespace)
    .bind(c.key.as_str())
    .bind(&c.method)
    .bind(&c.fingerprint)
    .bind(&c.result)
    .bind(record.completed_at)
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
        "SELECT method, fingerprint, result, completed_at, retain_until FROM operation_results
         WHERE namespace = $1 AND op_key = $2
           AND (retain_until IS NULL OR retain_until > NOW())",
    )
    .bind(namespace)
    .bind(key.as_str())
    .fetch_optional(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation result: {e}")))?;
    Ok(row.map(
        |(method, fingerprint, result, completed_at, retain_until)| OperationRecord {
            completion: OperationCompletion {
                namespace: namespace.to_string(),
                key: key.clone(),
                method,
                fingerprint,
                result,
                retain_until,
            },
            completed_at,
        },
    ))
}

#[async_trait]
impl OperationResultStore for PostgresBackend {
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
