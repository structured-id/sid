// SPDX-License-Identifier: AGPL-3.0-only
//! Completions of keyed commands, committed with their effect.

use chrono::{DateTime, Utc};
use sid_core::models::{OperationCompletion, OperationKey, OperationRecord};
use sid_core::{Error as SidError, Result as SidResult};
use sqlx::PgPool;

/// Record `operation` in `tx`. When another transaction already committed
/// the key, this one must commit nothing: `OperationCompleted`. A concurrent
/// transaction holding the same key makes this insert wait for its outcome.
pub(super) async fn record_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    operation: &OperationCompletion,
) -> SidResult<()> {
    let inserted = sqlx::query(
        "INSERT INTO operation_results (namespace, op_key, method, fingerprint, result)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (namespace, op_key) DO NOTHING",
    )
    .bind(&operation.namespace)
    .bind(operation.key.as_str())
    .bind(&operation.method)
    .bind(&operation.fingerprint)
    .bind(&operation.result)
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
type RecordRow = (String, Vec<u8>, Vec<u8>, DateTime<Utc>);

/// namespace, op_key, method, fingerprint, result, completed_at
type FullRow = (String, String, String, Vec<u8>, Vec<u8>, DateTime<Utc>);

pub(super) async fn export(pool: &PgPool) -> SidResult<Vec<OperationRecord>> {
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
                    completed_at,
                })
            },
        )
        .collect()
}

pub(super) async fn import(pool: &PgPool, record: &OperationRecord) -> SidResult<bool> {
    let c = &record.completion;
    let inserted = sqlx::query(
        "INSERT INTO operation_results (namespace, op_key, method, fingerprint, result, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (namespace, op_key) DO NOTHING",
    )
    .bind(&c.namespace)
    .bind(c.key.as_str())
    .bind(&c.method)
    .bind(&c.fingerprint)
    .bind(&c.result)
    .bind(record.completed_at)
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
        "SELECT method, fingerprint, result, completed_at FROM operation_results
         WHERE namespace = $1 AND op_key = $2",
    )
    .bind(namespace)
    .bind(key.as_str())
    .fetch_optional(pool)
    .await
    .map_err(|e| SidError::Storage(format!("operation result: {e}")))?;
    Ok(row.map(
        |(method, fingerprint, result, completed_at)| OperationRecord {
            completion: OperationCompletion {
                namespace: namespace.to_string(),
                key: key.clone(),
                method,
                fingerprint,
                result,
            },
            completed_at,
        },
    ))
}
