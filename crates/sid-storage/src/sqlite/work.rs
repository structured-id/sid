// SPDX-License-Identifier: AGPL-3.0-only
//! Durable work on SQLite: enqueue inside the caller's transaction, claims
//! under the database write lock (`BEGIN IMMEDIATE`) with a lease, outcomes
//! fenced by the claim generation.

use super::{SqliteBackend, col, fmt_dt};
use async_trait::async_trait;
use sid_core::models::{
    ClaimedWork, NewWork, WorkFailure, WorkId, WorkKind, WorkRecord, WorkSnapshot, WorkState,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::WorkStore;
use sqlx::SqliteConnection;

fn storage(e: sqlx::Error) -> SidError {
    SidError::Storage(e.to_string())
}

/// Store `work` inside `tx`, the transaction of the state change that owes
/// it. Returns `false` when work with its id already exists; refuses with
/// `ResourceExhausted` when `capacity` open items of its kind are stored.
pub(crate) async fn insert_work_in_tx(
    tx: &mut SqliteConnection,
    work: &NewWork,
    capacity: u64,
) -> SidResult<bool> {
    // The same obligation again is already stored: accepted, whatever the load.
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM durable_work WHERE id = ?)")
            .bind(work.id.0.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
    if exists {
        return Ok(false);
    }
    let open: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM durable_work
         WHERE kind = ? AND state IN ('pending', 'claimed')",
    )
    .bind(work.kind.as_str())
    .fetch_one(&mut *tx)
    .await
    .map_err(storage)?;
    if u64::try_from(open).unwrap_or(u64::MAX) >= capacity {
        return Err(SidError::ResourceExhausted(format!(
            "durable work queue full ({capacity} open items)"
        )));
    }
    if work.max_attempts == 0 {
        return Err(SidError::Validation("max_attempts out of range".into()));
    }
    let now = fmt_dt(&chrono::Utc::now());
    let inserted = sqlx::query(
        "INSERT INTO durable_work (id, kind, payload, max_attempts, not_before, expires_at,
            created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
    )
    .bind(work.id.0.to_string())
    .bind(work.kind.as_str())
    .bind(&work.payload)
    .bind(i64::from(work.max_attempts))
    .bind(fmt_dt(&work.not_before.unwrap_or_else(chrono::Utc::now)))
    .bind(work.expires_at.as_ref().map(fmt_dt))
    .bind(&now)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .map_err(storage)?
    .rows_affected()
        == 1;
    Ok(inserted)
}

#[async_trait]
impl WorkStore for SqliteBackend {
    async fn enqueue_work(&self, work: &NewWork, capacity: u64) -> SidResult<bool> {
        let mut conn = self.pool.acquire().await.map_err(storage)?;
        let mut tx = sqlx::Connection::begin_with(&mut *conn, "BEGIN IMMEDIATE")
            .await
            .map_err(storage)?;
        let inserted = insert_work_in_tx(&mut tx, work, capacity).await?;
        tx.commit().await.map_err(storage)?;
        Ok(inserted)
    }

    async fn claim_work(
        &self,
        kinds: &[WorkKind],
        worker: &str,
        limit: u32,
        lease: std::time::Duration,
    ) -> SidResult<Vec<ClaimedWork>> {
        if kinds.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let now = chrono::Utc::now();
        let now_s = fmt_dt(&now);
        let lease_until = fmt_dt(
            &(now
                + chrono::Duration::from_std(lease)
                    .map_err(|_| SidError::Validation("lease out of range".into()))?),
        );
        // The kinds travel as one JSON array bound to a fixed statement.
        let kinds_json =
            serde_json::to_string(&kinds.iter().map(WorkKind::as_str).collect::<Vec<_>>())
                .map_err(|e| SidError::Internal(format!("work kinds: {e}")))?;
        let mut conn = self.pool.acquire().await.map_err(storage)?;
        let mut tx = sqlx::Connection::begin_with(&mut *conn, "BEGIN IMMEDIATE")
            .await
            .map_err(storage)?;

        // Past its validity: expired, never attempted again.
        sqlx::query(
            "UPDATE durable_work SET state = 'expired', lease_owner = NULL,
                lease_until = NULL, updated_at = ?
             WHERE kind IN (SELECT value FROM json_each(?))
               AND state IN ('pending', 'claimed')
               AND expires_at IS NOT NULL AND expires_at <= ?",
        )
        .bind(&now_s)
        .bind(&kinds_json)
        .bind(&now_s)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;

        // Abandoned by a worker on its last attempt: failed.
        sqlx::query(
            "UPDATE durable_work SET state = 'failed', lease_owner = NULL,
                lease_until = NULL, updated_at = ?,
                last_error = COALESCE(last_error, 'lease expired on the last attempt')
             WHERE kind IN (SELECT value FROM json_each(?))
               AND state = 'claimed' AND lease_until <= ?
               AND attempts >= max_attempts",
        )
        .bind(&now_s)
        .bind(&kinds_json)
        .bind(&now_s)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;

        let due: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM durable_work
             WHERE kind IN (SELECT value FROM json_each(?))
               AND ((state = 'pending' AND not_before <= ?)
                    OR (state = 'claimed' AND lease_until <= ?))
             ORDER BY not_before LIMIT ?",
        )
        .bind(&kinds_json)
        .bind(&now_s)
        .bind(&now_s)
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await
        .map_err(storage)?;

        let mut claimed = Vec::with_capacity(due.len());
        for id in due {
            let row = sqlx::query(
                "UPDATE durable_work SET state = 'claimed', attempts = attempts + 1,
                    generation = generation + 1, lease_owner = ?, lease_until = ?,
                    updated_at = ?
                 WHERE id = ?
                 RETURNING id, kind, payload, attempts, max_attempts, generation, expires_at",
            )
            .bind(worker)
            .bind(&lease_until)
            .bind(&now_s)
            .bind(&id)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
            claimed.push(ClaimedWork {
                id: work_id(col(&row, "id")?)?,
                kind: WorkKind::new(&col::<String>(&row, "kind")?)?,
                payload: col(&row, "payload")?,
                attempt: count(col(&row, "attempts")?)?,
                max_attempts: count(col(&row, "max_attempts")?)?,
                generation: col(&row, "generation")?,
                expires_at: time_opt(col(&row, "expires_at")?)?,
            });
        }
        tx.commit().await.map_err(storage)?;
        Ok(claimed)
    }

    async fn complete_work(
        &self,
        id: WorkId,
        generation: i64,
        result: Option<&str>,
    ) -> SidResult<bool> {
        let done = sqlx::query(
            "UPDATE durable_work SET state = 'completed', result = ?, lease_owner = NULL,
                lease_until = NULL, updated_at = ?
             WHERE id = ? AND generation = ? AND state = 'claimed'",
        )
        .bind(result)
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(id.0.to_string())
        .bind(generation)
        .execute(&self.pool)
        .await
        .map_err(storage)?
        .rows_affected();
        Ok(done == 1)
    }

    async fn fail_work(
        &self,
        id: WorkId,
        generation: i64,
        failure: &WorkFailure,
    ) -> SidResult<bool> {
        let mut conn = self.pool.acquire().await.map_err(storage)?;
        let mut tx = sqlx::Connection::begin_with(&mut *conn, "BEGIN IMMEDIATE")
            .await
            .map_err(storage)?;
        let retry_at = failure.retry_at.as_ref().map(fmt_dt);
        let state: Option<String> = sqlx::query_scalar(
            "UPDATE durable_work SET
                state = CASE WHEN ? IS NULL OR attempts >= max_attempts
                             THEN 'failed' ELSE 'pending' END,
                not_before = COALESCE(?, not_before), last_error = ?, ambiguous = ?,
                lease_owner = NULL, lease_until = NULL, updated_at = ?
             WHERE id = ? AND generation = ? AND state = 'claimed'
             RETURNING state",
        )
        .bind(&retry_at)
        .bind(&retry_at)
        .bind(&failure.error)
        .bind(failure.ambiguous)
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(id.0.to_string())
        .bind(generation)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
        let Some(state) = state else {
            return Ok(false);
        };
        if state == WorkState::Failed.as_str()
            && let Some(alert) = &failure.on_dead
        {
            // One alert per dead work, never refused for load: the failure it
            // reports is already recorded.
            insert_work_in_tx(&mut tx, alert, u64::MAX).await?;
        }
        tx.commit().await.map_err(storage)?;
        Ok(true)
    }

    async fn get_work(&self, id: WorkId) -> SidResult<Option<WorkRecord>> {
        let row = sqlx::query(
            "SELECT id, kind, state, attempts, max_attempts, generation, last_error,
                ambiguous, result, not_before, expires_at, created_at, updated_at
             FROM durable_work WHERE id = ?",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.as_ref().map(record).transpose()
    }

    async fn export_work(&self) -> SidResult<Vec<WorkSnapshot>> {
        let rows = sqlx::query(
            "SELECT id, kind, payload, state, attempts, max_attempts, generation, last_error,
                ambiguous, result, not_before, expires_at, created_at, updated_at
             FROM durable_work ORDER BY created_at, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.iter()
            .map(|row| {
                Ok(WorkSnapshot {
                    record: record(row)?,
                    payload: col(row, "payload")?,
                })
            })
            .collect()
    }

    async fn import_work(&self, work: &WorkSnapshot) -> SidResult<bool> {
        let record = work.at_rest();
        if record.max_attempts == 0 {
            return Err(SidError::Validation("max_attempts out of range".into()));
        }
        let inserted = sqlx::query(
            "INSERT INTO durable_work (id, kind, payload, state, attempts, max_attempts,
                generation, last_error, ambiguous, result, not_before, expires_at,
                created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(record.id.0.to_string())
        .bind(record.kind.as_str())
        .bind(&work.payload)
        .bind(record.state.as_str())
        .bind(i64::from(record.attempts))
        .bind(i64::from(record.max_attempts))
        .bind(record.generation)
        .bind(&record.last_error)
        .bind(record.ambiguous)
        .bind(&record.result)
        .bind(fmt_dt(&record.not_before))
        .bind(record.expires_at.as_ref().map(fmt_dt))
        .bind(fmt_dt(&record.created_at))
        .bind(fmt_dt(&record.updated_at))
        .execute(&self.pool)
        .await
        .map_err(storage)?
        .rows_affected()
            == 1;
        Ok(inserted)
    }

    async fn purge_ended_work(
        &self,
        kind: &WorkKind,
        before: chrono::DateTime<chrono::Utc>,
    ) -> SidResult<u64> {
        let mut conn = self.pool.acquire().await.map_err(storage)?;
        let mut tx = sqlx::Connection::begin_with(&mut *conn, "BEGIN IMMEDIATE")
            .await
            .map_err(storage)?;
        // Compared as instants: stored timestamps do not all sort as text.
        let ended: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, updated_at FROM durable_work
             WHERE kind = ? AND state NOT IN ('pending', 'claimed')",
        )
        .bind(kind.as_str())
        .fetch_all(&mut *tx)
        .await
        .map_err(storage)?;
        let mut dropped = 0;
        for (id, updated_at) in ended {
            let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at)
                .map_err(|e| SidError::Storage(format!("work updated_at: {e}")))?;
            if updated_at < before {
                sqlx::query("DELETE FROM durable_work WHERE id = ?")
                    .bind(&id)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage)?;
                dropped += 1;
            }
        }
        tx.commit().await.map_err(storage)?;
        Ok(dropped)
    }
}

/// The work record in `row`.
fn record(row: &sqlx::sqlite::SqliteRow) -> SidResult<WorkRecord> {
    Ok(WorkRecord {
        id: work_id(col(row, "id")?)?,
        kind: WorkKind::new(&col::<String>(row, "kind")?)?,
        state: WorkState::parse(&col::<String>(row, "state")?)?,
        attempts: count(col(row, "attempts")?)?,
        max_attempts: count(col(row, "max_attempts")?)?,
        generation: col(row, "generation")?,
        last_error: col(row, "last_error")?,
        ambiguous: col(row, "ambiguous")?,
        result: col(row, "result")?,
        not_before: time(&col::<String>(row, "not_before")?)?,
        expires_at: time_opt(col(row, "expires_at")?)?,
        created_at: time(&col::<String>(row, "created_at")?)?,
        updated_at: time(&col::<String>(row, "updated_at")?)?,
    })
}

fn work_id(value: String) -> SidResult<WorkId> {
    uuid::Uuid::parse_str(&value)
        .map(WorkId)
        .map_err(|e| SidError::Storage(format!("bad work id {value}: {e}")))
}

/// A stored timestamp. A malformed one is an error: expiry and retry times
/// decide whether work runs, so no substitute value is acceptable.
fn time(value: &str) -> SidResult<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|e| SidError::Storage(format!("bad work timestamp {value}: {e}")))
}

fn time_opt(value: Option<String>) -> SidResult<Option<chrono::DateTime<chrono::Utc>>> {
    value.as_deref().map(time).transpose()
}

/// A stored non-negative count.
fn count(value: i64) -> SidResult<u32> {
    u32::try_from(value).map_err(|_| SidError::Storage(format!("bad count: {value}")))
}
