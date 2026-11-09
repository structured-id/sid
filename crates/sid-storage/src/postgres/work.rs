// SPDX-License-Identifier: AGPL-3.0-only
//! Durable work on PostgreSQL: enqueue inside the caller's transaction,
//! claims with `FOR UPDATE SKIP LOCKED` under a lease, outcomes fenced by
//! the claim generation.

use super::PostgresBackend;
use async_trait::async_trait;
use sid_core::models::{
    ClaimedWork, NewWork, WorkFailure, WorkId, WorkKind, WorkRecord, WorkSnapshot, WorkState,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::WorkStore;
use sqlx::{PgConnection, PgPool, Row};

/// The durable work table of a service that keeps its own database
/// (sid-notify); the engine's schema holds the same table.
const SCHEMA: &str = include_str!("durable_work.sql");

/// Durable work in a PostgreSQL database of its own owner, apart from the
/// engine backend (a delivery service's job store).
pub struct PgWorkStore {
    pool: PgPool,
}

impl PgWorkStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create the work table if it does not exist. Replicas starting together
    /// take turns under a transaction-scoped advisory lock: concurrent
    /// `CREATE ... IF NOT EXISTS` of one name collides in the catalog.
    pub async fn ensure_schema(&self) -> SidResult<()> {
        let schema_error = |e: sqlx::Error| SidError::Storage(format!("durable work schema: {e}"));
        let mut tx = self.pool.begin().await.map_err(schema_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('sid.durable_work.schema'))")
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

    /// Store `works`, owed by a state change of this database's owner,
    /// inside that change's transaction `tx`: they commit with it or not at
    /// all, admitted under each kind's lock up to
    /// [`OWED_WORK_CAPACITY`](sid_plugin::OWED_WORK_CAPACITY) open items.
    /// For a host whose own tables live beside this work table.
    pub async fn owe_in_tx(tx: &mut PgConnection, works: &[NewWork]) -> SidResult<()> {
        insert_owed_work_in_tx(tx, works, sid_plugin::OWED_WORK_CAPACITY).await
    }
}

/// Store `work` inside `tx`, which holds its kind's admission lock
/// ([`lock_kind`]). Returns `false` when work with its id already exists;
/// refuses with `ResourceExhausted` when `capacity` open items of its kind
/// are stored.
async fn insert_work_in_tx(
    tx: &mut PgConnection,
    work: &NewWork,
    capacity: u64,
) -> SidResult<bool> {
    // The same obligation again is already stored: accepted, whatever the load.
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM durable_work WHERE id = $1)")
            .bind(work.id.0)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("find work: {e}")))?;
    if exists {
        return Ok(false);
    }
    // The count the triggers keep, not a count of the rows: reading every
    // open item made each admission as slow as the backlog was long. Under
    // the kind's lock no other insert of the kind can raise it meanwhile;
    // concurrent completions only lower it.
    let open: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(open), 0)::BIGINT FROM durable_work_open WHERE kind = $1",
    )
    .bind(work.kind.as_str())
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| SidError::Storage(format!("count open work: {e}")))?;
    if u64::try_from(open).unwrap_or(u64::MAX) >= capacity {
        return Err(SidError::ResourceExhausted(format!(
            "durable work queue full ({capacity} open items)"
        )));
    }
    let max_attempts = i32::try_from(work.max_attempts)
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| SidError::Validation("max_attempts out of range".into()))?;
    let inserted = sqlx::query(
        "INSERT INTO durable_work (id, kind, payload, max_attempts, not_before, expires_at)
         VALUES ($1, $2, $3, $4, COALESCE($5, NOW()), $6) ON CONFLICT (id) DO NOTHING",
    )
    .bind(work.id.0)
    .bind(work.kind.as_str())
    .bind(&work.payload)
    .bind(max_attempts)
    .bind(work.not_before)
    .bind(work.expires_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| SidError::Storage(format!("insert work: {e}")))?
    .rows_affected()
        == 1;
    Ok(inserted)
}

/// Hold the admission lock of `kind` until the transaction ends: count and
/// insert are one step per kind, so writers enqueuing together, standalone
/// or with a mutation, never each see room and pass the capacity between
/// them.
async fn lock_kind(tx: &mut PgConnection, kind: &WorkKind) -> SidResult<()> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('sid.durable_work.capacity:' || $1, 0))",
    )
    .bind(kind.as_str())
    .execute(&mut *tx)
    .await
    .map_err(|e| SidError::Storage(format!("lock work kind: {e}")))?;
    Ok(())
}

/// Store the work a business mutation owes inside its transaction `tx`,
/// under the admission lock of each kind. The kinds are locked in their
/// order, so two mutations owing the same kinds never wait on each other in
/// a cycle.
pub(crate) async fn insert_owed_work_in_tx(
    tx: &mut PgConnection,
    works: &[NewWork],
    capacity: u64,
) -> SidResult<()> {
    lock_kinds_of(tx, works).await?;
    for work in works {
        insert_work_in_tx(tx, work, capacity).await?;
    }
    Ok(())
}

/// Take the admission lock of each kind `works` hold, in the kinds' order.
async fn lock_kinds_of(tx: &mut PgConnection, works: &[NewWork]) -> SidResult<()> {
    let mut kinds: Vec<&WorkKind> = works.iter().map(|w| &w.kind).collect();
    kinds.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
    kinds.dedup();
    for kind in kinds {
        lock_kind(tx, kind).await?;
    }
    Ok(())
}

async fn enqueue(pool: &PgPool, work: &NewWork, capacity: u64) -> SidResult<bool> {
    let storage = |e: sqlx::Error| SidError::Storage(format!("enqueue work: {e}"));
    let mut tx = pool.begin().await.map_err(storage)?;
    lock_kind(&mut tx, &work.kind).await?;
    let inserted = insert_work_in_tx(&mut tx, work, capacity).await?;
    tx.commit().await.map_err(storage)?;
    Ok(inserted)
}

/// A claim's sweep of open work past its validity, through the expiry index.
const EXPIRE_SQL: &str = "UPDATE durable_work SET state = 'expired', lease_owner = NULL,
        lease_until = NULL, updated_at = NOW()
     WHERE kind = ANY($1) AND state IN ('pending', 'claimed')
       AND expires_at IS NOT NULL AND expires_at <= NOW()";

/// A claim's sweep of work abandoned on its last attempt, through the lease
/// index.
const ABANDONED_SQL: &str = "UPDATE durable_work SET state = 'failed', lease_owner = NULL,
        lease_until = NULL, updated_at = NOW(),
        last_error = COALESCE(last_error, 'lease expired on the last attempt')
     WHERE kind = ANY($1) AND state = 'claimed' AND lease_until <= NOW()
       AND attempts >= max_attempts";

/// The work a claim takes. Each kind gives its first `limit` unlocked items
/// from the due and the lease indexes, locked as they are read, so the read
/// is bounded by kinds times the limit whatever the backlog (one index
/// ordered across several kinds would sort every open item) and concurrent
/// claims step past each other's rows instead of all waiting for the first
/// ones. The earliest `limit` of them are claimed; the rest are released at
/// commit. The ids are an array the update looks up by key: joined as a
/// relation, the planner hashed the whole table to find 32 rows.
const CLAIM_SQL: &str = "UPDATE durable_work w SET state = 'claimed', attempts = w.attempts + 1,
        generation = w.generation + 1, lease_owner = $2,
        lease_until = NOW() + make_interval(secs => $3), updated_at = NOW()
     WHERE w.id = ANY (ARRAY(SELECT c.id FROM (
           SELECT due.id, due.not_before FROM unnest($1::text[]) k(kind)
           CROSS JOIN LATERAL (SELECT id, not_before FROM durable_work
               WHERE kind = k.kind AND state = 'pending' AND not_before <= NOW()
               ORDER BY not_before LIMIT $4 FOR UPDATE SKIP LOCKED) due
           UNION ALL
           SELECT lapsed.id, lapsed.not_before FROM unnest($1::text[]) k(kind)
           CROSS JOIN LATERAL (SELECT id, not_before FROM durable_work
               WHERE kind = k.kind AND state = 'claimed' AND lease_until <= NOW()
               ORDER BY lease_until LIMIT $4 FOR UPDATE SKIP LOCKED) lapsed
         ) c
         ORDER BY c.not_before
         LIMIT $4))
     RETURNING w.id, w.kind, w.payload, w.attempts, w.max_attempts,
        w.generation, w.expires_at";

async fn claim(
    pool: &PgPool,
    kinds: &[WorkKind],
    worker: &str,
    limit: u32,
    lease: std::time::Duration,
) -> SidResult<Vec<ClaimedWork>> {
    // A set: a kind named twice would give its candidates twice.
    let mut kinds: Vec<&str> = kinds.iter().map(WorkKind::as_str).collect();
    kinds.sort_unstable();
    kinds.dedup();
    let storage = |e: sqlx::Error| SidError::Storage(format!("claim work: {e}"));
    let mut tx = pool.begin().await.map_err(storage)?;
    // Past its validity: expired, never attempted again.
    sqlx::query(EXPIRE_SQL)
        .bind(&kinds)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    // Abandoned by a worker on its last attempt: failed.
    sqlx::query(ABANDONED_SQL)
        .bind(&kinds)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
    let rows = sqlx::query(CLAIM_SQL)
        .bind(&kinds)
        .bind(worker)
        .bind(lease.as_secs_f64())
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await
        .map_err(storage)?;
    tx.commit().await.map_err(storage)?;
    rows.iter()
        .map(|row| {
            Ok(ClaimedWork {
                id: WorkId(col(row, "id")?),
                kind: WorkKind::new(col(row, "kind")?)?,
                payload: col(row, "payload")?,
                attempt: count(col(row, "attempts")?)?,
                max_attempts: count(col(row, "max_attempts")?)?,
                generation: col(row, "generation")?,
                expires_at: col(row, "expires_at")?,
            })
        })
        .collect()
}

async fn complete(
    pool: &PgPool,
    id: WorkId,
    generation: i64,
    result: Option<&str>,
) -> SidResult<bool> {
    let done = sqlx::query(
        "UPDATE durable_work SET state = 'completed', result = $3, lease_owner = NULL,
            lease_until = NULL, updated_at = NOW()
         WHERE id = $1 AND generation = $2 AND state = 'claimed'",
    )
    .bind(id.0)
    .bind(generation)
    .bind(result)
    .execute(pool)
    .await
    .map_err(|e| SidError::Storage(format!("complete work: {e}")))?
    .rows_affected();
    Ok(done == 1)
}

/// Complete claimed work `id` and store `owed` in one transaction. Each
/// child kind's admission lock is taken first, in order, and then the
/// parent's row: completing the parent updates its kind's open count, and
/// an enqueue takes its kind's lock before the count, so a completion
/// holding a count shard while waiting for a lock would deadlock with an
/// enqueue holding that lock while waiting for the shard.
async fn complete_owing(
    pool: &PgPool,
    id: WorkId,
    generation: i64,
    result: Option<&str>,
    owed: &[NewWork],
    capacity: u64,
) -> SidResult<bool> {
    let storage = |e: sqlx::Error| SidError::Storage(format!("complete work: {e}"));
    let mut tx = pool.begin().await.map_err(storage)?;
    lock_kinds_of(&mut tx, owed).await?;
    let done = sqlx::query(
        "UPDATE durable_work SET state = 'completed', result = $3, lease_owner = NULL,
            lease_until = NULL, updated_at = NOW()
         WHERE id = $1 AND generation = $2 AND state = 'claimed'",
    )
    .bind(id.0)
    .bind(generation)
    .bind(result)
    .execute(&mut *tx)
    .await
    .map_err(storage)?
    .rows_affected();
    if done != 1 {
        return Ok(false);
    }
    insert_owed_work_in_tx(&mut tx, owed, capacity).await?;
    tx.commit().await.map_err(storage)?;
    Ok(true)
}

async fn fail(
    pool: &PgPool,
    id: WorkId,
    generation: i64,
    failure: &WorkFailure,
) -> SidResult<bool> {
    let storage = |e: sqlx::Error| SidError::Storage(format!("fail work: {e}"));
    let mut tx = pool.begin().await.map_err(storage)?;
    let state: Option<String> = sqlx::query_scalar(
        "UPDATE durable_work SET
            state = CASE WHEN $4::timestamptz IS NULL OR attempts >= max_attempts
                         THEN 'failed' ELSE 'pending' END,
            not_before = COALESCE($4, not_before), last_error = $3, ambiguous = $5,
            lease_owner = NULL, lease_until = NULL, updated_at = NOW()
         WHERE id = $1 AND generation = $2 AND state = 'claimed'
         RETURNING state",
    )
    .bind(id.0)
    .bind(generation)
    .bind(&failure.error)
    .bind(failure.retry_at)
    .bind(failure.ambiguous)
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

async fn get(pool: &PgPool, id: WorkId) -> SidResult<Option<WorkRecord>> {
    let row = sqlx::query(
        "SELECT id, kind, state, attempts, max_attempts, generation, last_error,
            ambiguous, result, not_before, expires_at, created_at, updated_at
         FROM durable_work WHERE id = $1",
    )
    .bind(id.0)
    .fetch_optional(pool)
    .await
    .map_err(|e| SidError::Storage(format!("get work: {e}")))?;
    row.as_ref().map(record).transpose()
}

/// The work record in `row`.
fn record(row: &sqlx::postgres::PgRow) -> SidResult<WorkRecord> {
    Ok(WorkRecord {
        id: WorkId(col(row, "id")?),
        kind: WorkKind::new(col(row, "kind")?)?,
        state: WorkState::parse(col(row, "state")?)?,
        attempts: count(col(row, "attempts")?)?,
        max_attempts: count(col(row, "max_attempts")?)?,
        generation: col(row, "generation")?,
        last_error: col(row, "last_error")?,
        ambiguous: col(row, "ambiguous")?,
        result: col(row, "result")?,
        not_before: col(row, "not_before")?,
        expires_at: col(row, "expires_at")?,
        created_at: col(row, "created_at")?,
        updated_at: col(row, "updated_at")?,
    })
}

async fn export(pool: &PgPool) -> SidResult<Vec<WorkSnapshot>> {
    let rows = sqlx::query(
        "SELECT id, kind, payload, state, attempts, max_attempts, generation, last_error,
            ambiguous, result, not_before, expires_at, created_at, updated_at
         FROM durable_work ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| SidError::Storage(format!("export work: {e}")))?;
    rows.iter()
        .map(|row| {
            Ok(WorkSnapshot {
                record: record(row)?,
                payload: col(row, "payload")?,
            })
        })
        .collect()
}

async fn import(pool: &PgPool, work: &WorkSnapshot) -> SidResult<bool> {
    let record = work.at_rest();
    let attempts = i32::try_from(record.attempts)
        .map_err(|_| SidError::Validation("attempts out of range".into()))?;
    let max_attempts = i32::try_from(record.max_attempts)
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| SidError::Validation("max_attempts out of range".into()))?;
    let inserted = sqlx::query(
        "INSERT INTO durable_work (id, kind, payload, state, attempts, max_attempts,
            generation, last_error, ambiguous, result, not_before, expires_at,
            created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(record.id.0)
    .bind(record.kind.as_str())
    .bind(&work.payload)
    .bind(record.state.as_str())
    .bind(attempts)
    .bind(max_attempts)
    .bind(record.generation)
    .bind(&record.last_error)
    .bind(record.ambiguous)
    .bind(&record.result)
    .bind(record.not_before)
    .bind(record.expires_at)
    .bind(record.created_at)
    .bind(record.updated_at)
    .execute(pool)
    .await
    .map_err(|e| SidError::Storage(format!("import work: {e}")))?
    .rows_affected()
        == 1;
    Ok(inserted)
}

macro_rules! work_store_over_pool {
    ($ty:ty) => {
        #[async_trait]
        impl WorkStore for $ty {
            async fn enqueue_work(&self, work: &NewWork, capacity: u64) -> SidResult<bool> {
                enqueue(&self.pool, work, capacity).await
            }

            async fn claim_work(
                &self,
                kinds: &[WorkKind],
                worker: &str,
                limit: u32,
                lease: std::time::Duration,
            ) -> SidResult<Vec<ClaimedWork>> {
                claim(&self.pool, kinds, worker, limit, lease).await
            }

            async fn complete_work(
                &self,
                id: WorkId,
                generation: i64,
                result: Option<&str>,
            ) -> SidResult<bool> {
                complete(&self.pool, id, generation, result).await
            }

            async fn complete_work_owing(
                &self,
                id: WorkId,
                generation: i64,
                result: Option<&str>,
                owed: &[NewWork],
                capacity: u64,
            ) -> SidResult<bool> {
                complete_owing(&self.pool, id, generation, result, owed, capacity).await
            }

            async fn fail_work(
                &self,
                id: WorkId,
                generation: i64,
                failure: &WorkFailure,
            ) -> SidResult<bool> {
                fail(&self.pool, id, generation, failure).await
            }

            async fn get_work(&self, id: WorkId) -> SidResult<Option<WorkRecord>> {
                get(&self.pool, id).await
            }

            async fn export_work(&self) -> SidResult<Vec<WorkSnapshot>> {
                export(&self.pool).await
            }

            async fn has_work_of_kind(&self, kind: &WorkKind) -> SidResult<bool> {
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM durable_work WHERE kind = $1)")
                    .bind(kind.as_str())
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| SidError::Storage(format!("work of a kind: {e}")))
            }

            async fn import_work(&self, work: &WorkSnapshot) -> SidResult<bool> {
                import(&self.pool, work).await
            }

            async fn purge_ended_work(
                &self,
                kind: &WorkKind,
                before: chrono::DateTime<chrono::Utc>,
            ) -> SidResult<u64> {
                sqlx::query(
                    "DELETE FROM durable_work
                     WHERE kind = $1 AND state NOT IN ('pending', 'claimed') AND updated_at < $2",
                )
                .bind(kind.as_str())
                .bind(before)
                .execute(&self.pool)
                .await
                .map(|done| done.rows_affected())
                .map_err(|e| SidError::Storage(format!("purge work: {e}")))
            }
        }
    };
}

work_store_over_pool!(PgWorkStore);
work_store_over_pool!(PostgresBackend);

/// Decode one column, naming it in the error.
fn col<'r, T>(row: &'r sqlx::postgres::PgRow, name: &str) -> SidResult<T>
where
    T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(name)
        .map_err(|e| SidError::Storage(format!("work column {name}: {e}")))
}

/// A stored non-negative count.
fn count(value: i32) -> SidResult<u32> {
    u32::try_from(value).map_err(|_| SidError::Storage(format!("negative count: {value}")))
}

#[cfg(test)]
mod tests;
