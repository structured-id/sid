// SPDX-License-Identifier: AGPL-3.0-only
//! Durable work on PostgreSQL: enqueue inside the caller's transaction,
//! claims with `FOR UPDATE SKIP LOCKED` under a lease, outcomes fenced by
//! the claim generation.

use super::PostgresBackend;
use async_trait::async_trait;
use sid_core::models::{
    ClaimedWork, NewWork, WorkCompletion, WorkFailure, WorkId, WorkKind, WorkRecord, WorkSnapshot,
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
    /// all. For a host whose own tables live beside this work table.
    pub async fn owe_in_tx(tx: &mut PgConnection, works: &[NewWork]) -> SidResult<()> {
        insert_owed_work_in_tx(tx, works).await
    }
}

/// `works` as the column arrays [`INSERT_WORKS`] unnests, so any number of
/// items is one statement.
struct WorkRows<'a> {
    ids: Vec<uuid::Uuid>,
    kinds: Vec<&'a str>,
    payloads: Vec<&'a [u8]>,
    max_attempts: Vec<i32>,
    not_before: Vec<Option<chrono::DateTime<chrono::Utc>>>,
    expires_at: Vec<Option<chrono::DateTime<chrono::Utc>>>,
}

impl<'a> WorkRows<'a> {
    fn of(works: impl IntoIterator<Item = &'a NewWork>) -> SidResult<Self> {
        let works = works.into_iter();
        let n = works.size_hint().0;
        let mut rows = Self {
            ids: Vec::with_capacity(n),
            kinds: Vec::with_capacity(n),
            payloads: Vec::with_capacity(n),
            max_attempts: Vec::with_capacity(n),
            not_before: Vec::with_capacity(n),
            expires_at: Vec::with_capacity(n),
        };
        for work in works {
            rows.ids.push(work.id.0);
            rows.kinds.push(work.kind.as_str());
            rows.payloads.push(&work.payload);
            rows.max_attempts.push(
                i32::try_from(work.max_attempts)
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| SidError::Validation("max_attempts out of range".into()))?,
            );
            rows.not_before.push(work.not_before);
            rows.expires_at.push(work.expires_at);
        }
        Ok(rows)
    }

    /// Bind the arrays as `$1..$6`.
    fn bind<'q>(
        &'q self,
        query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    ) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
        query
            .bind(&self.ids)
            .bind(&self.kinds)
            .bind(&self.payloads)
            .bind(&self.max_attempts)
            .bind(&self.not_before)
            .bind(&self.expires_at)
    }
}

/// New work from the column arrays at `$1..$6`. Work whose id is already
/// stored is the same obligation again and is left as it is.
const INSERT_WORKS: &str =
    "INSERT INTO durable_work (id, kind, payload, max_attempts, not_before, expires_at)
     SELECT id, kind, payload, max_attempts, COALESCE(not_before, NOW()), expires_at
     FROM unnest($1::uuid[], $2::text[], $3::bytea[], $4::int[], $5::timestamptz[],
                 $6::timestamptz[]) AS w(id, kind, payload, max_attempts, not_before, expires_at)
     ON CONFLICT (id) DO NOTHING";

/// Store the work a business mutation owes inside its transaction `tx`.
pub(crate) async fn insert_owed_work_in_tx(
    tx: &mut PgConnection,
    works: &[NewWork],
) -> SidResult<()> {
    if works.is_empty() {
        return Ok(());
    }
    let rows = WorkRows::of(works)?;
    rows.bind(sqlx::query(INSERT_WORKS))
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("insert work: {e}")))?;
    Ok(())
}

async fn enqueue(pool: &PgPool, work: &NewWork) -> SidResult<bool> {
    let rows = WorkRows::of([work])?;
    let inserted = rows
        .bind(sqlx::query(INSERT_WORKS))
        .execute(pool)
        .await
        .map_err(|e| SidError::Storage(format!("enqueue work: {e}")))?
        .rows_affected();
    Ok(inserted == 1)
}

/// A claim's sweep of open work past its validity, through the expiry index.
const EXPIRE_SQL: &str = "UPDATE durable_work SET state = 'expired', lease_owner = NULL,
        lease_until = NULL, updated_at = NOW()
     WHERE kind = ANY($1) AND state IN ('pending', 'claimed')
       AND expires_at IS NOT NULL AND expires_at <= NOW()";

/// Whether a claim has anything to sweep: open work past its expiry or work
/// abandoned on its last attempt, asked through the sweeps' own indexes. One
/// read in the usual case instead of two updates finding nothing.
const SWEEP_DUE_SQL: &str = "SELECT EXISTS (SELECT 1 FROM durable_work
         WHERE kind = ANY($1) AND state IN ('pending', 'claimed')
           AND expires_at IS NOT NULL AND expires_at <= NOW())
     OR EXISTS (SELECT 1 FROM durable_work
         WHERE kind = ANY($1) AND state = 'claimed' AND lease_until <= NOW()
           AND attempts >= max_attempts)";

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
/// relation, the planner hashed the whole table to find 32 rows. Each
/// candidate is checked for its validity and, after a lapsed lease, for an
/// attempt left: work can cross either line after the sweeps ran, and the
/// claim reads a later clock than they did.
const CLAIM_SQL: &str = "UPDATE durable_work w SET state = 'claimed', attempts = w.attempts + 1,
        generation = w.generation + 1, lease_owner = $2,
        lease_until = NOW() + make_interval(secs => $3), updated_at = NOW()
     WHERE w.id = ANY (ARRAY(SELECT c.id FROM (
           SELECT due.id, due.not_before FROM unnest($1::text[]) k(kind)
           CROSS JOIN LATERAL (SELECT id, not_before FROM durable_work
               WHERE kind = k.kind AND state = 'pending' AND not_before <= NOW()
                 AND (expires_at IS NULL OR expires_at > NOW())
               ORDER BY not_before LIMIT $4 FOR UPDATE SKIP LOCKED) due
           UNION ALL
           SELECT lapsed.id, lapsed.not_before FROM unnest($1::text[]) k(kind)
           CROSS JOIN LATERAL (SELECT id, not_before FROM durable_work
               WHERE kind = k.kind AND state = 'claimed' AND lease_until <= NOW()
                 AND attempts < max_attempts
                 AND (expires_at IS NULL OR expires_at > NOW())
               ORDER BY lease_until LIMIT $4 FOR UPDATE SKIP LOCKED) lapsed
         ) c
         ORDER BY c.not_before
         LIMIT $4))
     RETURNING w.id, w.kind, w.payload, w.attempts, w.max_attempts,
        w.generation, w.expires_at, w.created_at, w.not_before";

/// Each statement commits on its own: a sweep only ends work that is already
/// over, so it needs nothing in common with the claim that follows it.
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
    let sweep: bool = sqlx::query_scalar(SWEEP_DUE_SQL)
        .bind(&kinds)
        .fetch_one(pool)
        .await
        .map_err(storage)?;
    if sweep {
        // Past its validity: expired, never attempted again.
        sqlx::query(EXPIRE_SQL)
            .bind(&kinds)
            .execute(pool)
            .await
            .map_err(storage)?;
        // Abandoned by a worker on its last attempt: failed.
        sqlx::query(ABANDONED_SQL)
            .bind(&kinds)
            .execute(pool)
            .await
            .map_err(storage)?;
    }
    let rows = sqlx::query(CLAIM_SQL)
        .bind(&kinds)
        .bind(worker)
        .bind(lease.as_secs_f64())
        .bind(i64::from(limit))
        .fetch_all(pool)
        .await
        .map_err(storage)?;
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
                created_at: col(row, "created_at")?,
                due_at: col(row, "not_before")?,
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

/// The completion and the work it owes as one statement: the children are
/// inserted only when the current claim completed, and both commit together.
const COMPLETE_OWING_SQL: &str = "WITH done AS (
         UPDATE durable_work SET state = 'completed', result = $9, lease_owner = NULL,
             lease_until = NULL, updated_at = NOW()
         WHERE id = $7 AND generation = $8 AND state = 'claimed'
         RETURNING id),
     owed AS (
         INSERT INTO durable_work (id, kind, payload, max_attempts, not_before, expires_at)
         SELECT id, kind, payload, max_attempts, COALESCE(not_before, NOW()), expires_at
         FROM unnest($1::uuid[], $2::text[], $3::bytea[], $4::int[], $5::timestamptz[],
                     $6::timestamptz[]) AS w(id, kind, payload, max_attempts, not_before, expires_at)
         WHERE EXISTS (SELECT 1 FROM done)
         ON CONFLICT (id) DO NOTHING)
     SELECT EXISTS (SELECT 1 FROM done)";

async fn complete_owing(
    pool: &PgPool,
    id: WorkId,
    generation: i64,
    result: Option<&str>,
    owed: &[NewWork],
) -> SidResult<bool> {
    let rows = WorkRows::of(owed)?;
    rows.bind(sqlx::query(COMPLETE_OWING_SQL))
        .bind(id.0)
        .bind(generation)
        .bind(result)
        .fetch_one(pool)
        .await
        .and_then(|row| row.try_get::<bool, _>(0))
        .map_err(|e| SidError::Storage(format!("complete work: {e}")))
}

/// Several completions and the work they owe as one statement: each item is
/// fenced by its own claim, and an owed child is inserted only when the claim
/// it came with completed. A batch may hold a lapsed claim and the claim that
/// took the same work over, so items are told apart by id and generation.
/// Returns the claims that completed.
const COMPLETE_MANY_SQL: &str = "WITH done AS (
         UPDATE durable_work w SET state = 'completed', result = c.result, lease_owner = NULL,
             lease_until = NULL, updated_at = NOW()
         FROM unnest($9::uuid[], $10::bigint[], $11::text[]) AS c(id, generation, result)
         WHERE w.id = c.id AND w.generation = c.generation AND w.state = 'claimed'
         RETURNING c.id, c.generation),
     owed AS (
         INSERT INTO durable_work (id, kind, payload, max_attempts, not_before, expires_at)
         SELECT o.id, o.kind, o.payload, o.max_attempts, COALESCE(o.not_before, NOW()),
             o.expires_at
         FROM unnest($1::uuid[], $2::text[], $3::bytea[], $4::int[], $5::timestamptz[],
                     $6::timestamptz[], $7::uuid[], $8::bigint[])
             AS o(id, kind, payload, max_attempts, not_before, expires_at, parent, parent_generation)
         JOIN done ON done.id = o.parent AND done.generation = o.parent_generation
         ON CONFLICT (id) DO NOTHING)
     SELECT id, generation FROM done";

async fn complete_many(pool: &PgPool, works: &[WorkCompletion]) -> SidResult<Vec<bool>> {
    if works.is_empty() {
        return Ok(Vec::new());
    }
    let owed = WorkRows::of(works.iter().flat_map(|w| &w.owed))?;
    let (parents, parent_generations): (Vec<uuid::Uuid>, Vec<i64>) = works
        .iter()
        .flat_map(|w| w.owed.iter().map(|_| (w.id.0, w.generation)))
        .unzip();
    let ids: Vec<uuid::Uuid> = works.iter().map(|w| w.id.0).collect();
    let generations: Vec<i64> = works.iter().map(|w| w.generation).collect();
    let results: Vec<Option<&str>> = works.iter().map(|w| w.result.as_deref()).collect();
    let storage = |e: sqlx::Error| SidError::Storage(format!("complete work: {e}"));
    let rows = owed
        .bind(sqlx::query(COMPLETE_MANY_SQL))
        .bind(&parents)
        .bind(&parent_generations)
        .bind(&ids)
        .bind(&generations)
        .bind(&results)
        .fetch_all(pool)
        .await
        .map_err(storage)?;
    let done = rows
        .iter()
        .map(|row| Ok((row.try_get::<uuid::Uuid, _>(0)?, row.try_get::<i64, _>(1)?)))
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(storage)?;
    // A batch is bounded by the runner's slots, so a scan stays short.
    Ok(works
        .iter()
        .map(|w| done.contains(&(w.id.0, w.generation)))
        .collect())
}

/// A failed attempt and its dead-letter alert as one statement: the alert is
/// inserted only when this attempt ended the work as failed.
const FAIL_SQL: &str = "WITH failed AS (
         UPDATE durable_work SET
             state = CASE WHEN $10::timestamptz IS NULL OR attempts >= max_attempts
                          THEN 'failed' ELSE 'pending' END,
             not_before = COALESCE($10, not_before), last_error = $9, ambiguous = $11,
             lease_owner = NULL, lease_until = NULL, updated_at = NOW()
         WHERE id = $7 AND generation = $8 AND state = 'claimed'
         RETURNING state),
     alert AS (
         INSERT INTO durable_work (id, kind, payload, max_attempts, not_before, expires_at)
         SELECT id, kind, payload, max_attempts, COALESCE(not_before, NOW()), expires_at
         FROM unnest($1::uuid[], $2::text[], $3::bytea[], $4::int[], $5::timestamptz[],
                     $6::timestamptz[]) AS w(id, kind, payload, max_attempts, not_before, expires_at)
         WHERE EXISTS (SELECT 1 FROM failed WHERE state = 'failed')
         ON CONFLICT (id) DO NOTHING)
     SELECT EXISTS (SELECT 1 FROM failed)";

async fn fail(
    pool: &PgPool,
    id: WorkId,
    generation: i64,
    failure: &WorkFailure,
) -> SidResult<bool> {
    // One alert per dead work: the failure it reports is already recorded.
    let rows = WorkRows::of(failure.on_dead.iter())?;
    rows.bind(sqlx::query(FAIL_SQL))
        .bind(id.0)
        .bind(generation)
        .bind(&failure.error)
        .bind(failure.retry_at)
        .bind(failure.ambiguous)
        .fetch_one(pool)
        .await
        .and_then(|row| row.try_get::<bool, _>(0))
        .map_err(|e| SidError::Storage(format!("fail work: {e}")))
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
        state: sid_core::models::WorkState::parse(col(row, "state")?)?,
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
            async fn enqueue_work(&self, work: &NewWork) -> SidResult<bool> {
                enqueue(&self.pool, work).await
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
            ) -> SidResult<bool> {
                complete_owing(&self.pool, id, generation, result, owed).await
            }

            async fn complete_works(&self, works: &[WorkCompletion]) -> SidResult<Vec<bool>> {
                complete_many(&self.pool, works).await
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
