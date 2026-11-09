// SPDX-License-Identifier: AGPL-3.0-only
//! Durable work in CoordiNode: one `SidWork` node per item, claimed under a
//! lease and fenced by its claim generation. Enqueues of one kind serialize
//! on that kind's `SidWorkKind` node, so its open-item bound holds however
//! many writers enqueue at once; claims of one item conflict on its node.

use async_trait::async_trait;
use coordinode_core::graph::types::Value;
use sid_core::models::{
    ClaimedWork, NewWork, WorkFailure, WorkId, WorkKind, WorkRecord, WorkSnapshot, WorkState,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::WorkStore;

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, get_bool, get_bytes, get_int,
    get_opt_text, get_opt_time, get_text, get_time, opt_text, opt_time, time,
};

/// Every property of a work node, as `RETURN` lists them.
const FIELDS: &str = "w.id AS id, w.kind AS kind, w.payload AS payload, w.state AS state,
    w.attempts AS attempts, w.max_attempts AS max_attempts, w.generation AS generation,
    w.last_error AS last_error, w.ambiguous AS ambiguous, w.result AS result,
    w.not_before AS not_before, w.expires_at AS expires_at, w.created_at AS created_at,
    w.updated_at AS updated_at";

fn id_value(id: WorkId) -> Value {
    Value::Binary(id.0.as_bytes().to_vec())
}

fn kinds_value(kinds: &[WorkKind]) -> Value {
    Value::Array(
        kinds
            .iter()
            .map(|k| Value::String(k.as_str().to_owned()))
            .collect(),
    )
}

/// Store `work` in the open transaction `tx`. Returns `false` when work with
/// its id is stored already; refuses with `ResourceExhausted` when `capacity`
/// open items of its kind are stored.
pub(super) fn insert(tx: &Statements<'_>, work: &NewWork, capacity: u64) -> SidResult<bool> {
    // The same obligation again is already stored: accepted, whatever the load.
    let found = tx.run(
        "MATCH (w:SidWork) WHERE w.id = $id RETURN w.id AS id",
        Params::default().with("id", id_value(work.id)),
    )?;
    if !found.is_empty() {
        return Ok(false);
    }
    // Every enqueue of the kind writes its turn: concurrent ones conflict and
    // run again, so none counts room another has already taken.
    tx.run(
        "MERGE (k:SidWorkKind {kind: $kind}) SET k.turn = coalesce(k.turn, 0) + 1",
        Params::default().with("kind", Value::String(work.kind.as_str().to_owned())),
    )?;
    let open = tx.run(
        "MATCH (w:SidWork) WHERE w.kind = $kind AND w.state IN ['pending', 'claimed']
         RETURN count(w) AS n",
        Params::default().with("kind", Value::String(work.kind.as_str().to_owned())),
    )?;
    let open = open
        .first()
        .map(|row| get_int(row, "n"))
        .transpose()?
        .unwrap_or(0);
    if u64::try_from(open).unwrap_or(u64::MAX) >= capacity {
        return Err(SidError::ResourceExhausted(format!(
            "durable work queue full ({capacity} open items)"
        )));
    }
    if work.max_attempts == 0 {
        return Err(SidError::Validation("max_attempts out of range".into()));
    }
    let now = chrono::Utc::now();
    tx.run(
        "CREATE (w:SidWork {id: $id, kind: $kind, payload: $payload, state: 'pending',
            attempts: 0, max_attempts: $max_attempts, generation: 0, ambiguous: false,
            not_before: $not_before, expires_at: $expires_at, created_at: $now,
            updated_at: $now})",
        Params::default()
            .with("id", id_value(work.id))
            .with("kind", Value::String(work.kind.as_str().to_owned()))
            .with("payload", Value::Binary(work.payload.clone()))
            .with("max_attempts", Value::Int(i64::from(work.max_attempts)))
            .with("not_before", time(work.not_before.unwrap_or(now)))
            .with("expires_at", opt_time(work.expires_at))
            .with("now", time(now)),
    )?;
    Ok(true)
}

#[async_trait]
impl WorkStore for CoordinodeBackend {
    async fn enqueue_work(&self, work: &NewWork, capacity: u64) -> SidResult<bool> {
        let work = work.clone();
        self.transaction(move |tx| {
            let inserted = insert(tx, &work, capacity)?;
            Ok(if inserted {
                Decision::Commit(true)
            } else {
                Decision::Abandon(false)
            })
        })
        .await
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
        let lease = chrono::Duration::from_std(lease)
            .map_err(|_| SidError::Validation("lease out of range".into()))?;
        let kinds = kinds_value(kinds);
        let worker = worker.to_owned();
        self.transaction(move |tx| {
            let now = chrono::Utc::now();
            let at = |p: Params| p.with("kinds", kinds.clone()).with("now", time(now));
            // Past its validity: expired, never attempted again.
            tx.run(
                "MATCH (w:SidWork) WHERE w.kind IN $kinds AND w.state IN ['pending', 'claimed']
                   AND w.expires_at IS NOT NULL AND w.expires_at <= $now
                 SET w.state = 'expired', w.lease_owner = null, w.lease_until = null,
                     w.updated_at = $now",
                at(Params::default()),
            )?;
            // Abandoned by a worker on its last attempt: failed.
            tx.run(
                "MATCH (w:SidWork) WHERE w.kind IN $kinds AND w.state = 'claimed'
                   AND w.lease_until <= $now AND w.attempts >= w.max_attempts
                 SET w.state = 'failed', w.lease_owner = null, w.lease_until = null,
                     w.updated_at = $now,
                     w.last_error = coalesce(w.last_error, 'lease expired on the last attempt')",
                at(Params::default()),
            )?;
            // Due pending work and work whose lease ran out, asked apart: each
            // query compares only a property every work it matches holds.
            let limit_value = Value::Int(i64::from(limit));
            let mut due = tx.run(
                "MATCH (w:SidWork) WHERE w.kind IN $kinds AND w.state = 'pending'
                   AND w.not_before <= $now
                 RETURN w.id AS id, w.not_before AS not_before
                 ORDER BY w.not_before LIMIT $limit",
                at(Params::default()).with("limit", limit_value.clone()),
            )?;
            due.extend(tx.run(
                "MATCH (w:SidWork) WHERE w.kind IN $kinds AND w.state = 'claimed'
                   AND w.lease_until <= $now
                 RETURN w.id AS id, w.not_before AS not_before
                 ORDER BY w.not_before LIMIT $limit",
                at(Params::default()).with("limit", limit_value),
            )?);
            let mut order = Vec::with_capacity(due.len());
            for row in &due {
                order.push((get_int(row, "not_before")?, row));
            }
            order.sort_by_key(|(not_before, _)| *not_before);
            let due: Vec<&Row> = order
                .into_iter()
                .take(usize::try_from(limit).unwrap_or(usize::MAX))
                .map(|(_, row)| row)
                .collect();
            let mut claimed = Vec::with_capacity(due.len());
            for row in &due {
                let rows = tx.run(
                    &format!(
                        "MATCH (w:SidWork) WHERE w.id = $id
                         SET w.state = 'claimed', w.attempts = w.attempts + 1,
                             w.generation = w.generation + 1, w.lease_owner = $worker,
                             w.lease_until = $until, w.updated_at = $now
                         RETURN {FIELDS}"
                    ),
                    Params::default()
                        .with("id", Value::Binary(get_bytes(row, "id")?))
                        .with("worker", Value::String(worker.clone()))
                        .with("until", time(now + lease))
                        .with("now", time(now)),
                )?;
                let row = rows
                    .first()
                    .ok_or_else(|| SidError::Storage("claimed work vanished".into()))?;
                let record = record(row)?;
                claimed.push(ClaimedWork {
                    id: record.id,
                    kind: record.kind,
                    payload: get_bytes(row, "payload")?,
                    attempt: record.attempts,
                    max_attempts: record.max_attempts,
                    generation: record.generation,
                    expires_at: record.expires_at,
                });
            }
            // Committed even with nothing claimed: the expiry and abandonment
            // recorded above stand.
            Ok(Decision::Commit(claimed))
        })
        .await
    }

    async fn complete_work(
        &self,
        id: WorkId,
        generation: i64,
        result: Option<&str>,
    ) -> SidResult<bool> {
        let result = result.map(str::to_owned);
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (w:SidWork) WHERE w.id = $id AND w.generation = $generation
                   AND w.state = 'claimed'
                 SET w.state = 'completed', w.result = $result, w.lease_owner = null,
                     w.lease_until = null, w.updated_at = $now
                 RETURN w.id AS id",
                Params::default()
                    .with("id", id_value(id))
                    .with("generation", Value::Int(generation))
                    .with("result", opt_text(result.as_deref()))
                    .with("now", time(chrono::Utc::now())),
            )?;
            Ok(if rows.is_empty() {
                Decision::Abandon(false)
            } else {
                Decision::Commit(true)
            })
        })
        .await
    }

    async fn complete_work_owing(
        &self,
        id: WorkId,
        generation: i64,
        result: Option<&str>,
        owed: &[NewWork],
        capacity: u64,
    ) -> SidResult<bool> {
        let (result, owed) = (result.map(str::to_owned), owed.to_vec());
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (w:SidWork) WHERE w.id = $id AND w.generation = $generation
                   AND w.state = 'claimed'
                 SET w.state = 'completed', w.result = $result, w.lease_owner = null,
                     w.lease_until = null, w.updated_at = $now
                 RETURN w.id AS id",
                Params::default()
                    .with("id", id_value(id))
                    .with("generation", Value::Int(generation))
                    .with("result", opt_text(result.as_deref()))
                    .with("now", time(chrono::Utc::now())),
            )?;
            if rows.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            for work in &owed {
                insert(tx, work, capacity)?;
            }
            Ok(Decision::Commit(true))
        })
        .await
    }

    async fn fail_work(
        &self,
        id: WorkId,
        generation: i64,
        failure: &WorkFailure,
    ) -> SidResult<bool> {
        let failure = failure.clone();
        self.transaction(move |tx| {
            let current = tx.run(
                "MATCH (w:SidWork) WHERE w.id = $id AND w.generation = $generation
                   AND w.state = 'claimed'
                 RETURN w.attempts AS attempts, w.max_attempts AS max_attempts",
                Params::default()
                    .with("id", id_value(id))
                    .with("generation", Value::Int(generation)),
            )?;
            let Some(row) = current.first() else {
                return Ok(Decision::Abandon(false));
            };
            let dead = failure.retry_at.is_none()
                || get_int(row, "attempts")? >= get_int(row, "max_attempts")?;
            let state = if dead {
                WorkState::Failed
            } else {
                WorkState::Pending
            };
            tx.run(
                "MATCH (w:SidWork) WHERE w.id = $id
                 SET w.state = $state, w.not_before = coalesce($retry_at, w.not_before),
                     w.last_error = $error, w.ambiguous = $ambiguous, w.lease_owner = null,
                     w.lease_until = null, w.updated_at = $now",
                Params::default()
                    .with("id", id_value(id))
                    .with("state", Value::String(state.as_str().to_owned()))
                    .with("retry_at", opt_time(failure.retry_at))
                    .with("error", Value::String(failure.error.clone()))
                    .with("ambiguous", Value::Bool(failure.ambiguous))
                    .with("now", time(chrono::Utc::now())),
            )?;
            if dead && let Some(alert) = &failure.on_dead {
                // One alert per dead work, never refused for load: the failure
                // it reports is already recorded.
                insert(tx, alert, u64::MAX)?;
            }
            Ok(Decision::Commit(true))
        })
        .await
    }

    async fn get_work(&self, id: WorkId) -> SidResult<Option<WorkRecord>> {
        self.transaction(move |tx| {
            let rows = tx.run(
                &format!("MATCH (w:SidWork) WHERE w.id = $id RETURN {FIELDS}"),
                Params::default().with("id", id_value(id)),
            )?;
            Ok(Decision::Abandon(rows.first().map(record).transpose()?))
        })
        .await
    }

    async fn purge_ended_work(
        &self,
        kind: &WorkKind,
        before: chrono::DateTime<chrono::Utc>,
    ) -> SidResult<u64> {
        let kind = kind.as_str().to_owned();
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (w:SidWork) WHERE w.kind = $kind
                   AND NOT w.state IN ['pending', 'claimed'] AND w.updated_at < $before
                 DETACH DELETE w RETURN count(*) AS n",
                Params::default()
                    .with("kind", Value::String(kind.clone()))
                    .with("before", time(before)),
            )?;
            let dropped = rows
                .first()
                .map(|row| get_int(row, "n"))
                .transpose()?
                .unwrap_or(0);
            let dropped = u64::try_from(dropped)
                .map_err(|_| SidError::Storage(format!("bad purge count: {dropped}")))?;
            Ok(if dropped == 0 {
                Decision::Abandon(0)
            } else {
                Decision::Commit(dropped)
            })
        })
        .await
    }

    async fn has_work_of_kind(&self, kind: &WorkKind) -> SidResult<bool> {
        let kind = kind.as_str().to_owned();
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (w:SidWork) WHERE w.kind = $kind RETURN w.id AS id LIMIT 1",
                Params::default().with("kind", Value::String(kind.clone())),
            )?;
            Ok(Decision::Abandon(!rows.is_empty()))
        })
        .await
    }

    async fn export_work(&self) -> SidResult<Vec<WorkSnapshot>> {
        self.transaction(|tx| {
            let rows = tx.run(
                &format!("MATCH (w:SidWork) RETURN {FIELDS}"),
                Params::default(),
            )?;
            let work = rows
                .iter()
                .map(|row| {
                    Ok(WorkSnapshot {
                        record: record(row)?,
                        payload: get_bytes(row, "payload")?,
                    })
                })
                .collect::<SidResult<Vec<_>>>()?;
            Ok(Decision::Abandon(super::sorted_page(
                work,
                |w| (w.record.created_at, w.record.id.0),
                0,
                u64::MAX,
            )))
        })
        .await
    }

    async fn import_work(&self, work: &WorkSnapshot) -> SidResult<bool> {
        let record = work.at_rest();
        let payload = work.payload.clone();
        if record.max_attempts == 0 {
            return Err(SidError::Validation("max_attempts out of range".into()));
        }
        self.transaction(move |tx| {
            let found = tx.run(
                "MATCH (w:SidWork) WHERE w.id = $id RETURN w.id AS id",
                Params::default().with("id", id_value(record.id)),
            )?;
            if !found.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                "CREATE (w:SidWork {id: $id, kind: $kind, payload: $payload, state: $state,
                    attempts: $attempts, max_attempts: $max_attempts, generation: $generation,
                    last_error: $last_error, ambiguous: $ambiguous, result: $result,
                    not_before: $not_before, expires_at: $expires_at,
                    created_at: $created_at, updated_at: $updated_at})",
                Params::default()
                    .with("id", id_value(record.id))
                    .with("kind", Value::String(record.kind.as_str().to_owned()))
                    .with("payload", Value::Binary(payload.clone()))
                    .with("state", Value::String(record.state.as_str().to_owned()))
                    .with("attempts", Value::Int(i64::from(record.attempts)))
                    .with("max_attempts", Value::Int(i64::from(record.max_attempts)))
                    .with("generation", Value::Int(record.generation))
                    .with("last_error", opt_text(record.last_error.as_deref()))
                    .with("ambiguous", Value::Bool(record.ambiguous))
                    .with("result", opt_text(record.result.as_deref()))
                    .with("not_before", time(record.not_before))
                    .with("expires_at", opt_time(record.expires_at))
                    .with("created_at", time(record.created_at))
                    .with("updated_at", time(record.updated_at)),
            )?;
            Ok(Decision::Commit(true))
        })
        .await
    }
}

/// The work record `row` holds.
fn record(row: &Row) -> SidResult<WorkRecord> {
    let id = get_bytes(row, "id")?;
    let id =
        uuid::Uuid::from_slice(&id).map_err(|e| SidError::Storage(format!("bad work id: {e}")))?;
    Ok(WorkRecord {
        id: WorkId(id),
        kind: WorkKind::new(&get_text(row, "kind")?)?,
        state: WorkState::parse(&get_text(row, "state")?)?,
        attempts: count(get_int(row, "attempts")?)?,
        max_attempts: count(get_int(row, "max_attempts")?)?,
        generation: get_int(row, "generation")?,
        last_error: get_opt_text(row, "last_error")?,
        ambiguous: get_bool(row, "ambiguous")?,
        result: get_opt_text(row, "result")?,
        not_before: get_time(row, "not_before")?,
        expires_at: get_opt_time(row, "expires_at")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

/// A stored non-negative count.
fn count(value: i64) -> SidResult<u32> {
    u32::try_from(value).map_err(|_| SidError::Storage(format!("bad count: {value}")))
}
