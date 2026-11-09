// SPDX-License-Identifier: AGPL-3.0-only
//! Completions of keyed commands in CoordiNode, committed with their effect,
//! and the periods they are admitted under.
//!
//! One `SidOperation` node per command key holds both its completion and the
//! identifier a keyed creation bound to it, so every writer of a key writes
//! that node and concurrent ones conflict. A command admitted under a period
//! holds the period's node rather than writing it: commands of one period do
//! not wait for each other, and retiring the period refuses each one still
//! in flight. Retirement marks a period first and then drops what it held,
//! from a snapshot every admitted command has committed into; a completion
//! under a retired period reads as absent from the mark on.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use coordinode_core::graph::types::Value;
use sid_core::models::{
    IssuedOperationPeriod, MutationContext, OperationCompletion, OperationKey, OperationPeriod,
    OperationPeriodPolicy, OperationPeriodRecord, OperationPeriodRefusal, OperationPeriodState,
    OperationRecord, OperationResourceBinding,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::OperationResultStore;
use uuid::Uuid;

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, get_bool, get_bytes, get_int,
    get_opt_bytes, get_opt_int, get_text, get_time, opt_time, time,
};

/// The store's period state: the last period issued and the policy.
const STATE: &str = "MATCH (s:SidOperationState) WHERE s.id = 1
    RETURN s.issued_through AS issued_through, s.acceptance_seconds AS acceptance,
           s.retention_seconds AS retention, s.capacity AS capacity,
           s.result_bytes AS result_bytes";

/// Every property of a key's node, as `RETURN` lists them.
const FIELDS: &str = "o.slot AS slot, o.namespace AS namespace, o.key AS key,
    o.completed AS completed, o.c_method AS c_method, o.c_fingerprint AS c_fingerprint,
    o.c_result AS c_result, o.c_at AS c_at, o.c_period AS c_period, o.c_retain AS c_retain,
    o.bound AS bound, o.b_method AS b_method, o.b_fingerprint AS b_fingerprint,
    o.b_period AS b_period, o.b_resource AS b_resource, o.b_at AS b_at";

/// Create the period state of an empty store: nothing issued yet, commands
/// accepted for an hour, completions kept a day after, at most 100000 of
/// them per period and 64 KiB per result.
pub(super) fn init_state(tx: &Statements<'_>) -> SidResult<Decision<()>> {
    if let Some(row) = tx.run(STATE, Params::default())?.first() {
        // A store written before the policy held its bounds lacks them, and
        // its periods their counts: refused at opening, not at a commit.
        if get_opt_int(row, "capacity")?.is_none() || get_opt_int(row, "result_bytes")?.is_none() {
            return Err(SidError::Storage(
                "the operation period state predates this schema; the store must be recreated"
                    .into(),
            ));
        }
        return Ok(Decision::Abandon(()));
    }
    tx.run(
        "CREATE (s:SidOperationState {id: 1, issued_through: 0, acceptance_seconds: 3600,
            retention_seconds: 86400, capacity: 100000, result_bytes: 65536})",
        Params::default(),
    )?;
    Ok(Decision::Commit(()))
}

fn slot(namespace: &str, key: &OperationKey) -> SidResult<Vec<u8>> {
    super::slot(namespace, key.as_str())
}

/// `period` as its stored integer.
fn column(period: OperationPeriod) -> SidResult<i64> {
    i64::try_from(period.get())
        .map_err(|_| SidError::OperationPeriodRefused(OperationPeriodRefusal::NotIssued))
}

fn period_of(value: i64) -> SidResult<OperationPeriod> {
    u64::try_from(value)
        .map(OperationPeriod::new)
        .map_err(|_| SidError::Storage(format!("bad operation period: {value}")))
}

fn opt_period(period: Option<OperationPeriod>) -> SidResult<Value> {
    Ok(period
        .map(column)
        .transpose()?
        .map_or(Value::Null, Value::Int))
}

fn opt_bytes(bytes: Option<&[u8]>) -> Value {
    bytes.map_or(Value::Null, |b| Value::Binary(b.to_vec()))
}

/// What one key holds.
struct Entry {
    slot: Vec<u8>,
    namespace: String,
    key: OperationKey,
    /// Whether its node is stored.
    stored: bool,
    completion: Option<OperationRecord>,
    /// The bound identifier and when it was bound.
    binding: Option<(OperationResourceBinding, DateTime<Utc>)>,
}

impl Entry {
    fn empty(namespace: &str, key: &OperationKey) -> SidResult<Self> {
        Ok(Self {
            slot: slot(namespace, key)?,
            namespace: namespace.to_owned(),
            key: key.clone(),
            stored: false,
            completion: None,
            binding: None,
        })
    }
}

/// The entry `row` holds.
fn entry(row: &Row) -> SidResult<Entry> {
    let namespace = get_text(row, "namespace")?;
    let key = OperationKey::parse(&get_text(row, "key")?)
        .map_err(|e| SidError::Storage(format!("stored operation key: {e}")))?;
    let completion = if get_bool(row, "completed")? {
        Some(OperationRecord {
            completion: OperationCompletion {
                namespace: namespace.clone(),
                key: key.clone(),
                method: get_text(row, "c_method")?,
                fingerprint: get_bytes(row, "c_fingerprint")?,
                result: get_bytes(row, "c_result")?,
                period: get_opt_int(row, "c_period")?.map(period_of).transpose()?,
                retain_until: get_opt_int(row, "c_retain")?
                    .map(|_| super::get_time(row, "c_retain"))
                    .transpose()?,
            },
            completed_at: get_time(row, "c_at")?,
        })
    } else {
        None
    };
    let binding = if get_bool(row, "bound")? {
        let resource = get_opt_bytes(row, "b_resource")?
            .ok_or_else(|| SidError::Storage("binding without its identifier".into()))?;
        Some((
            OperationResourceBinding {
                namespace: namespace.clone(),
                key: key.clone(),
                method: get_text(row, "b_method")?,
                fingerprint: get_bytes(row, "b_fingerprint")?,
                period: get_opt_int(row, "b_period")?.map(period_of).transpose()?,
                resource: Uuid::from_slice(&resource)
                    .map_err(|e| SidError::Storage(format!("bound identifier: {e}")))?,
            },
            get_time(row, "b_at")?,
        ))
    } else {
        None
    };
    Ok(Entry {
        slot: get_bytes(row, "slot")?,
        namespace,
        key,
        stored: true,
        completion,
        binding,
    })
}

/// What `key` in `namespace` holds, as stored.
fn load(tx: &Statements<'_>, namespace: &str, key: &OperationKey) -> SidResult<Entry> {
    let mut found = Entry::empty(namespace, key)?;
    let rows = tx.run(
        &format!("MATCH (o:SidOperation) WHERE o.slot = $slot RETURN {FIELDS}"),
        Params::default().with("slot", Value::Binary(found.slot.clone())),
    )?;
    if let Some(row) = rows.first() {
        found = entry(row)?;
    }
    Ok(found)
}

/// Store `entry`: its node goes when it holds nothing.
fn save(tx: &Statements<'_>, entry: &Entry) -> SidResult<()> {
    let slot = Value::Binary(entry.slot.clone());
    if entry.completion.is_none() && entry.binding.is_none() {
        if entry.stored {
            tx.run(
                "MATCH (o:SidOperation) WHERE o.slot = $slot DETACH DELETE o",
                Params::default().with("slot", slot),
            )?;
        }
        return Ok(());
    }
    let c = entry.completion.as_ref();
    let b = entry.binding.as_ref();
    let params = Params::default()
        .with("slot", slot)
        .with("namespace", Value::String(entry.namespace.clone()))
        .with("key", Value::String(entry.key.as_str().to_owned()))
        .with("completed", Value::Bool(c.is_some()))
        .with(
            "c_method",
            c.map_or(Value::Null, |c| Value::String(c.completion.method.clone())),
        )
        .with(
            "c_fingerprint",
            opt_bytes(c.map(|c| c.completion.fingerprint.as_slice())),
        )
        .with(
            "c_result",
            opt_bytes(c.map(|c| c.completion.result.as_slice())),
        )
        .with("c_at", opt_time(c.map(|c| c.completed_at)))
        .with("c_period", opt_period(c.and_then(|c| c.completion.period))?)
        .with(
            "c_retain",
            opt_time(c.and_then(|c| c.completion.retain_until)),
        )
        .with("bound", Value::Bool(b.is_some()))
        .with(
            "b_method",
            b.map_or(Value::Null, |(b, _)| Value::String(b.method.clone())),
        )
        .with(
            "b_fingerprint",
            opt_bytes(b.map(|(b, _)| b.fingerprint.as_slice())),
        )
        .with("b_period", opt_period(b.and_then(|(b, _)| b.period))?)
        .with(
            "b_resource",
            opt_bytes(b.map(|(b, _)| b.resource.as_bytes().as_slice())),
        )
        .with("b_at", opt_time(b.map(|(_, at)| *at)));
    let query = if entry.stored {
        "MATCH (o:SidOperation) WHERE o.slot = $slot
         SET o.completed = $completed, o.c_method = $c_method,
             o.c_fingerprint = $c_fingerprint, o.c_result = $c_result, o.c_at = $c_at,
             o.c_period = $c_period, o.c_retain = $c_retain, o.bound = $bound,
             o.b_method = $b_method, o.b_fingerprint = $b_fingerprint,
             o.b_period = $b_period, o.b_resource = $b_resource, o.b_at = $b_at"
    } else {
        "CREATE (o:SidOperation {slot: $slot, namespace: $namespace, key: $key,
            completed: $completed, c_method: $c_method, c_fingerprint: $c_fingerprint,
            c_result: $c_result, c_at: $c_at, c_period: $c_period, c_retain: $c_retain,
            bound: $bound, b_method: $b_method, b_fingerprint: $b_fingerprint,
            b_period: $b_period, b_resource: $b_resource, b_at: $b_at})"
    };
    tx.run(query, params)?;
    Ok(())
}

/// Whether periods are still admitted, asked once per period per call.
#[derive(Default)]
struct Admitted(HashMap<OperationPeriod, bool>);

impl Admitted {
    fn get(&mut self, tx: &Statements<'_>, period: OperationPeriod) -> SidResult<bool> {
        if let Some(admitted) = self.0.get(&period) {
            return Ok(*admitted);
        }
        let admitted = !tx
            .run(
                "MATCH (p:SidOperationPeriod) WHERE p.period = $period AND p.retired = false
                 RETURN p.period AS period",
                Params::default().with("period", Value::Int(column(period)?)),
            )?
            .is_empty();
        self.0.insert(period, admitted);
        Ok(admitted)
    }
}

/// `entry` as it stands at `now`: a completion past its retention no longer
/// holds the key and takes its binding with it; one under a retired period
/// goes, with the binding its creation made under that period.
fn settle(
    tx: &Statements<'_>,
    entry: &mut Entry,
    now: DateTime<Utc>,
    admitted: &mut Admitted,
) -> SidResult<()> {
    let Some(record) = &entry.completion else {
        return Ok(());
    };
    if record
        .completion
        .retain_until
        .is_some_and(|until| until <= now)
    {
        entry.completion = None;
        entry.binding = None;
        return Ok(());
    }
    if let Some(period) = record.completion.period
        && !admitted.get(tx, period)?
    {
        entry.completion = None;
        if entry
            .binding
            .as_ref()
            .is_some_and(|(b, _)| b.period == Some(period))
        {
            entry.binding = None;
        }
    }
    Ok(())
}

/// Admit `period` for the open transaction: it commits only while the
/// period stays admitted. Refused as retired when its number was issued,
/// else as never issued.
fn admit(tx: &Statements<'_>, period: OperationPeriod) -> SidResult<()> {
    let number = column(period)?;
    let rows = tx.run(
        "MATCH (p:SidOperationPeriod) WHERE p.period = $period
         RETURN id(p) AS node, p.retired AS retired",
        Params::default().with("period", Value::Int(number)),
    )?;
    let refusal = match rows.first() {
        Some(row) => {
            if !get_bool(row, "retired")? && tx.hold(get_int(row, "node")?)? {
                return Ok(());
            }
            OperationPeriodRefusal::Retired
        }
        None if number <= issued_through(tx)? => OperationPeriodRefusal::Retired,
        None => OperationPeriodRefusal::NotIssued,
    };
    Err(SidError::OperationPeriodRefused(refusal))
}

/// The last period issued; a store without its state has lost it and
/// admits nothing rather than starting over.
fn issued_through(tx: &Statements<'_>) -> SidResult<i64> {
    let rows = tx.run(STATE, Params::default())?;
    let row = rows
        .first()
        .ok_or_else(|| SidError::Storage("operation period state missing".into()))?;
    get_int(row, "issued_through")
}

/// The stored limits of the policy: completions per period, bytes per result.
fn limits(tx: &Statements<'_>) -> SidResult<(i64, i64)> {
    let rows = tx.run(STATE, Params::default())?;
    let row = rows
        .first()
        .ok_or_else(|| SidError::Storage("operation period state missing".into()))?;
    Ok((get_int(row, "capacity")?, get_int(row, "result_bytes")?))
}

/// Count a completion into admitted `period`: the write to its node makes
/// concurrent commits under it, and its retirement mark, conflict and run
/// again, so the count never passes `capacity`.
fn take_place(tx: &Statements<'_>, period: OperationPeriod, capacity: i64) -> SidResult<()> {
    let number = column(period)?;
    let rows = tx.run(
        "MATCH (p:SidOperationPeriod) WHERE p.period = $period
         RETURN p.retired AS retired, p.recorded AS recorded",
        Params::default().with("period", Value::Int(number)),
    )?;
    let Some(row) = rows.first() else {
        return Err(SidError::OperationPeriodRefused(
            if number <= issued_through(tx)? {
                OperationPeriodRefusal::Retired
            } else {
                OperationPeriodRefusal::NotIssued
            },
        ));
    };
    if get_bool(row, "retired")? {
        return Err(SidError::OperationPeriodRefused(
            OperationPeriodRefusal::Retired,
        ));
    }
    let recorded = get_int(row, "recorded")?;
    if recorded >= capacity {
        return Err(SidError::ResourceExhausted(format!(
            "operation period full ({capacity} completions)"
        )));
    }
    tx.run(
        "MATCH (p:SidOperationPeriod) WHERE p.period = $period SET p.recorded = $recorded",
        Params::default()
            .with("period", Value::Int(number))
            .with("recorded", Value::Int(recorded + 1)),
    )?;
    Ok(())
}

/// Record `operation` in the open transaction `tx`. A key completed already
/// commits nothing: `OperationCompleted`. A key a creation bound completes
/// only that creation's command: another is refused as `OperationKeyReused`.
/// A result larger than the policy keeps, or a full period, is
/// `ResourceExhausted`.
pub(super) fn record(tx: &Statements<'_>, operation: &OperationCompletion) -> SidResult<()> {
    let (capacity, limit) = limits(tx)?;
    // The period's admission comes first, as for every commit; its own write
    // stands for the hold another commit takes.
    if let Some(period) = operation.period
        && let Err(e) = take_place(tx, period, capacity)
    {
        // A completed key answers as completed, full period or not.
        if matches!(e, SidError::ResourceExhausted(_)) {
            let mut entry = load(tx, &operation.namespace, &operation.key)?;
            settle(tx, &mut entry, Utc::now(), &mut Admitted::default())?;
            if entry.completion.is_some() {
                return Err(SidError::OperationCompleted(operation.key.as_str().into()));
            }
        }
        return Err(e);
    }
    if i64::try_from(operation.result.len()).unwrap_or(i64::MAX) > limit {
        return Err(SidError::ResourceExhausted(format!(
            "operation result larger than {limit} bytes"
        )));
    }
    let now = Utc::now();
    let mut entry = load(tx, &operation.namespace, &operation.key)?;
    settle(tx, &mut entry, now, &mut Admitted::default())?;
    if let Some((bound, _)) = &entry.binding
        && (bound.method != operation.method
            || bound.fingerprint != operation.fingerprint
            || bound.period != operation.period)
    {
        return Err(SidError::OperationKeyReused(operation.key.as_str().into()));
    }
    if entry.completion.is_some() {
        return Err(SidError::OperationCompleted(operation.key.as_str().into()));
    }
    entry.completion = Some(OperationRecord {
        completion: operation.clone(),
        completed_at: now,
    });
    save(tx, &entry)
}

/// Drop what retired `period` held: its completions, and the bindings its
/// completed creations made under it; an unfinished creation's binding is
/// kept to reconcile what it began. Then the period itself.
fn drop_retired(tx: &Statements<'_>, period: i64) -> SidResult<()> {
    let params = || Params::default().with("period", Value::Int(period));
    let mut slots: Vec<Vec<u8>> = Vec::new();
    for query in [
        "MATCH (o:SidOperation) WHERE o.completed = true AND o.c_period = $period
         RETURN o.slot AS slot",
        "MATCH (o:SidOperation) WHERE o.bound = true AND o.b_period = $period
           AND o.completed = true
         RETURN o.slot AS slot",
    ] {
        for row in tx.run(query, params())? {
            let slot = get_bytes(&row, "slot")?;
            if !slots.contains(&slot) {
                slots.push(slot);
            }
        }
    }
    let retired = Some(period_of(period)?);
    for slot in slots {
        let rows = tx.run(
            &format!("MATCH (o:SidOperation) WHERE o.slot = $slot RETURN {FIELDS}"),
            Params::default().with("slot", Value::Binary(slot)),
        )?;
        let Some(row) = rows.first() else { continue };
        let mut entry = entry(row)?;
        if entry.completion.is_some()
            && entry
                .binding
                .as_ref()
                .is_some_and(|(b, _)| b.period == retired)
        {
            entry.binding = None;
        }
        if entry
            .completion
            .as_ref()
            .is_some_and(|c| c.completion.period == retired)
        {
            entry.completion = None;
        }
        save(tx, &entry)?;
    }
    tx.run(
        "MATCH (p:SidOperationPeriod) WHERE p.period = $period DETACH DELETE p",
        params(),
    )?;
    Ok(())
}

/// A stored policy duration; a negative one is an error.
fn seconds(name: &str, value: i64) -> SidResult<Duration> {
    Duration::try_seconds(value)
        .filter(|d| *d >= Duration::zero())
        .ok_or_else(|| SidError::Storage(format!("{name}: {value}")))
}

/// A stored positive bound.
fn bound(name: &str, value: i64) -> SidResult<u64> {
    u64::try_from(value)
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| SidError::Storage(format!("{name}: {value}")))
}

/// The issued period `row` holds.
fn issued(row: &Row) -> SidResult<IssuedOperationPeriod> {
    Ok(IssuedOperationPeriod {
        period: period_of(get_int(row, "period")?)?,
        accepted_until: get_time(row, "accepted_until")?,
    })
}

impl CoordinodeBackend {
    /// Drop what every marked period held, after the mark committed: each
    /// command admitted under one either committed before the mark, and so
    /// into this snapshot, or was refused.
    async fn drop_marked_periods(&self) -> SidResult<()> {
        self.transaction(|tx| {
            let marked = tx.run(
                "MATCH (p:SidOperationPeriod) WHERE p.retired = true RETURN p.period AS period",
                Params::default(),
            )?;
            if marked.is_empty() {
                return Ok(Decision::Abandon(()));
            }
            for row in &marked {
                drop_retired(tx, get_int(row, "period")?)?;
            }
            Ok(Decision::Commit(()))
        })
        .await
    }
}

#[async_trait]
impl OperationResultStore for CoordinodeBackend {
    async fn operation_period_policy(&self) -> SidResult<OperationPeriodPolicy> {
        self.transaction(|tx| {
            let rows = tx.run(STATE, Params::default())?;
            let row = rows
                .first()
                .ok_or_else(|| SidError::Storage("operation period state missing".into()))?;
            Ok(Decision::Abandon(OperationPeriodPolicy {
                acceptance: seconds("acceptance", get_int(row, "acceptance")?)?,
                retention: seconds("retention", get_int(row, "retention")?)?,
                capacity: bound("capacity", get_int(row, "capacity")?)?,
                result_bytes: bound("result_bytes", get_int(row, "result_bytes")?)?,
            }))
        })
        .await
    }

    async fn current_operation_period(
        &self,
        now: DateTime<Utc>,
        acceptance: Duration,
    ) -> SidResult<IssuedOperationPeriod> {
        let until = now
            .checked_add_signed(acceptance)
            .map(super::stored_time)
            .ok_or_else(|| {
                SidError::Validation("operation period acceptance out of range".into())
            })?;
        self.transaction(move |tx| {
            let current = tx.run(
                "MATCH (p:SidOperationPeriod) WHERE p.retired = false AND p.issued_at <= $now
                   AND p.accepted_until > $now
                 RETURN p.period AS period, p.accepted_until AS accepted_until
                 ORDER BY p.period DESC LIMIT 1",
                Params::default().with("now", time(now)),
            )?;
            if let Some(row) = current.first() {
                return Ok(Decision::Abandon(issued(row)?));
            }
            // The next period follows every one ever issued, so a retired
            // number is never admitted again. Concurrent issuers both write
            // the state and conflict: the one run again finds this period.
            let next = issued_through(tx)?
                .checked_add(1)
                .ok_or_else(|| SidError::Storage("operation periods exhausted".into()))?;
            tx.run(
                "MATCH (s:SidOperationState) WHERE s.id = 1 SET s.issued_through = $next",
                Params::default().with("next", Value::Int(next)),
            )?;
            tx.run(
                "CREATE (p:SidOperationPeriod {period: $next, issued_at: $now,
                    accepted_until: $until, retired: false, recorded: 0})",
                Params::default()
                    .with("next", Value::Int(next))
                    .with("now", time(now))
                    .with("until", time(until)),
            )?;
            Ok(Decision::Commit(IssuedOperationPeriod {
                period: period_of(next)?,
                accepted_until: until,
            }))
        })
        .await
    }

    async fn admit_operation_period(&self, period: OperationPeriod) -> SidResult<()> {
        self.transaction(move |tx| admit(tx, period).map(Decision::Abandon))
            .await
    }

    async fn retire_operation_periods(&self, before: DateTime<Utc>) -> SidResult<u64> {
        let marked = self
            .transaction(move |tx| {
                let rows = tx.run(
                    "MATCH (p:SidOperationPeriod) WHERE p.retired = false
                       AND p.accepted_until < $before
                     SET p.retired = true RETURN p.period AS period",
                    Params::default().with("before", time(before)),
                )?;
                let marked = rows.len() as u64;
                Ok(if marked == 0 {
                    Decision::Abandon(0)
                } else {
                    Decision::Commit(marked)
                })
            })
            .await?;
        // Also finishes a retirement an earlier call marked and never ended.
        self.drop_marked_periods().await?;
        Ok(marked)
    }

    async fn export_operation_periods(&self) -> SidResult<OperationPeriodState> {
        self.transaction(|tx| {
            let last = issued_through(tx)?;
            let rows = tx.run(
                "MATCH (p:SidOperationPeriod) WHERE p.retired = false
                 RETURN p.period AS period, p.issued_at AS issued_at,
                        p.accepted_until AS accepted_until
                 ORDER BY p.period",
                Params::default(),
            )?;
            let active = rows
                .iter()
                .map(|row| {
                    Ok(OperationPeriodRecord {
                        issued: issued(row)?,
                        issued_at: get_time(row, "issued_at")?,
                    })
                })
                .collect::<SidResult<_>>()?;
            Ok(Decision::Abandon(OperationPeriodState {
                issued_through: period_of(last)?,
                active,
            }))
        })
        .await
    }

    async fn import_operation_periods(&self, state: &OperationPeriodState) -> SidResult<()> {
        let state = state.clone();
        self.transaction(move |tx| {
            let last = issued_through(tx)?;
            let source_last = column(state.issued_through)?;
            let source_active = state
                .active
                .iter()
                .map(|p| column(p.issued.period))
                .collect::<SidResult<Vec<i64>>>()?;
            // Retired at the source: issued there, no longer admitted there.
            let local = tx.run(
                "MATCH (p:SidOperationPeriod) WHERE p.retired = false RETURN p.period AS period",
                Params::default(),
            )?;
            for row in &local {
                let period = get_int(row, "period")?;
                if period <= source_last && !source_active.contains(&period) {
                    tx.run(
                        "MATCH (p:SidOperationPeriod) WHERE p.period = $period
                         SET p.retired = true",
                        Params::default().with("period", Value::Int(period)),
                    )?;
                }
            }
            for (record, &period) in state.active.iter().zip(&source_active) {
                // A period this store issued and no longer holds is retired here.
                if period <= last {
                    continue;
                }
                tx.run(
                    "CREATE (p:SidOperationPeriod {period: $period, issued_at: $issued_at,
                        accepted_until: $until, retired: false, recorded: 0})",
                    Params::default()
                        .with("period", Value::Int(period))
                        .with("issued_at", time(record.issued_at))
                        .with("until", time(record.issued.accepted_until)),
                )?;
            }
            tx.run(
                "MATCH (s:SidOperationState) WHERE s.id = 1 SET s.issued_through = $last",
                Params::default().with("last", Value::Int(last.max(source_last))),
            )?;
            Ok(Decision::Commit(()))
        })
        .await?;
        self.drop_marked_periods().await
    }

    async fn record_outcome(&self, ctx: MutationContext) -> SidResult<()> {
        let chain = ctx.operation.as_ref().map_or_else(
            || "operation".to_owned(),
            |o| format!("operation:{}", o.namespace),
        );
        self.mutate(chain, ctx, |_| Ok(())).await
    }

    async fn purge_operation_results(
        &self,
        namespace: &str,
        method: &str,
        before: DateTime<Utc>,
    ) -> SidResult<u64> {
        let (namespace, method) = (namespace.to_owned(), method.to_owned());
        self.transaction(move |tx| {
            // The binding of a dropped completion goes with it.
            let rows = tx.run(
                "MATCH (o:SidOperation) WHERE o.namespace = $namespace AND o.completed = true
                   AND o.c_method = $method AND o.c_at < $before
                 DETACH DELETE o RETURN count(*) AS n",
                Params::default()
                    .with("namespace", Value::String(namespace.clone()))
                    .with("method", Value::String(method.clone()))
                    .with("before", time(before)),
            )?;
            dropped(&rows)
        })
        .await
    }

    async fn purge_expired_operation_results(&self, now: DateTime<Utc>) -> SidResult<u64> {
        self.transaction(move |tx| {
            // The bindings of the dropped completions go with them.
            let rows = tx.run(
                "MATCH (o:SidOperation) WHERE o.completed = true AND o.c_retain IS NOT NULL
                   AND o.c_retain <= $now
                 DETACH DELETE o RETURN count(*) AS n",
                Params::default().with("now", time(now)),
            )?;
            dropped(&rows)
        })
        .await
    }

    async fn get_operation_result(
        &self,
        namespace: &str,
        key: &OperationKey,
    ) -> SidResult<Option<OperationRecord>> {
        let (namespace, key) = (namespace.to_owned(), key.clone());
        self.transaction(move |tx| {
            let mut entry = load(tx, &namespace, &key)?;
            settle(tx, &mut entry, Utc::now(), &mut Admitted::default())?;
            Ok(Decision::Abandon(entry.completion))
        })
        .await
    }

    async fn export_operation_results(&self) -> SidResult<Vec<OperationRecord>> {
        self.transaction(|tx| {
            let rows = tx.run(
                &format!("MATCH (o:SidOperation) WHERE o.completed = true RETURN {FIELDS}"),
                Params::default(),
            )?;
            let (now, mut admitted) = (Utc::now(), Admitted::default());
            let mut records = Vec::with_capacity(rows.len());
            for row in &rows {
                let mut entry = entry(row)?;
                settle(tx, &mut entry, now, &mut admitted)?;
                records.extend(entry.completion);
            }
            records.sort_by(|a, b| {
                (
                    a.completed_at,
                    &a.completion.namespace,
                    a.completion.key.as_str(),
                )
                    .cmp(&(
                        b.completed_at,
                        &b.completion.namespace,
                        b.completion.key.as_str(),
                    ))
            });
            Ok(Decision::Abandon(records))
        })
        .await
    }

    async fn import_operation_result(&self, record: &OperationRecord) -> SidResult<bool> {
        let record = record.clone();
        self.transaction(move |tx| {
            // One under a period this store does not admit is not taken: its
            // command is refused here anyway.
            // A carried completion counts toward its period's capacity here
            // too, whatever the count.
            if let Some(period) = record.completion.period {
                match take_place(tx, period, i64::MAX) {
                    Ok(()) => {}
                    Err(SidError::OperationPeriodRefused(_)) => {
                        return Ok(Decision::Abandon(false));
                    }
                    Err(e) => return Err(e),
                }
            }
            let mut entry = load(tx, &record.completion.namespace, &record.completion.key)?;
            if entry.completion.is_some() {
                return Ok(Decision::Abandon(false));
            }
            entry.completion = Some(record.clone());
            save(tx, &entry)?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    async fn bind_operation_resource(
        &self,
        proposal: &OperationResourceBinding,
    ) -> SidResult<Uuid> {
        let proposal = proposal.clone();
        self.transaction(move |tx| {
            let reused = || SidError::OperationKeyReused(proposal.key.as_str().into());
            if let Some(period) = proposal.period {
                admit(tx, period)?;
            }
            let now = Utc::now();
            let mut entry = load(tx, &proposal.namespace, &proposal.key)?;
            // A key whose completion's retention ended is free again; one
            // completed for another command binds nothing.
            settle(tx, &mut entry, now, &mut Admitted::default())?;
            if let Some(done) = &entry.completion
                && (done.completion.method != proposal.method
                    || done.completion.fingerprint != proposal.fingerprint
                    || done.completion.period != proposal.period)
            {
                return Err(reused());
            }
            if let Some((held, _)) = &entry.binding {
                if held.method != proposal.method
                    || held.fingerprint != proposal.fingerprint
                    || held.period != proposal.period
                {
                    return Err(reused());
                }
                let resource = held.resource;
                // What the expiry released is written down with it.
                save(tx, &entry)?;
                return Ok(Decision::Commit(resource));
            }
            entry.binding = Some((proposal.clone(), now));
            save(tx, &entry)?;
            Ok(Decision::Commit(proposal.resource))
        })
        .await
    }

    async fn export_operation_resources(&self) -> SidResult<Vec<OperationResourceBinding>> {
        self.transaction(|tx| {
            let rows = tx.run(
                &format!("MATCH (o:SidOperation) WHERE o.bound = true RETURN {FIELDS}"),
                Params::default(),
            )?;
            // A binding whose completion expired holds a key already
            // released: it is not carried elsewhere.
            let (now, mut admitted) = (Utc::now(), Admitted::default());
            let mut bindings = Vec::with_capacity(rows.len());
            for row in &rows {
                let mut entry = entry(row)?;
                settle(tx, &mut entry, now, &mut admitted)?;
                bindings.extend(entry.binding);
            }
            bindings.sort_by(|(a, at), (b, bt)| {
                (at, &a.namespace, a.key.as_str()).cmp(&(bt, &b.namespace, b.key.as_str()))
            });
            Ok(Decision::Abandon(
                bindings.into_iter().map(|(b, _)| b).collect(),
            ))
        })
        .await
    }

    async fn import_operation_resource(
        &self,
        binding: &OperationResourceBinding,
    ) -> SidResult<bool> {
        let binding = binding.clone();
        self.transaction(move |tx| {
            // A binding under a retired period is an unfinished creation's,
            // kept to reconcile it: it is carried and holds its key, though
            // nothing runs under that period any more. One under a period
            // never issued here is not taken.
            if let Some(period) = binding.period {
                match admit(tx, period) {
                    Ok(())
                    | Err(SidError::OperationPeriodRefused(OperationPeriodRefusal::Retired)) => {}
                    Err(SidError::OperationPeriodRefused(_)) => {
                        return Ok(Decision::Abandon(false));
                    }
                    Err(e) => return Err(e),
                }
            }
            let mut entry = load(tx, &binding.namespace, &binding.key)?;
            if entry.binding.is_some() {
                return Ok(Decision::Abandon(false));
            }
            entry.binding = Some((binding.clone(), Utc::now()));
            save(tx, &entry)?;
            Ok(Decision::Commit(true))
        })
        .await
    }
}

/// The count a purge returned; a purge that dropped nothing writes nothing.
fn dropped(rows: &[Row]) -> SidResult<Decision<u64>> {
    let n = rows
        .first()
        .map(|row| get_int(row, "n"))
        .transpose()?
        .unwrap_or(0);
    let n = u64::try_from(n).map_err(|_| SidError::Storage(format!("bad purge count: {n}")))?;
    Ok(if n == 0 {
        Decision::Abandon(0)
    } else {
        Decision::Commit(n)
    })
}
