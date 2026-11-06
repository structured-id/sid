// SPDX-License-Identifier: AGPL-3.0-only
//! SID's records in a host's CoordiNode database, through the database handle
//! the host already holds. Every change runs in one interactive transaction:
//! CoordiNode refuses a commit whose write set another transaction changed
//! since it began, or whose pinned reads ([`Statements::hold`]) changed, and
//! the whole transaction is run again from the start. A plain read is not
//! checked at commit: what a decision rests on is either written or held.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;

use coordinode_core::graph::node::NodeId;
use coordinode_core::graph::types::Value;
use coordinode_embed::{Database, DatabaseError, TransactionId};
use sid_core::models::MutationContext;
use sid_core::{Error as SidError, Result as SidResult};

mod audit;
mod backend;
mod ceremony;
mod instance_secret;
mod operation;
mod profile;
mod work;

/// How often one change is run again after a conflicting commit before it is
/// reported: each retry follows a commit that changed what it read, so a
/// change that keeps losing is contended past any useful bound.
const CONFLICT_RETRIES: u32 = 64;

/// The pause before a run again, multiplied by the round (up to 40).
const RETRY_PAUSE: std::time::Duration = std::time::Duration::from_micros(50);

/// The schema SID's records rely on: what keeps an identifier unique across
/// concurrent writers. Nodes that writers of one thing meet on (a work kind's
/// admission, an audit chain's head, a command key) are unique too, so the
/// first writers create one node and conflict instead of each creating its
/// own.
const SCHEMA: &[&str] = &[
    "CREATE CONSTRAINT sid_work_id FOR (w:SidWork) REQUIRE w.id IS UNIQUE",
    "CREATE CONSTRAINT sid_work_kind FOR (k:SidWorkKind) REQUIRE k.kind IS UNIQUE",
    "CREATE CONSTRAINT sid_audit_head FOR (h:SidAuditHead) REQUIRE h.chain IS UNIQUE",
    "CREATE CONSTRAINT sid_audit_record FOR (r:SidAuditRecord) REQUIRE r.id IS UNIQUE",
    "CREATE CONSTRAINT sid_operation_slot FOR (o:SidOperation) REQUIRE o.slot IS UNIQUE",
    "CREATE CONSTRAINT sid_operation_period FOR (p:SidOperationPeriod) REQUIRE p.period IS UNIQUE",
    "CREATE CONSTRAINT sid_operation_state FOR (s:SidOperationState) REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT sid_ceremony_state FOR (c:SidCeremonyState) REQUIRE c.slot IS UNIQUE",
    "CREATE CONSTRAINT sid_ceremony_count FOR (c:SidCeremonyCount) REQUIRE c.slot IS UNIQUE",
    "CREATE CONSTRAINT sid_instance_secret FOR (s:SidInstanceSecret) REQUIRE s.name IS UNIQUE",
    "CREATE CONSTRAINT sid_profile_id FOR (p:SidProfile) REQUIRE p.id IS UNIQUE",
    "CREATE CONSTRAINT sid_profile_username FOR (p:SidProfile) REQUIRE p.username IS UNIQUE",
    "CREATE INDEX sid_profile_status ON :SidProfile(status)",
    "CREATE INDEX sid_profile_migration ON :SidProfile(migration_pending)",
    "CREATE CONSTRAINT sid_phone_id FOR (c:SidPhone) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT sid_phone_number FOR (c:SidPhone) REQUIRE c.number_key IS UNIQUE",
    "CREATE CONSTRAINT sid_phone_primary FOR (c:SidPhone) REQUIRE c.primary_of IS UNIQUE",
    "CREATE INDEX sid_phone_profile ON :SidPhone(profile_id)",
    "CREATE CONSTRAINT sid_email_id FOR (c:SidEmail) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT sid_email_address FOR (c:SidEmail) REQUIRE c.address_key IS UNIQUE",
    "CREATE CONSTRAINT sid_email_primary FOR (c:SidEmail) REQUIRE c.primary_of IS UNIQUE",
    "CREATE INDEX sid_email_profile ON :SidEmail(profile_id)",
    "CREATE INDEX sid_email_address_lookup ON :SidEmail(email)",
];

/// SID's storage over the host's CoordiNode database.
#[derive(Clone)]
pub struct CoordinodeBackend {
    db: Arc<Database>,
}

impl CoordinodeBackend {
    /// SID's storage in `db`, the host's own database. Declares the schema
    /// SID's records need; a constraint declared before is kept as it is.
    pub async fn new(db: Arc<Database>) -> SidResult<Self> {
        let backend = Self { db };
        backend
            .blocking(|db| {
                for statement in SCHEMA {
                    match db.execute_cypher_shared(statement, None, None, None, None) {
                        Ok(_) | Err(DatabaseError::CatalogObjectExists { .. }) => {}
                        Err(e) => return Err(storage(e)),
                    }
                }
                Ok(())
            })
            .await?;
        backend.transaction(operation::init_state).await?;
        Ok(backend)
    }

    /// Run `f` on the database off the async runtime: CoordiNode's API
    /// blocks the calling thread.
    async fn blocking<T, F>(&self, f: F) -> SidResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&Database) -> SidResult<T> + Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || f(&db))
            .await
            .map_err(|e| SidError::Internal(format!("CoordiNode call: {e}")))?
    }

    /// Run `change` in a transaction and commit what it decided, again from
    /// the start whenever the commit conflicts.
    async fn transaction<T, F>(&self, change: F) -> SidResult<T>
    where
        T: Send + 'static,
        F: FnMut(&Statements<'_>) -> SidResult<Decision<T>> + Send + 'static,
    {
        self.blocking(move |db| in_transaction(db, change)).await
    }

    /// Commit `ctx` with whatever `change` wrote in the same transaction:
    /// its audit record on `chain`, its command completion and its owed
    /// work, all of it or none.
    async fn mutate<F>(&self, chain: String, ctx: MutationContext, mut change: F) -> SidResult<()>
    where
        F: FnMut(&Statements<'_>) -> SidResult<()> + Send + 'static,
    {
        self.transaction(move |tx| {
            change(tx)?;
            finalize(tx, &chain, ctx.clone())?;
            Ok(Decision::Commit(()))
        })
        .await
    }
}

/// What every mutation commits besides its own state, in its transaction.
fn finalize(tx: &Statements<'_>, chain: &str, ctx: MutationContext) -> SidResult<()> {
    // The authority first: a write whose actor or policy changed commits
    // nothing. Fences are checked against the stores that hold the actor or
    // policy; this backend holds none of them yet, so it cannot confirm one.
    if let Some(fence) = &ctx.fence {
        return Err(SidError::Storage(format!(
            "CoordiNode storage cannot check the fence {fence:?}"
        )));
    }
    // Then the completion: a keyed command another commit already completed
    // commits nothing, not even its audit or work.
    if let Some(completion) = &ctx.operation {
        operation::record(tx, completion)?;
    }
    audit::append(tx, chain, ctx.audit, chrono::Utc::now())?;
    for owed in &ctx.work {
        work::insert(tx, owed, sid_plugin::OWED_WORK_CAPACITY)?;
    }
    Ok(())
}

/// What a transaction's body decided.
pub(super) enum Decision<T> {
    /// Commit its writes and answer `T`.
    Commit(T),
    /// Write nothing and answer `T`.
    Abandon(T),
}

/// The statements of one open transaction.
pub(super) struct Statements<'a> {
    db: &'a Database,
    id: TransactionId,
    /// Set when a statement was refused for a concurrent transaction: the
    /// whole transaction runs again rather than failing.
    contended: Cell<bool>,
}

impl Statements<'_> {
    pub(super) fn run(&self, query: &str, params: Params) -> SidResult<Vec<Row>> {
        self.db
            .execute_in_transaction(self.id, query, Some(params.0))
            .map_err(|e| {
                if contention(&e) {
                    self.contended.set(true);
                }
                storage(e)
            })
    }

    /// Commit only while the node `node` (its `id(n)`) stays as it is now:
    /// a decision built on it is refused, and run again, when another commit
    /// changed or deleted it meanwhile. `false` when it is gone already.
    pub(super) fn hold(&self, node: i64) -> SidResult<bool> {
        let node = NodeId::from_raw(
            u64::try_from(node).map_err(|_| SidError::Storage(format!("bad node id {node}")))?,
        );
        let Some(version) = self.db.node_version(node).map_err(storage)? else {
            return Ok(false);
        };
        self.db
            .expect_node_version(self.id, node, Some(version))
            .map_err(storage)?;
        Ok(true)
    }
}

/// One result row, by column name (CoordiNode's row shape).
pub(super) type Row = std::collections::BTreeMap<String, Value>;

/// Statement parameters by name.
#[derive(Default)]
pub(super) struct Params(HashMap<String, Value>);

impl Params {
    pub(super) fn with(mut self, name: &str, value: Value) -> Self {
        self.0.insert(name.to_owned(), value);
        self
    }
}

fn in_transaction<T, F>(db: &Database, mut change: F) -> SidResult<T>
where
    F: FnMut(&Statements<'_>) -> SidResult<Decision<T>>,
{
    for attempt in 0..=CONFLICT_RETRIES {
        if attempt > 0 {
            // A refusal for a claim another transaction holds clears only
            // when that one ends: give it the time, longer each round.
            std::thread::sleep(RETRY_PAUSE * attempt.min(40));
        }
        let id = db.begin_transaction().map_err(storage)?;
        let statements = Statements {
            db,
            id,
            contended: Cell::new(false),
        };
        let decided = match change(&statements) {
            Ok(decided) => decided,
            Err(e) => {
                // A failed statement already ended the transaction.
                db.rollback_transaction(id).ok();
                if statements.contended.get() {
                    continue;
                }
                return Err(e);
            }
        };
        match decided {
            Decision::Abandon(answer) => {
                db.rollback_transaction(id).map_err(storage)?;
                return Ok(answer);
            }
            Decision::Commit(answer) => match db.commit_transaction(id) {
                Ok(_) => return Ok(answer),
                Err(e) if contention(&e) => continue,
                Err(e) => return Err(storage(e)),
            },
        }
    }
    Err(SidError::Storage(format!(
        "CoordiNode transaction conflicted {CONFLICT_RETRIES} times in a row"
    )))
}

/// A refusal caused by a concurrent transaction, which nothing applied and
/// a run again resolves on what that transaction left.
fn contention(e: &DatabaseError) -> bool {
    matches!(
        e,
        DatabaseError::TransactionConflict { .. }
            | DatabaseError::RevisionMismatch { .. }
            | DatabaseError::InvariantRefused { .. }
    )
}

fn storage(e: DatabaseError) -> SidError {
    match e {
        // A unique key already held: the record exists. The index names it;
        // the value is the caller's input and stays out of the message.
        DatabaseError::UniqueViolation { index, .. } => {
            SidError::Conflict(format!("{index} already exists"))
        }
        e => SidError::Storage(format!("CoordiNode: {e}")),
    }
}

// ─── Values ───

/// The node key of `key` in `namespace`: the namespace's length first, so
/// no two pairs share one.
pub(super) fn slot(namespace: &str, key: &str) -> SidResult<Vec<u8>> {
    let length = u32::try_from(namespace.len())
        .map_err(|_| SidError::Validation("namespace too long".into()))?;
    let mut slot = Vec::with_capacity(4 + namespace.len() + key.len());
    slot.extend_from_slice(&length.to_be_bytes());
    slot.extend_from_slice(namespace.as_bytes());
    slot.extend_from_slice(key.as_bytes());
    Ok(slot)
}

/// A UUID as its 16 bytes.
pub(super) fn uuid(id: &uuid::Uuid) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

pub(super) fn opt_uuid(id: Option<&uuid::Uuid>) -> Value {
    id.map_or(Value::Null, uuid)
}

/// Key bytes of `parts`, each prefixed by its length, so no two lists of
/// parts share one.
pub(super) fn key(parts: &[&[u8]]) -> SidResult<Value> {
    let mut key = Vec::with_capacity(parts.iter().map(|p| 4 + p.len()).sum());
    for part in parts {
        let length = u32::try_from(part.len())
            .map_err(|_| SidError::Validation("key part too long".into()))?;
        key.extend_from_slice(&length.to_be_bytes());
        key.extend_from_slice(part);
    }
    Ok(Value::Binary(key))
}

pub(super) fn texts(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

pub(super) fn get_uuid(row: &Row, name: &str) -> SidResult<uuid::Uuid> {
    uuid::Uuid::from_slice(&get_bytes(row, name)?)
        .map_err(|e| SidError::Storage(format!("{name} is no UUID: {e}")))
}

pub(super) fn get_opt_uuid(row: &Row, name: &str) -> SidResult<Option<uuid::Uuid>> {
    get_opt_bytes(row, name)?
        .map(|b| {
            uuid::Uuid::from_slice(&b)
                .map_err(|e| SidError::Storage(format!("{name} is no UUID: {e}")))
        })
        .transpose()
}

pub(super) fn get_texts(row: &Row, name: &str) -> SidResult<Vec<String>> {
    match field(row, name)? {
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(s) => Ok(s.clone()),
                other => Err(SidError::Storage(format!("{name} holds {other:?}"))),
            })
            .collect(),
        other => Err(SidError::Storage(format!(
            "{name} is not a list: {other:?}"
        ))),
    }
}

/// The count a `count(..) AS n` query returned.
pub(super) fn get_count(rows: &[Row]) -> SidResult<u64> {
    let n = rows
        .first()
        .map(|row| get_int(row, "n"))
        .transpose()?
        .unwrap_or(0);
    u64::try_from(n).map_err(|_| SidError::Storage(format!("bad count: {n}")))
}

/// A page bound as the statement's integer.
pub(super) fn page(value: u64) -> SidResult<Value> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| SidError::Validation(format!("page bound {value} out of range")))
}

pub(super) fn time(t: chrono::DateTime<chrono::Utc>) -> Value {
    Value::Int(t.timestamp_micros())
}

pub(super) fn opt_time(t: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    t.map_or(Value::Null, time)
}

pub(super) fn opt_text(t: Option<&str>) -> Value {
    t.map_or(Value::Null, |t| Value::String(t.to_owned()))
}

/// The value `name` of `row`; a missing column is a storage error.
fn field<'r>(row: &'r Row, name: &str) -> SidResult<&'r Value> {
    row.get(name)
        .ok_or_else(|| SidError::Storage(format!("CoordiNode row without {name}")))
}

pub(super) fn get_int(row: &Row, name: &str) -> SidResult<i64> {
    match field(row, name)? {
        Value::Int(v) => Ok(*v),
        other => Err(SidError::Storage(format!(
            "{name} is not an integer: {other:?}"
        ))),
    }
}

pub(super) fn get_bool(row: &Row, name: &str) -> SidResult<bool> {
    match field(row, name)? {
        Value::Bool(v) => Ok(*v),
        other => Err(SidError::Storage(format!(
            "{name} is not a boolean: {other:?}"
        ))),
    }
}

pub(super) fn get_text(row: &Row, name: &str) -> SidResult<String> {
    match field(row, name)? {
        Value::String(v) => Ok(v.clone()),
        other => Err(SidError::Storage(format!("{name} is not text: {other:?}"))),
    }
}

pub(super) fn get_opt_text(row: &Row, name: &str) -> SidResult<Option<String>> {
    match row.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(v)) => Ok(Some(v.clone())),
        Some(other) => Err(SidError::Storage(format!("{name} is not text: {other:?}"))),
    }
}

pub(super) fn get_opt_int(row: &Row, name: &str) -> SidResult<Option<i64>> {
    match row.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => get_int(row, name).map(Some),
    }
}

pub(super) fn get_opt_bytes(row: &Row, name: &str) -> SidResult<Option<Vec<u8>>> {
    match row.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => get_bytes(row, name).map(Some),
    }
}

pub(super) fn get_bytes(row: &Row, name: &str) -> SidResult<Vec<u8>> {
    match field(row, name)? {
        Value::Binary(v) => Ok(v.clone()),
        other => Err(SidError::Storage(format!(
            "{name} is not binary: {other:?}"
        ))),
    }
}

pub(super) fn get_time(row: &Row, name: &str) -> SidResult<chrono::DateTime<chrono::Utc>> {
    let micros = get_int(row, name)?;
    chrono::DateTime::from_timestamp_micros(micros)
        .ok_or_else(|| SidError::Storage(format!("{name} is no instant: {micros}")))
}

pub(super) fn get_opt_time(
    row: &Row,
    name: &str,
) -> SidResult<Option<chrono::DateTime<chrono::Utc>>> {
    match row.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => get_time(row, name).map(Some),
    }
}
