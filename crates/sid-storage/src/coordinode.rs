// SPDX-License-Identifier: AGPL-3.0-only
//! SID's records in a host's CoordiNode database, through the database handle
//! the host already holds. Every change runs in one interactive transaction:
//! CoordiNode refuses a commit whose write set another transaction changed
//! since it began, or whose pinned reads ([`Statements::hold`]) changed, and
//! the whole transaction is run again from the start. A plain read is not
//! checked at commit: what a decision rests on is either written or held.
//! A decision on the absence of children cannot hold what is not there, so
//! every child creation claims its parent ([`Statements::claim`]) and the
//! parent's deletion, which writes the parent, conflicts with it.

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
mod binding;
mod branding;
mod ceremony;
mod consent;
mod credential;
mod device;
mod directory;
mod enrollment;
mod flow;
mod history;
mod history_keys;

pub use history_keys::CoordinodeHistoryKeyStore;
mod instance_secret;
mod job_lock;
mod keys;
mod lifecycle;
mod login_policy;
mod machine;
mod operation;
mod principal;
mod profile;
mod project;
mod rbac;
mod registry;
mod reset;
mod schema;
mod scim;
mod session;
mod signals;
mod work;

#[cfg(test)]
mod tests;

/// How often one change is run again after a conflicting commit before it is
/// reported: each retry follows a commit that changed what it read, so a
/// change that keeps losing is contended past any useful bound.
const CONFLICT_RETRIES: u32 = 64;

/// The pause before a run again, multiplied by the round (up to 40).
const RETRY_PAUSE: std::time::Duration = std::time::Duration::from_micros(50);

/// SID's storage over the host's CoordiNode database.
#[derive(Clone)]
pub struct CoordinodeBackend {
    db: Arc<Database>,
}

impl CoordinodeBackend {
    /// SID's storage in `db`, the host's own database. Declares the schema
    /// SID's records need, a part declared before kept as it is, and returns
    /// only once its constraints hold: a store that cannot hold them is
    /// refused before anything is served.
    pub async fn new(db: Arc<Database>) -> SidResult<Self> {
        let backend = Self { db };
        backend.blocking(schema::declare).await?;
        backend.transaction(operation::init_state).await?;
        backend.transaction(principal::init_email_policy).await?;
        backend.transaction(project::init_system_project).await?;
        backend.transaction(credential::init_cutoff).await?;
        backend.transaction(enrollment::init_policies).await?;
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

    /// Run `read` in a transaction that writes nothing.
    async fn read<T, F>(&self, mut read: F) -> SidResult<T>
    where
        T: Send + 'static,
        F: FnMut(&Statements<'_>) -> SidResult<T> + Send + 'static,
    {
        self.transaction(move |tx| read(tx).map(Decision::Abandon))
            .await
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
    // nothing. What the fence names is held for the commit.
    match ctx.fence {
        Some(sid_core::models::ActorFence::Connector {
            connector,
            revision,
            credential,
        }) => machine::check_connector_fence(tx, connector, revision, credential)?,
        Some(sid_core::models::ActorFence::LoginPolicy { epoch }) => {
            login_policy::check_fence(tx, epoch)?
        }
        Some(sid_core::models::ActorFence::Authority(basis)) => rbac::check_authority(tx, &basis)?,
        None => {}
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
    /// A time drawn before the transaction began: every commit at or before
    /// it is in the transaction's snapshot, or not yet in the store at all.
    snapshot_floor: u64,
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
        // A version written after the snapshot is not the one the decision
        // read: holding it would commit that decision over the newer node.
        if version > self.snapshot_floor {
            self.contended.set(true);
            return Err(SidError::Storage(
                "a held node changed since the transaction began".into(),
            ));
        }
        self.db
            .expect_node_version(self.id, node, Some(version))
            .map_err(storage)?;
        Ok(true)
    }

    /// Hold the parent node `node` for a child this transaction creates, and
    /// write it: a deletion of the parent that read its children before this
    /// commit then conflicts and runs again, seeing the child. A hold alone
    /// would leave that deletion's decision, built on no child, unchecked.
    pub(super) fn claim(&self, node: i64) -> SidResult<bool> {
        if !self.hold(node)? {
            return Ok(false);
        }
        // The owner's `turn`, as the owners of other records take it.
        self.run(
            "MATCH (n) WHERE id(n) = $node SET n.turn = coalesce(n.turn, 0) + 1",
            Params::default().with("node", Value::Int(node)),
        )?;
        Ok(true)
    }
}

/// One result row, by column name (CoordiNode's row shape).
pub(super) type Row = std::collections::BTreeMap<String, Value>;

/// Statement parameters by name.
#[derive(Default, Clone)]
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
        let snapshot_floor = db.read_ts().as_raw();
        let id = db.begin_transaction().map_err(storage)?;
        let statements = Statements {
            db,
            id,
            snapshot_floor,
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

/// A structured value as a CoordiNode document, never as serialized text.
pub(super) fn document<T: serde::Serialize>(value: &T, name: &str) -> SidResult<Value> {
    // Structs as maps by field name: positional fields would shift into the
    // place of one left out (`skip_serializing_if`).
    let bytes =
        rmp_serde::to_vec_named(value).map_err(|e| SidError::Validation(format!("{name}: {e}")))?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map(Value::Document)
        .map_err(|e| SidError::Internal(format!("{name}: {e}")))
}

/// The structured value the document `name` of `row` holds.
pub(super) fn get_document<T: serde::de::DeserializeOwned>(row: &Row, name: &str) -> SidResult<T> {
    match field(row, name)? {
        // Read back by the codec that wrote it.
        Value::Document(document) => {
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, document)
                .map_err(|e| SidError::Storage(format!("{name}: {e}")))?;
            rmp_serde::from_slice(&bytes).map_err(|e| SidError::Storage(format!("{name}: {e}")))
        }
        other => Err(SidError::Storage(format!(
            "{name} is not a document: {other:?}"
        ))),
    }
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

/// A stored name of an owning enum; an unknown one is an error, never a
/// default.
pub(super) fn get_parsed<T: std::str::FromStr<Err = String>>(
    row: &Row,
    name: &str,
) -> SidResult<T> {
    get_text(row, name)?
        .parse()
        .map_err(|e| SidError::Storage(format!("{name}: {e}")))
}

pub(super) fn get_opt_parsed<T: std::str::FromStr<Err = String>>(
    row: &Row,
    name: &str,
) -> SidResult<Option<T>> {
    get_opt_text(row, name)?
        .map(|text| {
            text.parse()
                .map_err(|e| SidError::Storage(format!("{name}: {e}")))
        })
        .transpose()
}

/// Hold the node the first row's `node` column names for the commit:
/// true when there is one and it still stands as read.
pub(super) fn hold_first(tx: &Statements<'_>, rows: &[Row]) -> SidResult<bool> {
    match rows.first() {
        Some(row) => tx.hold(get_int(row, "node")?),
        None => Ok(false),
    }
}

/// Claim the parent node the first row's `node` column names for a child
/// this transaction creates: true when there is one and it still stands.
pub(super) fn claim_first(tx: &Statements<'_>, rows: &[Row]) -> SidResult<bool> {
    match rows.first() {
        Some(row) => tx.claim(get_int(row, "node")?),
        None => Ok(false),
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

/// Page `offset..offset + limit` of `items`, ordered by `key`. CoordiNode
/// orders no binary values (coordinode#84), and ids are 16 bytes: an order
/// they break ties of is taken here.
pub(super) fn sorted_page<T, K: Ord>(
    mut items: Vec<T>,
    key: impl Fn(&T) -> K,
    offset: u64,
    limit: u64,
) -> Vec<T> {
    items.sort_by_key(|item| key(item));
    let offset = usize::try_from(offset).unwrap_or(usize::MAX);
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    items.into_iter().skip(offset).take(limit).collect()
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

/// `t` as [`time`] stores it and [`get_time`] reads it back: a value the
/// store issues itself is answered as every later reader sees it.
pub(super) fn stored_time(t: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    use chrono::SubsecRound;
    t.trunc_subsecs(6)
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
