// SPDX-License-Identifier: AGPL-3.0-only
//! SID's records in a host's CoordiNode database, through the database handle
//! the host already holds. Every change runs in one interactive transaction:
//! CoordiNode refuses a commit whose write set another transaction changed
//! since it began, and the whole transaction is run again from the start.

use std::collections::HashMap;
use std::sync::Arc;

use coordinode_core::graph::types::Value;
use coordinode_embed::{Database, DatabaseError, TransactionId};
use sid_core::{Error as SidError, Result as SidResult};

mod work;

/// How often one change is run again after a conflicting commit before it is
/// reported: each retry follows a commit that changed what it read, so a
/// change that keeps losing is contended past any useful bound.
const CONFLICT_RETRIES: u32 = 64;

/// The schema SID's records rely on: what keeps an identifier unique across
/// concurrent writers. A work kind's admission node is unique too, so the
/// first enqueues of a kind meet on one node instead of each creating its own.
const SCHEMA: &[&str] = &[
    "CREATE CONSTRAINT sid_work_id FOR (w:SidWork) REQUIRE w.id IS UNIQUE",
    "CREATE CONSTRAINT sid_work_kind FOR (k:SidWorkKind) REQUIRE k.kind IS UNIQUE",
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
}

impl Statements<'_> {
    pub(super) fn run(&self, query: &str, params: Params) -> SidResult<Vec<Row>> {
        self.db
            .execute_in_transaction(self.id, query, Some(params.0))
            .map_err(storage)
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
    for _ in 0..=CONFLICT_RETRIES {
        let id = db.begin_transaction().map_err(storage)?;
        let statements = Statements { db, id };
        let decided = match change(&statements) {
            Ok(decided) => decided,
            Err(e) => {
                // A failed statement already ended the transaction.
                db.rollback_transaction(id).ok();
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
                Err(DatabaseError::TransactionConflict { .. }) => continue,
                Err(e) => return Err(storage(e)),
            },
        }
    }
    Err(SidError::Storage(format!(
        "CoordiNode transaction conflicted {CONFLICT_RETRIES} times in a row"
    )))
}

fn storage(e: DatabaseError) -> SidError {
    SidError::Storage(format!("CoordiNode: {e}"))
}

// ─── Values ───

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
