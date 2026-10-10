// SPDX-License-Identifier: AGPL-3.0-only
//! Private password history on SQLite: the credential service's epoch
//! descriptors and retained entries, and the evaluator's own key store
//! ([`SqliteHistoryKeyStore`], tables `history_key_*`) in the same embedded
//! file. No cryptography runs here; keys arrive sealed and tags never arrive.
//! Every write runs in a `BEGIN IMMEDIATE` transaction, which holds the
//! database write lock: two writers of one owner's history are serialized.

use async_trait::async_trait;
use sid_core::models::{
    AuditEntry, EnrollmentCleanup, HistoryArchive, HistoryCommit, HistoryEntry, HistoryEpoch,
    HistoryEpochDescriptor, HistoryEpochId, HistoryEpochUse, HistoryEvidence, HistoryKsf,
    HistoryPreparation, HistorySuite, KeyArchive, KeyEpoch, KeyEpochs, NewKeyEpoch,
    PasswordHistory, ProfileId, WrappedHistoryKey,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::history_keys::HistoryKeyStore;
use sqlx::SqlitePool;

use super::{SqliteBackend, WriteTx, col, dt_col, fmt_dt, uuid_col};

fn storage(what: &str) -> impl FnOnce(sqlx::Error) -> SidError + '_ {
    move |e| SidError::Storage(format!("password history {what}: {e}"))
}

fn fixed32(row: &sqlx::sqlite::SqliteRow, column: &str) -> SidResult<[u8; 32]> {
    col::<Vec<u8>>(row, column)?
        .try_into()
        .map_err(|_| SidError::Storage(format!("column {column}: not 32 bytes")))
}

fn positive(row: &sqlx::sqlite::SqliteRow, column: &str) -> SidResult<u32> {
    u32::try_from(col::<i64>(row, column)?)
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| SidError::Storage(format!("column {column}: not positive")))
}

fn ksf(row: &sqlx::sqlite::SqliteRow) -> SidResult<HistoryKsf> {
    Ok(HistoryKsf {
        memory_kib: positive(row, "ksf_memory_kib")?,
        passes: positive(row, "ksf_passes")?,
        lanes: positive(row, "ksf_lanes")?,
    })
}

/// The epoch columns [`row_to_epoch`] reads, as a literal for static queries.
macro_rules! epoch_columns {
    () => {
        "id, owner_id, suite, public_key, ksf_memory_kib, ksf_passes, \
         ksf_lanes, ksf_salt, status, created_at"
    };
}

/// The key epoch columns [`row_to_key_epoch`] reads.
macro_rules! key_epoch_columns {
    () => {
        "id, owner_domain, suite, public_key, ksf_memory_kib, ksf_passes, \
         ksf_lanes, ksf_salt, status, created_at"
    };
}

fn row_to_epoch(row: &sqlx::sqlite::SqliteRow) -> SidResult<HistoryEpoch> {
    Ok(HistoryEpoch {
        id: HistoryEpochId(uuid_col(row, "id")?),
        owner: col(row, "owner_id")?,
        suite: HistorySuite::parse(&col::<String>(row, "suite")?)?,
        public_key: fixed32(row, "public_key")?,
        ksf: ksf(row)?,
        ksf_salt: fixed32(row, "ksf_salt")?,
        status: HistoryEpochUse::parse(&col::<String>(row, "status")?)?,
        created_at: dt_col(row, "created_at")?,
    })
}

fn row_to_key_epoch(row: &sqlx::sqlite::SqliteRow) -> SidResult<KeyEpoch> {
    Ok(KeyEpoch {
        id: HistoryEpochId(uuid_col(row, "id")?),
        owner_domain: fixed32(row, "owner_domain")?,
        suite: HistorySuite::parse(&col::<String>(row, "suite")?)?,
        public_key: fixed32(row, "public_key")?,
        ksf: ksf(row)?,
        ksf_salt: fixed32(row, "ksf_salt")?,
        status: HistoryEpochUse::parse(&col::<String>(row, "status")?)?,
        created_at: dt_col(row, "created_at")?,
    })
}

fn row_to_entry(row: &sqlx::sqlite::SqliteRow) -> SidResult<HistoryEntry> {
    Ok(HistoryEntry {
        epoch: HistoryEpochId(uuid_col(row, "epoch_id")?),
        seq: col(row, "seq")?,
        entry: fixed32(row, "entry")?,
        evidence: HistoryEvidence {
            operation: uuid_col(row, "operation_id")?,
            policy_version: u32::try_from(col::<i64>(row, "policy_version")?)
                .map_err(|_| SidError::Storage("column policy_version: negative".into()))?,
        },
        created_at: dt_col(row, "created_at")?,
    })
}

/// The owner's revision, every epoch and every entry; `None` without history.
async fn read(
    conn: &mut sqlx::SqliteConnection,
    owner: ProfileId,
) -> SidResult<Option<(i64, Vec<HistoryEpoch>, Vec<HistoryEntry>)>> {
    let revision: Option<i64> =
        sqlx::query_scalar("SELECT revision FROM password_histories WHERE owner_id = ?")
            .bind(owner)
            .fetch_optional(&mut *conn)
            .await
            .map_err(storage("revision"))?;
    let Some(revision) = revision else {
        return Ok(None);
    };
    let rows = sqlx::query(concat!(
        "SELECT ",
        epoch_columns!(),
        " FROM password_history_epochs WHERE owner_id = ?"
    ))
    .bind(owner)
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("epochs"))?;
    let mut epochs = rows
        .iter()
        .map(row_to_epoch)
        .collect::<SidResult<Vec<_>>>()?;
    // Old files may mix millisecond and microsecond text encodings. SQL's
    // lexical order is not temporal order across those representations.
    epochs.sort_by_key(|e| (e.created_at, e.id));
    let rows = sqlx::query(
        "SELECT epoch_id, seq, entry, operation_id, policy_version, created_at
         FROM password_history_entries WHERE owner_id = ? ORDER BY seq DESC, epoch_id",
    )
    .bind(owner)
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("entries"))?;
    let entries = rows
        .iter()
        .map(row_to_entry)
        .collect::<SidResult<Vec<_>>>()?;
    Ok(Some((revision, epochs, entries)))
}

async fn insert_epoch(tx: &mut WriteTx, e: &HistoryEpoch) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO password_history_epochs (id, owner_id, suite, public_key,
             ksf_memory_kib, ksf_passes, ksf_lanes, ksf_salt, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(e.id.0.to_string())
    .bind(e.owner)
    .bind(e.suite.as_str())
    .bind(e.public_key.as_slice())
    .bind(i64::from(e.ksf.memory_kib))
    .bind(i64::from(e.ksf.passes))
    .bind(i64::from(e.ksf.lanes))
    .bind(e.ksf_salt.as_slice())
    .bind(e.status.as_str())
    .bind(fmt_dt(&e.created_at))
    .execute(&mut **tx)
    .await
    .map_err(storage("epoch insert"))?;
    Ok(())
}

/// Record the descriptor `d` for `owner` unless it is recorded already; one
/// recorded with any other immutable field, or for another owner, is a
/// `Conflict`: the evaluator never issues two descriptors for one epoch.
async fn record_descriptor(
    tx: &mut WriteTx,
    owner: ProfileId,
    d: &HistoryEpochDescriptor,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO password_history_epochs (id, owner_id, suite, public_key,
             ksf_memory_kib, ksf_passes, ksf_lanes, ksf_salt, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'compare_only', ?)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(d.id.0.to_string())
    .bind(owner)
    .bind(d.suite.as_str())
    .bind(d.public_key.as_slice())
    .bind(i64::from(d.ksf.memory_kib))
    .bind(i64::from(d.ksf.passes))
    .bind(i64::from(d.ksf.lanes))
    .bind(d.ksf_salt.as_slice())
    .bind(fmt_dt(&d.created_at))
    .execute(&mut **tx)
    .await
    .map_err(storage("descriptor insert"))?;
    let row = sqlx::query(concat!(
        "SELECT ",
        epoch_columns!(),
        " FROM password_history_epochs WHERE id = ?"
    ))
    .bind(d.id.0.to_string())
    .fetch_one(&mut **tx)
    .await
    .map_err(storage("descriptor read"))?;
    let recorded = row_to_epoch(&row)?;
    if recorded.owner != owner || recorded.descriptor() != *d {
        return Err(SidError::Conflict(format!(
            "history epoch {} is recorded with another descriptor",
            d.id.0
        )));
    }
    Ok(())
}

/// Whose history write cutoff: the credential service's, which fences its
/// commits, or the evaluator's, which fences selection and evaluation.
#[derive(Clone, Copy)]
enum Cutoff {
    Credential,
    Evaluator,
}

impl Cutoff {
    fn select(self) -> &'static str {
        match self {
            Self::Credential => "SELECT not_before FROM password_history_write_cutoff",
            Self::Evaluator => "SELECT not_before FROM history_key_write_cutoff",
        }
    }

    fn update(self) -> &'static str {
        match self {
            Self::Credential => "UPDATE password_history_write_cutoff SET not_before = ?",
            Self::Evaluator => "UPDATE history_key_write_cutoff SET not_before = ?",
        }
    }
}

/// The write cutoff `which` records (`None` when none was set). A stored
/// value that does not parse is an error, never read as no cutoff.
async fn read_cutoff(
    conn: &mut sqlx::SqliteConnection,
    which: Cutoff,
) -> SidResult<Option<chrono::DateTime<chrono::Utc>>> {
    let stored: Option<String> = sqlx::query_scalar(which.select())
        .fetch_one(&mut *conn)
        .await
        .map_err(storage("write cutoff"))?;
    stored
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .map(|t| t.with_timezone(&chrono::Utc))
                .map_err(|e| SidError::Storage(format!("stored write cutoff {s:?}: {e}")))
        })
        .transpose()
}

/// Raise the write cutoff `which` to `not_before` inside `tx`; monotonic.
/// Returns the cutoff in force and whether it moved.
async fn raise_cutoff(
    tx: &mut WriteTx,
    which: Cutoff,
    not_before: chrono::DateTime<chrono::Utc>,
) -> SidResult<(chrono::DateTime<chrono::Utc>, bool)> {
    let not_before = sid_core::models::password_history::write_cutoff_instant(not_before);
    if let Some(current) = read_cutoff(tx, which).await?
        && current >= not_before
    {
        return Ok((current, false));
    }
    sqlx::query(which.update())
        .bind(fmt_dt(&not_before))
        .execute(&mut **tx)
        .await
        .map_err(storage("write cutoff raise"))?;
    Ok((not_before, true))
}

/// Apply `commit` inside `tx`. `Ok(false)` when the owner's history is no
/// longer at `commit.expected_revision`: the caller drops everything.
pub(super) async fn apply_in_tx(tx: &mut WriteTx, commit: &HistoryCommit) -> SidResult<bool> {
    commit.validate()?;
    // The write transaction holds the file's write lock, so a raise of the
    // cutoff and this commit are serialized.
    commit.check_write_cutoff(read_cutoff(tx, Cutoff::Credential).await?)?;
    let owner = commit.owner;
    let moved = if commit.expected_revision == 0 {
        sqlx::query(
            "INSERT INTO password_histories (owner_id, revision) VALUES (?, 1)
             ON CONFLICT (owner_id) DO NOTHING",
        )
        .bind(owner)
        .execute(&mut **tx)
        .await
        .map_err(storage("history row"))?
        .rows_affected()
    } else {
        sqlx::query(
            "UPDATE password_histories SET revision = revision + 1
             WHERE owner_id = ? AND revision = ?",
        )
        .bind(owner)
        .bind(commit.expected_revision)
        .execute(&mut **tx)
        .await
        .map_err(storage("revision"))?
        .rows_affected()
    };
    if moved == 0 {
        return Ok(false);
    }
    // The operation's epochs as the evaluator described them, published with
    // the entries; the revision fence makes this the newest selection.
    for d in &commit.epochs {
        record_descriptor(tx, owner, d).await?;
    }
    let accepted_at = chrono::Utc::now();
    let now = fmt_dt(&accepted_at);
    let active = commit.epochs[0].id.0.to_string();
    sqlx::query(
        "UPDATE password_history_epochs SET status = 'compare_only'
         WHERE owner_id = ? AND status = 'active' AND id <> ?",
    )
    .bind(owner)
    .bind(&active)
    .execute(&mut **tx)
    .await
    .map_err(storage("epoch status"))?;
    sqlx::query("UPDATE password_history_epochs SET status = 'active' WHERE id = ?")
        .bind(&active)
        .execute(&mut **tx)
        .await
        .map_err(storage("epoch status"))?;
    let seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM password_history_entries WHERE owner_id = ?",
    )
    .bind(owner)
    .fetch_one(&mut **tx)
    .await
    .map_err(storage("next seq"))?;
    for (epoch, entry) in &commit.entries {
        sqlx::query(
            "INSERT INTO password_history_entries
                 (epoch_id, owner_id, seq, entry, operation_id, policy_version, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(epoch.0.to_string())
        .bind(owner)
        .bind(seq)
        .bind(entry.as_slice())
        .bind(commit.evidence.operation.to_string())
        .bind(i64::from(commit.evidence.policy_version))
        .bind(&now)
        .execute(&mut **tx)
        .await
        .map_err(storage("entry insert"))?;
    }
    // Retain the newest `depth` accepted passwords; every commit takes the
    // next seq, so those are the last `depth` seqs. An epoch emptied here is
    // retired by the evaluator, from the live set, never by this commit.
    sqlx::query("DELETE FROM password_history_entries WHERE owner_id = ? AND seq <= ?")
        .bind(owner)
        .bind(seq - i64::from(commit.depth))
        .execute(&mut **tx)
        .await
        .map_err(storage("retention"))?;
    // Age retention, under the same revision fence: older accepted passwords
    // go, the newest (this commit's) always stays. Compared as instants,
    // since stored timestamps do not all sort as text.
    if let Some(before) = commit.expires_before(accepted_at) {
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT seq, created_at FROM password_history_entries WHERE owner_id = ? AND seq < ?",
        )
        .bind(owner)
        .bind(seq)
        .fetch_all(&mut **tx)
        .await
        .map_err(storage("age retention"))?;
        for (old, created_at) in rows {
            let created_at = chrono::DateTime::parse_from_rfc3339(&created_at)
                .map_err(|e| SidError::Storage(format!("entry created_at: {e}")))?;
            if created_at < before {
                sqlx::query("DELETE FROM password_history_entries WHERE owner_id = ? AND seq = ?")
                    .bind(owner)
                    .bind(old)
                    .execute(&mut **tx)
                    .await
                    .map_err(storage("age retention"))?;
            }
        }
    }
    Ok(true)
}

impl SqliteBackend {
    pub(crate) async fn export_password_history_impl(
        &self,
        owner: ProfileId,
    ) -> SidResult<Option<HistoryArchive>> {
        let mut tx = self.pool.begin().await.map_err(storage("archive read"))?;
        let read = read(&mut tx, owner).await?;
        tx.commit().await.map_err(storage("archive read"))?;
        let Some((revision, epochs, entries)) = read else {
            return Ok(None);
        };
        let archive = HistoryArchive {
            owner,
            revision,
            epochs,
            entries,
        };
        archive.validate()?;
        Ok(Some(archive))
    }

    pub(crate) async fn import_password_history_impl(
        &self,
        archive: &HistoryArchive,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        archive.validate()?;
        let mut tx = self.begin_write().await?;
        let inserted = sqlx::query(
            "INSERT INTO password_histories (owner_id, revision) VALUES (?, ?)
             ON CONFLICT (owner_id) DO NOTHING",
        )
        .bind(archive.owner)
        .bind(archive.revision)
        .execute(&mut *tx)
        .await
        .map_err(storage("archive insert"))?
        .rows_affected();
        if inserted == 0 {
            let existing =
                read(&mut tx, archive.owner)
                    .await?
                    .map(|(revision, epochs, entries)| HistoryArchive {
                        owner: archive.owner,
                        revision,
                        epochs,
                        entries,
                    });
            if existing.as_ref() == Some(archive) {
                return Ok(false);
            }
            return Err(SidError::Conflict(
                "existing password history differs from archive".into(),
            ));
        }
        for epoch in &archive.epochs {
            insert_epoch(&mut tx, epoch).await?;
        }
        for entry in &archive.entries {
            sqlx::query(
                "INSERT INTO password_history_entries
                     (epoch_id, owner_id, seq, entry, operation_id, policy_version, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(entry.epoch.0.to_string())
            .bind(archive.owner)
            .bind(entry.seq)
            .bind(entry.entry.as_slice())
            .bind(entry.evidence.operation.to_string())
            .bind(i64::from(entry.evidence.policy_version))
            .bind(fmt_dt(&entry.created_at))
            .execute(&mut *tx)
            .await
            .map_err(storage("archive entry"))?;
        }
        Self::commit_mutation(tx, &format!("profile:{}", archive.owner), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn get_password_history_impl(
        &self,
        owner: ProfileId,
    ) -> SidResult<PasswordHistory> {
        // One read transaction: the revision and the rows it covers.
        let mut tx = self.pool.begin().await.map_err(storage("read"))?;
        let read = read(&mut tx, owner).await?;
        tx.commit().await.map_err(storage("read"))?;
        Ok(match read {
            Some((revision, epochs, entries)) => PasswordHistory {
                revision,
                epochs: epochs
                    .into_iter()
                    .filter(|e| e.status != HistoryEpochUse::Retired)
                    .collect(),
                entries,
            },
            None => PasswordHistory::default(),
        })
    }

    pub(crate) async fn raise_history_write_cutoff_impl(
        &self,
        not_before: chrono::DateTime<chrono::Utc>,
        audit: sid_core::models::MutationContext,
    ) -> SidResult<chrono::DateTime<chrono::Utc>> {
        let mut tx = self.begin_write().await?;
        let (cutoff, moved) = raise_cutoff(&mut tx, Cutoff::Credential, not_before).await?;
        if moved {
            Self::commit_mutation(tx, "password_history_write_cutoff", audit).await?;
        }
        Ok(cutoff)
    }

    /// The evaluator's store over this embedded file.
    pub fn history_keys(&self) -> SqliteHistoryKeyStore {
        SqliteHistoryKeyStore {
            pool: self.pool.clone(),
        }
    }
}

/// The history evaluator's store in an embedded SQLite file: its own tables
/// in the same database as the credential service's, for a standalone
/// installation that runs both in one process.
#[derive(Clone)]
pub struct SqliteHistoryKeyStore {
    pool: SqlitePool,
}

impl SqliteHistoryKeyStore {
    async fn begin_write(&self) -> SidResult<WriteTx> {
        self.pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage("begin"))
    }
}

async fn key_audit(tx: &mut WriteTx, audit: AuditEntry) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO history_key_audit (actor_id, actor_type, action, resource, outcome, metadata)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&audit.actor_id)
    .bind(audit.actor_type.to_string())
    .bind(&audit.action)
    .bind(&audit.resource)
    .bind(audit.outcome.to_string())
    .bind(audit.metadata.to_string())
    .execute(&mut **tx)
    .await
    .map_err(storage("audit"))?;
    Ok(())
}

/// Insert `new`; `created_by` is the first enrollment that made it, if any.
async fn insert_key_epoch(
    tx: &mut WriteTx,
    new: &NewKeyEpoch,
    created_by: Option<uuid::Uuid>,
) -> SidResult<()> {
    let e = &new.epoch;
    sqlx::query(
        "INSERT INTO history_key_epochs (id, owner_domain, suite, public_key, wrapped_key,
             ksf_memory_kib, ksf_passes, ksf_lanes, ksf_salt, status, created_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(e.id.0.to_string())
    .bind(e.owner_domain.as_slice())
    .bind(e.suite.as_str())
    .bind(e.public_key.as_slice())
    .bind(new.key.0.as_slice())
    .bind(i64::from(e.ksf.memory_kib))
    .bind(i64::from(e.ksf.passes))
    .bind(i64::from(e.ksf.lanes))
    .bind(e.ksf_salt.as_slice())
    .bind(e.status.as_str())
    .bind(fmt_dt(&e.created_at))
    .bind(created_by.map(|o| o.to_string()))
    .execute(&mut **tx)
    .await
    .map_err(storage("key epoch insert"))?;
    Ok(())
}

/// Whether `operation` was cleaned up as an aborted first enrollment.
async fn abandoned(conn: &mut sqlx::SqliteConnection, operation: uuid::Uuid) -> SidResult<bool> {
    let found: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM history_key_abandoned WHERE operation_id = ?")
            .bind(operation.to_string())
            .fetch_optional(conn)
            .await
            .map_err(storage("abandoned enrollment"))?;
    Ok(found.is_some())
}

async fn owner_key_epochs(
    conn: &mut sqlx::SqliteConnection,
    owner_domain: &[u8; 32],
    with_retired: bool,
) -> SidResult<Vec<KeyEpoch>> {
    let rows = sqlx::query(concat!(
        "SELECT ",
        key_epoch_columns!(),
        " FROM history_key_epochs WHERE owner_domain = ?"
    ))
    .bind(owner_domain.as_slice())
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("key epochs"))?;
    let mut epochs = rows
        .iter()
        .map(row_to_key_epoch)
        .collect::<SidResult<Vec<_>>>()?;
    epochs.retain(|e| with_retired || e.status != HistoryEpochUse::Retired);
    epochs.sort_by_key(|e| (e.created_at, e.id));
    Ok(epochs)
}

fn require_active(new: &NewKeyEpoch) -> SidResult<()> {
    if new.epoch.status != HistoryEpochUse::Active {
        return Err(SidError::Validation(
            "a prepared history epoch is active".into(),
        ));
    }
    Ok(())
}

/// A live set as stored: a JSON array of epoch ids, sorted.
fn live_text(live: &[HistoryEpochId]) -> String {
    serde_json::to_string(&live.iter().map(|e| e.0.to_string()).collect::<Vec<_>>())
        .expect("a list of strings serializes")
}

async fn read_key_archive(
    conn: &mut sqlx::SqliteConnection,
    owner_domain: &[u8; 32],
) -> SidResult<Option<KeyArchive>> {
    let epochs = owner_key_epochs(conn, owner_domain, true).await?;
    if epochs.is_empty() {
        return Ok(None);
    }
    let mut with_keys = Vec::with_capacity(epochs.len());
    for epoch in epochs {
        let key: Vec<u8> =
            sqlx::query_scalar("SELECT wrapped_key FROM history_key_epochs WHERE id = ?")
                .bind(epoch.id.0.to_string())
                .fetch_one(&mut *conn)
                .await
                .map_err(storage("archive key"))?;
        with_keys.push(NewKeyEpoch {
            epoch,
            key: WrappedHistoryKey(key),
        });
    }
    let rows = sqlx::query(
        "SELECT epoch_id, replaced_at_revision FROM history_key_replaced WHERE owner_domain = ?",
    )
    .bind(owner_domain.as_slice())
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("archive replacements"))?;
    let mut replaced = rows
        .iter()
        .map(|row| {
            Ok((
                HistoryEpochId(uuid_col(row, "epoch_id")?),
                col::<i64>(row, "replaced_at_revision")?,
            ))
        })
        .collect::<SidResult<Vec<_>>>()?;
    replaced.sort_unstable();
    let archive = KeyArchive {
        owner_domain: *owner_domain,
        epochs: with_keys,
        replaced,
    };
    archive.validate()?;
    Ok(Some(archive))
}

#[async_trait]
impl HistoryKeyStore for SqliteHistoryKeyStore {
    async fn get_key_epochs(&self, owner_domain: &[u8; 32]) -> SidResult<KeyEpochs> {
        let mut conn = self.pool.acquire().await.map_err(storage("read"))?;
        Ok(KeyEpochs {
            epochs: owner_key_epochs(&mut conn, owner_domain, false).await?,
        })
    }

    async fn create_first_epoch(
        &self,
        new: &NewKeyEpoch,
        operation: uuid::Uuid,
        audit: AuditEntry,
    ) -> SidResult<KeyEpoch> {
        require_active(new)?;
        let mut tx = self.begin_write().await?;
        // The write lock serializes this with the cleanup: a preparation
        // that arrives after its operation was abandoned creates nothing.
        if abandoned(&mut tx, operation).await? {
            return Err(SidError::Fenced(format!(
                "first enrollment {operation} was aborted"
            )));
        }
        let existing = owner_key_epochs(&mut tx, &new.epoch.owner_domain, true).await?;
        if let [only] = existing.as_slice()
            && *only == new.epoch
        {
            return Ok(only.clone());
        }
        if !existing.is_empty() {
            return Err(SidError::Conflict(
                "the owner already has a history epoch".into(),
            ));
        }
        insert_key_epoch(&mut tx, new, Some(operation)).await?;
        key_audit(&mut tx, audit).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(new.epoch.clone())
    }

    async fn ensure_epoch(&self, new: &NewKeyEpoch, audit: AuditEntry) -> SidResult<KeyEpoch> {
        require_active(new)?;
        let mut tx = self.begin_write().await?;
        let existing = owner_key_epochs(&mut tx, &new.epoch.owner_domain, false).await?;
        if let Some(active) = existing
            .into_iter()
            .find(|e| e.status == HistoryEpochUse::Active)
        {
            return Ok(active);
        }
        insert_key_epoch(&mut tx, new, None).await?;
        key_audit(&mut tx, audit).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(new.epoch.clone())
    }

    async fn rotate_epoch(
        &self,
        new: &NewKeyEpoch,
        replaces: HistoryEpochId,
        replaced_at_revision: i64,
        audit: AuditEntry,
    ) -> SidResult<KeyEpoch> {
        require_active(new)?;
        if replaced_at_revision <= 0 {
            return Err(SidError::Validation(
                "a replacement revision is positive".into(),
            ));
        }
        let owner_domain = &new.epoch.owner_domain;
        let mut tx = self.begin_write().await?;
        let existing = owner_key_epochs(&mut tx, owner_domain, false).await?;
        if let Some(current) = existing
            .into_iter()
            .find(|e| e.status == HistoryEpochUse::Active)
            && current.id != replaces
        {
            return Ok(current);
        }
        sqlx::query(
            "UPDATE history_key_epochs SET status = 'compare_only'
             WHERE id = ? AND owner_domain = ? AND status = 'active'",
        )
        .bind(replaces.0.to_string())
        .bind(owner_domain.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(storage("epoch rotation"))?;
        insert_key_epoch(&mut tx, new, None).await?;
        sqlx::query(
            "INSERT INTO history_key_replaced (epoch_id, owner_domain, replaced_at_revision)
             VALUES (?, ?, ?) ON CONFLICT (epoch_id) DO NOTHING",
        )
        .bind(replaces.0.to_string())
        .bind(owner_domain.as_slice())
        .bind(replaced_at_revision)
        .execute(&mut *tx)
        .await
        .map_err(storage("epoch replacement"))?;
        key_audit(&mut tx, audit).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(new.epoch.clone())
    }

    async fn prepare_epochs(
        &self,
        prep: &HistoryPreparation,
        audit: AuditEntry,
    ) -> SidResult<Vec<KeyEpoch>> {
        let owner_domain = prep.owner_domain.as_slice();
        let mut tx = self.begin_write().await?;
        for epoch in &prep.live.live {
            let owned: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM history_key_epochs WHERE id = ? AND owner_domain = ?",
            )
            .bind(epoch.0.to_string())
            .bind(owner_domain)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("live set"))?;
            if owned.is_none() {
                return Err(SidError::Validation(
                    "the live set names an epoch that is not the owner's".into(),
                ));
            }
        }
        let live = live_text(&prep.live.live);
        sqlx::query(
            "INSERT INTO history_key_lifecycle (owner_domain, revision, live_epochs)
             VALUES (?, ?, ?) ON CONFLICT (owner_domain) DO NOTHING",
        )
        .bind(owner_domain)
        .bind(prep.live.revision)
        .bind(&live)
        .execute(&mut *tx)
        .await
        .map_err(storage("lifecycle row"))?;
        let (recorded, mut recorded_live): (i64, String) = sqlx::query_as(
            "SELECT revision, live_epochs FROM history_key_lifecycle WHERE owner_domain = ?",
        )
        .bind(owner_domain)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("lifecycle read"))?;
        let revision = match recorded.cmp(&prep.live.revision) {
            std::cmp::Ordering::Less => {
                sqlx::query(
                    "UPDATE history_key_lifecycle SET revision = ?, live_epochs = ?
                     WHERE owner_domain = ?",
                )
                .bind(prep.live.revision)
                .bind(&live)
                .bind(owner_domain)
                .execute(&mut *tx)
                .await
                .map_err(storage("lifecycle update"))?;
                recorded_live = live.clone();
                prep.live.revision
            }
            std::cmp::Ordering::Equal if recorded_live != live => {
                return Err(SidError::Conflict(format!(
                    "history revision {recorded} already has another live set"
                )));
            }
            _ => recorded,
        };
        sqlx::query("DELETE FROM history_key_uses WHERE owner_domain = ? AND expires_at <= ?")
            .bind(owner_domain)
            .bind(fmt_dt(&prep.now))
            .execute(&mut *tx)
            .await
            .map_err(storage("use expiry"))?;
        for operation in &prep.live.settled {
            sqlx::query("DELETE FROM history_key_uses WHERE owner_domain = ? AND operation_id = ?")
                .bind(owner_domain)
                .bind(operation.to_string())
                .execute(&mut *tx)
                .await
                .map_err(storage("use release"))?;
        }
        // `json_each` reads the recorded live set as rows.
        sqlx::query(
            "UPDATE history_key_epochs SET status = 'retired'
             WHERE owner_domain = ? AND status = 'compare_only'
               AND id IN (SELECT epoch_id FROM history_key_replaced
                          WHERE replaced_at_revision <= ?)
               AND id NOT IN (SELECT value FROM json_each(?))
               AND id NOT IN (SELECT epoch_id FROM history_key_uses)",
        )
        .bind(owner_domain)
        .bind(revision)
        .bind(&recorded_live)
        .execute(&mut *tx)
        .await
        .map_err(storage("epoch retirement"))?;
        let rows = sqlx::query(concat!(
            "SELECT ",
            key_epoch_columns!(),
            " FROM history_key_epochs
             WHERE owner_domain = ?
               AND (status = 'active'
                    OR (status = 'compare_only' AND id IN (SELECT value FROM json_each(?))))"
        ))
        .bind(owner_domain)
        .bind(&live)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage("selection"))?;
        let mut selected = rows
            .iter()
            .map(row_to_key_epoch)
            .collect::<SidResult<Vec<_>>>()?;
        // Active first, then by creation, as the PostgreSQL backend orders them:
        // compared in Rust, since mixed timestamp encodings do not sort as text.
        selected.sort_by_key(|e| (e.status != HistoryEpochUse::Active, e.created_at, e.id));
        let expires = fmt_dt(&prep.expires_at);
        for epoch in &selected {
            sqlx::query(
                "INSERT INTO history_key_uses (operation_id, epoch_id, owner_domain, expires_at)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT (operation_id, epoch_id) DO UPDATE SET expires_at = excluded.expires_at",
            )
            .bind(prep.operation.to_string())
            .bind(epoch.id.0.to_string())
            .bind(owner_domain)
            .bind(&expires)
            .execute(&mut *tx)
            .await
            .map_err(storage("use record"))?;
        }
        key_audit(&mut tx, audit).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(selected)
    }

    async fn abandon_enrollment(
        &self,
        owner_domain: &[u8; 32],
        operation: uuid::Uuid,
        audit: AuditEntry,
    ) -> SidResult<EnrollmentCleanup> {
        let op = operation.to_string();
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO history_key_abandoned (operation_id, owner_domain) VALUES (?, ?)
             ON CONFLICT (operation_id) DO NOTHING",
        )
        .bind(&op)
        .bind(owner_domain.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(storage("enrollment fence"))?;
        let fenced: Vec<u8> = sqlx::query_scalar(
            "SELECT owner_domain FROM history_key_abandoned WHERE operation_id = ?",
        )
        .bind(&op)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("enrollment fence"))?;
        if fenced != owner_domain.as_slice() {
            return Err(SidError::Validation(
                "the aborted enrollment was recorded for another owner".into(),
            ));
        }
        let created: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM history_key_epochs WHERE created_by = ? AND owner_domain = ?",
        )
        .bind(&op)
        .bind(owner_domain.as_slice())
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("enrollment epochs"))?;
        let outcome = if created == 0 {
            EnrollmentCleanup::NothingCreated
        } else {
            // A committed owner is what a lifecycle, another epoch or another
            // operation's use shows; any of them keeps the key.
            let (lifecycle, others, uses): (i64, i64, i64) = sqlx::query_as(
                "SELECT
                     (SELECT count(*) FROM history_key_lifecycle WHERE owner_domain = ?1),
                     (SELECT count(*) FROM history_key_epochs
                      WHERE owner_domain = ?1 AND created_by IS NOT ?2),
                     (SELECT count(*) FROM history_key_uses
                      WHERE owner_domain = ?1 AND operation_id <> ?2)",
            )
            .bind(owner_domain.as_slice())
            .bind(&op)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage("enrollment eligibility"))?;
            if lifecycle > 0 || others > 0 || uses > 0 {
                EnrollmentCleanup::Retained(format!(
                    "lifecycle recorded: {}, other epochs: {others}, other uses: {uses}",
                    lifecycle > 0
                ))
            } else {
                sqlx::query("DELETE FROM history_key_uses WHERE operation_id = ?")
                    .bind(&op)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage("enrollment uses"))?;
                sqlx::query(
                    "DELETE FROM history_key_epochs WHERE created_by = ? AND owner_domain = ?",
                )
                .bind(&op)
                .bind(owner_domain.as_slice())
                .execute(&mut *tx)
                .await
                .map_err(storage("enrollment key"))?;
                EnrollmentCleanup::Reclaimed
            }
        };
        key_audit(&mut tx, audit).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(outcome)
    }

    async fn enrollment_abandoned(&self, operation: uuid::Uuid) -> SidResult<bool> {
        let mut conn = self.pool.acquire().await.map_err(storage("read"))?;
        abandoned(&mut conn, operation).await
    }

    async fn get_epoch_key(&self, epoch: HistoryEpochId) -> SidResult<Option<WrappedHistoryKey>> {
        let key: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT wrapped_key FROM history_key_epochs WHERE id = ?")
                .bind(epoch.0.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(storage("epoch key"))?;
        Ok(key.map(WrappedHistoryKey))
    }

    async fn write_cutoff(&self) -> SidResult<Option<chrono::DateTime<chrono::Utc>>> {
        let mut conn = self.pool.acquire().await.map_err(storage("read"))?;
        read_cutoff(&mut conn, Cutoff::Evaluator).await
    }

    async fn raise_write_cutoff(
        &self,
        not_before: chrono::DateTime<chrono::Utc>,
        audit: AuditEntry,
    ) -> SidResult<chrono::DateTime<chrono::Utc>> {
        let mut tx = self.begin_write().await?;
        let (cutoff, moved) = raise_cutoff(&mut tx, Cutoff::Evaluator, not_before).await?;
        if moved {
            key_audit(&mut tx, audit).await?;
            tx.commit().await.map_err(storage("commit"))?;
        }
        Ok(cutoff)
    }

    async fn export_keys(&self, owner_domain: &[u8; 32]) -> SidResult<Option<KeyArchive>> {
        let mut tx = self.pool.begin().await.map_err(storage("archive read"))?;
        let archive = read_key_archive(&mut tx, owner_domain).await?;
        tx.commit().await.map_err(storage("archive read"))?;
        Ok(archive)
    }

    async fn import_keys(&self, archive: &KeyArchive, audit: AuditEntry) -> SidResult<bool> {
        archive.validate()?;
        let mut tx = self.begin_write().await?;
        if let Some(existing) = read_key_archive(&mut tx, &archive.owner_domain).await? {
            if existing == *archive {
                return Ok(false);
            }
            return Err(SidError::Conflict(
                "existing history keys differ from archive".into(),
            ));
        }
        for epoch in &archive.epochs {
            insert_key_epoch(&mut tx, epoch, None).await?;
        }
        for (epoch, revision) in &archive.replaced {
            sqlx::query(
                "INSERT INTO history_key_replaced (epoch_id, owner_domain, replaced_at_revision)
                 VALUES (?, ?, ?)",
            )
            .bind(epoch.0.to_string())
            .bind(archive.owner_domain.as_slice())
            .bind(revision)
            .execute(&mut *tx)
            .await
            .map_err(storage("archive replacement"))?;
        }
        key_audit(&mut tx, audit).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(true)
    }
}
