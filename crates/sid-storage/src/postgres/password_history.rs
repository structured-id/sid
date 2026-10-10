// SPDX-License-Identifier: AGPL-3.0-only
//! Private password history, the credential service's side: per-owner epoch
//! descriptors and retained entries. No key is stored here and no tag ever
//! arrives; the evaluator keeps its keys in its own store.

use chrono::{DateTime, Utc};
use sid_core::models::{
    HistoryArchive, HistoryCommit, HistoryEntry, HistoryEpoch, HistoryEpochDescriptor,
    HistoryEpochId, HistoryEpochUse, HistoryEvidence, HistoryKsf, HistorySuite, PasswordHistory,
    ProfileId,
};
use sid_core::{Error as SidError, Result as SidResult};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) fn storage(what: &str) -> impl FnOnce(sqlx::Error) -> SidError + '_ {
    move |e| SidError::Storage(format!("password history {what}: {e}"))
}

pub(super) fn fixed32(bytes: Vec<u8>, column: &str) -> SidResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| SidError::Storage(format!("column {column}: not 32 bytes")))
}

pub(super) fn positive(v: i32, column: &str) -> SidResult<u32> {
    u32::try_from(v)
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| SidError::Storage(format!("column {column}: not positive")))
}

pub(super) fn signed(v: u32, what: &str) -> SidResult<i32> {
    i32::try_from(v).map_err(|_| SidError::Validation(format!("{what} out of range")))
}

/// id, owner, suite, public_key, memory, passes, lanes, salt, status, created_at
type EpochRow = (
    Uuid,
    Uuid,
    String,
    Vec<u8>,
    i32,
    i32,
    i32,
    Vec<u8>,
    String,
    DateTime<Utc>,
);

/// epoch_id, seq, entry, operation_id, policy_version, created_at
type EntryRow = (Uuid, i64, Vec<u8>, Uuid, i32, DateTime<Utc>);

/// The epoch columns [`EpochRow`] reads, as a literal for static queries.
macro_rules! epoch_columns {
    () => {
        "id, owner_id, suite, public_key, ksf_memory_kib, ksf_passes, \
         ksf_lanes, ksf_salt, status, created_at"
    };
}

fn epoch_from_row(row: EpochRow) -> SidResult<HistoryEpoch> {
    let (id, owner, suite, public_key, memory, passes, lanes, salt, status, created_at) = row;
    Ok(HistoryEpoch {
        id: HistoryEpochId(id),
        owner: ProfileId::from_uuid(owner)
            .map_err(|e| SidError::Storage(format!("column owner_id: {e}")))?,
        suite: HistorySuite::parse(&suite)?,
        public_key: fixed32(public_key, "public_key")?,
        ksf: HistoryKsf {
            memory_kib: positive(memory, "ksf_memory_kib")?,
            passes: positive(passes, "ksf_passes")?,
            lanes: positive(lanes, "ksf_lanes")?,
        },
        ksf_salt: fixed32(salt, "ksf_salt")?,
        status: HistoryEpochUse::parse(&status)?,
        created_at,
    })
}

fn entry_from_row(row: EntryRow) -> SidResult<HistoryEntry> {
    let (epoch, seq, entry, operation, policy_version, created_at) = row;
    Ok(HistoryEntry {
        epoch: HistoryEpochId(epoch),
        seq,
        entry: fixed32(entry, "entry")?,
        evidence: HistoryEvidence {
            operation,
            policy_version: u32::try_from(policy_version)
                .map_err(|_| SidError::Storage("column policy_version: negative".into()))?,
        },
        created_at,
    })
}

/// The owner's revision, every epoch and every entry; `None` without history.
async fn read(
    conn: &mut sqlx::PgConnection,
    owner: ProfileId,
) -> SidResult<Option<(i64, Vec<HistoryEpoch>, Vec<HistoryEntry>)>> {
    let revision: Option<i64> =
        sqlx::query_scalar("SELECT revision FROM password_histories WHERE owner_id = $1")
            .bind(owner)
            .fetch_optional(&mut *conn)
            .await
            .map_err(storage("revision"))?;
    let Some(revision) = revision else {
        return Ok(None);
    };
    let epochs: Vec<EpochRow> = sqlx::query_as(concat!(
        "SELECT ",
        epoch_columns!(),
        " FROM password_history_epochs WHERE owner_id = $1 ORDER BY created_at, id"
    ))
    .bind(owner)
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("epochs"))?;
    let entries: Vec<EntryRow> = sqlx::query_as(
        "SELECT epoch_id, seq, entry, operation_id, policy_version, created_at
         FROM password_history_entries WHERE owner_id = $1 ORDER BY seq DESC, epoch_id",
    )
    .bind(owner)
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("entries"))?;
    Ok(Some((
        revision,
        epochs
            .into_iter()
            .map(epoch_from_row)
            .collect::<SidResult<_>>()?,
        entries
            .into_iter()
            .map(entry_from_row)
            .collect::<SidResult<_>>()?,
    )))
}

/// A read-only snapshot transaction: a revision and the rows it covers.
async fn snapshot(pool: &PgPool) -> SidResult<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = pool.begin().await.map_err(storage("read"))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(storage("read"))?;
    Ok(tx)
}

pub(super) async fn get(pool: &PgPool, owner: ProfileId) -> SidResult<PasswordHistory> {
    let mut tx = snapshot(pool).await?;
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

pub(super) async fn export_archive(
    pool: &PgPool,
    owner: ProfileId,
) -> SidResult<Option<HistoryArchive>> {
    let mut tx = snapshot(pool).await?;
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

pub(super) async fn import_archive(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    archive: &HistoryArchive,
) -> SidResult<bool> {
    archive.validate()?;
    let inserted = sqlx::query(
        "INSERT INTO password_histories (owner_id, revision) VALUES ($1, $2)
         ON CONFLICT (owner_id) DO NOTHING",
    )
    .bind(archive.owner)
    .bind(archive.revision)
    .execute(&mut **tx)
    .await
    .map_err(storage("archive insert"))?
    .rows_affected();
    if inserted == 0 {
        sqlx::query("SELECT owner_id FROM password_histories WHERE owner_id = $1 FOR UPDATE")
            .bind(archive.owner)
            .fetch_one(&mut **tx)
            .await
            .map_err(storage("archive lock"))?;
        let existing = read(tx, archive.owner)
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
        insert_epoch(tx, epoch).await?;
    }
    for entry in &archive.entries {
        sqlx::query(
            "INSERT INTO password_history_entries
                 (epoch_id, owner_id, seq, entry, operation_id, policy_version, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(entry.epoch.0)
        .bind(archive.owner)
        .bind(entry.seq)
        .bind(entry.entry.as_slice())
        .bind(entry.evidence.operation)
        .bind(signed(entry.evidence.policy_version, "policy version")?)
        .bind(entry.created_at)
        .execute(&mut **tx)
        .await
        .map_err(storage("archive entry"))?;
    }
    Ok(true)
}

/// Insert `epoch` as its owner's epoch descriptor inside `tx`.
async fn insert_epoch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &HistoryEpoch,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO password_history_epochs (id, owner_id, suite, public_key,
             ksf_memory_kib, ksf_passes, ksf_lanes, ksf_salt, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(e.id.0)
    .bind(e.owner)
    .bind(e.suite.as_str())
    .bind(e.public_key.as_slice())
    .bind(signed(e.ksf.memory_kib, "KSF memory")?)
    .bind(signed(e.ksf.passes, "KSF passes")?)
    .bind(signed(e.ksf.lanes, "KSF lanes")?)
    .bind(e.ksf_salt.as_slice())
    .bind(e.status.as_str())
    .bind(e.created_at)
    .execute(&mut **tx)
    .await
    .map_err(storage("epoch insert"))?;
    Ok(())
}

/// Record the descriptor `d` for `owner` unless it is recorded already; one
/// recorded with any other immutable field, or for another owner, is a
/// `Conflict`: the evaluator never issues two descriptors for one epoch.
async fn record_descriptor(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: ProfileId,
    d: &HistoryEpochDescriptor,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO password_history_epochs (id, owner_id, suite, public_key,
             ksf_memory_kib, ksf_passes, ksf_lanes, ksf_salt, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'compare_only', $9)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(d.id.0)
    .bind(owner)
    .bind(d.suite.as_str())
    .bind(d.public_key.as_slice())
    .bind(signed(d.ksf.memory_kib, "KSF memory")?)
    .bind(signed(d.ksf.passes, "KSF passes")?)
    .bind(signed(d.ksf.lanes, "KSF lanes")?)
    .bind(d.ksf_salt.as_slice())
    .bind(d.created_at)
    .execute(&mut **tx)
    .await
    .map_err(storage("descriptor insert"))?;
    let row: EpochRow = sqlx::query_as(concat!(
        "SELECT ",
        epoch_columns!(),
        " FROM password_history_epochs WHERE id = $1"
    ))
    .bind(d.id.0)
    .fetch_one(&mut **tx)
    .await
    .map_err(storage("descriptor read"))?;
    let recorded = epoch_from_row(row)?;
    if recorded.owner != owner || recorded.descriptor() != *d {
        return Err(SidError::Conflict(format!(
            "history epoch {} is recorded with another descriptor",
            d.id.0
        )));
    }
    Ok(())
}

/// Apply `commit` inside `tx`. `Ok(false)` when the owner's history is no
/// longer at `commit.expected_revision`: the caller rolls back everything.
pub(super) async fn apply_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    commit: &HistoryCommit,
) -> SidResult<bool> {
    commit.validate()?;
    // The write cutoff first, shared: a raise holds this row exclusively, so
    // a raise and a commit are serialized in one order on every path.
    let not_before: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT not_before FROM password_history_write_cutoff FOR SHARE")
            .fetch_one(&mut **tx)
            .await
            .map_err(storage("write cutoff"))?;
    commit.check_write_cutoff(not_before)?;
    let owner = commit.owner;
    if commit.expected_revision == 0 {
        // First history of this owner: whoever creates the row owns revision 1.
        let created = sqlx::query(
            "INSERT INTO password_histories (owner_id, revision) VALUES ($1, 1)
             ON CONFLICT (owner_id) DO NOTHING",
        )
        .bind(owner)
        .execute(&mut **tx)
        .await
        .map_err(storage("history row"))?
        .rows_affected();
        if created == 0 {
            return Ok(false);
        }
    } else {
        let moved = sqlx::query(
            "UPDATE password_histories SET revision = revision + 1
             WHERE owner_id = $1 AND revision = $2",
        )
        .bind(owner)
        .bind(commit.expected_revision)
        .execute(&mut **tx)
        .await
        .map_err(storage("revision"))?
        .rows_affected();
        if moved == 0 {
            return Ok(false);
        }
    }
    // The operation's epochs as the evaluator described them, published with
    // the entries. The revision fence above makes this the newest selection,
    // so the first becomes the owner's one active epoch and every other
    // epoch it named, or that was active, compare-only.
    for d in &commit.epochs {
        record_descriptor(tx, owner, d).await?;
    }
    let now = Utc::now();
    let active = commit.epochs[0].id.0;
    sqlx::query(
        "UPDATE password_history_epochs SET status = 'compare_only'
         WHERE owner_id = $1 AND status = 'active' AND id <> $2",
    )
    .bind(owner)
    .bind(active)
    .execute(&mut **tx)
    .await
    .map_err(storage("epoch status"))?;
    sqlx::query("UPDATE password_history_epochs SET status = 'active' WHERE id = $1")
        .bind(active)
        .execute(&mut **tx)
        .await
        .map_err(storage("epoch status"))?;
    let seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM password_history_entries WHERE owner_id = $1",
    )
    .bind(owner)
    .fetch_one(&mut **tx)
    .await
    .map_err(storage("next seq"))?;
    let policy_version = signed(commit.evidence.policy_version, "policy version")?;
    for (epoch, entry) in &commit.entries {
        sqlx::query(
            "INSERT INTO password_history_entries
                 (epoch_id, owner_id, seq, entry, operation_id, policy_version, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(epoch.0)
        .bind(owner)
        .bind(seq)
        .bind(entry.as_slice())
        .bind(commit.evidence.operation)
        .bind(policy_version)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(storage("entry insert"))?;
    }
    // Retain the newest `depth` accepted passwords; every commit takes the
    // next seq, so those are the last `depth` seqs. An epoch emptied here is
    // retired by the evaluator, from the live set, never by this commit.
    sqlx::query("DELETE FROM password_history_entries WHERE owner_id = $1 AND seq <= $2")
        .bind(owner)
        .bind(seq - i64::from(commit.depth))
        .execute(&mut **tx)
        .await
        .map_err(storage("retention"))?;
    // Age retention, under the same revision fence: older accepted passwords
    // go, the newest (this commit's) always stays.
    if let Some(before) = commit.expires_before(now) {
        sqlx::query(
            "DELETE FROM password_history_entries
             WHERE owner_id = $1 AND seq < $2 AND created_at < $3",
        )
        .bind(owner)
        .bind(seq)
        .bind(before)
        .execute(&mut **tx)
        .await
        .map_err(storage("age retention"))?;
    }
    Ok(true)
}
