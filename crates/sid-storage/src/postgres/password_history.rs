// SPDX-License-Identifier: AGPL-3.0-only
//! Private password history: per-owner epochs and retained entries. No
//! cryptography runs here; keys arrive sealed and tags never arrive at all.

use chrono::{DateTime, Utc};
use sid_core::models::{
    HistoryArchive, HistoryCommit, HistoryEntry, HistoryEpoch, HistoryEpochId, HistoryEpochUse,
    HistoryEpochs, HistoryEvidence, HistoryKsf, HistorySuite, NewHistoryEpoch, PasswordHistory,
    ProfileId, WrappedHistoryKey,
};
use sid_core::{Error as SidError, Result as SidResult};
use sqlx::PgPool;
use uuid::Uuid;

fn storage(what: &str) -> impl FnOnce(sqlx::Error) -> SidError + '_ {
    move |e| SidError::Storage(format!("password history {what}: {e}"))
}

fn fixed32(bytes: Vec<u8>, column: &str) -> SidResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| SidError::Storage(format!("column {column}: not 32 bytes")))
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
    let positive = |v: i32, column: &str| {
        u32::try_from(v)
            .ok()
            .filter(|v| *v > 0)
            .ok_or_else(|| SidError::Storage(format!("column {column}: not positive")))
    };
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

/// Refuse an incomplete comparison set before reading or publishing history.
/// Migration never writes this inventory concurrently with serving; live
/// replacement still checks it in its own transaction, not just at Begin.
pub(super) async fn require_current_format(
    conn: &mut sqlx::PgConnection,
    owner: ProfileId,
) -> SidResult<()> {
    let legacy: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM password_history_legacy WHERE owner_id = $1)",
    )
    .bind(owner)
    .fetch_one(&mut *conn)
    .await
    .map_err(storage("legacy inventory"))?;
    if legacy {
        return Err(SidError::InvalidState(
            "unconverted password history requires reconciliation".into(),
        ));
    }
    Ok(())
}

async fn read_archive(
    conn: &mut sqlx::PgConnection,
    owner: ProfileId,
) -> SidResult<Option<HistoryArchive>> {
    require_current_format(conn, owner).await?;
    let revision: Option<i64> =
        sqlx::query_scalar("SELECT revision FROM password_histories WHERE owner_id = $1")
            .bind(owner)
            .fetch_optional(&mut *conn)
            .await
            .map_err(storage("archive revision"))?;
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
    .map_err(storage("archive epochs"))?;
    let keys: Vec<(Uuid, Vec<u8>)> =
        sqlx::query_as("SELECT id, wrapped_key FROM password_history_epochs WHERE owner_id = $1")
            .bind(owner)
            .fetch_all(&mut *conn)
            .await
            .map_err(storage("archive keys"))?;
    let mut keys: std::collections::BTreeMap<_, _> = keys.into_iter().collect();
    let epochs = epochs
        .into_iter()
        .map(|row| {
            let epoch = epoch_from_row(row)?;
            let key = keys
                .remove(&epoch.id.0)
                .ok_or_else(|| SidError::Storage("missing history epoch key".into()))?;
            Ok(NewHistoryEpoch {
                epoch,
                key: WrappedHistoryKey(key),
            })
        })
        .collect::<SidResult<Vec<_>>>()?;
    let rows: Vec<EntryRow> = sqlx::query_as("SELECT epoch_id, seq, entry, operation_id, policy_version, created_at FROM password_history_entries WHERE owner_id = $1 ORDER BY seq DESC, epoch_id")
        .bind(owner).fetch_all(&mut *conn).await.map_err(storage("archive entries"))?;
    let entries = rows
        .into_iter()
        .map(|(epoch, seq, entry, operation, version, created_at)| {
            Ok(HistoryEntry {
                epoch: HistoryEpochId(epoch),
                seq,
                entry: fixed32(entry, "entry")?,
                evidence: HistoryEvidence {
                    operation,
                    policy_version: u32::try_from(version)
                        .map_err(|_| SidError::Storage("negative policy version".into()))?,
                },
                created_at,
            })
        })
        .collect::<SidResult<Vec<_>>>()?;
    let archive = HistoryArchive {
        owner,
        revision,
        epochs,
        entries,
    };
    archive.validate()?;
    Ok(Some(archive))
}

pub(super) async fn export_archive(
    pool: &PgPool,
    owner: ProfileId,
) -> SidResult<Option<HistoryArchive>> {
    let mut tx = pool.begin().await.map_err(storage("archive read"))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(storage("archive read"))?;
    let archive = read_archive(&mut tx, owner).await?;
    tx.commit().await.map_err(storage("archive read"))?;
    Ok(archive)
}

pub(super) async fn import_archive(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    archive: &HistoryArchive,
) -> SidResult<bool> {
    archive.validate()?;
    // Reconciliation of old-format rows is required even when no current
    // history row exists; a restore must not turn that state into fresh history.
    read_archive(tx, archive.owner).await?;
    let inserted = sqlx::query("INSERT INTO password_histories (owner_id, revision) VALUES ($1, $2) ON CONFLICT (owner_id) DO NOTHING")
        .bind(archive.owner).bind(archive.revision).execute(&mut **tx).await.map_err(storage("archive insert"))?.rows_affected();
    if inserted == 0 {
        sqlx::query("SELECT owner_id FROM password_histories WHERE owner_id = $1 FOR UPDATE")
            .bind(archive.owner)
            .fetch_one(&mut **tx)
            .await
            .map_err(storage("archive lock"))?;
        if read_archive(tx, archive.owner).await?.as_ref() == Some(archive) {
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
        sqlx::query("INSERT INTO password_history_entries (epoch_id, owner_id, seq, entry, operation_id, policy_version, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(entry.epoch.0).bind(archive.owner).bind(entry.seq).bind(entry.entry.as_slice())
            .bind(entry.evidence.operation).bind(entry.evidence.policy_version as i32).bind(entry.created_at)
            .execute(&mut **tx).await.map_err(storage("archive entry"))?;
    }
    Ok(true)
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

/// The owner's revision and epochs not retired; `None` without history.
async fn read_epochs(
    conn: &mut sqlx::PgConnection,
    owner: ProfileId,
) -> SidResult<Option<HistoryEpochs>> {
    require_current_format(conn, owner).await?;
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
        " FROM password_history_epochs
         WHERE owner_id = $1 AND status <> 'retired' ORDER BY created_at, id"
    ))
    .bind(owner)
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("epochs"))?;
    Ok(Some(HistoryEpochs {
        revision,
        epochs: epochs
            .into_iter()
            .map(epoch_from_row)
            .collect::<SidResult<_>>()?,
    }))
}

pub(super) async fn epochs(pool: &PgPool, owner: ProfileId) -> SidResult<HistoryEpochs> {
    let mut tx = snapshot(pool).await?;
    let epochs = read_epochs(&mut tx, owner).await?.unwrap_or_default();
    tx.commit().await.map_err(storage("read"))?;
    Ok(epochs)
}

pub(super) async fn get(pool: &PgPool, owner: ProfileId) -> SidResult<PasswordHistory> {
    let mut tx = snapshot(pool).await?;
    let Some(HistoryEpochs { revision, epochs }) = read_epochs(&mut tx, owner).await? else {
        return Ok(PasswordHistory::default());
    };
    let entries: Vec<EntryRow> = sqlx::query_as(
        "SELECT epoch_id, seq, entry, operation_id, policy_version, created_at
         FROM password_history_entries WHERE owner_id = $1 ORDER BY seq DESC, epoch_id",
    )
    .bind(owner)
    .fetch_all(&mut *tx)
    .await
    .map_err(storage("entries"))?;
    tx.commit().await.map_err(storage("read"))?;

    Ok(PasswordHistory {
        revision,
        epochs,
        entries: entries
            .into_iter()
            .map(
                |(epoch, seq, entry, operation, policy_version, created_at)| {
                    Ok(HistoryEntry {
                        epoch: HistoryEpochId(epoch),
                        seq,
                        entry: fixed32(entry, "entry")?,
                        evidence: HistoryEvidence {
                            operation,
                            policy_version: u32::try_from(policy_version).map_err(|_| {
                                SidError::Storage("column policy_version: negative".into())
                            })?,
                        },
                        created_at,
                    })
                },
            )
            .collect::<SidResult<_>>()?,
    })
}

/// Insert `new` as its owner's epoch inside `tx`.
async fn insert_epoch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    new: &NewHistoryEpoch,
) -> SidResult<()> {
    let e = &new.epoch;
    let signed = |v: u32, what: &str| {
        i32::try_from(v).map_err(|_| SidError::Validation(format!("{what} out of range")))
    };
    sqlx::query(
        "INSERT INTO password_history_epochs (id, owner_id, suite, public_key, wrapped_key,
             ksf_memory_kib, ksf_passes, ksf_lanes, ksf_salt, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(e.id.0)
    .bind(e.owner)
    .bind(e.suite.as_str())
    .bind(e.public_key.as_slice())
    .bind(new.key.0.as_slice())
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

/// The owner's history row, locked for this transaction; created at
/// revision 1 when absent. `NotFound` when the owner does not exist.
async fn lock_history(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: ProfileId,
) -> SidResult<i64> {
    sqlx::query(
        "INSERT INTO password_histories (owner_id, revision)
         SELECT id, 1 FROM profiles WHERE id = $1
         ON CONFLICT (owner_id) DO NOTHING",
    )
    .bind(owner)
    .execute(&mut **tx)
    .await
    .map_err(storage("history row"))?;
    sqlx::query_scalar("SELECT revision FROM password_histories WHERE owner_id = $1 FOR UPDATE")
        .bind(owner)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage("history lock"))?
        .ok_or_else(|| SidError::NotFound(format!("profile {owner}")))
}

pub(super) async fn ensure_epoch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    new: &NewHistoryEpoch,
) -> SidResult<HistoryEpoch> {
    let owner = new.epoch.owner;
    if new.epoch.status != HistoryEpochUse::Active {
        return Err(SidError::Validation(
            "a prepared history epoch is active".into(),
        ));
    }
    require_current_format(tx, owner).await?;
    lock_history(tx, owner).await?;
    let existing: Option<EpochRow> = sqlx::query_as(concat!(
        "SELECT ",
        epoch_columns!(),
        " FROM password_history_epochs WHERE owner_id = $1 AND status = 'active'"
    ))
    .bind(owner)
    .fetch_optional(&mut **tx)
    .await
    .map_err(storage("active epoch"))?;
    if let Some(row) = existing {
        return epoch_from_row(row);
    }
    insert_epoch(tx, new).await?;
    sqlx::query("UPDATE password_histories SET revision = revision + 1 WHERE owner_id = $1")
        .bind(owner)
        .execute(&mut **tx)
        .await
        .map_err(storage("revision"))?;
    Ok(new.epoch.clone())
}

pub(super) async fn epoch_key(
    pool: &PgPool,
    epoch: HistoryEpochId,
) -> SidResult<Option<WrappedHistoryKey>> {
    let key: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT wrapped_key FROM password_history_epochs WHERE id = $1")
            .bind(epoch.0)
            .fetch_optional(pool)
            .await
            .map_err(storage("epoch key"))?;
    Ok(key.map(WrappedHistoryKey))
}

/// Apply `commit` inside `tx`. `Ok(false)` when the owner's history is no
/// longer at `commit.expected_revision`: the caller rolls back everything.
pub(super) async fn apply_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    commit: &HistoryCommit,
) -> SidResult<bool> {
    commit.validate()?;
    let owner = commit.owner;
    require_current_format(tx, owner).await?;
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
    if let Some(new) = &commit.new_epoch {
        insert_epoch(tx, new).await?;
    }
    let seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM password_history_entries WHERE owner_id = $1",
    )
    .bind(owner)
    .fetch_one(&mut **tx)
    .await
    .map_err(storage("next seq"))?;
    let now = Utc::now();
    let policy_version = i32::try_from(commit.evidence.policy_version)
        .map_err(|_| SidError::Validation("policy version out of range".into()))?;
    for (epoch, entry) in &commit.entries {
        // Only the owner's active epoch takes new entries.
        let inserted = sqlx::query(
            "INSERT INTO password_history_entries
                 (epoch_id, owner_id, seq, entry, operation_id, policy_version, created_at)
             SELECT id, owner_id, $3, $4, $5, $6, $7 FROM password_history_epochs
             WHERE id = $1 AND owner_id = $2 AND status = 'active'",
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
        .map_err(storage("entry insert"))?
        .rows_affected();
        if inserted == 0 {
            return Ok(false);
        }
    }
    // Retain the newest `depth` accepted passwords; every commit takes the
    // next seq, so those are the last `depth` seqs.
    sqlx::query("DELETE FROM password_history_entries WHERE owner_id = $1 AND seq <= $2")
        .bind(owner)
        .bind(seq - i64::from(commit.depth))
        .execute(&mut **tx)
        .await
        .map_err(storage("retention"))?;
    retire_unused(tx, owner).await?;
    Ok(true)
}

/// Retire every compare-only epoch of `owner` that retains no entry and
/// destroy its sealed key: nothing will be compared or written under it again,
/// and the epoch row stays only as provenance.
async fn retire_unused(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: ProfileId,
) -> SidResult<()> {
    sqlx::query(
        "UPDATE password_history_epochs e SET status = 'retired', wrapped_key = ''::bytea
         WHERE e.owner_id = $1 AND e.status = 'compare_only'
           AND NOT EXISTS (SELECT 1 FROM password_history_entries x WHERE x.epoch_id = e.id)",
    )
    .bind(owner)
    .execute(&mut **tx)
    .await
    .map_err(storage("epoch retirement"))?;
    Ok(())
}

pub(super) async fn rotate_epoch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    new: &NewHistoryEpoch,
    replaces: HistoryEpochId,
) -> SidResult<HistoryEpoch> {
    let owner = new.epoch.owner;
    if new.epoch.status != HistoryEpochUse::Active {
        return Err(SidError::Validation(
            "a prepared history epoch is active".into(),
        ));
    }
    require_current_format(tx, owner).await?;
    lock_history(tx, owner).await?;
    let active: Option<EpochRow> = sqlx::query_as(concat!(
        "SELECT ",
        epoch_columns!(),
        " FROM password_history_epochs WHERE owner_id = $1 AND status = 'active'"
    ))
    .bind(owner)
    .fetch_optional(&mut **tx)
    .await
    .map_err(storage("active epoch"))?;
    if let Some(row) = active {
        let current = epoch_from_row(row)?;
        if current.id != replaces {
            return Ok(current);
        }
    }
    sqlx::query(
        "UPDATE password_history_epochs SET status = 'compare_only'
         WHERE id = $1 AND owner_id = $2 AND status = 'active'",
    )
    .bind(replaces.0)
    .bind(owner)
    .execute(&mut **tx)
    .await
    .map_err(storage("epoch rotation"))?;
    retire_unused(tx, owner).await?;
    insert_epoch(tx, new).await?;
    sqlx::query("UPDATE password_histories SET revision = revision + 1 WHERE owner_id = $1")
        .bind(owner)
        .execute(&mut **tx)
        .await
        .map_err(storage("revision"))?;
    Ok(new.epoch.clone())
}
