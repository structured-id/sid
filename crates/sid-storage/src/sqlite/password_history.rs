// SPDX-License-Identifier: AGPL-3.0-only
//! Private password history: per-owner epochs and retained entries. No
//! cryptography runs here; keys arrive sealed and tags never arrive at all.
//! Every write runs in a `BEGIN IMMEDIATE` transaction, which holds the
//! database write lock: two writers of one owner's history are serialized.

use sid_core::models::{
    HistoryCommit, HistoryEntry, HistoryEpoch, HistoryEpochId, HistoryEpochUse, HistoryEvidence,
    HistoryKsf, HistorySuite, NewHistoryEpoch, PasswordHistory, ProfileId, WrappedHistoryKey,
};
use sid_core::{Error as SidError, Result as SidResult};

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

/// The epoch columns [`row_to_epoch`] reads, as a literal for static queries.
macro_rules! epoch_columns {
    () => {
        "id, owner_id, suite, public_key, ksf_memory_kib, ksf_passes, \
         ksf_lanes, ksf_salt, status, created_at"
    };
}

fn row_to_epoch(row: &sqlx::sqlite::SqliteRow) -> SidResult<HistoryEpoch> {
    Ok(HistoryEpoch {
        id: HistoryEpochId(uuid_col(row, "id")?),
        owner: col(row, "owner_id")?,
        suite: HistorySuite::parse(&col::<String>(row, "suite")?)?,
        public_key: fixed32(row, "public_key")?,
        ksf: HistoryKsf {
            memory_kib: positive(row, "ksf_memory_kib")?,
            passes: positive(row, "ksf_passes")?,
            lanes: positive(row, "ksf_lanes")?,
        },
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

async fn insert_epoch(tx: &mut WriteTx, new: &NewHistoryEpoch) -> SidResult<()> {
    let e = &new.epoch;
    sqlx::query(
        "INSERT INTO password_history_epochs (id, owner_id, suite, public_key, wrapped_key,
             ksf_memory_kib, ksf_passes, ksf_lanes, ksf_salt, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(e.id.0.to_string())
    .bind(e.owner)
    .bind(e.suite.as_str())
    .bind(e.public_key.as_slice())
    .bind(new.key.0.as_slice())
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

/// Apply `commit` inside `tx`. `Ok(false)` when the owner's history is no
/// longer at `commit.expected_revision`: the caller drops everything.
pub(super) async fn apply_in_tx(tx: &mut WriteTx, commit: &HistoryCommit) -> SidResult<bool> {
    commit.validate()?;
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
    if let Some(new) = &commit.new_epoch {
        insert_epoch(tx, new).await?;
    }
    let seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM password_history_entries WHERE owner_id = ?",
    )
    .bind(owner)
    .fetch_one(&mut **tx)
    .await
    .map_err(storage("next seq"))?;
    let now = fmt_dt(&chrono::Utc::now());
    for (epoch, entry) in &commit.entries {
        // Only the owner's active epoch takes new entries.
        let inserted = sqlx::query(
            "INSERT INTO password_history_entries
                 (epoch_id, owner_id, seq, entry, operation_id, policy_version, created_at)
             SELECT id, owner_id, ?, ?, ?, ?, ? FROM password_history_epochs
             WHERE id = ? AND owner_id = ? AND status = 'active'",
        )
        .bind(seq)
        .bind(entry.as_slice())
        .bind(commit.evidence.operation.to_string())
        .bind(i64::from(commit.evidence.policy_version))
        .bind(&now)
        .bind(epoch.0.to_string())
        .bind(owner)
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
    sqlx::query("DELETE FROM password_history_entries WHERE owner_id = ? AND seq <= ?")
        .bind(owner)
        .bind(seq - i64::from(commit.depth))
        .execute(&mut **tx)
        .await
        .map_err(storage("retention"))?;
    sqlx::query(
        "UPDATE password_history_epochs SET status = 'retired'
         WHERE owner_id = ? AND status = 'compare_only'
           AND NOT EXISTS (SELECT 1 FROM password_history_entries x
                           WHERE x.epoch_id = password_history_epochs.id)",
    )
    .bind(owner)
    .execute(&mut **tx)
    .await
    .map_err(storage("epoch retirement"))?;
    Ok(true)
}

impl SqliteBackend {
    pub(crate) async fn get_password_history_impl(
        &self,
        owner: ProfileId,
    ) -> SidResult<PasswordHistory> {
        // One read transaction: the revision and the rows it covers.
        let mut tx = self.pool.begin().await.map_err(storage("read"))?;
        let revision: Option<i64> =
            sqlx::query_scalar("SELECT revision FROM password_histories WHERE owner_id = ?")
                .bind(owner)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage("revision"))?;
        let Some(revision) = revision else {
            return Ok(PasswordHistory::default());
        };
        let epochs = sqlx::query(concat!(
            "SELECT ",
            epoch_columns!(),
            " FROM password_history_epochs
             WHERE owner_id = ? AND status <> 'retired' ORDER BY created_at, id"
        ))
        .bind(owner)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage("epochs"))?;
        let entries = sqlx::query(
            "SELECT epoch_id, seq, entry, operation_id, policy_version, created_at
             FROM password_history_entries WHERE owner_id = ? ORDER BY seq DESC, epoch_id",
        )
        .bind(owner)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage("entries"))?;
        tx.commit().await.map_err(storage("read"))?;
        Ok(PasswordHistory {
            revision,
            epochs: epochs.iter().map(row_to_epoch).collect::<SidResult<_>>()?,
            entries: entries.iter().map(row_to_entry).collect::<SidResult<_>>()?,
        })
    }

    pub(crate) async fn ensure_history_epoch_impl(
        &self,
        new: &NewHistoryEpoch,
        audit: sid_core::models::MutationContext,
    ) -> SidResult<HistoryEpoch> {
        if new.epoch.status != HistoryEpochUse::Active {
            return Err(SidError::Validation(
                "a prepared history epoch is active".into(),
            ));
        }
        let owner = new.epoch.owner;
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO password_histories (owner_id, revision)
             SELECT id, 1 FROM profiles WHERE id = ?
             ON CONFLICT (owner_id) DO NOTHING",
        )
        .bind(owner)
        .execute(&mut *tx)
        .await
        .map_err(storage("history row"))?;
        let exists: Option<i64> =
            sqlx::query_scalar("SELECT revision FROM password_histories WHERE owner_id = ?")
                .bind(owner)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage("history row"))?;
        if exists.is_none() {
            return Err(SidError::NotFound(format!("profile {owner}")));
        }
        let active = sqlx::query(concat!(
            "SELECT ",
            epoch_columns!(),
            " FROM password_history_epochs WHERE owner_id = ? AND status = 'active'"
        ))
        .bind(owner)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("active epoch"))?;
        if let Some(row) = active {
            return row_to_epoch(&row);
        }
        insert_epoch(&mut tx, new).await?;
        sqlx::query("UPDATE password_histories SET revision = revision + 1 WHERE owner_id = ?")
            .bind(owner)
            .execute(&mut *tx)
            .await
            .map_err(storage("revision"))?;
        Self::commit_mutation(tx, &format!("profile:{owner}"), audit).await?;
        Ok(new.epoch.clone())
    }

    pub(crate) async fn get_history_epoch_key_impl(
        &self,
        epoch: HistoryEpochId,
    ) -> SidResult<Option<WrappedHistoryKey>> {
        let key: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT wrapped_key FROM password_history_epochs WHERE id = ?")
                .bind(epoch.0.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(storage("epoch key"))?;
        Ok(key.map(WrappedHistoryKey))
    }
}
