// SPDX-License-Identifier: AGPL-3.0-only
//! Private password history: per-owner epochs and retained entries. No
//! cryptography runs here; keys arrive sealed and tags never arrive at all.
//! Every write runs in a `BEGIN IMMEDIATE` transaction, which holds the
//! database write lock: two writers of one owner's history are serialized.

use sid_core::models::{
    HistoryArchive, HistoryCommit, HistoryEntry, HistoryEpoch, HistoryEpochId, HistoryEpochUse,
    HistoryEpochs, HistoryEvidence, HistoryKsf, HistoryPreparation, HistorySuite, NewHistoryEpoch,
    PasswordHistory, ProfileId, WrappedHistoryKey,
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

async fn read_archive(
    conn: &mut sqlx::SqliteConnection,
    owner: ProfileId,
) -> SidResult<Option<HistoryArchive>> {
    let revision: Option<i64> =
        sqlx::query_scalar("SELECT revision FROM password_histories WHERE owner_id = ?")
            .bind(owner)
            .fetch_optional(&mut *conn)
            .await
            .map_err(storage("archive revision"))?;
    let Some(revision) = revision else {
        return Ok(None);
    };
    let rows = sqlx::query(concat!(
        "SELECT ",
        epoch_columns!(),
        ", wrapped_key FROM password_history_epochs WHERE owner_id = ? ORDER BY created_at, id"
    ))
    .bind(owner)
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("archive epochs"))?;
    let mut epochs = rows
        .iter()
        .map(|row| {
            Ok(NewHistoryEpoch {
                epoch: row_to_epoch(row)?,
                key: WrappedHistoryKey(col(row, "wrapped_key")?),
            })
        })
        .collect::<SidResult<Vec<_>>>()?;
    // Old files may mix millisecond and microsecond text encodings. SQL's
    // lexical order is not temporal order across those representations.
    epochs.sort_by_key(|e| (e.epoch.created_at, e.epoch.id));
    let rows = sqlx::query("SELECT epoch_id, seq, entry, operation_id, policy_version, created_at FROM password_history_entries WHERE owner_id = ? ORDER BY seq DESC, epoch_id")
        .bind(owner).fetch_all(&mut *conn).await.map_err(storage("archive entries"))?;
    let entries = rows
        .iter()
        .map(row_to_entry)
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

/// The owner's revision and epochs not retired; `None` without history.
async fn read_epochs(
    conn: &mut sqlx::SqliteConnection,
    owner: ProfileId,
) -> SidResult<Option<HistoryEpochs>> {
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
        " FROM password_history_epochs
         WHERE owner_id = ? AND status <> 'retired' ORDER BY created_at, id"
    ))
    .bind(owner)
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("epochs"))?;
    Ok(Some(HistoryEpochs {
        revision,
        epochs: rows.iter().map(row_to_epoch).collect::<SidResult<_>>()?,
    }))
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
    // next seq, so those are the last `depth` seqs. An epoch emptied here is
    // retired by the evaluator, from the live set, never by this commit.
    sqlx::query("DELETE FROM password_history_entries WHERE owner_id = ? AND seq <= ?")
        .bind(owner)
        .bind(seq - i64::from(commit.depth))
        .execute(&mut **tx)
        .await
        .map_err(storage("retention"))?;
    Ok(true)
}

/// A live set as stored: a JSON array of epoch ids, sorted.
fn live_text(live: &[HistoryEpochId]) -> String {
    serde_json::to_string(&live.iter().map(|e| e.0.to_string()).collect::<Vec<_>>())
        .expect("a list of strings serializes")
}

/// The evaluator's side of preparing an operation; see
/// `StorageBackend::prepare_history_epochs`.
async fn prepare_epochs(
    tx: &mut WriteTx,
    prep: &HistoryPreparation,
) -> SidResult<Vec<HistoryEpoch>> {
    let owner = prep.owner;
    for epoch in &prep.live.live {
        let owned: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM password_history_epochs WHERE id = ? AND owner_id = ?",
        )
        .bind(epoch.0.to_string())
        .bind(owner)
        .fetch_optional(&mut **tx)
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
        "INSERT INTO password_history_lifecycle (owner_id, revision, live_epochs)
         SELECT id, ?, ? FROM profiles WHERE id = ?
         ON CONFLICT (owner_id) DO NOTHING",
    )
    .bind(prep.live.revision)
    .bind(&live)
    .bind(owner)
    .execute(&mut **tx)
    .await
    .map_err(storage("lifecycle row"))?;
    let recorded: Option<(i64, String)> = sqlx::query_as(
        "SELECT revision, live_epochs FROM password_history_lifecycle WHERE owner_id = ?",
    )
    .bind(owner)
    .fetch_optional(&mut **tx)
    .await
    .map_err(storage("lifecycle read"))?;
    let (recorded, mut recorded_live) =
        recorded.ok_or_else(|| SidError::NotFound(format!("profile {owner}")))?;
    let revision = match recorded.cmp(&prep.live.revision) {
        std::cmp::Ordering::Less => {
            sqlx::query(
                "UPDATE password_history_lifecycle SET revision = ?, live_epochs = ?
                 WHERE owner_id = ?",
            )
            .bind(prep.live.revision)
            .bind(&live)
            .bind(owner)
            .execute(&mut **tx)
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
    let now = fmt_dt(&prep.now);
    sqlx::query("DELETE FROM password_history_uses WHERE owner_id = ? AND expires_at <= ?")
        .bind(owner)
        .bind(&now)
        .execute(&mut **tx)
        .await
        .map_err(storage("use expiry"))?;
    for operation in &prep.live.settled {
        sqlx::query("DELETE FROM password_history_uses WHERE owner_id = ? AND operation_id = ?")
            .bind(owner)
            .bind(operation.to_string())
            .execute(&mut **tx)
            .await
            .map_err(storage("use release"))?;
    }
    // `json_each` reads the recorded live set as rows.
    sqlx::query(
        "UPDATE password_history_epochs SET status = 'retired'
         WHERE owner_id = ? AND status = 'compare_only'
           AND id IN (SELECT epoch_id FROM password_history_replaced
                      WHERE replaced_at_revision <= ?)
           AND id NOT IN (SELECT value FROM json_each(?))
           AND id NOT IN (SELECT epoch_id FROM password_history_uses)",
    )
    .bind(owner)
    .bind(revision)
    .bind(&recorded_live)
    .execute(&mut **tx)
    .await
    .map_err(storage("epoch retirement"))?;
    let rows = sqlx::query(concat!(
        "SELECT ",
        epoch_columns!(),
        " FROM password_history_epochs
         WHERE owner_id = ?
           AND (status = 'active'
                OR (status = 'compare_only' AND id IN (SELECT value FROM json_each(?))))"
    ))
    .bind(owner)
    .bind(&live)
    .fetch_all(&mut **tx)
    .await
    .map_err(storage("selection"))?;
    let mut selected = rows
        .iter()
        .map(row_to_epoch)
        .collect::<SidResult<Vec<_>>>()?;
    // Active first, then by creation, as the PostgreSQL backend orders them:
    // compared in Rust, since mixed timestamp encodings do not sort as text.
    selected.sort_by_key(|e| (e.status != HistoryEpochUse::Active, e.created_at, e.id));
    let expires = fmt_dt(&prep.expires_at);
    for epoch in &selected {
        sqlx::query(
            "INSERT INTO password_history_uses (operation_id, epoch_id, owner_id, expires_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT (operation_id, epoch_id) DO UPDATE SET expires_at = excluded.expires_at",
        )
        .bind(prep.operation.to_string())
        .bind(epoch.id.0.to_string())
        .bind(owner)
        .bind(&expires)
        .execute(&mut **tx)
        .await
        .map_err(storage("use record"))?;
    }
    Ok(selected)
}

impl SqliteBackend {
    pub(crate) async fn export_password_history_impl(
        &self,
        owner: ProfileId,
    ) -> SidResult<Option<HistoryArchive>> {
        let mut tx = self.pool.begin().await.map_err(storage("archive read"))?;
        let archive = read_archive(&mut tx, owner).await?;
        tx.commit().await.map_err(storage("archive read"))?;
        Ok(archive)
    }

    pub(crate) async fn import_password_history_impl(
        &self,
        archive: &HistoryArchive,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        archive.validate()?;
        let mut tx = self.begin_write().await?;
        let inserted = sqlx::query("INSERT INTO password_histories (owner_id, revision) VALUES (?, ?) ON CONFLICT (owner_id) DO NOTHING")
            .bind(archive.owner).bind(archive.revision).execute(&mut *tx).await.map_err(storage("archive insert"))?.rows_affected();
        if inserted == 0 {
            if read_archive(&mut tx, archive.owner).await?.as_ref() == Some(archive) {
                return Ok(false);
            }
            return Err(SidError::Conflict(
                "existing password history differs from archive".into(),
            ));
        }
        for epoch in &archive.epochs {
            insert_epoch(&mut tx, epoch).await?;
            // Replaced no later than the archive's revision: a live set at
            // least that new may retire it.
            if epoch.epoch.status == HistoryEpochUse::CompareOnly {
                sqlx::query(
                    "INSERT INTO password_history_replaced
                         (epoch_id, owner_id, replaced_at_revision) VALUES (?, ?, ?)",
                )
                .bind(epoch.epoch.id.0.to_string())
                .bind(archive.owner)
                .bind(archive.revision)
                .execute(&mut *tx)
                .await
                .map_err(storage("archive replacement"))?;
            }
        }
        for entry in &archive.entries {
            sqlx::query("INSERT INTO password_history_entries (epoch_id, owner_id, seq, entry, operation_id, policy_version, created_at) VALUES (?,?,?,?,?,?,?)")
                .bind(entry.epoch.0.to_string()).bind(archive.owner).bind(entry.seq).bind(entry.entry.as_slice())
                .bind(entry.evidence.operation.to_string()).bind(i64::from(entry.evidence.policy_version)).bind(fmt_dt(&entry.created_at))
                .execute(&mut *tx).await.map_err(storage("archive entry"))?;
        }
        Self::commit_mutation(tx, &format!("profile:{}", archive.owner), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn get_history_epochs_impl(
        &self,
        owner: ProfileId,
    ) -> SidResult<HistoryEpochs> {
        let mut tx = self.pool.begin().await.map_err(storage("read"))?;
        let epochs = read_epochs(&mut tx, owner).await?.unwrap_or_default();
        tx.commit().await.map_err(storage("read"))?;
        Ok(epochs)
    }

    pub(crate) async fn get_password_history_impl(
        &self,
        owner: ProfileId,
    ) -> SidResult<PasswordHistory> {
        // One read transaction: the revision and the rows it covers.
        let mut tx = self.pool.begin().await.map_err(storage("read"))?;
        let Some(HistoryEpochs { revision, epochs }) = read_epochs(&mut tx, owner).await? else {
            return Ok(PasswordHistory::default());
        };
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
            epochs,
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

    pub(crate) async fn rotate_history_epoch_impl(
        &self,
        new: &NewHistoryEpoch,
        replaces: HistoryEpochId,
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
            let current = row_to_epoch(&row)?;
            if current.id != replaces {
                return Ok(current);
            }
        }
        sqlx::query(
            "UPDATE password_history_epochs SET status = 'compare_only'
             WHERE id = ? AND owner_id = ? AND status = 'active'",
        )
        .bind(replaces.0.to_string())
        .bind(owner)
        .execute(&mut *tx)
        .await
        .map_err(storage("epoch rotation"))?;
        insert_epoch(&mut tx, new).await?;
        let revision: i64 = sqlx::query_scalar(
            "UPDATE password_histories SET revision = revision + 1 WHERE owner_id = ?
             RETURNING revision",
        )
        .bind(owner)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("revision"))?;
        // A live set read before this revision was read while the replaced
        // epoch could still take entries: it cannot retire it.
        sqlx::query(
            "INSERT INTO password_history_replaced (epoch_id, owner_id, replaced_at_revision)
             VALUES (?, ?, ?) ON CONFLICT (epoch_id) DO NOTHING",
        )
        .bind(replaces.0.to_string())
        .bind(owner)
        .bind(revision)
        .execute(&mut *tx)
        .await
        .map_err(storage("epoch replacement"))?;
        Self::commit_mutation(tx, &format!("profile:{owner}"), audit).await?;
        Ok(new.epoch.clone())
    }

    pub(crate) async fn prepare_history_epochs_impl(
        &self,
        prep: &HistoryPreparation,
        audit: sid_core::models::MutationContext,
    ) -> SidResult<Vec<HistoryEpoch>> {
        let mut tx = self.begin_write().await?;
        let selected = prepare_epochs(&mut tx, prep).await?;
        Self::commit_mutation(tx, &format!("profile:{}", prep.owner), audit).await?;
        Ok(selected)
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
