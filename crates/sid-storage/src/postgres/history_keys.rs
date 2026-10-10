// SPDX-License-Identifier: AGPL-3.0-only
//! The password-history evaluator's store on PostgreSQL: its own tables
//! (`history_key_*`), its own migrations and its own pool, so the evaluator can
//! run against a database and role that reach nothing else.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sid_core::models::{
    AuditEntry, HistoryEpochId, HistoryEpochUse, HistoryKsf, HistoryPreparation, HistorySuite,
    KeyArchive, KeyEpoch, KeyEpochs, NewKeyEpoch, WrappedHistoryKey,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::history_keys::HistoryKeyStore;
use sqlx::PgPool;
use uuid::Uuid;

use super::password_history::{fixed32, positive, signed, storage};

/// id, owner_domain, suite, public_key, memory, passes, lanes, salt, status, created_at
type KeyEpochRow = (
    Uuid,
    Vec<u8>,
    String,
    Vec<u8>,
    i32,
    i32,
    i32,
    Vec<u8>,
    String,
    DateTime<Utc>,
);

macro_rules! key_epoch_columns {
    () => {
        "id, owner_domain, suite, public_key, ksf_memory_kib, ksf_passes, \
         ksf_lanes, ksf_salt, status, created_at"
    };
}

fn key_epoch_from_row(row: KeyEpochRow) -> SidResult<KeyEpoch> {
    let (id, owner_domain, suite, public_key, memory, passes, lanes, salt, status, created_at) =
        row;
    Ok(KeyEpoch {
        id: HistoryEpochId(id),
        owner_domain: fixed32(owner_domain, "owner_domain")?,
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

/// The history evaluator's store over its own PostgreSQL pool.
#[derive(Clone)]
pub struct PgHistoryKeyStore {
    pool: PgPool,
}

impl PgHistoryKeyStore {
    /// The store over `pool`, whose migrations
    /// ([`crate::migrator::run_history_key_migrations`]) are applied.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The store in the evaluator's own database at `database_url`, apart
    /// from the credential service's. A schema is named in the URL
    /// (`options=-c search_path=...`).
    pub async fn connect(database_url: &str) -> SidResult<Self> {
        PgPool::connect(database_url)
            .await
            .map(Self::new)
            .map_err(|e| SidError::Storage(format!("history key store: {e}")))
    }

    /// Apply the store's own migrations to its database.
    pub async fn migrate(&self) -> SidResult<()> {
        crate::migrator::run_history_key_migrations(&self.pool).await
    }

    async fn begin(&self) -> SidResult<sqlx::Transaction<'static, sqlx::Postgres>> {
        self.pool.begin().await.map_err(storage("begin"))
    }
}

async fn audit_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    audit: AuditEntry,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO history_key_audit (actor_id, actor_type, action, resource, outcome, metadata)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&audit.actor_id)
    .bind(audit.actor_type.to_string())
    .bind(&audit.action)
    .bind(&audit.resource)
    .bind(audit.outcome.to_string())
    .bind(&audit.metadata)
    .execute(&mut **tx)
    .await
    .map_err(storage("audit"))?;
    Ok(())
}

async fn insert_key_epoch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    new: &NewKeyEpoch,
) -> SidResult<()> {
    let e = &new.epoch;
    sqlx::query(
        "INSERT INTO history_key_epochs (id, owner_domain, suite, public_key, wrapped_key,
             ksf_memory_kib, ksf_passes, ksf_lanes, ksf_salt, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(e.id.0)
    .bind(e.owner_domain.as_slice())
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
    .map_err(storage("key epoch insert"))?;
    Ok(())
}

/// Serialize every write of one owner: a transaction-scoped advisory lock on
/// the owner domain, since an owner may have no row to lock yet.
async fn lock_owner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner_domain: &[u8; 32],
) -> SidResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 43))")
        .bind(owner_domain.as_slice())
        .execute(&mut **tx)
        .await
        .map_err(storage("owner lock"))?;
    Ok(())
}

async fn active_epoch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner_domain: &[u8; 32],
) -> SidResult<Option<KeyEpoch>> {
    let row: Option<KeyEpochRow> = sqlx::query_as(concat!(
        "SELECT ",
        key_epoch_columns!(),
        " FROM history_key_epochs WHERE owner_domain = $1 AND status = 'active'"
    ))
    .bind(owner_domain.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(storage("active epoch"))?;
    row.map(key_epoch_from_row).transpose()
}

fn require_active(new: &NewKeyEpoch) -> SidResult<()> {
    if new.epoch.status != HistoryEpochUse::Active {
        return Err(SidError::Validation(
            "a prepared history epoch is active".into(),
        ));
    }
    Ok(())
}

async fn read_key_archive(
    conn: &mut sqlx::PgConnection,
    owner_domain: &[u8; 32],
) -> SidResult<Option<KeyArchive>> {
    let rows: Vec<KeyEpochRow> = sqlx::query_as(concat!(
        "SELECT ",
        key_epoch_columns!(),
        " FROM history_key_epochs WHERE owner_domain = $1 ORDER BY created_at, id"
    ))
    .bind(owner_domain.as_slice())
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("archive epochs"))?;
    if rows.is_empty() {
        return Ok(None);
    }
    let keys: Vec<(Uuid, Vec<u8>)> =
        sqlx::query_as("SELECT id, wrapped_key FROM history_key_epochs WHERE owner_domain = $1")
            .bind(owner_domain.as_slice())
            .fetch_all(&mut *conn)
            .await
            .map_err(storage("archive keys"))?;
    let mut keys: std::collections::BTreeMap<_, _> = keys.into_iter().collect();
    let epochs = rows
        .into_iter()
        .map(|row| {
            let epoch = key_epoch_from_row(row)?;
            let key = keys
                .remove(&epoch.id.0)
                .ok_or_else(|| SidError::Storage("missing history epoch key".into()))?;
            Ok(NewKeyEpoch {
                epoch,
                key: WrappedHistoryKey(key),
            })
        })
        .collect::<SidResult<Vec<_>>>()?;
    let replaced: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT epoch_id, replaced_at_revision FROM history_key_replaced
         WHERE owner_domain = $1 ORDER BY epoch_id",
    )
    .bind(owner_domain.as_slice())
    .fetch_all(&mut *conn)
    .await
    .map_err(storage("archive replacements"))?;
    let archive = KeyArchive {
        owner_domain: *owner_domain,
        epochs,
        replaced: replaced
            .into_iter()
            .map(|(epoch, revision)| (HistoryEpochId(epoch), revision))
            .collect(),
    };
    archive.validate()?;
    Ok(Some(archive))
}

#[async_trait]
impl HistoryKeyStore for PgHistoryKeyStore {
    async fn get_key_epochs(&self, owner_domain: &[u8; 32]) -> SidResult<KeyEpochs> {
        let rows: Vec<KeyEpochRow> = sqlx::query_as(concat!(
            "SELECT ",
            key_epoch_columns!(),
            " FROM history_key_epochs
             WHERE owner_domain = $1 AND status <> 'retired' ORDER BY created_at, id"
        ))
        .bind(owner_domain.as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(storage("key epochs"))?;
        Ok(KeyEpochs {
            epochs: rows
                .into_iter()
                .map(key_epoch_from_row)
                .collect::<SidResult<_>>()?,
        })
    }

    async fn create_first_epoch(
        &self,
        new: &NewKeyEpoch,
        audit: AuditEntry,
    ) -> SidResult<KeyEpoch> {
        require_active(new)?;
        let owner_domain = &new.epoch.owner_domain;
        let mut tx = self.begin().await?;
        lock_owner(&mut tx, owner_domain).await?;
        let existing: Vec<KeyEpochRow> = sqlx::query_as(concat!(
            "SELECT ",
            key_epoch_columns!(),
            " FROM history_key_epochs WHERE owner_domain = $1"
        ))
        .bind(owner_domain.as_slice())
        .fetch_all(&mut *tx)
        .await
        .map_err(storage("owner epochs"))?;
        if let [only] = existing.as_slice() {
            let only = key_epoch_from_row(only.clone())?;
            if only == new.epoch {
                return Ok(only);
            }
        }
        if !existing.is_empty() {
            return Err(SidError::Conflict(
                "the owner already has a history epoch".into(),
            ));
        }
        insert_key_epoch(&mut tx, new).await?;
        audit_in_tx(&mut tx, audit).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(new.epoch.clone())
    }

    async fn ensure_epoch(&self, new: &NewKeyEpoch, audit: AuditEntry) -> SidResult<KeyEpoch> {
        require_active(new)?;
        let mut tx = self.begin().await?;
        lock_owner(&mut tx, &new.epoch.owner_domain).await?;
        if let Some(active) = active_epoch(&mut tx, &new.epoch.owner_domain).await? {
            return Ok(active);
        }
        insert_key_epoch(&mut tx, new).await?;
        audit_in_tx(&mut tx, audit).await?;
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
        let mut tx = self.begin().await?;
        lock_owner(&mut tx, owner_domain).await?;
        if let Some(current) = active_epoch(&mut tx, owner_domain).await?
            && current.id != replaces
        {
            return Ok(current);
        }
        sqlx::query(
            "UPDATE history_key_epochs SET status = 'compare_only'
             WHERE id = $1 AND owner_domain = $2 AND status = 'active'",
        )
        .bind(replaces.0)
        .bind(owner_domain.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(storage("epoch rotation"))?;
        insert_key_epoch(&mut tx, new).await?;
        sqlx::query(
            "INSERT INTO history_key_replaced (epoch_id, owner_domain, replaced_at_revision)
             VALUES ($1, $2, $3) ON CONFLICT (epoch_id) DO NOTHING",
        )
        .bind(replaces.0)
        .bind(owner_domain.as_slice())
        .bind(replaced_at_revision)
        .execute(&mut *tx)
        .await
        .map_err(storage("epoch replacement"))?;
        audit_in_tx(&mut tx, audit).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(new.epoch.clone())
    }

    async fn prepare_epochs(
        &self,
        prep: &HistoryPreparation,
        audit: AuditEntry,
    ) -> SidResult<Vec<KeyEpoch>> {
        let owner_domain = prep.owner_domain.as_slice();
        let live: Vec<Uuid> = prep.live.live.iter().map(|e| e.0).collect();
        let mut tx = self.begin().await?;
        lock_owner(&mut tx, &prep.owner_domain).await?;
        let foreign: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM unnest($2::uuid[]) AS l(id)
             WHERE NOT EXISTS (SELECT 1 FROM history_key_epochs e
                               WHERE e.id = l.id AND e.owner_domain = $1)",
        )
        .bind(owner_domain)
        .bind(&live)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("live set"))?;
        if foreign > 0 {
            return Err(SidError::Validation(
                "the live set names an epoch that is not the owner's".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO history_key_lifecycle (owner_domain, revision, live_epochs)
             VALUES ($1, $2, $3) ON CONFLICT (owner_domain) DO NOTHING",
        )
        .bind(owner_domain)
        .bind(prep.live.revision)
        .bind(&live)
        .execute(&mut *tx)
        .await
        .map_err(storage("lifecycle row"))?;
        let (recorded, mut recorded_live): (i64, Vec<Uuid>) = sqlx::query_as(
            "SELECT revision, live_epochs FROM history_key_lifecycle WHERE owner_domain = $1",
        )
        .bind(owner_domain)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("lifecycle read"))?;
        let revision = match recorded.cmp(&prep.live.revision) {
            std::cmp::Ordering::Less => {
                sqlx::query(
                    "UPDATE history_key_lifecycle SET revision = $2, live_epochs = $3
                     WHERE owner_domain = $1",
                )
                .bind(owner_domain)
                .bind(prep.live.revision)
                .bind(&live)
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
        sqlx::query(
            "DELETE FROM history_key_uses
             WHERE owner_domain = $1 AND (operation_id = ANY($2) OR expires_at <= $3)",
        )
        .bind(owner_domain)
        .bind(&prep.live.settled)
        .bind(prep.now)
        .execute(&mut *tx)
        .await
        .map_err(storage("use release"))?;
        sqlx::query(
            "UPDATE history_key_epochs e SET status = 'retired'
             FROM history_key_replaced r
             WHERE r.epoch_id = e.id AND e.owner_domain = $1 AND e.status = 'compare_only'
               AND r.replaced_at_revision <= $2
               AND NOT (e.id = ANY($3))
               AND NOT EXISTS (SELECT 1 FROM history_key_uses u WHERE u.epoch_id = e.id)",
        )
        .bind(owner_domain)
        .bind(revision)
        .bind(&recorded_live)
        .execute(&mut *tx)
        .await
        .map_err(storage("epoch retirement"))?;
        let rows: Vec<KeyEpochRow> = sqlx::query_as(concat!(
            "SELECT ",
            key_epoch_columns!(),
            " FROM history_key_epochs
             WHERE owner_domain = $1
               AND (status = 'active' OR (status = 'compare_only' AND id = ANY($2)))
             ORDER BY status <> 'active', created_at, id"
        ))
        .bind(owner_domain)
        .bind(&live)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage("selection"))?;
        let selected = rows
            .into_iter()
            .map(key_epoch_from_row)
            .collect::<SidResult<Vec<_>>>()?;
        for epoch in &selected {
            sqlx::query(
                "INSERT INTO history_key_uses (operation_id, epoch_id, owner_domain, expires_at)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (operation_id, epoch_id) DO UPDATE SET expires_at = EXCLUDED.expires_at",
            )
            .bind(prep.operation)
            .bind(epoch.id.0)
            .bind(owner_domain)
            .bind(prep.expires_at)
            .execute(&mut *tx)
            .await
            .map_err(storage("use record"))?;
        }
        audit_in_tx(&mut tx, audit).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(selected)
    }

    async fn get_epoch_key(&self, epoch: HistoryEpochId) -> SidResult<Option<WrappedHistoryKey>> {
        let key: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT wrapped_key FROM history_key_epochs WHERE id = $1")
                .bind(epoch.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage("epoch key"))?;
        Ok(key.map(WrappedHistoryKey))
    }

    async fn write_cutoff(&self) -> SidResult<Option<DateTime<Utc>>> {
        sqlx::query_scalar("SELECT not_before FROM history_key_write_cutoff")
            .fetch_one(&self.pool)
            .await
            .map_err(storage("write cutoff"))
    }

    async fn raise_write_cutoff(
        &self,
        not_before: DateTime<Utc>,
        audit: AuditEntry,
    ) -> SidResult<DateTime<Utc>> {
        let not_before = sid_core::models::password_history::write_cutoff_instant(not_before);
        let mut tx = self.begin().await?;
        let current: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT not_before FROM history_key_write_cutoff FOR UPDATE")
                .fetch_one(&mut *tx)
                .await
                .map_err(storage("write cutoff"))?;
        if let Some(current) = current
            && current >= not_before
        {
            return Ok(current);
        }
        sqlx::query("UPDATE history_key_write_cutoff SET not_before = $1")
            .bind(not_before)
            .execute(&mut *tx)
            .await
            .map_err(storage("write cutoff raise"))?;
        audit_in_tx(&mut tx, audit).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(not_before)
    }

    async fn export_keys(&self, owner_domain: &[u8; 32]) -> SidResult<Option<KeyArchive>> {
        let mut tx = self.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(storage("archive read"))?;
        let archive = read_key_archive(&mut tx, owner_domain).await?;
        tx.commit().await.map_err(storage("archive read"))?;
        Ok(archive)
    }

    async fn import_keys(&self, archive: &KeyArchive, audit: AuditEntry) -> SidResult<bool> {
        archive.validate()?;
        let mut tx = self.begin().await?;
        lock_owner(&mut tx, &archive.owner_domain).await?;
        if let Some(existing) = read_key_archive(&mut tx, &archive.owner_domain).await? {
            if existing == *archive {
                return Ok(false);
            }
            return Err(SidError::Conflict(
                "existing history keys differ from archive".into(),
            ));
        }
        for epoch in &archive.epochs {
            insert_key_epoch(&mut tx, epoch).await?;
        }
        for (epoch, revision) in &archive.replaced {
            sqlx::query(
                "INSERT INTO history_key_replaced (epoch_id, owner_domain, replaced_at_revision)
                 VALUES ($1, $2, $3)",
            )
            .bind(epoch.0)
            .bind(archive.owner_domain.as_slice())
            .bind(revision)
            .execute(&mut *tx)
            .await
            .map_err(storage("archive replacement"))?;
        }
        audit_in_tx(&mut tx, audit).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(true)
    }
}
