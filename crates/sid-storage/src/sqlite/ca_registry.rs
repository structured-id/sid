// SPDX-License-Identifier: AGPL-3.0-only
//! CA generations and their lifecycle (`CaRegistry`) for the SQLite backend.
//! Every transition runs under the database write lock (`BEGIN IMMEDIATE`),
//! which orders it with every other transition of every scope.

use async_trait::async_trait;
use sid_core::models::{
    CaGeneration, CaGenerationId, CaScope, CaState, KeyCustody, MutationContext, NewCaGeneration,
    OrgId, RecoveryConfirmation, SerialAllocation, ca_generation_chain, ca_retirement_entry,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::CaRegistry;
use sqlx::sqlite::SqliteRow;

use super::{SqliteBackend, WriteTx, col, dt_col, dt_col_opt, fmt_dt, uuid_col};

/// The scope's columns; a deployment stores the empty organization.
fn scope_columns(scope: CaScope) -> (&'static str, String) {
    match scope {
        CaScope::Deployment => ("deployment", String::new()),
        CaScope::Organization(org) => ("organization", org.into_uuid().to_string()),
    }
}

fn custody(sealed: Option<Vec<u8>>, external: Option<String>) -> SidResult<KeyCustody> {
    match (sealed, external) {
        (Some(s), None) => Ok(KeyCustody::Sealed(s)),
        (None, Some(e)) => Ok(KeyCustody::External(e)),
        _ => Err(SidError::Storage("CA key needs exactly one custody".into())),
    }
}

fn custody_columns(key: &KeyCustody) -> (Option<&[u8]>, Option<&str>) {
    match key {
        KeyCustody::Sealed(s) => (Some(s.as_slice()), None),
        KeyCustody::External(e) => (None, Some(e.as_str())),
    }
}

fn confirmation(row: &SqliteRow, prefix: &str) -> SidResult<Option<RecoveryConfirmation>> {
    let reference: Option<String> = col(row, &format!("{prefix}_ref"))?;
    let by: Option<String> = col(row, &format!("{prefix}_by"))?;
    let at = dt_col_opt(row, &format!("{prefix}_at"))?;
    Ok(match (reference, by, at) {
        (Some(reference), Some(confirmed_by), Some(confirmed_at)) => Some(RecoveryConfirmation {
            reference,
            confirmed_by,
            confirmed_at,
        }),
        (None, None, None) => None,
        _ => {
            return Err(SidError::Storage(format!(
                "partial CA {prefix} confirmation"
            )));
        }
    })
}

fn unsigned(value: i64, what: &str) -> SidResult<u64> {
    u64::try_from(value).map_err(|_| SidError::Storage(format!("negative CA {what}")))
}

fn generation_of(row: &SqliteRow) -> SidResult<CaGeneration> {
    let kind: String = col(row, "scope_kind")?;
    let org: String = col(row, "scope_org")?;
    let scope = match (kind.as_str(), org.as_str()) {
        ("deployment", "") => CaScope::Deployment,
        ("organization", org) => {
            let uuid = uuid::Uuid::parse_str(org)
                .map_err(|e| SidError::Storage(format!("column scope_org: {e}")))?;
            CaScope::Organization(
                OrgId::from_uuid(uuid).map_err(|e| SidError::Storage(format!("CA scope: {e}")))?,
            )
        }
        _ => return Err(SidError::Storage("malformed CA scope".into())),
    };
    let key = custody(col(row, "key_sealed")?, col(row, "key_external")?)?;
    let state: String = col(row, "state")?;
    let generation: i64 = col(row, "generation")?;
    Ok(CaGeneration {
        id: CaGenerationId(uuid_col(row, "id")?),
        scope,
        generation: u32::try_from(generation)
            .map_err(|_| SidError::Storage("CA generation out of range".into()))?,
        key,
        certificate: col(row, "certificate")?,
        database_recovery: confirmation(row, "database_recovery")?,
        key_recovery: confirmation(row, "key_recovery")?,
        state: CaState::parse(&state)
            .ok_or_else(|| SidError::Storage(format!("unknown CA state {state}")))?,
        revision: unsigned(col(row, "revision")?, "revision")?,
        last_serial: unsigned(col(row, "last_serial")?, "serial")?,
        prepared_at: dt_col(row, "prepared_at")?,
    })
}

/// A static generation query: every column, then `$filter`.
macro_rules! select {
    ($filter:literal) => {
        concat!(
            "SELECT id, scope_kind, scope_org, generation, key_sealed, key_external, \
             certificate, \
             database_recovery_ref, database_recovery_by, database_recovery_at, \
             key_recovery_ref, key_recovery_by, key_recovery_at, state, revision, \
             last_serial, prepared_at FROM ca_generations ",
            $filter
        )
    };
}

async fn stored(tx: &mut WriteTx, id: CaGenerationId) -> SidResult<Option<CaGeneration>> {
    sqlx::query(select!("WHERE id = ?"))
        .bind(id.0.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| SidError::Storage(format!("read CA generation: {e}")))?
        .as_ref()
        .map(generation_of)
        .transpose()
}

async fn existing(tx: &mut WriteTx, id: CaGenerationId) -> SidResult<CaGeneration> {
    stored(tx, id)
        .await?
        .ok_or_else(|| SidError::NotFound(format!("CA generation {id}")))
}

fn conflict(id: CaGenerationId, why: &str) -> SidError {
    SidError::Conflict(format!("CA generation {id}: {why}"))
}

/// Which recovery confirmation a call records.
#[derive(Clone, Copy)]
enum Recovery {
    Database,
    Keys,
}

impl SqliteBackend {
    /// Commit the transition and return the generation as it now stands.
    async fn commit_transition(
        mut tx: WriteTx,
        id: CaGenerationId,
        ctx: MutationContext,
    ) -> SidResult<CaGeneration> {
        let g = existing(&mut tx, id).await?;
        Self::commit_mutation(tx, &ca_generation_chain(id), ctx).await?;
        Ok(g)
    }

    async fn confirm_recovery(
        &self,
        id: CaGenerationId,
        expected_revision: u64,
        recovery: Recovery,
        given: &RecoveryConfirmation,
        ctx: MutationContext,
    ) -> SidResult<CaGeneration> {
        let mut tx = self.begin_write().await?;
        let g = existing(&mut tx, id).await?;
        let recorded = match recovery {
            Recovery::Database => &g.database_recovery,
            Recovery::Keys => &g.key_recovery,
        };
        if recorded.as_ref().is_some_and(|r| r.is_same(given)) {
            return Ok(g);
        }
        if g.state != CaState::Prepared || g.certificate.is_none() || recorded.is_some() {
            return Err(conflict(
                id,
                "not a certified, unconfirmed prepared generation",
            ));
        }
        if g.revision != expected_revision {
            return Err(conflict(id, "stale revision"));
        }
        let sql = match recovery {
            Recovery::Database => {
                "UPDATE ca_generations SET database_recovery_ref = ?, database_recovery_by = ?, \
                 database_recovery_at = ?, revision = revision + 1 WHERE id = ?"
            }
            Recovery::Keys => {
                "UPDATE ca_generations SET key_recovery_ref = ?, key_recovery_by = ?, \
                 key_recovery_at = ?, revision = revision + 1 WHERE id = ?"
            }
        };
        sqlx::query(sql)
            .bind(&given.reference)
            .bind(&given.confirmed_by)
            .bind(fmt_dt(&given.confirmed_at))
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("confirm CA recovery: {e}")))?;
        Self::commit_transition(tx, id, ctx).await
    }
}

#[async_trait]
impl CaRegistry for SqliteBackend {
    async fn prepare_generation(
        &self,
        new: &NewCaGeneration,
        ctx: MutationContext,
    ) -> SidResult<CaGeneration> {
        let mut tx = self.begin_write().await?;
        if let Some(stored) = stored(&mut tx, new.id).await? {
            return if stored.scope == new.scope && stored.key == new.key {
                Ok(stored)
            } else {
                Err(conflict(new.id, "prepared with other content"))
            };
        }
        let (kind, org) = scope_columns(new.scope);
        let next: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(generation), 0) + 1 FROM ca_generations \
             WHERE scope_kind = ? AND scope_org = ?",
        )
        .bind(kind)
        .bind(&org)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("number CA generation: {e}")))?;
        let (key_sealed, key_external) = custody_columns(&new.key);
        sqlx::query(
            "INSERT INTO ca_generations (id, scope_kind, scope_org, generation, \
             key_sealed, key_external, state, revision, prepared_at) \
             VALUES (?, ?, ?, ?, ?, ?, 'prepared', 1, ?)",
        )
        .bind(new.id.0.to_string())
        .bind(kind)
        .bind(&org)
        .bind(next)
        .bind(key_sealed)
        .bind(key_external)
        .bind(fmt_dt(&chrono::Utc::now()))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("CA generation", e))?;
        Self::commit_transition(tx, new.id, ctx).await
    }

    async fn ca_generation(&self, id: CaGenerationId) -> SidResult<Option<CaGeneration>> {
        sqlx::query(select!("WHERE id = ?"))
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("read CA generation: {e}")))?
            .as_ref()
            .map(generation_of)
            .transpose()
    }

    async fn current_ca_generation(&self, scope: CaScope) -> SidResult<Option<CaGeneration>> {
        let (kind, org) = scope_columns(scope);
        sqlx::query(select!(
            "WHERE scope_kind = ? AND scope_org = ? AND state = 'current'"
        ))
        .bind(kind)
        .bind(org)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("read current CA generation: {e}")))?
        .as_ref()
        .map(generation_of)
        .transpose()
    }

    async fn record_ca_certificate(
        &self,
        id: CaGenerationId,
        expected_revision: u64,
        certificate: &[u8],
        ctx: MutationContext,
    ) -> SidResult<CaGeneration> {
        let mut tx = self.begin_write().await?;
        let g = existing(&mut tx, id).await?;
        if let Some(stored) = &g.certificate {
            return if stored.as_slice() == certificate {
                Ok(g)
            } else {
                Err(conflict(id, "already certified with another certificate"))
            };
        }
        if g.state != CaState::Prepared {
            return Err(conflict(id, "not prepared"));
        }
        if g.revision != expected_revision {
            return Err(conflict(id, "stale revision"));
        }
        sqlx::query(
            "UPDATE ca_generations SET certificate = ?, revision = revision + 1 WHERE id = ?",
        )
        .bind(certificate)
        .bind(id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("record CA certificate: {e}")))?;
        Self::commit_transition(tx, id, ctx).await
    }

    async fn confirm_database_recovery(
        &self,
        id: CaGenerationId,
        expected_revision: u64,
        confirmation: &RecoveryConfirmation,
        ctx: MutationContext,
    ) -> SidResult<CaGeneration> {
        self.confirm_recovery(id, expected_revision, Recovery::Database, confirmation, ctx)
            .await
    }

    async fn confirm_key_recovery(
        &self,
        id: CaGenerationId,
        expected_revision: u64,
        confirmation: &RecoveryConfirmation,
        ctx: MutationContext,
    ) -> SidResult<CaGeneration> {
        self.confirm_recovery(id, expected_revision, Recovery::Keys, confirmation, ctx)
            .await
    }

    async fn activate_ca_generation(
        &self,
        id: CaGenerationId,
        expected_revision: u64,
        ctx: MutationContext,
    ) -> SidResult<CaGeneration> {
        let mut tx = self.begin_write().await?;
        let g = existing(&mut tx, id).await?;
        if g.state == CaState::Current {
            return Ok(g);
        }
        if !g.activatable() {
            return Err(conflict(id, "not certified and recovery-confirmed"));
        }
        if g.revision != expected_revision {
            return Err(conflict(id, "stale revision"));
        }
        let (kind, org) = scope_columns(g.scope);
        let retired: Vec<String> = sqlx::query_scalar(
            "UPDATE ca_generations SET state = 'retired', revision = revision + 1 \
             WHERE scope_kind = ? AND scope_org = ? AND state = 'current' RETURNING id",
        )
        .bind(kind)
        .bind(org)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("retire CA generation: {e}")))?;
        // The retired generation's own chain records its retirement; the
        // operation completion and owed work stay with the activation.
        for retired in retired {
            let retired = CaGenerationId(
                uuid::Uuid::parse_str(&retired)
                    .map_err(|e| SidError::Storage(format!("CA generation id: {e}")))?,
            );
            super::SqliteAuditLog::log_in_conn(
                &mut tx,
                &ca_generation_chain(retired),
                ca_retirement_entry(&ctx.audit, retired, id),
            )
            .await
            .map_err(|e| SidError::Storage(format!("Audit log failed: {e}")))?;
        }
        sqlx::query(
            "UPDATE ca_generations SET state = 'current', revision = revision + 1 WHERE id = ?",
        )
        .bind(id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("activate CA generation: {e}")))?;
        Self::commit_transition(tx, id, ctx).await
    }

    async fn revoke_ca_generation(
        &self,
        id: CaGenerationId,
        ctx: MutationContext,
    ) -> SidResult<CaGeneration> {
        let mut tx = self.begin_write().await?;
        let g = existing(&mut tx, id).await?;
        if g.state == CaState::Revoked {
            return Ok(g);
        }
        sqlx::query(
            "UPDATE ca_generations SET state = 'revoked', revision = revision + 1 WHERE id = ?",
        )
        .bind(id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("revoke CA generation: {e}")))?;
        Self::commit_transition(tx, id, ctx).await
    }

    async fn allocate_ca_serial(
        &self,
        id: CaGenerationId,
        expected_revision: u64,
    ) -> SidResult<SerialAllocation> {
        let Ok(revision) = i64::try_from(expected_revision) else {
            return Err(conflict(id, "stale revision"));
        };
        let allocated: Option<(i64, i64)> = sqlx::query_as(
            "UPDATE ca_generations SET last_serial = last_serial + 1 \
             WHERE id = ? AND state = 'current' AND revision = ? \
             RETURNING last_serial, revision",
        )
        .bind(id.0.to_string())
        .bind(revision)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("allocate CA serial: {e}")))?;
        match allocated {
            Some((serial, revision)) => Ok(SerialAllocation {
                generation: id,
                revision: unsigned(revision, "revision")?,
                serial: unsigned(serial, "serial")?,
            }),
            None => match self.ca_generation(id).await? {
                None => Err(SidError::NotFound(format!("CA generation {id}"))),
                Some(_) => Err(conflict(id, "not current at the expected revision")),
            },
        }
    }
}
