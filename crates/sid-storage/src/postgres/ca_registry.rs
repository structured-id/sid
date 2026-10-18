// SPDX-License-Identifier: AGPL-3.0-only
//! CA generations and their lifecycle (`CaRegistry`). Transitions of one scope
//! are serialized by a transaction-scoped advisory lock on the scope; the
//! partial unique index keeps at most one current generation per scope even
//! so.

use async_trait::async_trait;
use sid_core::models::{
    CaGeneration, CaGenerationId, CaScope, CaState, KeyCustody, MutationContext, NewCaGeneration,
    OrgId, RecoveryConfirmation, SerialAllocation,
};
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::CaRegistry;
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use super::PostgresBackend;

type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

fn storage(context: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{context}: {e}"))
}

fn scope_columns(scope: CaScope) -> (&'static str, Option<Uuid>) {
    match scope {
        CaScope::Deployment => ("deployment", None),
        CaScope::Organization(org) => ("organization", Some(org.into_uuid())),
    }
}

/// Serialize the scope's transitions for the rest of the transaction.
async fn lock_scope(tx: &mut Tx<'_>, scope: CaScope) -> SidResult<()> {
    let key = match scope {
        CaScope::Deployment => "sid.ca:deployment".to_string(),
        CaScope::Organization(org) => format!("sid.ca:org:{}", org.into_uuid()),
    };
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(key)
        .execute(&mut **tx)
        .await
        .map_err(storage("lock CA scope"))?;
    Ok(())
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

fn confirmation(
    reference: Option<String>,
    by: Option<String>,
    at: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<RecoveryConfirmation> {
    Some(RecoveryConfirmation {
        reference: reference?,
        confirmed_by: by?,
        confirmed_at: at?,
    })
}

fn unsigned(value: i64, what: &str) -> SidResult<u64> {
    u64::try_from(value).map_err(|_| SidError::Storage(format!("negative CA {what}")))
}

fn generation_of(row: &PgRow) -> SidResult<CaGeneration> {
    let get = storage("read CA generation");
    let scope = match (
        row.try_get::<String, _>("scope_kind")
            .map_err(&get)?
            .as_str(),
        row.try_get::<Option<Uuid>, _>("scope_org").map_err(&get)?,
    ) {
        ("deployment", None) => CaScope::Deployment,
        ("organization", Some(org)) => CaScope::Organization(
            OrgId::from_uuid(org).map_err(|e| SidError::Storage(format!("CA scope: {e}")))?,
        ),
        _ => return Err(SidError::Storage("malformed CA scope".into())),
    };
    let key = custody(
        row.try_get("key_sealed").map_err(&get)?,
        row.try_get("key_external").map_err(&get)?,
    )?;
    let state: String = row.try_get("state").map_err(&get)?;
    let generation: i32 = row.try_get("generation").map_err(&get)?;
    Ok(CaGeneration {
        id: CaGenerationId(row.try_get("id").map_err(&get)?),
        scope,
        generation: u32::try_from(generation)
            .map_err(|_| SidError::Storage("negative CA generation".into()))?,
        key,
        certificate: row.try_get("certificate").map_err(&get)?,
        database_recovery: confirmation(
            row.try_get("database_recovery_ref").map_err(&get)?,
            row.try_get("database_recovery_by").map_err(&get)?,
            row.try_get("database_recovery_at").map_err(&get)?,
        ),
        key_recovery: confirmation(
            row.try_get("key_recovery_ref").map_err(&get)?,
            row.try_get("key_recovery_by").map_err(&get)?,
            row.try_get("key_recovery_at").map_err(&get)?,
        ),
        state: CaState::parse(&state)
            .ok_or_else(|| SidError::Storage(format!("unknown CA state {state}")))?,
        revision: unsigned(row.try_get("revision").map_err(&get)?, "revision")?,
        last_serial: unsigned(row.try_get("last_serial").map_err(&get)?, "serial")?,
        prepared_at: row.try_get("prepared_at").map_err(&get)?,
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

async fn locked(tx: &mut Tx<'_>, id: CaGenerationId) -> SidResult<CaGeneration> {
    let row = sqlx::query(select!("WHERE id = $1 FOR UPDATE"))
        .bind(id.0)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage("read CA generation"))?
        .ok_or_else(|| SidError::NotFound(format!("CA generation {id}")))?;
    generation_of(&row)
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

impl PostgresBackend {
    async fn read_generation(&self, id: CaGenerationId) -> SidResult<Option<CaGeneration>> {
        sqlx::query(select!("WHERE id = $1"))
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage("read CA generation"))?
            .as_ref()
            .map(generation_of)
            .transpose()
    }

    async fn confirm_recovery(
        &self,
        id: CaGenerationId,
        expected_revision: u64,
        recovery: Recovery,
        given: &RecoveryConfirmation,
        ctx: MutationContext,
    ) -> SidResult<CaGeneration> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let g = locked(&mut tx, id).await?;
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
                "UPDATE ca_generations SET database_recovery_ref = $2, database_recovery_by = $3, \
                 database_recovery_at = $4, revision = revision + 1 WHERE id = $1"
            }
            Recovery::Keys => {
                "UPDATE ca_generations SET key_recovery_ref = $2, key_recovery_by = $3, \
                 key_recovery_at = $4, revision = revision + 1 WHERE id = $1"
            }
        };
        sqlx::query(sql)
            .bind(id.0)
            .bind(&given.reference)
            .bind(&given.confirmed_by)
            .bind(given.confirmed_at)
            .execute(&mut *tx)
            .await
            .map_err(storage("confirm CA recovery"))?;
        Self::audit_in_tx(&mut tx, &format!("ca_generation:{id}"), ctx).await?;
        let g = locked(&mut tx, id).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(g)
    }
}

#[async_trait]
impl CaRegistry for PostgresBackend {
    async fn prepare_generation(
        &self,
        new: &NewCaGeneration,
        ctx: MutationContext,
    ) -> SidResult<CaGeneration> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        lock_scope(&mut tx, new.scope).await?;
        if let Some(row) = sqlx::query(select!("WHERE id = $1"))
            .bind(new.id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("read CA generation"))?
        {
            let stored = generation_of(&row)?;
            return if stored.scope == new.scope && stored.key == new.key {
                Ok(stored)
            } else {
                Err(conflict(new.id, "prepared with other content"))
            };
        }
        let (kind, org) = scope_columns(new.scope);
        let next: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(generation), 0) + 1 FROM ca_generations \
             WHERE scope_kind = $1 AND scope_org IS NOT DISTINCT FROM $2",
        )
        .bind(kind)
        .bind(org)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage("number CA generation"))?;
        let (key_sealed, key_external) = custody_columns(&new.key);
        sqlx::query(
            "INSERT INTO ca_generations (id, scope_kind, scope_org, generation, \
             key_sealed, key_external, state, revision) \
             VALUES ($1, $2, $3, $4, $5, $6, 'prepared', 1)",
        )
        .bind(new.id.0)
        .bind(kind)
        .bind(org)
        .bind(next)
        .bind(key_sealed)
        .bind(key_external)
        .execute(&mut *tx)
        .await
        .map_err(storage("prepare CA generation"))?;
        Self::audit_in_tx(&mut tx, &format!("ca_generation:{}", new.id), ctx).await?;
        let g = locked(&mut tx, new.id).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(g)
    }

    async fn ca_generation(&self, id: CaGenerationId) -> SidResult<Option<CaGeneration>> {
        self.read_generation(id).await
    }

    async fn current_ca_generation(&self, scope: CaScope) -> SidResult<Option<CaGeneration>> {
        let (kind, org) = scope_columns(scope);
        sqlx::query(select!(
            "WHERE scope_kind = $1 AND scope_org IS NOT DISTINCT FROM $2 AND state = 'current'"
        ))
        .bind(kind)
        .bind(org)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("read current CA generation"))?
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
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let g = locked(&mut tx, id).await?;
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
            "UPDATE ca_generations SET certificate = $2, revision = revision + 1 WHERE id = $1",
        )
        .bind(id.0)
        .bind(certificate)
        .execute(&mut *tx)
        .await
        .map_err(storage("record CA certificate"))?;
        Self::audit_in_tx(&mut tx, &format!("ca_generation:{id}"), ctx).await?;
        let g = locked(&mut tx, id).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(g)
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
        let scope = self
            .read_generation(id)
            .await?
            .ok_or_else(|| SidError::NotFound(format!("CA generation {id}")))?
            .scope;
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        lock_scope(&mut tx, scope).await?;
        let g = locked(&mut tx, id).await?;
        if g.state == CaState::Current {
            return Ok(g);
        }
        if !g.activatable() {
            return Err(conflict(id, "not certified and recovery-confirmed"));
        }
        if g.revision != expected_revision {
            return Err(conflict(id, "stale revision"));
        }
        let (kind, org) = scope_columns(scope);
        sqlx::query(
            "UPDATE ca_generations SET state = 'retired', revision = revision + 1 \
             WHERE scope_kind = $1 AND scope_org IS NOT DISTINCT FROM $2 AND state = 'current'",
        )
        .bind(kind)
        .bind(org)
        .execute(&mut *tx)
        .await
        .map_err(storage("retire CA generation"))?;
        sqlx::query(
            "UPDATE ca_generations SET state = 'current', revision = revision + 1 WHERE id = $1",
        )
        .bind(id.0)
        .execute(&mut *tx)
        .await
        .map_err(storage("activate CA generation"))?;
        Self::audit_in_tx(&mut tx, &format!("ca_generation:{id}"), ctx).await?;
        let g = locked(&mut tx, id).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(g)
    }

    async fn revoke_ca_generation(
        &self,
        id: CaGenerationId,
        ctx: MutationContext,
    ) -> SidResult<CaGeneration> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let g = locked(&mut tx, id).await?;
        if g.state == CaState::Revoked {
            return Ok(g);
        }
        sqlx::query(
            "UPDATE ca_generations SET state = 'revoked', revision = revision + 1 WHERE id = $1",
        )
        .bind(id.0)
        .execute(&mut *tx)
        .await
        .map_err(storage("revoke CA generation"))?;
        Self::audit_in_tx(&mut tx, &format!("ca_generation:{id}"), ctx).await?;
        let g = locked(&mut tx, id).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(g)
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
             WHERE id = $1 AND state = 'current' AND revision = $2 \
             RETURNING last_serial, revision",
        )
        .bind(id.0)
        .bind(revision)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage("allocate CA serial"))?;
        match allocated {
            Some((serial, revision)) => Ok(SerialAllocation {
                generation: id,
                revision: unsigned(revision, "revision")?,
                serial: unsigned(serial, "serial")?,
            }),
            None => match self.read_generation(id).await? {
                None => Err(SidError::NotFound(format!("CA generation {id}"))),
                Some(_) => Err(conflict(id, "not current at the expected revision")),
            },
        }
    }
}
