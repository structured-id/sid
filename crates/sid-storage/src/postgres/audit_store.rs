// SPDX-License-Identifier: AGPL-3.0-only
//! Audit chains in the PostgreSQL database of a host whose own tables live
//! there, so its mutations commit their audit record with their effect.

use chrono::{DateTime, Months, Utc};
use sid_core::models::audit::AuditEntry;
use sid_core::{Error as SidError, Result as SidResult};
use sqlx::PgPool;

use super::audit_retention;
use crate::audit_log::PostgresAuditLog;

/// The audit tables of a host keeping its own database; the engine's schema
/// holds the same tables.
const SCHEMA: &str = include_str!("audit.sql");

/// Audit chains in a PostgreSQL database of a host apart from the engine
/// backend (the SaaS tenant runtime's catalog): its mutations append their
/// record inside their own transaction ([`Self::record_in_tx`]), and its
/// upkeep keeps the monthly partitions ([`Self::prepare_partitions`],
/// [`Self::drop_expired`]). Chains are read and verified through
/// [`Self::log`].
#[derive(Clone)]
pub struct PgAuditStore {
    pool: PgPool,
}

impl PgAuditStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create the audit tables if they do not exist, recording the digest of
    /// the schema that made them; tables another schema made are refused
    /// unchanged (`CREATE ... IF NOT EXISTS` would keep them as they are).
    /// Replicas starting together take turns under a transaction-scoped
    /// advisory lock. The partitions of this and the next month are prepared
    /// once the tables exist.
    pub async fn ensure_schema(&self) -> SidResult<()> {
        let schema_error = |e: sqlx::Error| SidError::Storage(format!("audit schema: {e}"));
        let digest = sid_core::models::operation::fingerprint(SCHEMA.as_bytes());
        let mut tx = self.pool.begin().await.map_err(schema_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('sid.audit.schema'))")
            .execute(&mut *tx)
            .await
            .map_err(schema_error)?;
        let existing: bool =
            sqlx::query_scalar("SELECT to_regclass('audit_chain_heads') IS NOT NULL")
                .fetch_one(&mut *tx)
                .await
                .map_err(schema_error)?;
        let recorded: Option<Vec<u8>> =
            if sqlx::query_scalar::<_, bool>("SELECT to_regclass('audit_schema') IS NOT NULL")
                .fetch_one(&mut *tx)
                .await
                .map_err(schema_error)?
            {
                sqlx::query_scalar("SELECT digest FROM audit_schema")
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(schema_error)?
            } else {
                None
            };
        if existing && recorded.as_deref() != Some(digest.as_slice()) {
            return Err(SidError::InvalidState(
                "the audit tables were made by another schema; the database must be recreated"
                    .into(),
            ));
        }
        sqlx::raw_sql(SCHEMA)
            .execute(&mut *tx)
            .await
            .map_err(schema_error)?;
        sqlx::query(
            "INSERT INTO audit_schema (id, digest) VALUES (true, $1) ON CONFLICT (id) DO NOTHING",
        )
        .bind(&digest)
        .execute(&mut *tx)
        .await
        .map_err(schema_error)?;
        tx.commit().await.map_err(schema_error)?;
        self.prepare_partitions(Utc::now()).await
    }

    /// Append `entry` to `chain_id` inside the host mutation's transaction
    /// `tx`: the record commits with the mutation or not at all. The chain's
    /// head stays locked until `tx` ends, so appenders of one chain on every
    /// replica take turns.
    pub async fn record_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        chain_id: &str,
        entry: AuditEntry,
    ) -> SidResult<()> {
        PostgresAuditLog::log_in_conn(tx, chain_id, entry)
            .await
            .map(|_| ())
            .map_err(|e| SidError::Storage(format!("audit record: {e}")))
    }

    /// Create the partitions of the month `now` falls in and the next one,
    /// so records never land in the default partition. Idempotent and safe
    /// on every replica.
    pub async fn prepare_partitions(&self, now: DateTime<Utc>) -> SidResult<()> {
        let this = audit_retention::month_start(now)?.date_naive();
        let next = this
            .checked_add_months(Months::new(1))
            .ok_or_else(|| SidError::Validation(format!("no month after {this}")))?;
        for month in [this, next] {
            audit_retention::ensure_partition(&self.pool, month).await?;
        }
        Ok(())
    }

    /// Remove every monthly partition whose month ended before the month
    /// `cut_before` falls in, leaving each chain a checkpoint its
    /// verification resumes from, and record the removal as `entry` on
    /// `chain_id` in the same transaction. Returns the records removed.
    pub async fn drop_expired(
        &self,
        cut_before: DateTime<Utc>,
        chain_id: &str,
        entry: AuditEntry,
    ) -> SidResult<u64> {
        let boundary = audit_retention::month_start(cut_before)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(format!("begin: {e}")))?;
        let (partitions, removed) = audit_retention::drop_expired(&mut tx, boundary).await?;
        if partitions == 0 {
            return Ok(0);
        }
        Self::record_in_tx(&mut tx, chain_id, entry).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(format!("commit: {e}")))?;
        Ok(removed)
    }

    /// The chains, to read, verify, export and import.
    pub fn log(&self) -> PostgresAuditLog {
        PostgresAuditLog::new(self.pool.clone())
    }
}

#[cfg(test)]
mod tests;
