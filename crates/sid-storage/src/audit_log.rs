// SPDX-License-Identifier: AGPL-3.0-only
//! PostgreSQL audit log implementation.
//!
//! Append-only with hash chains. Uses sqlx for persistence.
//! `log_in_conn()` writes the audit record in the same transaction as the
//! data mutation it records.

use async_trait::async_trait;
use jiff::Timestamp;
use jiff_sqlx::{Timestamp as PgTime, ToSqlx};
use sid_core::models::audit::{
    ActorType, AuditChain, AuditDigest, AuditEntry, AuditError, AuditOutcome, AuditRecord,
    ChainCheckpoint, ChainHead, compute_record_hash,
};
use sid_plugin::audit::{AuditLog, VerifyResult};
use sqlx::postgres::{PgConnection, PgRow};
use sqlx::{PgPool, Postgres, Row, Transaction};

/// PostgreSQL-backed audit log with hash chains.
///
/// StorageBackend methods append through `log_in_conn()` inside their own
/// transaction.
#[derive(Clone)]
pub struct PostgresAuditLog {
    pool: PgPool,
}

impl PostgresAuditLog {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn generate_id() -> String {
        uuid::Uuid::now_v7().to_string()
    }

    fn row_to_record(row: &PgRow) -> Result<AuditRecord, AuditError> {
        let actor_type_str: String = row.get("actor_type");
        let outcome_str: String = row.get("outcome");
        Ok(AuditRecord {
            id: row.get("id"),
            timestamp: row.get::<PgTime, _>("timestamp").to_jiff(),
            chain_id: row.get("chain_id"),
            sequence: row.get::<i64, _>("sequence") as u64,
            actor_id: row.get("actor_id"),
            actor_type: serde_json::from_value(serde_json::Value::String(actor_type_str))
                .unwrap_or(ActorType::System),
            action: row.get("action"),
            resource: row.get("resource"),
            outcome: serde_json::from_value(serde_json::Value::String(outcome_str))
                .unwrap_or(AuditOutcome::Success),
            metadata: row.get("metadata"),
            ip_address: row.get("ip_address"),
            device_id: row.get("device_id"),
            prev_hash: digest(row, "prev_hash")?,
            hash: digest(row, "hash")?,
        })
    }

    /// Append a record to `chain_id` inside the caller's transaction, shared by
    /// the standalone `log()` and the StorageBackend write methods.
    ///
    /// The chain head row stays locked until the transaction ends, so
    /// concurrent writers to one chain (other tasks, other replicas) append one
    /// after another instead of forking it from the same head.
    pub async fn log_in_conn(
        tx: &mut Transaction<'_, Postgres>,
        chain_id: &str,
        entry: AuditEntry,
    ) -> Result<AuditRecord, AuditError> {
        Self::append_at(tx, chain_id, entry, Timestamp::now()).await
    }

    /// Append a record stamped `at`.
    pub(crate) async fn append_at(
        tx: &mut Transaction<'_, Postgres>,
        chain_id: &str,
        entry: AuditEntry,
        at: Timestamp,
    ) -> Result<AuditRecord, AuditError> {
        let conn: &mut PgConnection = tx;
        // Creates the head at genesis if absent; the no-op update takes the
        // row lock and returns the head as the lock holder left it.
        let (prev_hash, head_sequence): (Vec<u8>, i64) = sqlx::query_as(
            "INSERT INTO audit_chain_heads (chain_id, last_record_id, last_hash, sequence) \
             VALUES ($1, '', $2, 0) \
             ON CONFLICT (chain_id) DO UPDATE SET chain_id = EXCLUDED.chain_id \
             RETURNING last_hash, sequence",
        )
        .bind(chain_id)
        .bind(AuditDigest::GENESIS.as_bytes().as_slice())
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| AuditError::WriteFailed(e.to_string()))?;
        let prev_hash = AuditDigest::stored(&prev_hash, "last_hash")?;
        let sequence = head_sequence as u64 + 1;

        let id = Self::generate_id();

        // Build record for hash computation. The hash covers the timestamp,
        // so it is taken at the resolution `timestamptz` stores (1 µs,
        // PostgreSQL 18 docs §8.5): a finer clock would hash digits the
        // record read back for verification no longer has.
        let mut record = AuditRecord {
            id: id.clone(),
            timestamp: crate::micros(at),
            chain_id: chain_id.to_string(),
            sequence,
            actor_id: entry.actor_id,
            actor_type: entry.actor_type,
            action: entry.action,
            resource: entry.resource,
            outcome: entry.outcome,
            metadata: entry.metadata,
            ip_address: entry.ip_address,
            device_id: entry.device_id,
            prev_hash,
            hash: AuditDigest::GENESIS,
        };
        record.hash = compute_record_hash(&record);

        // Insert audit record.
        sqlx::query(
            "INSERT INTO audit_records (id, timestamp, chain_id, sequence, actor_id, actor_type, \
             action, resource, outcome, metadata, ip_address, device_id, prev_hash, hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(&record.id)
        .bind(record.timestamp.to_sqlx())
        .bind(&record.chain_id)
        .bind(record.sequence as i64)
        .bind(&record.actor_id)
        .bind(record.actor_type.to_string())
        .bind(&record.action)
        .bind(&record.resource)
        .bind(record.outcome.to_string())
        .bind(&record.metadata)
        .bind(record.ip_address)
        .bind(&record.device_id)
        .bind(record.prev_hash.as_bytes().as_slice())
        .bind(record.hash.as_bytes().as_slice())
        .execute(&mut *conn)
        .await
        .map_err(|e| AuditError::WriteFailed(e.to_string()))?;

        // Advance the head this transaction holds locked.
        sqlx::query(
            "UPDATE audit_chain_heads \
             SET last_record_id = $2, last_hash = $3, sequence = $4 \
             WHERE chain_id = $1",
        )
        .bind(&record.chain_id)
        .bind(&record.id)
        .bind(record.hash.as_bytes().as_slice())
        .bind(record.sequence as i64)
        .execute(&mut *conn)
        .await
        .map_err(|e| AuditError::WriteFailed(e.to_string()))?;

        Ok(record)
    }
}

#[async_trait]
impl AuditLog for PostgresAuditLog {
    async fn log(&self, chain_id: &str, entry: AuditEntry) -> Result<AuditRecord, AuditError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AuditError::WriteFailed(e.to_string()))?;
        let record = Self::log_in_conn(&mut tx, chain_id, entry).await?;
        tx.commit()
            .await
            .map_err(|e| AuditError::WriteFailed(e.to_string()))?;
        Ok(record)
    }

    async fn query(
        &self,
        chain_id: &str,
        from: Option<Timestamp>,
        to: Option<Timestamp>,
    ) -> Result<Vec<AuditRecord>, AuditError> {
        let mut query = String::from(
            "SELECT id, timestamp, chain_id, sequence, actor_id, actor_type, \
             action, resource, outcome, metadata, ip_address, device_id, prev_hash, hash \
             FROM audit_records WHERE chain_id = $1",
        );
        let mut param_idx = 2u32;

        if from.is_some() {
            query.push_str(&format!(" AND timestamp >= ${param_idx}"));
            param_idx += 1;
        }
        if to.is_some() {
            query.push_str(&format!(" AND timestamp <= ${param_idx}"));
        }
        query.push_str(" ORDER BY sequence ASC");

        // The string is assembled from literals above; the only variable part
        // is a placeholder number, and every value arrives through `bind`.
        let mut q = sqlx::query(sqlx::AssertSqlSafe(query)).bind(chain_id);
        if let Some(from) = from {
            q = q.bind(from);
        }
        if let Some(to) = to {
            q = q.bind(to);
        }

        let rows = q
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AuditError::Other(e.to_string()))?;

        rows.iter().map(Self::row_to_record).collect()
    }

    async fn verify_chain(&self, chain_id: &str) -> Result<VerifyResult, AuditError> {
        // Retention may have removed the chain's oldest records; the chain
        // then resumes from the checkpoint the removal left, and records at or
        // below it are outside retention.
        let checkpoint: Option<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT sequence, hash FROM audit_chain_checkpoints WHERE chain_id = $1",
        )
        .bind(chain_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuditError::Other(e.to_string()))?;
        let (after, start) = match checkpoint {
            Some((sequence, hash)) => (sequence, AuditDigest::stored(&hash, "checkpoint hash")?),
            None => (0, AuditDigest::GENESIS),
        };

        let rows = sqlx::query(
            "SELECT id, timestamp, chain_id, sequence, actor_id, actor_type, \
             action, resource, outcome, metadata, ip_address, device_id, prev_hash, hash \
             FROM audit_records WHERE chain_id = $1 AND sequence > $2 ORDER BY sequence ASC",
        )
        .bind(chain_id)
        .bind(after)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuditError::Other(e.to_string()))?;

        let records = rows
            .iter()
            .map(Self::row_to_record)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(sid_plugin::audit::verify_records(&records, start))
    }

    async fn list_chain_ids(&self) -> Result<Vec<String>, AuditError> {
        let rows = sqlx::query("SELECT chain_id FROM audit_chain_heads")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AuditError::Other(e.to_string()))?;

        Ok(rows.iter().map(|r| r.get("chain_id")).collect())
    }

    async fn export_chain(&self, chain_id: &str) -> Result<AuditChain, AuditError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| AuditError::Other(e.to_string()))?;
        stored_chain(&mut conn, chain_id, false)
            .await?
            .ok_or_else(|| AuditError::ChainNotFound(chain_id.to_owned()))
    }

    async fn import_chain(&self, chain: &AuditChain) -> Result<bool, AuditError> {
        chain.check()?;
        let write = |e: sqlx::Error| AuditError::WriteFailed(e.to_string());
        let mut tx = self.pool.begin().await.map_err(write)?;
        // A concurrent importer or appender of the chain waits on its head.
        if let Some(held) = stored_chain(&mut tx, &chain.head.chain_id, true).await? {
            return if held.holds(chain) {
                Ok(false)
            } else {
                Err(AuditError::Conflict(format!(
                    "another chain {} is stored",
                    chain.head.chain_id
                )))
            };
        }
        let sequence =
            |s: u64| i64::try_from(s).map_err(|_| AuditError::Other(format!("sequence {s}")));
        // Each record into its month's partition, created as retention
        // expects to find it: a row parked in the default partition would
        // keep that month's partition from being created later.
        let months: std::collections::BTreeSet<(i16, i8)> = chain
            .records
            .iter()
            .map(|r| {
                let day = r.timestamp.to_zoned(jiff::tz::TimeZone::UTC);
                (day.year(), day.month())
            })
            .collect();
        for (year, month) in months {
            sqlx::query("SELECT create_audit_partition($1, $2)")
                .bind(i32::from(year))
                .bind(i32::from(month))
                .execute(&mut *tx)
                .await
                .map_err(write)?;
        }
        for record in &chain.records {
            sqlx::query(
                "INSERT INTO audit_records (id, timestamp, chain_id, sequence, actor_id, \
                 actor_type, action, resource, outcome, metadata, ip_address, device_id, \
                 prev_hash, hash) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            )
            .bind(&record.id)
            .bind(record.timestamp.to_sqlx())
            .bind(&record.chain_id)
            .bind(sequence(record.sequence)?)
            .bind(&record.actor_id)
            .bind(record.actor_type.to_string())
            .bind(&record.action)
            .bind(&record.resource)
            .bind(record.outcome.to_string())
            .bind(&record.metadata)
            .bind(record.ip_address)
            .bind(&record.device_id)
            .bind(record.prev_hash.as_bytes().as_slice())
            .bind(record.hash.as_bytes().as_slice())
            .execute(&mut *tx)
            .await
            .map_err(write)?;
        }
        sqlx::query(
            "INSERT INTO audit_chain_heads (chain_id, last_record_id, last_hash, sequence) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&chain.head.chain_id)
        .bind(&chain.head.last_record_id)
        .bind(chain.head.last_hash.as_bytes().as_slice())
        .bind(sequence(chain.head.sequence)?)
        .execute(&mut *tx)
        .await
        .map_err(|e| match &e {
            // A concurrent first appender took the chain id meanwhile.
            sqlx::Error::Database(db) if db.is_unique_violation() => AuditError::Conflict(format!(
                "chain {} was started meanwhile",
                chain.head.chain_id
            )),
            _ => write(e),
        })?;
        if let Some(checkpoint) = &chain.checkpoint {
            sqlx::query(
                "INSERT INTO audit_chain_checkpoints (chain_id, sequence, hash, cut_before) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(&chain.head.chain_id)
            .bind(sequence(checkpoint.sequence)?)
            .bind(checkpoint.hash.as_bytes().as_slice())
            .bind(checkpoint.cut_before.to_sqlx())
            .execute(&mut *tx)
            .await
            .map_err(write)?;
        }
        tx.commit().await.map_err(write)?;
        Ok(true)
    }
}

/// Chain `chain_id` as stored, read on `conn`, its head locked when `lock`;
/// `None` when it has no head.
async fn stored_chain(
    conn: &mut PgConnection,
    chain_id: &str,
    lock: bool,
) -> Result<Option<AuditChain>, AuditError> {
    let read = |e: sqlx::Error| AuditError::Other(e.to_string());
    let head_query = if lock {
        "SELECT * FROM audit_chain_heads WHERE chain_id = $1 FOR UPDATE"
    } else {
        "SELECT * FROM audit_chain_heads WHERE chain_id = $1"
    };
    let Some(head) = sqlx::query(head_query)
        .bind(chain_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(read)?
    else {
        return Ok(None);
    };
    let checkpoint = sqlx::query("SELECT * FROM audit_chain_checkpoints WHERE chain_id = $1")
        .bind(chain_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(read)?
        .map(|row| -> Result<_, AuditError> {
            Ok(ChainCheckpoint {
                sequence: row.get::<i64, _>("sequence") as u64,
                hash: digest(&row, "hash")?,
                cut_before: row.get::<PgTime, _>("cut_before").to_jiff(),
            })
        })
        .transpose()?;
    let records = sqlx::query(
        "SELECT id, timestamp, chain_id, sequence, actor_id, actor_type, \
         action, resource, outcome, metadata, ip_address, device_id, prev_hash, hash \
         FROM audit_records WHERE chain_id = $1 ORDER BY sequence ASC",
    )
    .bind(chain_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(read)?
    .iter()
    .map(PostgresAuditLog::row_to_record)
    .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(AuditChain {
        head: ChainHead {
            chain_id: head.get("chain_id"),
            last_record_id: head.get("last_record_id"),
            last_hash: digest(&head, "last_hash")?,
            sequence: head.get::<i64, _>("sequence") as u64,
        },
        checkpoint,
        records,
    }))
}

/// The digest in column `column` of `row`.
fn digest(row: &PgRow, column: &str) -> Result<AuditDigest, AuditError> {
    AuditDigest::stored(&row.get::<Vec<u8>, _>(column), column)
}

#[cfg(test)]
mod tests;
