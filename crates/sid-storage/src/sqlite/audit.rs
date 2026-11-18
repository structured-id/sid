// SPDX-License-Identifier: AGPL-3.0-only
//! SQLite-based AuditLog implementation with hash chain integrity.

use async_trait::async_trait;
use sid_core::models::audit::{
    ActorType, AuditChain, AuditDigest, AuditEntry, AuditError, AuditOutcome, AuditRecord,
    ChainCheckpoint, ChainHead, compute_record_hash,
};
use sid_plugin::audit::{AuditLog, VerifyResult};
use sqlx::{Row, SqliteConnection, SqlitePool};

/// SQLite audit log with tamper-evident hash chains.
///
/// Each chain (e.g., "profile:abc123") maintains an independent sequence
/// with linked hashes. Records are append-only — no UPDATE/DELETE.
pub struct SqliteAuditLog {
    pool: SqlitePool,
}

impl SqliteAuditLog {
    /// Create a new SQLite audit log using the given pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Append `entry` to `chain_id` inside `tx`, the transaction of the
    /// mutation it records. The transaction must hold the write lock
    /// (`BEGIN IMMEDIATE`) before the head is read, so concurrent writers to
    /// one chain append one after another instead of reading the same head.
    pub(crate) async fn log_in_conn(
        tx: &mut SqliteConnection,
        chain_id: &str,
        entry: AuditEntry,
    ) -> Result<AuditRecord, AuditError> {
        let head_row = sqlx::query("SELECT * FROM audit_chain_heads WHERE chain_id = ?")
            .bind(chain_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| AuditError::WriteFailed(e.to_string()))?;

        let (prev_hash, sequence) = match &head_row {
            Some(row) => {
                let seq: i64 = row.get("sequence");
                (digest(row, "last_hash")?, seq as u64 + 1)
            }
            None => (AuditDigest::GENESIS, 1),
        };

        let id = uuid::Uuid::now_v7().to_string();
        // Truncate to millisecond precision to match SQLite TEXT storage format.
        // This ensures compute_record_hash() produces the same hash before and after round-trip.
        let timestamp = jiff::Timestamp::now()
            .round(
                jiff::TimestampRound::new()
                    .smallest(jiff::Unit::Millisecond)
                    .mode(jiff::RoundMode::Trunc),
            )
            .map_err(|e| AuditError::Other(format!("record time: {e}")))?;

        let mut record = AuditRecord {
            id: id.clone(),
            timestamp,
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

        let ts_str = millis_text(&record.timestamp);
        let metadata_str = serde_json::to_string(&record.metadata).unwrap_or_default();

        // Insert record
        sqlx::query(
            "INSERT INTO audit_records (id, timestamp, chain_id, sequence, actor_id, actor_type, action, resource, outcome, metadata, ip_address, device_id, prev_hash, hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&record.id)
        .bind(&ts_str)
        .bind(&record.chain_id)
        .bind(record.sequence as i64)
        .bind(&record.actor_id)
        .bind(record.actor_type.to_string())
        .bind(&record.action)
        .bind(&record.resource)
        .bind(record.outcome.to_string())
        .bind(&metadata_str)
        .bind(record.ip_address.map(super::ip_to_bytes))
        .bind(&record.device_id)
        .bind(record.prev_hash.as_bytes().as_slice())
        .bind(record.hash.as_bytes().as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|e| AuditError::WriteFailed(e.to_string()))?;

        // Upsert chain head
        sqlx::query(
            "INSERT INTO audit_chain_heads (chain_id, last_record_id, last_hash, sequence)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(chain_id) DO UPDATE SET
                last_record_id=excluded.last_record_id, last_hash=excluded.last_hash,
                sequence=excluded.sequence",
        )
        .bind(&record.chain_id)
        .bind(&record.id)
        .bind(record.hash.as_bytes().as_slice())
        .bind(record.sequence as i64)
        .execute(&mut *tx)
        .await
        .map_err(|e| AuditError::WriteFailed(e.to_string()))?;
        Ok(record)
    }
}

#[async_trait]
impl AuditLog for SqliteAuditLog {
    async fn log(&self, chain_id: &str, entry: AuditEntry) -> Result<AuditRecord, AuditError> {
        let write = |e: sqlx::Error| AuditError::WriteFailed(e.to_string());
        let mut conn = self.pool.acquire().await.map_err(write)?;
        let mut tx = sqlx::Connection::begin_with(&mut *conn, "BEGIN IMMEDIATE")
            .await
            .map_err(write)?;
        let record = Self::log_in_conn(&mut tx, chain_id, entry).await?;
        tx.commit().await.map_err(write)?;
        Ok(record)
    }

    async fn query(
        &self,
        chain_id: &str,
        from: Option<jiff::Timestamp>,
        to: Option<jiff::Timestamp>,
    ) -> Result<Vec<AuditRecord>, AuditError> {
        let mut sql = String::from("SELECT * FROM audit_records WHERE chain_id = ?");
        let mut binds: Vec<String> = vec![chain_id.to_string()];

        if let Some(f) = from {
            sql.push_str(" AND timestamp >= ?");
            binds.push(millis_text(&f));
        }
        if let Some(t) = to {
            sql.push_str(" AND timestamp <= ?");
            binds.push(millis_text(&t));
        }
        sql.push_str(" ORDER BY sequence ASC");

        // Build query dynamically based on number of binds.
        // Every fragment appended above is a literal; the values themselves
        // are bound, so the assembled string carries no caller input.
        let sql = sqlx::AssertSqlSafe(sql);
        let rows = match binds.len() {
            1 => sqlx::query(sql).bind(&binds[0]).fetch_all(&self.pool).await,
            2 => {
                sqlx::query(sql)
                    .bind(&binds[0])
                    .bind(&binds[1])
                    .fetch_all(&self.pool)
                    .await
            }
            3 => {
                sqlx::query(sql)
                    .bind(&binds[0])
                    .bind(&binds[1])
                    .bind(&binds[2])
                    .fetch_all(&self.pool)
                    .await
            }
            _ => unreachable!(),
        }
        .map_err(|e| AuditError::Other(e.to_string()))?;

        rows.iter().map(row_to_audit_record).collect()
    }

    async fn verify_chain(&self, chain_id: &str) -> Result<VerifyResult, AuditError> {
        // After a retention cut the chain resumes from its checkpoint.
        let checkpoint: Option<(i64, Vec<u8>)> =
            sqlx::query_as("SELECT sequence, hash FROM audit_chain_checkpoints WHERE chain_id = ?")
                .bind(chain_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| AuditError::Other(e.to_string()))?;
        let (after, start) = match checkpoint {
            Some((sequence, hash)) => (sequence, AuditDigest::stored(&hash, "checkpoint hash")?),
            None => (0, AuditDigest::GENESIS),
        };
        let records: Vec<AuditRecord> = self
            .query(chain_id, None, None)
            .await?
            .into_iter()
            .filter(|r| r.sequence as i64 > after)
            .collect();
        Ok(sid_plugin::audit::verify_records(&records, start))
    }

    async fn list_chain_ids(&self) -> Result<Vec<String>, AuditError> {
        let rows = sqlx::query("SELECT chain_id FROM audit_chain_heads ORDER BY chain_id")
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
        stored_chain(&mut conn, chain_id)
            .await?
            .ok_or_else(|| AuditError::ChainNotFound(chain_id.to_owned()))
    }

    async fn import_chain(&self, chain: &AuditChain) -> Result<bool, AuditError> {
        chain.check()?;
        let write = |e: sqlx::Error| AuditError::WriteFailed(e.to_string());
        let mut conn = self.pool.acquire().await.map_err(write)?;
        let mut tx = sqlx::Connection::begin_with(&mut *conn, "BEGIN IMMEDIATE")
            .await
            .map_err(write)?;
        if let Some(held) = stored_chain(&mut tx, &chain.head.chain_id).await? {
            return if held.holds(chain) {
                Ok(false)
            } else {
                Err(AuditError::Conflict(format!(
                    "another chain {} is stored",
                    chain.head.chain_id
                )))
            };
        }
        for record in &chain.records {
            sqlx::query(
                "INSERT INTO audit_records (id, timestamp, chain_id, sequence, actor_id,
                    actor_type, action, resource, outcome, metadata, ip_address, device_id,
                    prev_hash, hash)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&record.id)
            // At the precision the record was taken: its hash covers it.
            .bind(record.timestamp.to_string())
            .bind(&record.chain_id)
            .bind(sequence_value(record.sequence)?)
            .bind(&record.actor_id)
            .bind(record.actor_type.to_string())
            .bind(&record.action)
            .bind(&record.resource)
            .bind(record.outcome.to_string())
            .bind(
                serde_json::to_string(&record.metadata)
                    .map_err(|e| AuditError::Other(e.to_string()))?,
            )
            .bind(record.ip_address.map(super::ip_to_bytes))
            .bind(&record.device_id)
            .bind(record.prev_hash.as_bytes().as_slice())
            .bind(record.hash.as_bytes().as_slice())
            .execute(&mut *tx)
            .await
            .map_err(write)?;
        }
        sqlx::query(
            "INSERT INTO audit_chain_heads (chain_id, last_record_id, last_hash, sequence)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&chain.head.chain_id)
        .bind(&chain.head.last_record_id)
        .bind(chain.head.last_hash.as_bytes().as_slice())
        .bind(sequence_value(chain.head.sequence)?)
        .execute(&mut *tx)
        .await
        .map_err(write)?;
        if let Some(checkpoint) = &chain.checkpoint {
            sqlx::query(
                "INSERT INTO audit_chain_checkpoints (chain_id, sequence, hash, cut_before)
                 VALUES (?, ?, ?, ?)",
            )
            .bind(&chain.head.chain_id)
            .bind(sequence_value(checkpoint.sequence)?)
            .bind(checkpoint.hash.as_bytes().as_slice())
            .bind(super::fmt_dt(&checkpoint.cut_before))
            .execute(&mut *tx)
            .await
            .map_err(write)?;
        }
        tx.commit().await.map_err(write)?;
        Ok(true)
    }
}

/// A record time as stored: milliseconds, fixed width, so the text sorts as
/// time does.
fn millis_text(at: &jiff::Timestamp) -> String {
    at.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn sequence_value(sequence: u64) -> Result<i64, AuditError> {
    i64::try_from(sequence).map_err(|_| AuditError::Other(format!("sequence {sequence}")))
}

/// Chain `chain_id` as stored, read on `conn`; `None` when it has no head.
async fn stored_chain(
    conn: &mut SqliteConnection,
    chain_id: &str,
) -> Result<Option<AuditChain>, AuditError> {
    let read = |e: sqlx::Error| AuditError::Other(e.to_string());
    let Some(head) = sqlx::query("SELECT * FROM audit_chain_heads WHERE chain_id = ?")
        .bind(chain_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(read)?
    else {
        return Ok(None);
    };
    let checkpoint = sqlx::query("SELECT * FROM audit_chain_checkpoints WHERE chain_id = ?")
        .bind(chain_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(read)?
        .map(|row| {
            Ok::<_, AuditError>(ChainCheckpoint {
                sequence: row.get::<i64, _>("sequence") as u64,
                hash: digest(&row, "hash")?,
                cut_before: row
                    .get::<String, _>("cut_before")
                    .parse()
                    .map_err(|e| AuditError::Other(format!("cut_before: {e}")))?,
            })
        })
        .transpose()?;
    let records = sqlx::query("SELECT * FROM audit_records WHERE chain_id = ? ORDER BY sequence")
        .bind(chain_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(read)?
        .iter()
        .map(row_to_audit_record)
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
fn digest(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<AuditDigest, AuditError> {
    AuditDigest::stored(&row.get::<Vec<u8>, _>(column), column)
}

fn row_to_audit_record(row: &sqlx::sqlite::SqliteRow) -> Result<AuditRecord, AuditError> {
    let actor_type = match row.get::<String, _>("actor_type").as_str() {
        "admin" => ActorType::Admin,
        "service" => ActorType::Service,
        "machine" => ActorType::Machine,
        "connector" => ActorType::Connector,
        "system" => ActorType::System,
        _ => ActorType::User,
    };
    let outcome = match row.get::<String, _>("outcome").as_str() {
        "failure" => AuditOutcome::Failure,
        "denied" => AuditOutcome::Denied,
        _ => AuditOutcome::Success,
    };
    let metadata: serde_json::Value = row
        .get::<Option<String>, _>("metadata")
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);
    let ts_str: String = row.get("timestamp");
    let timestamp = ts_str.parse().unwrap_or_else(|_| jiff::Timestamp::now());

    Ok(AuditRecord {
        id: row.get("id"),
        timestamp,
        chain_id: row.get("chain_id"),
        sequence: row.get::<i64, _>("sequence") as u64,
        actor_id: row.get("actor_id"),
        actor_type,
        action: row.get("action"),
        resource: row.get("resource"),
        outcome,
        metadata,
        ip_address: row
            .get::<Option<Vec<u8>>, _>("ip_address")
            .map(|ip| super::ip_from_bytes(&ip).expect("the schema admits 4 or 16 bytes")),
        device_id: row.get("device_id"),
        prev_hash: digest(row, "prev_hash")?,
        hash: digest(row, "hash")?,
    })
}
