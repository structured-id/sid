// SPDX-License-Identifier: AGPL-3.0-only
//! SQLite-based AuditLog implementation with hash chain integrity.

use async_trait::async_trait;
use sid_core::models::audit::{
    ActorType, AuditEntry, AuditError, AuditOutcome, AuditRecord, compute_record_hash,
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
                let hash: String = row.get("last_hash");
                let seq: i64 = row.get("sequence");
                (hash, seq as u64 + 1)
            }
            None => ("genesis".to_string(), 1),
        };

        let id = uuid::Uuid::now_v7().to_string();
        // Truncate to millisecond precision to match SQLite TEXT storage format.
        // This ensures compute_record_hash() produces the same hash before and after round-trip.
        let timestamp = {
            let now = chrono::Utc::now();
            let millis = now.timestamp_millis();
            chrono::DateTime::from_timestamp_millis(millis)
                .unwrap()
                .with_timezone(&chrono::Utc)
        };

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
            hash: String::new(),
        };
        record.hash = compute_record_hash(&record);

        let ts_str = record
            .timestamp
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
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
        .bind(&record.ip_address)
        .bind(&record.device_id)
        .bind(&record.prev_hash)
        .bind(&record.hash)
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
        .bind(&record.hash)
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
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<AuditRecord>, AuditError> {
        let mut sql = String::from("SELECT * FROM audit_records WHERE chain_id = ?");
        let mut binds: Vec<String> = vec![chain_id.to_string()];

        if let Some(f) = from {
            sql.push_str(" AND timestamp >= ?");
            binds.push(f.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
        }
        if let Some(t) = to {
            sql.push_str(" AND timestamp <= ?");
            binds.push(t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
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

        Ok(rows.iter().map(row_to_audit_record).collect())
    }

    async fn verify_chain(&self, chain_id: &str) -> Result<VerifyResult, AuditError> {
        // After a retention cut the chain resumes from its checkpoint.
        let checkpoint: Option<(i64, String)> =
            sqlx::query_as("SELECT sequence, hash FROM audit_chain_checkpoints WHERE chain_id = ?")
                .bind(chain_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| AuditError::Other(e.to_string()))?;
        let (after, start) = checkpoint.unwrap_or((0, "genesis".to_string()));
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
}

fn row_to_audit_record(row: &sqlx::sqlite::SqliteRow) -> AuditRecord {
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
    let timestamp = chrono::DateTime::parse_from_rfc3339(&ts_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    AuditRecord {
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
        ip_address: row.get("ip_address"),
        device_id: row.get("device_id"),
        prev_hash: row.get("prev_hash"),
        hash: row.get("hash"),
    }
}
