// SPDX-License-Identifier: AGPL-3.0-only
//! Anomaly events, IP reputation and the IP allowlist for SQLite backend.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{AnomalyEventId, AnomalyEventRecord, IpReputation, MutationContext},
};
use sqlx::Row;

use super::{SqliteBackend, col, fmt_dt, parse_dt, uuid_col};

fn row_to_anomaly_event(row: &sqlx::sqlite::SqliteRow) -> SidResult<AnomalyEventRecord> {
    Ok(AnomalyEventRecord {
        id: AnomalyEventId(uuid_col(row, "id")?),
        rule_id: col(row, "rule_id")?,
        profile_id: col(row, "profile_id")?,
        ip_address: super::ip_col(row, "ip_address")?,
        description: col(row, "description")?,
        risk_score: col(row, "risk_score")?,
        reaction: col(row, "reaction")?,
        timestamp: parse_dt(&row.get::<String, _>("timestamp")),
    })
}

impl SqliteBackend {
    pub(crate) async fn save_anomaly_event_impl(
        &self,
        event: &AnomalyEventRecord,
    ) -> SidResult<()> {
        sqlx::query(
            "INSERT INTO anomaly_events (id, rule_id, profile_id, ip_address, description, risk_score, reaction, timestamp) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(event.id.0)
        .bind(&event.rule_id)
        .bind(&event.profile_id)
        .bind(event.ip_address.map(super::ip_to_bytes))
        .bind(&event.description)
        .bind(event.risk_score)
        .bind(&event.reaction)
        .bind(fmt_dt(&event.timestamp))
        .execute(&self.writer)
        .await
        .map_err(|e| SidError::Storage(format!("save_anomaly_event: {e}")))?;
        Ok(())
    }

    pub(crate) async fn list_anomaly_events_impl(
        &self,
        rule_id: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> SidResult<Vec<AnomalyEventRecord>> {
        let rows = sqlx::query(
            "SELECT id, rule_id, profile_id, ip_address, description, risk_score, reaction, timestamp \
             FROM anomaly_events WHERE (?1 IS NULL OR rule_id = ?1) \
             ORDER BY timestamp DESC LIMIT ?2 OFFSET ?3",
        )
        .bind(rule_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("list_anomaly_events: {e}")))?;
        rows.iter().map(row_to_anomaly_event).collect()
    }

    /// Count one login outcome; the score is `failed / (failed + success + 1)`
    /// over the counts after this event.
    pub(crate) async fn record_ip_reputation_event_impl(
        &self,
        ip: &str,
        success: bool,
    ) -> SidResult<()> {
        let now = fmt_dt(&chrono::Utc::now());
        let (failed, succeeded) = if success { (0, 1) } else { (1, 0) };
        sqlx::query(
            "INSERT INTO ip_reputation (ip, failed_count, success_count, score, first_seen_at, last_failed_at, last_success_at, updated_at) \
             VALUES (?1, ?2, ?3, CAST(?2 AS REAL) / (?2 + ?3 + 1), ?4, \
                     CASE WHEN ?2 = 1 THEN ?4 END, CASE WHEN ?3 = 1 THEN ?4 END, ?4) \
             ON CONFLICT(ip) DO UPDATE SET \
                failed_count = failed_count + ?2, \
                success_count = success_count + ?3, \
                score = CAST(failed_count + ?2 AS REAL) / (failed_count + ?2 + success_count + ?3 + 1), \
                last_failed_at = CASE WHEN ?2 = 1 THEN ?4 ELSE last_failed_at END, \
                last_success_at = CASE WHEN ?3 = 1 THEN ?4 ELSE last_success_at END, \
                updated_at = ?4",
        )
        .bind(ip)
        .bind(failed)
        .bind(succeeded)
        .bind(now)
        .execute(&self.writer)
        .await
        .map_err(|e| SidError::Storage(format!("record_ip_reputation_event: {e}")))?;
        Ok(())
    }

    pub(crate) async fn get_ip_reputation_score_impl(&self, ip: &str) -> SidResult<Option<f32>> {
        let score: Option<f64> = sqlx::query_scalar("SELECT score FROM ip_reputation WHERE ip = ?")
            .bind(ip)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("get_ip_reputation_score: {e}")))?;
        // A score is a ratio in [0, 1]; f32 holds it without meaningful loss.
        Ok(score.map(|s| s as f32))
    }

    pub(crate) async fn list_suspicious_ips_impl(
        &self,
        min_score: f32,
        limit: i64,
    ) -> SidResult<Vec<(String, f32)>> {
        let rows: Vec<(String, f64)> = sqlx::query_as(
            "SELECT ip, score FROM ip_reputation WHERE score >= ? ORDER BY score DESC LIMIT ?",
        )
        .bind(f64::from(min_score))
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("list_suspicious_ips: {e}")))?;
        Ok(rows.into_iter().map(|(ip, s)| (ip, s as f32)).collect())
    }

    /// Halve the counts of entries idle for `older_than` and drop those left
    /// with none, in one transaction.
    pub(crate) async fn decay_ip_reputation_impl(
        &self,
        older_than: std::time::Duration,
    ) -> SidResult<u64> {
        let now = chrono::Utc::now();
        let cutoff = crate::decay_cutoff(older_than)?;
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "UPDATE ip_reputation SET \
                failed_count = failed_count / 2, success_count = success_count / 2, \
                score = CAST(failed_count / 2 AS REAL) / (failed_count / 2 + success_count / 2 + 1), \
                updated_at = ? \
             WHERE updated_at < ? AND (failed_count > 0 OR success_count > 0)",
        )
        .bind(fmt_dt(&now))
        .bind(fmt_dt(&cutoff))
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("decay_ip_reputation: {e}")))?;
        let removed =
            sqlx::query("DELETE FROM ip_reputation WHERE failed_count = 0 AND success_count = 0")
                .execute(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("decay_ip_reputation cleanup: {e}")))?
                .rows_affected();
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(removed)
    }

    pub(crate) async fn add_ip_allowlist_entry_impl(
        &self,
        cidr: &str,
        description: &str,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO ip_allowlist_entries (cidr, description, created_at) VALUES (?, ?, ?) \
             ON CONFLICT(cidr) DO UPDATE SET description = excluded.description",
        )
        .bind(cidr)
        .bind(description)
        .bind(fmt_dt(&chrono::Utc::now()))
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("add_ip_allowlist_entry: {e}")))?;
        Self::commit_allowlist_change(tx, ctx).await
    }

    pub(crate) async fn remove_ip_allowlist_entry_impl(
        &self,
        cidr: &str,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM ip_allowlist_entries WHERE cidr = ?")
            .bind(cidr)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("remove_ip_allowlist_entry: {e}")))?;
        Self::commit_allowlist_change(tx, ctx).await
    }

    /// Commit an allowlist change under `ctx`, recording for a keyed command
    /// the allowlist the transaction leaves.
    async fn commit_allowlist_change(
        mut tx: super::WriteTx,
        mut ctx: MutationContext,
    ) -> SidResult<()> {
        if ctx.operation.is_some() {
            let rows = sqlx::query(
                "SELECT cidr, description, created_at FROM ip_allowlist_entries ORDER BY created_at",
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("read the allowlist: {e}")))?;
            ctx.record_effect(&allowlist_rows(&rows)?)?;
        }
        Self::commit_mutation(tx, "ip_allowlist", ctx).await
    }

    pub(crate) async fn list_ip_allowlist_entries_impl(
        &self,
    ) -> SidResult<Vec<(String, String, chrono::DateTime<chrono::Utc>)>> {
        let rows = sqlx::query(
            "SELECT cidr, description, created_at FROM ip_allowlist_entries ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("list_ip_allowlist_entries: {e}")))?;
        allowlist_rows(&rows)
    }

    pub(crate) async fn import_anomaly_event_impl(
        &self,
        event: &AnomalyEventRecord,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let held = sqlx::query(
            "SELECT id, rule_id, profile_id, ip_address, description, risk_score, reaction, timestamp \
             FROM anomaly_events WHERE id = ?",
        )
        .bind(event.id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("import_anomaly_event: {e}")))?;
        if let Some(row) = held {
            return crate::transfer_repeat(&row_to_anomaly_event(&row)?, event, "anomaly event");
        }
        sqlx::query(
            "INSERT INTO anomaly_events (id, rule_id, profile_id, ip_address, description, risk_score, reaction, timestamp) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(event.id.0)
        .bind(&event.rule_id)
        .bind(&event.profile_id)
        .bind(event.ip_address.map(super::ip_to_bytes))
        .bind(&event.description)
        .bind(event.risk_score)
        .bind(&event.reaction)
        .bind(fmt_dt(&event.timestamp))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("anomaly event", e))?;
        Self::commit_mutation(tx, &format!("anomaly_event:{}", event.id), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn export_ip_reputation_impl(&self) -> SidResult<Vec<IpReputation>> {
        let rows = sqlx::query("SELECT * FROM ip_reputation ORDER BY ip")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("export_ip_reputation: {e}")))?;
        rows.iter().map(row_to_reputation).collect()
    }

    pub(crate) async fn import_ip_reputation_impl(
        &self,
        reputation: &IpReputation,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let held = sqlx::query("SELECT * FROM ip_reputation WHERE ip = ?")
            .bind(&reputation.ip)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("import_ip_reputation: {e}")))?;
        if let Some(row) = held {
            return crate::transfer_repeat(&row_to_reputation(&row)?, reputation, "IP reputation");
        }
        // The score as recording an event computes it from the counts.
        sqlx::query(
            "INSERT INTO ip_reputation (ip, failed_count, success_count, score, first_seen_at, \
                 last_failed_at, last_success_at, updated_at) \
             VALUES (?1, ?2, ?3, CAST(?2 AS REAL) / (?2 + ?3 + 1), ?4, ?5, ?6, ?7)",
        )
        .bind(&reputation.ip)
        .bind(reputation.failed_count)
        .bind(reputation.success_count)
        .bind(fmt_dt(&reputation.first_seen_at))
        .bind(super::fmt_dt_opt(reputation.last_failed_at))
        .bind(super::fmt_dt_opt(reputation.last_success_at))
        .bind(fmt_dt(&reputation.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("IP reputation", e))?;
        Self::commit_mutation(tx, "ip_reputation", ctx).await?;
        Ok(true)
    }

    pub(crate) async fn import_ip_allowlist_entry_impl(
        &self,
        cidr: &str,
        description: &str,
        created_at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let held = sqlx::query(
            "SELECT cidr, description, created_at FROM ip_allowlist_entries WHERE cidr = ?",
        )
        .bind(cidr)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("import_ip_allowlist_entry: {e}")))?;
        let wanted = (cidr.to_owned(), description.to_owned(), created_at);
        if let Some(row) = held {
            let stored = allowlist_rows(std::slice::from_ref(&row))?;
            return crate::transfer_repeat(&stored[0], &wanted, "IP allowlist entry");
        }
        sqlx::query(
            "INSERT INTO ip_allowlist_entries (cidr, description, created_at) VALUES (?, ?, ?)",
        )
        .bind(cidr)
        .bind(description)
        .bind(fmt_dt(&created_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("IP allowlist entry", e))?;
        Self::commit_allowlist_change(tx, ctx).await?;
        Ok(true)
    }
}

fn row_to_reputation(row: &sqlx::sqlite::SqliteRow) -> SidResult<IpReputation> {
    Ok(IpReputation {
        ip: col(row, "ip")?,
        failed_count: col(row, "failed_count")?,
        success_count: col(row, "success_count")?,
        first_seen_at: super::dt_col(row, "first_seen_at")?,
        last_failed_at: super::dt_col_opt(row, "last_failed_at")?,
        last_success_at: super::dt_col_opt(row, "last_success_at")?,
        updated_at: super::dt_col(row, "updated_at")?,
    })
}

/// The allowlist entries of `rows`.
fn allowlist_rows(
    rows: &[sqlx::sqlite::SqliteRow],
) -> SidResult<Vec<(String, String, chrono::DateTime<chrono::Utc>)>> {
    rows.iter()
        .map(|row| {
            Ok((
                col(row, "cidr")?,
                col(row, "description")?,
                parse_dt(&row.get::<String, _>("created_at")),
            ))
        })
        .collect()
}
