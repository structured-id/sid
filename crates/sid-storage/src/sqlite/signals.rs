// SPDX-License-Identifier: AGPL-3.0-only
//! Anomaly events, IP reputation and the IP allowlist for SQLite backend.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{AnomalyEventId, AnomalyEventRecord},
};
use sqlx::Row;
use uuid::Uuid;

use super::{SqliteBackend, col, fmt_dt, parse_dt};

fn row_to_anomaly_event(row: &sqlx::sqlite::SqliteRow) -> SidResult<AnomalyEventRecord> {
    let id: String = col(row, "id")?;
    Ok(AnomalyEventRecord {
        id: AnomalyEventId(
            Uuid::parse_str(&id).map_err(|e| SidError::Storage(format!("column id: {e}")))?,
        ),
        rule_id: col(row, "rule_id")?,
        profile_id: col(row, "profile_id")?,
        ip_address: col(row, "ip_address")?,
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
        .bind(event.id.0.to_string())
        .bind(&event.rule_id)
        .bind(&event.profile_id)
        .bind(&event.ip_address)
        .bind(&event.description)
        .bind(event.risk_score)
        .bind(&event.reaction)
        .bind(fmt_dt(&event.timestamp))
        .execute(&self.pool)
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
        .execute(&self.pool)
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
    ) -> SidResult<()> {
        sqlx::query(
            "INSERT INTO ip_allowlist_entries (cidr, description, created_at) VALUES (?, ?, ?) \
             ON CONFLICT(cidr) DO UPDATE SET description = excluded.description",
        )
        .bind(cidr)
        .bind(description)
        .bind(fmt_dt(&chrono::Utc::now()))
        .execute(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("add_ip_allowlist_entry: {e}")))?;
        Ok(())
    }

    pub(crate) async fn remove_ip_allowlist_entry_impl(&self, cidr: &str) -> SidResult<()> {
        sqlx::query("DELETE FROM ip_allowlist_entries WHERE cidr = ?")
            .bind(cidr)
            .execute(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("remove_ip_allowlist_entry: {e}")))?;
        Ok(())
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
}
