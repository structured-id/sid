// SPDX-License-Identifier: AGPL-3.0-only
//! PAT, Quarantine, ClosureRequest, ExportJob, and MagicLink operations for SQLite backend.

use chrono::{DateTime, Utc};
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        MutationContext, Profile, ProfileId,
        magic_link::MagicLinkSession,
        pat::{PatId, PatStatus, PersonalAccessToken},
        profile::{ClosureMode, ClosureRequest, ExportFormat, ExportJob, ExportStatus},
    },
};
use sqlx::Row;

use super::{
    SqliteBackend, WriteTx, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error, parsed_col,
};

/// Whitespace-separated list column.
fn words(row: &sqlx::sqlite::SqliteRow, name: &str) -> SidResult<Vec<String>> {
    let raw: String = col(row, name)?;
    Ok(raw.split_whitespace().map(String::from).collect())
}

fn row_to_pat(row: &sqlx::sqlite::SqliteRow) -> SidResult<PersonalAccessToken> {
    let id: String = col(row, "id")?;
    let use_count: i64 = col(row, "use_count")?;
    Ok(PersonalAccessToken {
        id: PatId(
            uuid::Uuid::parse_str(&id)
                .map_err(|e| SidError::Storage(format!("column id: bad PAT id {id}: {e}")))?,
        ),
        profile_id: col(row, "profile_id")?,
        name: col(row, "name")?,
        description: col(row, "description")?,
        token_hash: col(row, "token_hash")?,
        token_prefix: col(row, "token_prefix")?,
        scopes: words(row, "scopes")?,
        ip_allowlist: words(row, "ip_allowlist")?,
        status: parsed_col::<PatStatus>(row, "status")?,
        expires_at: dt_col_opt(row, "expires_at")?,
        last_used_at: dt_col_opt(row, "last_used_at")?,
        last_used_ip: col(row, "last_used_ip")?,
        use_count: u64::try_from(use_count)
            .map_err(|_| SidError::Storage(format!("column use_count: negative {use_count}")))?,
        revoked_at: dt_col_opt(row, "revoked_at")?,
        revoked_by: col(row, "revoked_by")?,
        created_at: dt_col(row, "created_at")?,
    })
}

fn row_to_closure_request(row: &sqlx::sqlite::SqliteRow) -> SidResult<ClosureRequest> {
    let cancel_count: i64 = col(row, "cancel_count")?;
    Ok(ClosureRequest {
        profile_id: col(row, "profile_id")?,
        mode: parsed_col::<ClosureMode>(row, "mode")?,
        closure_reason: col(row, "closure_reason")?,
        requested_by: col(row, "requested_by")?,
        requested_at: dt_col(row, "requested_at")?,
        grace_period_end: dt_col_opt(row, "grace_period_end")?,
        export_status: parsed_col::<ExportStatus>(row, "export_status")?,
        legal_hold: col::<Option<String>>(row, "legal_hold")?
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(|e| SidError::Storage(format!("legal_hold decode failed: {e}")))?,
        cancel_count: u32::try_from(cancel_count).map_err(|_| {
            SidError::Storage(format!("column cancel_count: bad count {cancel_count}"))
        })?,
    })
}

fn row_to_export_job(row: &sqlx::sqlite::SqliteRow) -> SidResult<ExportJob> {
    let id: String = col(row, "id")?;
    Ok(ExportJob {
        id: uuid::Uuid::parse_str(&id)
            .map_err(|e| SidError::Storage(format!("column id: bad export job id {id}: {e}")))?,
        profile_id: col(row, "profile_id")?,
        format: parsed_col::<ExportFormat>(row, "format")?,
        status: parsed_col::<ExportStatus>(row, "status")?,
        archive_path: col(row, "archive_path")?,
        size_bytes: col(row, "size_bytes")?,
        checksum_sha256: col(row, "checksum_sha256")?,
        created_at: dt_col(row, "created_at")?,
        ready_at: dt_col_opt(row, "ready_at")?,
        expires_at: dt_col_opt(row, "expires_at")?,
    })
}

fn row_to_magic_link(row: &sqlx::sqlite::SqliteRow) -> SidResult<MagicLinkSession> {
    let id: String = col(row, "id")?;
    Ok(MagicLinkSession {
        id: uuid::Uuid::parse_str(&id)
            .map_err(|e| SidError::Storage(format!("column id: bad magic link id {id}: {e}")))?,
        email: col(row, "email")?,
        token_hash: col(row, "token_hash")?,
        consumed: col(row, "consumed")?,
        created_at: dt_col(row, "created_at")?,
        expires_at: dt_col(row, "expires_at")?,
    })
}

/// Insert a closure request. With `replace`, it takes the place of the
/// profile's stored request but keeps that one's cancel count and legal hold,
/// which outlive a request; without, an existing request is `Conflict`.
async fn insert_closure_request(
    tx: &mut WriteTx,
    req: &ClosureRequest,
    replace: bool,
) -> SidResult<()> {
    let legal_hold = req
        .legal_hold
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| SidError::Storage(format!("legal_hold encode failed: {e}")))?;
    let cancel_count = i64::from(req.cancel_count);
    let sql = if replace {
        "INSERT INTO closure_requests (profile_id, mode, closure_reason, requested_by, requested_at, grace_period_end, export_status, cancel_count, legal_hold)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(profile_id) DO UPDATE SET
            mode = excluded.mode, closure_reason = excluded.closure_reason,
            requested_by = excluded.requested_by, requested_at = excluded.requested_at,
            grace_period_end = excluded.grace_period_end, export_status = excluded.export_status"
    } else {
        "INSERT INTO closure_requests (profile_id, mode, closure_reason, requested_by, requested_at, grace_period_end, export_status, cancel_count, legal_hold)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    };
    sqlx::query(sql)
        .bind(req.profile_id)
        .bind(req.mode.as_str())
        .bind(&req.closure_reason)
        .bind(req.requested_by)
        .bind(fmt_dt(&req.requested_at))
        .bind(fmt_dt_opt(req.grace_period_end))
        .bind(req.export_status.as_str())
        .bind(cancel_count)
        .bind(legal_hold)
        .execute(&mut **tx)
        .await
        .map_err(|e| insert_error("closure request", e))?;
    Ok(())
}

impl SqliteBackend {
    // === PersonalAccessToken ===

    pub(crate) async fn get_pat_impl(&self, id: PatId) -> SidResult<Option<PersonalAccessToken>> {
        let row = sqlx::query("SELECT * FROM personal_access_tokens WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_pat).transpose()
    }

    pub(crate) async fn get_pat_by_token_hash_impl(
        &self,
        token_hash: &str,
    ) -> SidResult<Option<PersonalAccessToken>> {
        let row = sqlx::query("SELECT * FROM personal_access_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_pat).transpose()
    }

    pub(crate) async fn create_pat_impl(
        &self,
        pat: &PersonalAccessToken,
        active_limit: Option<u64>,
        audit: MutationContext,
    ) -> SidResult<()> {
        // BEGIN IMMEDIATE: the count and the insert are one step.
        let mut tx = self.begin_write().await?;
        if let Some(limit) = active_limit {
            let active: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM personal_access_tokens WHERE profile_id = ? AND status = 'active'",
            )
            .bind(pat.profile_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
            // COUNT(*) is never negative.
            if active as u64 >= limit {
                return Err(SidError::ResourceExhausted(format!(
                    "profile already holds {limit} active PATs"
                )));
            }
        }
        sqlx::query(
            "INSERT INTO personal_access_tokens (id, profile_id, name, description, token_hash, token_prefix, scopes, ip_allowlist, status, expires_at, last_used_at, last_used_ip, use_count, revoked_at, revoked_by, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(pat.id.0.to_string()).bind(pat.profile_id)
        .bind(&pat.name)
        .bind(&pat.description)
        .bind(&pat.token_hash)
        .bind(&pat.token_prefix)
        .bind(pat.scopes.join(" "))
        .bind(pat.ip_allowlist.join(" "))
        .bind(pat.status.as_str())
        .bind(fmt_dt_opt(pat.expires_at))
        .bind(fmt_dt_opt(pat.last_used_at))
        .bind(&pat.last_used_ip)
        .bind(pat.use_count as i64)
        .bind(fmt_dt_opt(pat.revoked_at))
        .bind(&pat.revoked_by)
        .bind(fmt_dt(&pat.created_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                SidError::Conflict("PAT already exists".into())
            }
            _ => SidError::Storage(e.to_string()),
        })?;
        Self::commit_mutation(tx, &format!("pat:{}", pat.id.0), audit).await
    }

    pub(crate) async fn record_pat_use_impl(
        &self,
        id: PatId,
        ip: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        let used = sqlx::query(
            "UPDATE personal_access_tokens
             SET last_used_at = ?1, last_used_ip = ?2, use_count = use_count + 1
             WHERE id = ?3 AND status = 'active' AND (expires_at IS NULL OR expires_at > ?1)",
        )
        .bind(&now)
        .bind(ip)
        .bind(id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected()
            == 1;
        if !used {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("pat:{}", id.0), audit).await?;
        Ok(true)
    }

    pub(crate) async fn revoke_pat_impl(
        &self,
        id: PatId,
        revoked_by: &str,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        let revoked = sqlx::query(
            "UPDATE personal_access_tokens SET status = 'revoked', revoked_at = ?, revoked_by = ?
             WHERE id = ? AND status <> 'revoked'",
        )
        .bind(&now)
        .bind(revoked_by)
        .bind(id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected()
            == 1;
        if !revoked {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("pat:{}", id.0), audit).await?;
        Ok(true)
    }

    pub(crate) async fn list_pats_by_profile_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<PersonalAccessToken>> {
        let rows = sqlx::query("SELECT * FROM personal_access_tokens WHERE profile_id = ?")
            .bind(profile_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_pat).collect()
    }

    pub(crate) async fn list_all_pats_impl(&self) -> SidResult<Vec<PersonalAccessToken>> {
        let rows = sqlx::query("SELECT * FROM personal_access_tokens")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_pat).collect()
    }

    pub(crate) async fn count_active_pats_by_profile_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<u64> {
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM personal_access_tokens WHERE profile_id = ? AND status = 'active'",
        ).bind(profile_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(row.get::<i64, _>("cnt") as u64)
    }

    pub(crate) async fn revoke_active_pats_by_profile_impl(
        &self,
        profile_id: ProfileId,
        revoked_by: &str,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        let revoked = super::directory::revoke_pats(&mut tx, profile_id, revoked_by).await?;
        Self::commit_bulk(
            tx,
            revoked,
            &format!("pat:cascade_revoke:profile:{profile_id}"),
            audit,
        )
        .await
    }

    pub(crate) async fn revoke_unused_pats_impl(
        &self,
        days: u32,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
        let cutoff_str = fmt_dt(&cutoff);
        let mut tx = self.begin_write().await?;
        let result = sqlx::query(
            "UPDATE personal_access_tokens SET status = 'revoked', revoked_at = ?
             WHERE status = 'active'
             AND ((last_used_at IS NULL AND created_at < ?) OR (last_used_at IS NOT NULL AND last_used_at < ?))",
        )
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(&cutoff_str)
        .bind(&cutoff_str)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_bulk(tx, result.rows_affected(), "pat:revoke_unused", audit).await
    }

    // === Principal Quarantine ===

    pub(crate) async fn quarantine_principal_impl(
        &self,
        principal_hash: &str,
        principal_type: &str,
        quarantine_until: DateTime<Utc>,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO principal_quarantine (principal_hash, principal_type, quarantine_until, created_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(principal_hash) DO UPDATE SET quarantine_until=excluded.quarantine_until"
        )
        .bind(principal_hash)
        .bind(principal_type)
        .bind(fmt_dt(&quarantine_until))
        .bind(fmt_dt(&chrono::Utc::now()))
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, "quarantine", audit).await
    }

    pub(crate) async fn is_principal_quarantined_impl(
        &self,
        principal_hash: &str,
    ) -> SidResult<bool> {
        let now = fmt_dt(&chrono::Utc::now());
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM principal_quarantine WHERE principal_hash = ? AND quarantine_until > ?",
        )
        .bind(principal_hash)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(row.get::<i64, _>("cnt") > 0)
    }

    pub(crate) async fn cleanup_expired_quarantine_impl(
        &self,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        let result = sqlx::query("DELETE FROM principal_quarantine WHERE quarantine_until <= ?")
            .bind(&now)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_bulk(tx, result.rows_affected(), "quarantine:cleanup", audit).await
    }

    // === ClosureRequest ===

    pub(crate) async fn create_closure_request_impl(
        &self,
        req: &ClosureRequest,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        insert_closure_request(&mut tx, req, false).await?;
        Self::commit_mutation(tx, &format!("closure:{}", req.profile_id), ctx).await
    }

    pub(crate) async fn request_profile_closure_impl(
        &self,
        profile: &Profile,
        req: &ClosureRequest,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        // The write transaction holds the database lock: the administrators
        // counted here are the ones this write sees.
        let mut tx = self.begin_write().await?;
        if profile.is_admin() {
            let admins: Vec<(sid_core::models::ProfileId, String)> = sqlx::query_as(
                "SELECT id, status FROM profiles WHERE ' ' || roles || ' ' LIKE '% admin %'",
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("read administrators: {e}")))?;
            crate::check_other_administrator(profile.id, &admins)?;
        }
        if !super::directory::update_profile(&mut tx, profile).await? {
            return Ok(false);
        }
        insert_closure_request(&mut tx, req, true).await?;
        Self::commit_mutation(tx, &format!("closure:{}", req.profile_id), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn cancel_profile_closure_impl(
        &self,
        profile: &Profile,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        if !super::directory::update_profile(&mut tx, profile).await? {
            return Ok(false);
        }
        let counted = sqlx::query(
            "UPDATE closure_requests SET cancel_count = cancel_count + 1 WHERE profile_id = ?",
        )
        .bind(profile.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        if counted.rows_affected() == 0 {
            return Err(SidError::NotFound("no closure request".into()));
        }
        Self::commit_mutation(tx, &format!("closure:{}", profile.id), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn get_closure_request_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<ClosureRequest>> {
        let row = sqlx::query("SELECT * FROM closure_requests WHERE profile_id = ?")
            .bind(profile_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_closure_request).transpose()
    }

    // === ExportJob ===

    /// Run one export job status change (`?1` id, `?2` time, stored in the
    /// same text form); `true` when it applied.
    async fn transition_export_job(
        &self,
        id: uuid::Uuid,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
        sql: &'static str,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let changed = sqlx::query(sql)
            .bind(id.to_string())
            .bind(fmt_dt(&at))
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("export job status: {e}")))?
            .rows_affected()
            == 1;
        if !changed {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("export_job:{id}"), audit).await?;
        Ok(true)
    }

    pub(crate) async fn acknowledge_export_job_impl(
        &self,
        id: uuid::Uuid,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.transition_export_job(
            id,
            at,
            audit,
            "UPDATE export_jobs SET status = 'downloaded'
             WHERE id = ?1 AND status = 'ready' AND expires_at > ?2",
        )
        .await
    }

    pub(crate) async fn expire_export_job_impl(
        &self,
        id: uuid::Uuid,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.transition_export_job(
            id,
            at,
            audit,
            "UPDATE export_jobs SET status = 'expired'
             WHERE id = ?1 AND status = 'ready' AND expires_at <= ?2",
        )
        .await
    }

    pub(crate) async fn create_export_job_impl(
        &self,
        job: &ExportJob,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO export_jobs (id, profile_id, format, status, archive_path, size_bytes, checksum_sha256, created_at, ready_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(job.id.to_string())
        .bind(job.profile_id)
        .bind(job.format.as_str())
        .bind(job.status.as_str())
        .bind(&job.archive_path)
        .bind(job.size_bytes)
        .bind(&job.checksum_sha256)
        .bind(fmt_dt(&job.created_at))
        .bind(fmt_dt_opt(job.ready_at))
        .bind(fmt_dt_opt(job.expires_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("export job", e))?;
        Self::commit_mutation(tx, &format!("export_job:{}", job.id), audit).await
    }

    pub(crate) async fn get_export_job_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<ExportJob>> {
        let row = sqlx::query(
            "SELECT * FROM export_jobs WHERE profile_id = ? ORDER BY created_at DESC LIMIT 1",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_export_job).transpose()
    }

    pub(crate) async fn get_export_job_by_id_impl(
        &self,
        job_id: uuid::Uuid,
    ) -> SidResult<Option<ExportJob>> {
        let row = sqlx::query("SELECT * FROM export_jobs WHERE id = ?")
            .bind(job_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_export_job).transpose()
    }

    // === MagicLink ===

    pub(crate) async fn create_magic_link_session_impl(
        &self,
        session: &MagicLinkSession,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO magic_link_sessions (id, email, token_hash, consumed, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(session.id.to_string())
        .bind(&session.email)
        .bind(&session.token_hash)
        .bind(session.consumed)
        .bind(fmt_dt(&session.created_at))
        .bind(fmt_dt(&session.expires_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("magic link", e))?;
        Self::commit_mutation(tx, &format!("magic_link:{}", session.id), audit).await
    }

    pub(crate) async fn get_magic_link_session_impl(
        &self,
        id: uuid::Uuid,
    ) -> SidResult<Option<MagicLinkSession>> {
        let row = sqlx::query("SELECT * FROM magic_link_sessions WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_magic_link).transpose()
    }

    pub(crate) async fn consume_magic_link_session_impl(
        &self,
        id: uuid::Uuid,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("UPDATE magic_link_sessions SET consumed = 1 WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("magic_link:{}", id), audit).await
    }

    /// Consume the link if it is unconsumed and unexpired; the one conditional
    /// update decides between concurrent consumers, so only one gets it.
    pub(crate) async fn try_consume_magic_link_session_impl(
        &self,
        id: uuid::Uuid,
        audit: MutationContext,
    ) -> SidResult<Option<MagicLinkSession>> {
        let mut tx = self.begin_write().await?;
        let consumed = sqlx::query(
            "UPDATE magic_link_sessions SET consumed = 1
             WHERE id = ? AND consumed = 0 AND expires_at > ?
             RETURNING *",
        )
        .bind(id.to_string())
        .bind(fmt_dt(&chrono::Utc::now()))
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .as_ref()
        .map(row_to_magic_link)
        .transpose()?;
        if consumed.is_some() {
            Self::commit_mutation(tx, &format!("magic_link:{id}"), audit).await?;
        }
        Ok(consumed)
    }

    pub(crate) async fn delete_expired_magic_link_sessions_impl(
        &self,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        let result = sqlx::query("DELETE FROM magic_link_sessions WHERE expires_at < ?")
            .bind(&now)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_bulk(tx, result.rows_affected(), "magic_link:cleanup", audit).await
    }

    pub(crate) async fn count_active_magic_links_for_email_impl(
        &self,
        email: &str,
    ) -> SidResult<u32> {
        let now = fmt_dt(&chrono::Utc::now());
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM magic_link_sessions WHERE email = ? AND consumed = 0 AND expires_at > ?",
        )
        .bind(email)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(row.get::<i64, _>("cnt") as u32)
    }
}
