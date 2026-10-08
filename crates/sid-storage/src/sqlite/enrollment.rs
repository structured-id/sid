// SPDX-License-Identifier: AGPL-3.0-only
//! Invite and registration source operations for SQLite backend.

use super::{SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error, uuid_col};
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        Invite, InviteFilter, InviteId, MutationContext, ProfileId, RegistrationSource,
        RegistrationSourceType, UtmParams,
    },
};

/// The columns an invite is read from.
macro_rules! invite_columns {
    () => {
        "id, code, created_by, created_by_name, metadata, max_uses, use_count, expires_at, active, created_at"
    };
}

/// An invite row's status as of `?2` (now), in the order of `Invite::status`;
/// timestamps are RFC 3339 UTC text, which orders as time.
macro_rules! invite_status_sql {
    () => {
        "(CASE WHEN active = 0 THEN 'revoked' \
               WHEN expires_at IS NOT NULL AND expires_at < ?2 THEN 'expired' \
               WHEN max_uses > 0 AND use_count >= max_uses THEN 'consumed' \
               ELSE 'active' END)"
    };
}

fn row_to_invite(row: &sqlx::sqlite::SqliteRow) -> SidResult<Invite> {
    let metadata: String = col(row, "metadata")?;
    Ok(Invite {
        id: InviteId(uuid_col(row, "id")?),
        code: col(row, "code")?,
        created_by: col(row, "created_by")?,
        created_by_name: col(row, "created_by_name")?,
        metadata: serde_json::from_str(&metadata)
            .map_err(|e| SidError::Storage(format!("invite metadata: {e}")))?,
        max_uses: u32::try_from(col::<i64>(row, "max_uses")?)
            .map_err(|e| SidError::Storage(format!("column max_uses: {e}")))?,
        use_count: u32::try_from(col::<i64>(row, "use_count")?)
            .map_err(|e| SidError::Storage(format!("column use_count: {e}")))?,
        expires_at: dt_col_opt(row, "expires_at")?,
        active: col(row, "active")?,
        created_at: dt_col(row, "created_at")?,
    })
}

fn row_to_registration_source(row: &sqlx::sqlite::SqliteRow) -> SidResult<RegistrationSource> {
    Ok(RegistrationSource {
        source_type: col::<String>(row, "source_type")?
            .parse()
            .map_err(SidError::Storage)?,
        source_id: col(row, "source_id")?,
        referrer_id: col(row, "referrer_id")?,
        utm: UtmParams {
            source: col(row, "utm_source")?,
            medium: col(row, "utm_medium")?,
            campaign: col(row, "utm_campaign")?,
            term: col(row, "utm_term")?,
            content: col(row, "utm_content")?,
        },
        client_id: col(row, "client_id")?,
        created_at: dt_col(row, "created_at")?,
    })
}

/// Record where a new profile came from, inside its registration.
pub(super) async fn insert_registration_source(
    tx: &mut super::WriteTx,
    profile_id: ProfileId,
    source: &RegistrationSource,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO registration_sources (profile_id, source_type, source_id, referrer_id, utm_source, utm_medium, utm_campaign, utm_term, utm_content, client_id, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(profile_id)
    .bind(source.source_type.as_str())
    .bind(&source.source_id)
    .bind(source.referrer_id)
    .bind(&source.utm.source)
    .bind(&source.utm.medium)
    .bind(&source.utm.campaign)
    .bind(&source.utm.term)
    .bind(&source.utm.content)
    .bind(&source.client_id)
    .bind(fmt_dt(&source.created_at))
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("registration source", e))?;
    Ok(())
}

impl SqliteBackend {
    pub(crate) async fn create_invite_impl(
        &self,
        invite: &Invite,
        audit: MutationContext,
    ) -> SidResult<()> {
        let metadata = serde_json::to_string(&invite.metadata)
            .map_err(|e| SidError::Storage(format!("invite metadata: {e}")))?;
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO invites (id, code, created_by, created_by_name, metadata, max_uses, use_count, expires_at, active, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(invite.id.0.to_string())
        .bind(&invite.code)
        .bind(invite.created_by)
        .bind(&invite.created_by_name)
        .bind(metadata)
        .bind(i64::from(invite.max_uses))
        .bind(i64::from(invite.use_count))
        .bind(fmt_dt_opt(invite.expires_at))
        .bind(invite.active)
        .bind(fmt_dt(&invite.created_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("invite", e))?;
        Self::commit_mutation(tx, &format!("invite:{}", invite.id.0), audit).await
    }

    pub(crate) async fn get_invite_impl(&self, id: InviteId) -> SidResult<Option<Invite>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            invite_columns!(),
            " FROM invites WHERE id = ?"
        ))
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_invite).transpose()
    }

    pub(crate) async fn get_invite_by_code_impl(&self, code: &str) -> SidResult<Option<Invite>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            invite_columns!(),
            " FROM invites WHERE UPPER(code) = ?"
        ))
        .bind(code.trim().to_uppercase())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_invite).transpose()
    }

    pub(crate) async fn list_invites_impl(
        &self,
        filter: &InviteFilter,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<Invite>> {
        // SQLite's LIKE ignores ASCII case, as the filter asks.
        let rows = sqlx::query(concat!(
            "SELECT ",
            invite_columns!(),
            " FROM invites WHERE (?1 IS NULL OR ",
            invite_status_sql!(),
            " = ?1) AND (?5 IS NULL OR code LIKE ?5 ESCAPE '\\' \
             OR created_by_name LIKE ?5 ESCAPE '\\')",
            // Newest first in one total order: invites created together
            // (a bulk creation) share a time, so the id breaks the tie.
            " ORDER BY created_at DESC, id DESC LIMIT ?3 OFFSET ?4"
        ))
        .bind(filter.status.map(|s| s.as_str()))
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(i64::try_from(limit).map_err(|e| SidError::Storage(e.to_string()))?)
        .bind(i64::try_from(offset).map_err(|e| SidError::Storage(e.to_string()))?)
        .bind(filter.search_pattern())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_invite).collect()
    }

    pub(crate) async fn count_invites_impl(&self, filter: &InviteFilter) -> SidResult<u64> {
        let count: i64 = sqlx::query_scalar(concat!(
            "SELECT COUNT(*) FROM invites WHERE (?1 IS NULL OR ",
            invite_status_sql!(),
            " = ?1) AND (?3 IS NULL OR code LIKE ?3 ESCAPE '\\' \
             OR created_by_name LIKE ?3 ESCAPE '\\')"
        ))
        .bind(filter.status.map(|s| s.as_str()))
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(filter.search_pattern())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        u64::try_from(count).map_err(|e| SidError::Storage(e.to_string()))
    }

    pub(crate) async fn try_use_invite_impl(
        &self,
        id: InviteId,
        audit: MutationContext,
    ) -> SidResult<Option<Invite>> {
        let mut tx = self.begin_write().await?;
        let row = sqlx::query(concat!(
            "UPDATE invites SET use_count = use_count + 1 \
             WHERE id = ? AND active = 1 \
               AND (max_uses = 0 OR use_count < max_uses) \
               AND (expires_at IS NULL OR expires_at > ?) \
             RETURNING ",
            invite_columns!()
        ))
        .bind(id.0.to_string())
        .bind(fmt_dt(&chrono::Utc::now()))
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Try use invite failed: {e}")))?;
        // No use, nothing recorded: the transaction is dropped uncommitted.
        let Some(row) = row else {
            return Ok(None);
        };
        let invite = row_to_invite(&row)?;
        Self::commit_mutation(tx, &format!("invite:{}", id.0), audit).await?;
        Ok(Some(invite))
    }

    pub(crate) async fn revoke_invite_impl(
        &self,
        id: InviteId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("UPDATE invites SET active = 0 WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Revoke invite failed: {e}")))?;
        Self::commit_mutation(tx, &format!("invite:{}", id.0), audit).await
    }

    pub(crate) async fn get_registration_source_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<RegistrationSource>> {
        let row = sqlx::query(
            "SELECT profile_id, source_type, source_id, referrer_id, utm_source, utm_medium, utm_campaign, utm_term, utm_content, client_id, created_at \
             FROM registration_sources WHERE profile_id = ?",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_registration_source).transpose()
    }

    pub(crate) async fn count_registrations_by_source_impl(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> SidResult<Vec<(RegistrationSourceType, u64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT source_type, COUNT(*) FROM registration_sources \
             WHERE created_at >= ? GROUP BY source_type",
        )
        .bind(fmt_dt(&since))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.into_iter()
            .map(|(t, c)| {
                Ok((
                    t.parse().map_err(SidError::Storage)?,
                    u64::try_from(c).map_err(|e| SidError::Storage(e.to_string()))?,
                ))
            })
            .collect()
    }

    pub(crate) async fn top_referrers_impl(
        &self,
        since: chrono::DateTime<chrono::Utc>,
        limit: u64,
    ) -> SidResult<Vec<(ProfileId, u64)>> {
        let rows: Vec<(ProfileId, i64)> = sqlx::query_as(
            "SELECT referrer_id, COUNT(*) AS cnt FROM registration_sources \
             WHERE referrer_id IS NOT NULL AND created_at >= ? \
             GROUP BY referrer_id ORDER BY cnt DESC LIMIT ?",
        )
        .bind(fmt_dt(&since))
        .bind(i64::try_from(limit).map_err(|e| SidError::Storage(e.to_string()))?)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.into_iter()
            .map(|(id, c)| {
                Ok((
                    id,
                    u64::try_from(c).map_err(|e| SidError::Storage(e.to_string()))?,
                ))
            })
            .collect()
    }
}
