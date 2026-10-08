// SPDX-License-Identifier: AGPL-3.0-only
//! Session operations for SQLite backend.

use super::{SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error};
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        AuthLevel, BrowserSecretHash, MutationContext, ProfileId, RevocationReason, Session,
        SessionAuthentication, SessionEnd, SessionId, session::Elevation,
    },
};

/// A stored assurance level; an unknown one is an error, never `Basic`.
pub(super) fn auth_level(column: &str, value: &str) -> SidResult<AuthLevel> {
    AuthLevel::from_acr_value(value)
        .ok_or_else(|| SidError::Storage(format!("column {column}: unknown level {value}")))
}

/// The step-up stored in `elevation_level` / `elevation_until`: both or
/// neither.
pub(super) fn elevation_col(row: &sqlx::sqlite::SqliteRow) -> SidResult<Option<Elevation>> {
    let elevation_level: Option<String> = col(row, "elevation_level")?;
    match (elevation_level, dt_col_opt(row, "elevation_until")?) {
        (Some(level), Some(until)) => Ok(Some(Elevation {
            level: auth_level("elevation_level", &level)?,
            until,
        })),
        (None, None) => Ok(None),
        _ => Err(SidError::Storage(
            "elevation level and time must be stored together".into(),
        )),
    }
}

pub(super) fn row_to_session(row: &sqlx::sqlite::SqliteRow) -> SidResult<Session> {
    let assurance_level: String = col(row, "assurance_level")?;
    let elevation = elevation_col(row)?;
    let browser_secret_hash: Option<Vec<u8>> = col(row, "browser_secret_hash")?;
    let device_id: Option<String> = col(row, "device_id")?;
    let scopes: String = col(row, "scopes")?;
    let amr: String = col(row, "amr")?;

    Ok(Session {
        id: col(row, "id")?,
        profile_id: col(row, "profile_id")?,
        client_id: col(row, "client_id")?,
        device_id: device_id
            .map(|s| {
                uuid::Uuid::parse_str(&s)
                    .map_err(|e| SidError::Storage(format!("column device_id: {e}")))
            })
            .transpose()?,
        ip_address: col(row, "ip_address")?,
        user_agent: col(row, "user_agent")?,
        scopes: Session::parse_scopes(&scopes),
        assurance_level: auth_level("assurance_level", &assurance_level)?,
        elevation,
        authenticated_at: dt_col(row, "authenticated_at")?,
        amr: amr.split_whitespace().map(String::from).collect(),
        is_provisional: col(row, "is_provisional")?,
        passkey_prompt: col(row, "passkey_prompt")?,
        policy_grace: col(row, "policy_grace")?,
        grace_deadline: dt_col_opt(row, "grace_deadline")?,
        created_at: dt_col(row, "created_at")?,
        expires_at: dt_col(row, "expires_at")?,
        last_activity_at: dt_col_opt(row, "last_activity_at")?,
        browser_secret_hash: browser_secret_hash
            .as_deref()
            .map(BrowserSecretHash::try_from)
            .transpose()?,
        authenticated_by: col(row, "authenticated_by")?,
    })
}

/// Insert `session` through `executor`; an existing session with its id is a
/// `Conflict`, never replaced.
pub(super) async fn insert_session<'e, E>(executor: E, session: &Session) -> SidResult<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        "INSERT INTO sessions (id, profile_id, client_id, device_id, ip_address, user_agent,
            scopes, assurance_level, elevation_level, elevation_until, is_provisional,
            passkey_prompt, authenticated_at, amr, policy_grace, grace_deadline, created_at,
            expires_at, last_activity_at, browser_secret_hash, authenticated_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(session.id)
    .bind(session.profile_id)
    .bind(&session.client_id)
    .bind(session.device_id.map(|d| d.to_string()))
    .bind(&session.ip_address)
    .bind(&session.user_agent)
    .bind(session.scopes_string())
    .bind(session.assurance_level.as_str())
    .bind(session.elevation.map(|e| e.level.as_str()))
    .bind(fmt_dt_opt(session.elevation.map(|e| e.until)))
    .bind(session.is_provisional)
    .bind(session.passkey_prompt)
    .bind(fmt_dt(&session.authenticated_at))
    .bind(session.amr.join(" "))
    .bind(session.policy_grace)
    .bind(fmt_dt_opt(session.grace_deadline))
    .bind(fmt_dt(&session.created_at))
    .bind(fmt_dt(&session.expires_at))
    .bind(fmt_dt_opt(session.last_activity_at))
    .bind(session.browser_secret_hash.map(|h| h.as_bytes().to_vec()))
    .bind(session.authenticated_by)
    .execute(executor)
    .await
    .map_err(|e| insert_error("session", e))?;
    Ok(())
}

/// Delete session `id` and the sessions it authenticated in `tx`; returns
/// every session ended.
async fn end_with_dependents(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: SessionId,
) -> SidResult<Vec<Session>> {
    sqlx::query("DELETE FROM sessions WHERE id = ?1 OR authenticated_by = ?1 RETURNING *")
        .bind(id)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| SidError::Storage(format!("end session: {e}")))?
        .iter()
        .map(row_to_session)
        .collect()
}

impl SqliteBackend {
    pub(crate) async fn create_session_impl(
        &self,
        session: &Session,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        insert_session(&mut *tx, session).await?;
        Self::commit_mutation(tx, &format!("session:{}", session.id), ctx).await
    }

    /// Write `new` over the authentication of session `id` while the stored
    /// one equals `expected` and the session has not expired.
    pub(crate) async fn record_session_authentication_impl(
        &self,
        id: SessionId,
        expected: &SessionAuthentication,
        new: &SessionAuthentication,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let applied = sqlx::query(
            "UPDATE sessions SET assurance_level = ?, elevation_level = ?, elevation_until = ?,
                authenticated_at = ?, amr = ?
             WHERE id = ? AND expires_at > ?
               AND assurance_level = ? AND elevation_level IS ? AND elevation_until IS ?
               AND authenticated_at = ? AND amr = ?",
        )
        .bind(new.assurance_level.as_str())
        .bind(new.elevation.map(|e| e.level.as_str()))
        .bind(fmt_dt_opt(new.elevation.map(|e| e.until)))
        .bind(fmt_dt(&new.authenticated_at))
        .bind(new.amr.join(" "))
        .bind(id)
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(expected.assurance_level.as_str())
        .bind(expected.elevation.map(|e| e.level.as_str()))
        .bind(fmt_dt_opt(expected.elevation.map(|e| e.until)))
        .bind(fmt_dt(&expected.authenticated_at))
        .bind(expected.amr.join(" "))
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("record session authentication: {e}")))?
        .rows_affected()
            == 1;
        if !applied {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("session:{id}"), ctx).await?;
        Ok(true)
    }

    /// Insert `session`, first evicting the profile's oldest active sessions
    /// so that at most `max_sessions` remain (0 is unlimited). The write lock
    /// taken by `BEGIN IMMEDIATE` makes the count and the insert one step for
    /// concurrent sign-ins; each evicted session owes its client a logout,
    /// committed with the eviction.
    pub(crate) async fn create_session_atomic_impl(
        &self,
        session: &Session,
        max_sessions: u32,
        mut ctx: MutationContext,
    ) -> SidResult<Vec<SessionId>> {
        let storage = |e: sqlx::Error| SidError::Storage(e.to_string());
        let mut tx = self.begin_write().await?;
        let mut evicted = Vec::new();
        if max_sessions > 0 {
            let now = fmt_dt(&chrono::Utc::now());
            let active: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sessions WHERE profile_id = ? AND expires_at > ?",
            )
            .bind(session.profile_id)
            .bind(&now)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
            // One slot is taken by the new session.
            let excess = active - i64::from(max_sessions) + 1;
            if excess > 0 {
                let oldest: Vec<SessionId> = sqlx::query_scalar(
                    "SELECT id FROM sessions WHERE profile_id = ? AND expires_at > ?
                     ORDER BY created_at ASC LIMIT ?",
                )
                .bind(session.profile_id)
                .bind(&now)
                .bind(excess)
                .fetch_all(&mut *tx)
                .await
                .map_err(storage)?;
                // An evicted session ends like any other and owes the same,
                // and so do the sessions it authenticated. Refresh tokens go
                // with them (foreign key cascade).
                let end = SessionEnd::new(RevocationReason::SessionLimit, "system");
                for id in oldest {
                    for ended in end_with_dependents(&mut tx, id).await? {
                        ctx.work.extend(end.owed_by(&ended));
                        evicted.push(ended.id);
                    }
                }
            }
        }
        insert_session(&mut *tx, session).await?;
        Self::commit_mutation(tx, &format!("profile:{}", session.profile_id), ctx).await?;
        Ok(evicted)
    }

    pub(crate) async fn get_session_impl(&self, id: SessionId) -> SidResult<Option<Session>> {
        let row = sqlx::query("SELECT * FROM sessions WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_session).transpose()
    }

    pub(crate) async fn get_session_by_browser_secret_impl(
        &self,
        hash: &BrowserSecretHash,
    ) -> SidResult<Option<Session>> {
        let row = sqlx::query("SELECT * FROM sessions WHERE browser_secret_hash = ?")
            .bind(hash.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("session by browser secret: {e}")))?;
        row.as_ref().map(row_to_session).transpose()
    }

    /// Stored times share one fixed-width UTC format, so they order as text.
    pub(crate) async fn touch_session_impl(
        &self,
        id: SessionId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> SidResult<()> {
        sqlx::query(
            "UPDATE sessions SET last_activity_at = ?
             WHERE id = ? AND (last_activity_at IS NULL OR last_activity_at < ?)",
        )
        .bind(fmt_dt(&at))
        .bind(id)
        .bind(fmt_dt(&at))
        .execute(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("touch session: {e}")))?;
        Ok(())
    }

    /// Delete the session and the sessions it authenticated, and commit the
    /// work each owes under `end`, with the caller's work, in the same
    /// transaction.
    pub(crate) async fn delete_session_impl(
        &self,
        id: SessionId,
        end: &SessionEnd,
        mut ctx: MutationContext,
    ) -> SidResult<Vec<SessionId>> {
        let mut tx = self.begin_write().await?;
        let ended = end_with_dependents(&mut tx, id).await?;
        for session in &ended {
            ctx.work.extend(end.owed_by(session));
        }
        Self::commit_mutation(tx, &format!("session:{id}"), ctx).await?;
        Ok(ended.into_iter().map(|session| session.id).collect())
    }

    /// Delete the profile's sessions and commit the work they owe under
    /// `end` in the same transaction.
    pub(crate) async fn delete_sessions_by_profile_impl(
        &self,
        profile_id: ProfileId,
        end: &SessionEnd,
        mut ctx: MutationContext,
    ) -> SidResult<Vec<Session>> {
        let mut tx = self.begin_write().await?;
        let sessions = super::directory::end_sessions(&mut tx, profile_id, end, &mut ctx).await?;
        Self::commit_mutation(tx, &format!("profile:{profile_id}"), ctx).await?;
        Ok(sessions)
    }

    pub(crate) async fn list_sessions_by_profile_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<Session>> {
        let rows =
            sqlx::query("SELECT * FROM sessions WHERE profile_id = ? ORDER BY created_at DESC")
                .bind(profile_id)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_session).collect()
    }
}
