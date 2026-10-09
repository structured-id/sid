// SPDX-License-Identifier: AGPL-3.0-only
//! Password reset sessions for SQLite backend.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        Credential, CredentialType, MutationContext, PasswordResetSession, ProfileId,
        ResetSessionId, Session, SessionEnd,
    },
};
use sqlx::Row;
use uuid::Uuid;

use super::profile::insert_credential;
use super::session::row_to_session;
use super::{SqliteBackend, col, fmt_dt, fmt_dt_opt, parse_dt, parse_dt_opt};

fn row_to_reset_session(row: &sqlx::sqlite::SqliteRow) -> SidResult<PasswordResetSession> {
    let id: String = col(row, "id")?;
    Ok(PasswordResetSession {
        id: ResetSessionId(
            Uuid::parse_str(&id).map_err(|e| SidError::Storage(format!("column id: {e}")))?,
        ),
        profile_id: col(row, "profile_id")?,
        email: col(row, "email")?,
        token_hash: col(row, "token_hash")?,
        status: col::<String>(row, "status")?
            .parse()
            .map_err(SidError::Storage)?,
        created_at: parse_dt(&row.get::<String, _>("created_at")),
        expires_at: parse_dt(&row.get::<String, _>("expires_at")),
        verified_at: parse_dt_opt(row.get("verified_at")),
        completed_at: parse_dt_opt(row.get("completed_at")),
    })
}

impl SqliteBackend {
    pub(crate) async fn create_reset_session_impl(
        &self,
        session: &PasswordResetSession,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO password_reset_sessions \
                (id, profile_id, email, token_hash, status, created_at, expires_at, verified_at, completed_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(session.id.0.to_string())
        .bind(session.profile_id)
        .bind(&session.email)
        .bind(&session.token_hash)
        .bind(session.status.as_str())
        .bind(fmt_dt(&session.created_at))
        .bind(fmt_dt(&session.expires_at))
        .bind(fmt_dt_opt(session.verified_at))
        .bind(fmt_dt_opt(session.completed_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("reset session", e))?;
        Self::commit_mutation(tx, &format!("reset_session:{}", session.id.0), audit).await
    }

    pub(crate) async fn get_reset_session_impl(
        &self,
        id: ResetSessionId,
    ) -> SidResult<Option<PasswordResetSession>> {
        let row = sqlx::query(
            "SELECT id, profile_id, email, token_hash, status, created_at, expires_at, verified_at, completed_at \
             FROM password_reset_sessions WHERE id = ?",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_reset_session).transpose()
    }

    pub(crate) async fn verify_reset_session_impl(
        &self,
        id: ResetSessionId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        let verified = sqlx::query(
            "UPDATE password_reset_sessions SET status = 'verified', verified_at = ?1 \
             WHERE id = ?2 AND status = 'pending' AND expires_at > ?1",
        )
        .bind(&now)
        .bind(id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Verify reset_session failed: {e}")))?
        .rows_affected()
            == 1;
        // Not pending or expired: nothing written, nothing audited.
        if !verified {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("reset_session:{}", id.0), audit).await?;
        Ok(true)
    }

    pub(crate) async fn complete_password_reset_impl(
        &self,
        id: ResetSessionId,
        credential: &Credential,
        history: Option<&sid_core::models::HistoryCommit>,
        end: &SessionEnd,
        mut ctx: MutationContext,
    ) -> SidResult<Option<Vec<Session>>> {
        if history.is_some_and(|h| h.owner != credential.profile_id) {
            return Err(SidError::Validation(
                "password history belongs to the credential's profile".into(),
            ));
        }
        if credential.credential_type != CredentialType::Opaque {
            return Err(SidError::Validation(
                "a password replacement installs an OPAQUE credential".into(),
            ));
        }
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        let completed: Option<ProfileId> = sqlx::query_scalar(
            "UPDATE password_reset_sessions SET status = 'completed', completed_at = ?1 \
             WHERE id = ?2 AND status = 'verified' AND expires_at > ?1 \
             RETURNING profile_id",
        )
        .bind(&now)
        .bind(id.0.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Complete reset_session failed: {e}")))?;
        // Not verified or expired: nothing written.
        let Some(profile_id) = completed else {
            return Ok(None);
        };
        if profile_id != credential.profile_id {
            return Err(SidError::Validation(
                "the new password belongs to another profile than the reset".into(),
            ));
        }
        // Check retained history before deleting the old credential: an
        // adopted file can hold its constraint only on that row. All effects
        // still share this transaction and roll back on any later failure.
        if history.is_none() {
            super::password_history::require_current_format(&mut tx, profile_id).await?;
        }
        if let Some(history) = history
            && !super::password_history::apply_in_tx(&mut tx, history).await?
        {
            return Ok(None);
        }
        sqlx::query("DELETE FROM credentials WHERE profile_id = ? AND credential_type IN (?, ?)")
            .bind(profile_id)
            .bind(CredentialType::Opaque.as_str())
            .bind(CredentialType::LegacyHash.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        insert_credential(&mut *tx, credential).await?;
        let sessions = sqlx::query("DELETE FROM sessions WHERE profile_id = ? RETURNING *")
            .bind(profile_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?
            .iter()
            .map(row_to_session)
            .collect::<SidResult<Vec<Session>>>()?;
        for ended in &sessions {
            ctx.work.extend(end.owed_by(ended));
        }
        Self::commit_mutation(tx, &format!("profile:{profile_id}"), ctx).await?;
        Ok(Some(sessions))
    }

    pub(crate) async fn count_active_reset_sessions_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<u32> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM password_reset_sessions \
             WHERE profile_id = ? AND status IN ('pending', 'verified') AND expires_at > ?",
        )
        .bind(profile_id)
        .bind(fmt_dt(&chrono::Utc::now()))
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        u32::try_from(count).map_err(|e| SidError::Storage(e.to_string()))
    }

    pub(crate) async fn delete_expired_reset_sessions_impl(
        &self,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        let deleted = sqlx::query(
            "DELETE FROM password_reset_sessions WHERE expires_at < ? AND status = 'pending'",
        )
        .bind(fmt_dt(&chrono::Utc::now()))
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected();
        Self::commit_bulk(tx, deleted, "reset_sessions:cleanup", audit).await
    }

    /// Drop expired proofs; the assignment and its revision stay.
    pub(crate) async fn expire_principal_verifications_impl(&self) -> SidResult<i64> {
        let now = fmt_dt(&chrono::Utc::now());
        let expired = sqlx::query(
            "UPDATE principals SET verified = 0, updated_at = ?1 \
             WHERE verified = 1 AND verification_expires IS NOT NULL AND verification_expires < ?1",
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Expire failed: {e}")))?
        .rows_affected();
        i64::try_from(expired).map_err(|e| SidError::Storage(e.to_string()))
    }
}
