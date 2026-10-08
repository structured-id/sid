// SPDX-License-Identifier: AGPL-3.0-only
//! Access request and notification preference operations for SQLite backend.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        AccessRequest, AccessRequestId, AccessRequestStatus, MutationContext, ProfileId, ProjectId,
        RoleAssignment, notification::NotificationPreferences,
    },
};

use super::{SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error, uuid_col};

/// The columns an access request is read from.
macro_rules! access_request_columns {
    () => {
        "id, requester_id, project_id, role_key, justification, requested_duration_hours, \
         status, reviewed_by, review_comment, created_at, reviewed_at, expires_at"
    };
}

fn row_to_access_request(row: &sqlx::sqlite::SqliteRow) -> SidResult<AccessRequest> {
    let status: String = col(row, "status")?;
    Ok(AccessRequest {
        id: AccessRequestId(uuid_col(row, "id")?),
        requester_id: col(row, "requester_id")?,
        project_id: ProjectId(uuid_col(row, "project_id")?),
        role_key: col(row, "role_key")?,
        justification: col(row, "justification")?,
        requested_duration_hours: col::<Option<i64>>(row, "requested_duration_hours")?
            .map(u32::try_from)
            .transpose()
            .map_err(|e| SidError::Storage(format!("requested_duration_hours: {e}")))?,
        status: AccessRequestStatus::from_str_loose(&status)
            .ok_or_else(|| SidError::Storage(format!("unknown access request status: {status}")))?,
        reviewed_by: col(row, "reviewed_by")?,
        review_comment: col(row, "review_comment")?,
        created_at: dt_col(row, "created_at")?,
        reviewed_at: dt_col_opt(row, "reviewed_at")?,
        expires_at: dt_col_opt(row, "expires_at")?,
    })
}

/// Record the decision in `request` on a request still pending; false,
/// writing nothing, when it was already decided.
async fn decide_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request: &AccessRequest,
) -> SidResult<bool> {
    Ok(sqlx::query(
        "UPDATE access_requests SET status = ?, reviewed_by = ?, review_comment = ?, reviewed_at = ? \
         WHERE id = ? AND status = 'pending'",
    )
    .bind(request.status.as_str())
    .bind(request.reviewed_by)
    .bind(&request.review_comment)
    .bind(fmt_dt_opt(request.reviewed_at))
    .bind(request.id.0.to_string())
    .execute(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("Decide access_request failed: {e}")))?
    .rows_affected()
        == 1)
}

impl SqliteBackend {
    pub(crate) async fn create_access_request_impl(
        &self,
        request: &AccessRequest,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(concat!(
            "INSERT INTO access_requests (",
            access_request_columns!(),
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ))
        .bind(request.id.0.to_string())
        .bind(request.requester_id)
        .bind(request.project_id.0.to_string())
        .bind(&request.role_key)
        .bind(&request.justification)
        .bind(request.requested_duration_hours.map(i64::from))
        .bind(request.status.as_str())
        .bind(request.reviewed_by)
        .bind(&request.review_comment)
        .bind(fmt_dt(&request.created_at))
        .bind(fmt_dt_opt(request.reviewed_at))
        .bind(fmt_dt_opt(request.expires_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("access request", e))?;
        Self::commit_mutation(tx, &format!("access_request:{}", request.id.0), ctx).await
    }

    pub(crate) async fn get_access_request_impl(
        &self,
        id: AccessRequestId,
    ) -> SidResult<Option<AccessRequest>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            access_request_columns!(),
            " FROM access_requests WHERE id = ?"
        ))
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_access_request).transpose()
    }

    pub(crate) async fn list_pending_access_requests_impl(&self) -> SidResult<Vec<AccessRequest>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            access_request_columns!(),
            " FROM access_requests WHERE status = 'pending' \
              AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at ASC"
        ))
        .bind(fmt_dt(&chrono::Utc::now()))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_access_request).collect()
    }

    pub(crate) async fn decide_access_request_impl(
        &self,
        request: &AccessRequest,
        audit: MutationContext,
    ) -> SidResult<bool> {
        request.check_plain_decision()?;
        let mut tx = self.begin_write().await?;
        // Already decided: nothing written, nothing audited.
        if !decide_in_tx(&mut tx, request).await? {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("access_request:{}", request.id.0), audit).await?;
        Ok(true)
    }

    pub(crate) async fn approve_access_request_impl(
        &self,
        request: &AccessRequest,
        grant: &RoleAssignment,
        audit: MutationContext,
    ) -> SidResult<bool> {
        request.check_approval(grant)?;
        let mut tx = self.begin_write().await?;
        if !decide_in_tx(&mut tx, request).await? {
            return Ok(false);
        }
        // A grant that cannot be stored rolls the approval back.
        super::rbac::insert_role_assignment(&mut tx, grant).await?;
        Self::commit_mutation(tx, &format!("access_request:{}", request.id.0), audit).await?;
        Ok(true)
    }

    pub(crate) async fn get_notification_preferences_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<NotificationPreferences>> {
        let row = sqlx::query(
            "SELECT preferences, updated_at FROM notification_preferences WHERE profile_id = ?",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let preferences: String = col(&row, "preferences")?;
        Ok(Some(NotificationPreferences {
            profile_id,
            categories: serde_json::from_str(&preferences)
                .map_err(|e| SidError::Storage(format!("notification preferences: {e}")))?,
            updated_at: dt_col(&row, "updated_at")?,
        }))
    }

    pub(crate) async fn save_notification_preferences_impl(
        &self,
        preferences: &NotificationPreferences,
        audit: MutationContext,
    ) -> SidResult<()> {
        let json = serde_json::to_string(&preferences.categories)
            .map_err(|e| SidError::Storage(format!("notification preferences: {e}")))?;
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO notification_preferences (profile_id, preferences, updated_at) \
             VALUES (?, ?, ?) \
             ON CONFLICT(profile_id) DO UPDATE SET \
                preferences = excluded.preferences, updated_at = excluded.updated_at",
        )
        .bind(preferences.profile_id)
        .bind(json)
        .bind(fmt_dt(&preferences.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Save notification preferences failed: {e}")))?;
        Self::commit_mutation(tx, &format!("profile:{}", preferences.profile_id), audit).await
    }
}
