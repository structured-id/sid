// SPDX-License-Identifier: AGPL-3.0-only
//! Flow actions for the SQLite backend: content in `data`, the hook point,
//! execution order and revision in their columns.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{ActionId, ActionPoint, FlowAction, FlowType, MutationContext, ProjectId},
};

use super::{SqliteBackend, col, fmt_dt};

/// The revision inside `data` is not read: the column is the stored one.
fn row_to_action(row: &sqlx::sqlite::SqliteRow) -> SidResult<FlowAction> {
    let data: String = col(row, "data")?;
    let revision: i64 = col(row, "revision")?;
    let mut action: FlowAction =
        serde_json::from_str(&data).map_err(|e| SidError::Storage(format!("column data: {e}")))?;
    action.revision =
        u64::try_from(revision).map_err(|e| SidError::Storage(format!("column revision: {e}")))?;
    Ok(action)
}

fn data_of(action: &FlowAction) -> SidResult<String> {
    serde_json::to_string(action).map_err(|e| SidError::Internal(format!("flow action: {e}")))
}

impl SqliteBackend {
    pub(crate) async fn create_flow_action_impl(
        &self,
        action: &FlowAction,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let data = data_of(action)?;
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO flow_actions (id, project_id, flow_type, action_point, action_order,
                data, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(action.id.0.to_string())
        .bind(action.project_id.0.to_string())
        .bind(action.flow_type.as_str())
        .bind(action.action_point.as_str())
        .bind(action.order)
        .bind(&data)
        .bind(fmt_dt(&action.created_at))
        .bind(fmt_dt(&action.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("flow action", e))?;
        Self::commit_mutation(tx, &format!("flow_action:{}", action.id), ctx).await
    }

    /// The hook point and order move with the content, so the listing sees
    /// the action where it now runs.
    pub(crate) async fn update_flow_action_impl(
        &self,
        action: &FlowAction,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let data = data_of(action)?;
        let revision = i64::try_from(action.revision)
            .map_err(|e| SidError::Validation(format!("flow action revision: {e}")))?;
        let mut tx = self.begin_write().await?;
        let updated = sqlx::query(
            "UPDATE flow_actions SET action_point = ?, action_order = ?, data = ?, updated_at = ?,
                revision = revision + 1
             WHERE id = ? AND revision = ?",
        )
        .bind(action.action_point.as_str())
        .bind(action.order)
        .bind(&data)
        .bind(fmt_dt(&action.updated_at))
        .bind(action.id.0.to_string())
        .bind(revision)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("update flow action: {e}")))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("flow_action:{}", action.id), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn get_flow_action_impl(&self, id: ActionId) -> SidResult<Option<FlowAction>> {
        sqlx::query("SELECT data, revision FROM flow_actions WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("Query: {e}")))?
            .as_ref()
            .map(row_to_action)
            .transpose()
    }

    pub(crate) async fn list_flow_actions_impl(
        &self,
        project_id: ProjectId,
        flow_type: FlowType,
        action_point: Option<ActionPoint>,
    ) -> SidResult<Vec<FlowAction>> {
        let rows = match action_point {
            Some(point) => {
                sqlx::query(
                    "SELECT data, revision FROM flow_actions
                 WHERE project_id = ? AND flow_type = ? AND action_point = ?
                 ORDER BY action_order, id",
                )
                .bind(project_id.0.to_string())
                .bind(flow_type.as_str())
                .bind(point.as_str())
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query(
                    "SELECT data, revision FROM flow_actions
                 WHERE project_id = ? AND flow_type = ?
                 ORDER BY action_point, action_order, id",
                )
                .bind(project_id.0.to_string())
                .bind(flow_type.as_str())
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|e| SidError::Storage(format!("Query: {e}")))?;
        rows.iter().map(row_to_action).collect()
    }
}
