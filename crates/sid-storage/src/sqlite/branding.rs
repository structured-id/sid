// SPDX-License-Identifier: AGPL-3.0-only
//! Branding configurations for the SQLite backend: content in `data`,
//! status, revision and last change in their columns.

use chrono::{DateTime, Utc};
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{BrandingConfig, BrandingConfigId, MutationContext, ProjectId},
};

use super::{SqliteBackend, col, dt_col, fmt_dt, parsed_col};

/// The status inside `data` is not read: the column is the record's status.
fn row_to_branding(row: &sqlx::sqlite::SqliteRow) -> SidResult<BrandingConfig> {
    let data: String = col(row, "data")?;
    let revision: i64 = col(row, "revision")?;
    let mut config: BrandingConfig =
        serde_json::from_str(&data).map_err(|e| SidError::Storage(format!("column data: {e}")))?;
    config.status = parsed_col(row, "status")?;
    config.revision =
        u64::try_from(revision).map_err(|e| SidError::Storage(format!("column revision: {e}")))?;
    config.updated_at = dt_col(row, "updated_at")?;
    Ok(config)
}

fn data_of(config: &BrandingConfig) -> SidResult<String> {
    serde_json::to_string(config).map_err(|e| SidError::Internal(format!("branding data: {e}")))
}

impl SqliteBackend {
    pub(crate) async fn create_branding_config_impl(
        &self,
        config: &BrandingConfig,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let data = data_of(config)?;
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO branding_configs (id, project_id, status, data, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(config.id.0.to_string())
        .bind(config.project_id.0.to_string())
        .bind(config.status.as_str())
        .bind(&data)
        .bind(fmt_dt(&config.created_at))
        .bind(fmt_dt(&config.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("branding config", e))?;
        Self::commit_mutation(tx, &format!("branding:{}", config.id.0), ctx).await
    }

    pub(crate) async fn update_branding_draft_impl(
        &self,
        config: &BrandingConfig,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let data = data_of(config)?;
        let revision = i64::try_from(config.revision)
            .map_err(|e| SidError::Validation(format!("branding revision: {e}")))?;
        let mut tx = self.begin_write().await?;
        let updated = sqlx::query(
            "UPDATE branding_configs SET data = ?, updated_at = ?, revision = revision + 1
             WHERE id = ? AND status = 'draft' AND revision = ?",
        )
        .bind(&data)
        .bind(fmt_dt(&config.updated_at))
        .bind(config.id.0.to_string())
        .bind(revision)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("update branding draft: {e}")))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("branding:{}", config.id.0), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn publish_branding_config_impl(
        &self,
        id: BrandingConfigId,
        project_id: ProjectId,
        at: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let at = fmt_dt(&at);
        // `BEGIN IMMEDIATE`: a concurrent publish waits for this one.
        let mut tx = self.begin_write().await?;
        let draft = sqlx::query(
            "SELECT id FROM branding_configs WHERE id = ? AND project_id = ? AND status = 'draft'",
        )
        .bind(id.0.to_string())
        .bind(project_id.0.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("publish branding: {e}")))?;
        if draft.is_none() {
            return Ok(false);
        }
        sqlx::query(
            "UPDATE branding_configs SET status = 'archived', updated_at = ?,
                revision = revision + 1
             WHERE project_id = ? AND status = 'published'",
        )
        .bind(&at)
        .bind(project_id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("archive branding: {e}")))?;
        sqlx::query(
            "UPDATE branding_configs SET status = 'published', updated_at = ?,
                revision = revision + 1
             WHERE id = ?",
        )
        .bind(&at)
        .bind(id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("published branding", e))?;
        Self::commit_mutation(tx, &format!("branding:{}", id.0), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn get_published_branding_impl(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Option<BrandingConfig>> {
        sqlx::query(
            "SELECT status, revision, updated_at, data FROM branding_configs
             WHERE project_id = ? AND status = 'published'",
        )
        .bind(project_id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query: {e}")))?
        .as_ref()
        .map(row_to_branding)
        .transpose()
    }

    pub(crate) async fn get_branding_config_impl(
        &self,
        id: BrandingConfigId,
    ) -> SidResult<Option<BrandingConfig>> {
        sqlx::query("SELECT status, revision, updated_at, data FROM branding_configs WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("Query: {e}")))?
            .as_ref()
            .map(row_to_branding)
            .transpose()
    }

    pub(crate) async fn list_branding_configs_impl(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Vec<BrandingConfig>> {
        sqlx::query(
            "SELECT status, revision, updated_at, data FROM branding_configs
             WHERE project_id = ? ORDER BY updated_at DESC, id",
        )
        .bind(project_id.0.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query: {e}")))?
        .iter()
        .map(row_to_branding)
        .collect()
    }

    pub(crate) async fn delete_branding_config_impl(
        &self,
        id: BrandingConfigId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        // A published config is never deleted, even one published meanwhile.
        let deleted =
            sqlx::query("DELETE FROM branding_configs WHERE id = ? AND status <> 'published'")
                .bind(id.0.to_string())
                .execute(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("Delete: {e}")))?
                .rows_affected()
                == 1;
        if !deleted {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("branding:{}", id.0), ctx).await?;
        Ok(true)
    }
}
