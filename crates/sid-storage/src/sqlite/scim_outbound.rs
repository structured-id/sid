// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM outbound provisioning targets, sync records and dead letters for
//! SQLite backend.

use chrono::{DateTime, Utc};
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        MutationContext, OutboundDlqEntry, OutboundEntityType, ProjectId, ScimOutboundRecord,
        ScimOutboundTarget, ScimOutboundTargetId,
    },
};
use uuid::Uuid;

use super::{SqliteBackend, col, dt_col, fmt_dt, uuid_col};

fn json_col<T: serde::de::DeserializeOwned>(
    row: &sqlx::sqlite::SqliteRow,
    name: &str,
) -> SidResult<T> {
    let text: String = col(row, name)?;
    serde_json::from_str(&text).map_err(|e| SidError::Storage(format!("column {name}: {e}")))
}

fn to_json<T: serde::Serialize>(value: &T, name: &str) -> SidResult<String> {
    serde_json::to_string(value).map_err(|e| SidError::Storage(format!("{name}: {e}")))
}

fn entity_type_col(row: &sqlx::sqlite::SqliteRow) -> SidResult<OutboundEntityType> {
    col::<String>(row, "entity_type")?
        .parse()
        .map_err(SidError::Storage)
}

fn count_col(row: &sqlx::sqlite::SqliteRow, name: &str) -> SidResult<u32> {
    u32::try_from(col::<i64>(row, name)?)
        .map_err(|e| SidError::Storage(format!("column {name}: {e}")))
}

fn row_to_target(row: &sqlx::sqlite::SqliteRow) -> SidResult<ScimOutboundTarget> {
    Ok(ScimOutboundTarget {
        id: ScimOutboundTargetId(uuid_col(row, "id")?),
        client_id: col(row, "client_id")?,
        project_id: ProjectId(uuid_col(row, "project_id")?),
        display_name: col(row, "display_name")?,
        endpoint_url: col(row, "endpoint_url")?,
        auth: json_col(row, "auth_config")?,
        attribute_mapping: json_col(row, "attribute_mapping")?,
        group_push: json_col(row, "group_push")?,
        sync_config: json_col(row, "sync_config")?,
        enabled: col(row, "enabled")?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

fn row_to_record(row: &sqlx::sqlite::SqliteRow) -> SidResult<ScimOutboundRecord> {
    Ok(ScimOutboundRecord {
        target_id: ScimOutboundTargetId(uuid_col(row, "target_id")?),
        sid_entity_id: uuid_col(row, "sid_entity_id")?,
        entity_type: entity_type_col(row)?,
        downstream_id: col(row, "downstream_id")?,
        last_synced_at: dt_col(row, "last_synced_at")?,
        last_error: col(row, "last_error")?,
        failure_count: count_col(row, "failure_count")?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

fn row_to_dlq_entry(row: &sqlx::sqlite::SqliteRow) -> SidResult<OutboundDlqEntry> {
    Ok(OutboundDlqEntry {
        id: uuid_col(row, "id")?,
        target_id: ScimOutboundTargetId(uuid_col(row, "target_id")?),
        event_type: col(row, "event_type")?,
        payload: json_col(row, "payload")?,
        sid_entity_id: uuid_col(row, "sid_entity_id")?,
        entity_type: entity_type_col(row)?,
        error: col(row, "error")?,
        attempts: count_col(row, "attempts")?,
        first_attempt: dt_col(row, "first_attempt")?,
        last_attempt: dt_col(row, "last_attempt")?,
    })
}

fn record_audit_key(target_id: ScimOutboundTargetId, sid_entity_id: Uuid) -> String {
    format!("scim_outbound_record:{}:{}", target_id.0, sid_entity_id)
}

impl SqliteBackend {
    pub(crate) async fn create_scim_outbound_target_impl(
        &self,
        target: &ScimOutboundTarget,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO scim_outbound_targets (id, client_id, project_id, display_name, endpoint_url, \
                auth_config, attribute_mapping, group_push, sync_config, enabled, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(target.id.0.to_string())
        .bind(&target.client_id)
        .bind(target.project_id.0.to_string())
        .bind(&target.display_name)
        .bind(&target.endpoint_url)
        .bind(to_json(&target.auth, "auth")?)
        .bind(to_json(&target.attribute_mapping, "attribute mapping")?)
        .bind(to_json(&target.group_push, "group push")?)
        .bind(to_json(&target.sync_config, "sync config")?)
        .bind(target.enabled)
        .bind(fmt_dt(&target.created_at))
        .bind(fmt_dt(&target.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("scim outbound target", e))?;
        Self::commit_mutation(tx, &format!("scim_outbound_target:{}", target.id.0), audit).await
    }

    pub(crate) async fn get_scim_outbound_target_impl(
        &self,
        id: ScimOutboundTargetId,
    ) -> SidResult<Option<ScimOutboundTarget>> {
        let row = sqlx::query("SELECT * FROM scim_outbound_targets WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_target).transpose()
    }

    pub(crate) async fn list_scim_outbound_targets_impl(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Vec<ScimOutboundTarget>> {
        let rows =
            sqlx::query("SELECT * FROM scim_outbound_targets WHERE project_id = ? AND enabled = 1")
                .bind(project_id.0.to_string())
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_target).collect()
    }

    pub(crate) async fn delete_scim_outbound_target_impl(
        &self,
        id: ScimOutboundTargetId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        // Its sync records and dead letters go with it (ON DELETE CASCADE).
        sqlx::query("DELETE FROM scim_outbound_targets WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {e}")))?;
        Self::commit_mutation(tx, &format!("scim_outbound_target:{}", id.0), audit).await
    }

    pub(crate) async fn create_scim_outbound_record_impl(
        &self,
        record: &ScimOutboundRecord,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO scim_outbound_records (target_id, sid_entity_id, entity_type, \
                downstream_id, last_synced_at, last_error, failure_count, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(record.target_id.0.to_string())
        .bind(record.sid_entity_id.to_string())
        .bind(record.entity_type.as_str())
        .bind(&record.downstream_id)
        .bind(fmt_dt(&record.last_synced_at))
        .bind(&record.last_error)
        .bind(i64::from(record.failure_count))
        .bind(fmt_dt(&record.created_at))
        .bind(fmt_dt(&record.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("scim outbound record", e))?;
        Self::commit_mutation(
            tx,
            &record_audit_key(record.target_id, record.sid_entity_id),
            audit,
        )
        .await
    }

    /// Point the mapping at the downstream id just provisioned and clear its
    /// error; an existing mapping keeps its creation time.
    pub(crate) async fn record_scim_outbound_sync_impl(
        &self,
        record: &ScimOutboundRecord,
        audit: MutationContext,
    ) -> SidResult<()> {
        let synced = fmt_dt(&record.last_synced_at);
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO scim_outbound_records (target_id, sid_entity_id, entity_type, \
                downstream_id, last_synced_at, last_error, failure_count, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, 0, ?5, ?5) \
             ON CONFLICT(target_id, sid_entity_id, entity_type) DO UPDATE SET \
                downstream_id = excluded.downstream_id, last_synced_at = excluded.last_synced_at, \
                last_error = NULL, failure_count = 0, updated_at = excluded.updated_at",
        )
        .bind(record.target_id.0.to_string())
        .bind(record.sid_entity_id.to_string())
        .bind(record.entity_type.as_str())
        .bind(&record.downstream_id)
        .bind(&synced)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("record scim sync: {e}")))?;
        Self::commit_mutation(
            tx,
            &record_audit_key(record.target_id, record.sid_entity_id),
            audit,
        )
        .await
    }

    pub(crate) async fn record_scim_outbound_failure_impl(
        &self,
        target_id: ScimOutboundTargetId,
        sid_entity_id: Uuid,
        entity_type: OutboundEntityType,
        error: &str,
        at: DateTime<Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let recorded = sqlx::query(
            "UPDATE scim_outbound_records SET last_error = ?, \
                failure_count = failure_count + 1, updated_at = ? \
             WHERE target_id = ? AND sid_entity_id = ? AND entity_type = ?",
        )
        .bind(error)
        .bind(fmt_dt(&at))
        .bind(target_id.0.to_string())
        .bind(sid_entity_id.to_string())
        .bind(entity_type.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("record scim failure: {e}")))?
        .rows_affected()
            == 1;
        if !recorded {
            return Ok(false);
        }
        Self::commit_mutation(tx, &record_audit_key(target_id, sid_entity_id), audit).await?;
        Ok(true)
    }

    pub(crate) async fn get_scim_outbound_record_impl(
        &self,
        target_id: ScimOutboundTargetId,
        sid_entity_id: Uuid,
        entity_type: OutboundEntityType,
    ) -> SidResult<Option<ScimOutboundRecord>> {
        let row = sqlx::query(
            "SELECT * FROM scim_outbound_records \
             WHERE target_id = ? AND sid_entity_id = ? AND entity_type = ?",
        )
        .bind(target_id.0.to_string())
        .bind(sid_entity_id.to_string())
        .bind(entity_type.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_record).transpose()
    }

    pub(crate) async fn create_outbound_dlq_entry_impl(
        &self,
        entry: &OutboundDlqEntry,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO scim_outbound_dlq (id, target_id, event_type, payload, sid_entity_id, \
                entity_type, error, attempts, first_attempt, last_attempt) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(entry.id.to_string())
        .bind(entry.target_id.0.to_string())
        .bind(&entry.event_type)
        .bind(to_json(&entry.payload, "payload")?)
        .bind(entry.sid_entity_id.to_string())
        .bind(entry.entity_type.as_str())
        .bind(&entry.error)
        .bind(i64::from(entry.attempts))
        .bind(fmt_dt(&entry.first_attempt))
        .bind(fmt_dt(&entry.last_attempt))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("outbound dlq entry", e))?;
        Self::commit_mutation(tx, &format!("outbound_dlq:{}", entry.id), audit).await
    }

    pub(crate) async fn list_outbound_dlq_entries_impl(
        &self,
        target_id: ScimOutboundTargetId,
    ) -> SidResult<Vec<OutboundDlqEntry>> {
        let rows = sqlx::query("SELECT * FROM scim_outbound_dlq WHERE target_id = ?")
            .bind(target_id.0.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_dlq_entry).collect()
    }

    pub(crate) async fn delete_outbound_dlq_entry_impl(
        &self,
        id: Uuid,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM scim_outbound_dlq WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {e}")))?;
        Self::commit_mutation(tx, &format!("outbound_dlq:{id}"), audit).await
    }
}
