// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM outbound worker.
//!
//! Subscribes to corporate profile/group change events and dispatches
//! SCIM requests to configured downstream apps.

use std::sync::Arc;

use chrono::Utc;
use sid_core::models::{
    AuditEntry, MutationContext, OutboundEntityType, ProfileId, ScimOutboundRecord,
    ScimOutboundTarget, ScimOutboundTargetId,
    event::{Event, EventFilter, event_types},
};
use sid_plugin::StorageBackend;
use sid_plugin::event_bus::EventBus;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::client::{ScimClientError, ScimHttpClient};
use super::mapper::{self, ScimPatchPayload};

/// Outbound worker that processes events and dispatches SCIM requests.
pub struct ScimOutboundWorker {
    storage: Arc<dyn StorageBackend>,
    event_bus: Arc<dyn EventBus>,
    /// Loaded outbound targets (cached at startup, reloaded on config change).
    targets: Vec<ScimOutboundTarget>,
}

impl ScimOutboundWorker {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        event_bus: Arc<dyn EventBus>,
        targets: Vec<ScimOutboundTarget>,
    ) -> Self {
        Self {
            storage,
            event_bus,
            targets,
        }
    }

    /// Subscribe to SCIM events and process them on a background task. A
    /// subscription that cannot be made is returned, not logged away.
    pub async fn start(
        self: Arc<Self>,
    ) -> Result<tokio::task::JoinHandle<()>, sid_plugin::event_bus::EventBusError> {
        let filter = EventFilter {
            event_types: vec!["sid.scim.*".into()],
            queue_group: Some("sid-scim-worker".into()),
            ..Default::default()
        };
        let rx = self.event_bus.subscribe(filter).await?;
        info!(targets = self.targets.len(), "SCIM outbound worker started");
        Ok(tokio::spawn(self.process_events(rx)))
    }

    async fn process_events(self: Arc<Self>, mut rx: mpsc::Receiver<Event>) {
        while let Some(event) = rx.recv().await {
            let active_targets: Vec<&ScimOutboundTarget> =
                self.targets.iter().filter(|t| t.enabled).collect();

            if active_targets.is_empty() {
                continue;
            }

            debug!(
                event_type = %event.event_type,
                subject = ?event.subject,
                "processing SCIM outbound event"
            );

            for target in &active_targets {
                if let Err(e) = self.dispatch_to_target(target, &event).await {
                    error!(
                        target = %target.display_name,
                        event_type = %event.event_type,
                        error = %e,
                        "SCIM outbound dispatch failed"
                    );
                    self.handle_dispatch_failure(target, &event, &e).await;
                }
            }
        }

        info!("SCIM outbound worker stopped (event channel closed)");
    }

    /// Dispatch a single event to a single outbound target.
    async fn dispatch_to_target(
        &self,
        target: &ScimOutboundTarget,
        event: &Event,
    ) -> Result<(), ScimClientError> {
        let client = ScimHttpClient::new(target);

        match event.event_type.as_str() {
            t if t == event_types::SCIM_USER_PROVISIONED => {
                self.handle_user_provisioned(target, &client, event).await
            }
            t if t == event_types::SCIM_USER_UPDATED => {
                self.handle_user_updated(target, &client, event).await
            }
            t if t == event_types::SCIM_USER_DEACTIVATED => {
                self.handle_user_deactivated(target, &client, event).await
            }
            t if t == event_types::SCIM_USER_REACTIVATED => {
                self.handle_user_reactivated(target, &client, event).await
            }
            t if t == event_types::SCIM_GROUP_CREATED => {
                self.handle_group_created(target, &client, event).await
            }
            t if t == event_types::SCIM_GROUP_UPDATED => {
                self.handle_group_updated(target, &client, event).await
            }
            t if t == event_types::SCIM_GROUP_DELETED => {
                self.handle_group_deleted(target, &client, event).await
            }
            _ => {
                debug!(event_type = %event.event_type, "ignoring unknown event type");
                Ok(())
            }
        }
    }

    /// POST /Users — provision a new user to downstream app.
    async fn handle_user_provisioned(
        &self,
        target: &ScimOutboundTarget,
        client: &ScimHttpClient,
        event: &Event,
    ) -> Result<(), ScimClientError> {
        let profile_id = extract_profile_id(&event.data)?;

        // Load profile data from storage
        let (profile, principals, metadata) = self.load_profile_data(profile_id).await?;

        let payload =
            mapper::build_scim_user(&profile, &principals, &metadata, &target.attribute_mapping);

        let response = client.create_user(&payload).await?;

        // Store downstream mapping for future PATCH/DELETE
        if let Some(downstream_id) = response.id {
            self.save_outbound_record(
                target.id,
                profile_id.into_uuid(),
                OutboundEntityType::User,
                &downstream_id,
            )
            .await;
        }

        info!(
            target = %target.display_name,
            profile_id = %profile_id,
            "user provisioned to downstream"
        );

        Ok(())
    }

    /// PATCH /Users/{id} — update user in downstream app.
    async fn handle_user_updated(
        &self,
        target: &ScimOutboundTarget,
        client: &ScimHttpClient,
        event: &Event,
    ) -> Result<(), ScimClientError> {
        let profile_id = extract_profile_id(&event.data)?;

        let downstream_id = match self
            .find_downstream_id(target.id, profile_id.into_uuid(), OutboundEntityType::User)
            .await
        {
            Some(id) => id,
            None => {
                // Not previously provisioned — do a full POST instead
                return self.handle_user_provisioned(target, client, event).await;
            }
        };

        let (profile, principals, metadata) = self.load_profile_data(profile_id).await?;

        let payload =
            mapper::build_scim_user(&profile, &principals, &metadata, &target.attribute_mapping);

        // Build a PATCH with replace operations for all mapped attributes
        let json_value = serde_json::to_value(&payload)
            .map_err(|e| ScimClientError::Serialization(e.to_string()))?;

        let mut ops = Vec::new();
        if let serde_json::Value::Object(map) = json_value {
            for (key, value) in map {
                if key == "schemas" {
                    continue;
                }
                ops.push(mapper::ScimPatchOp {
                    op: "replace".into(),
                    path: Some(key),
                    value: Some(value),
                });
            }
        }

        let patch = ScimPatchPayload::new(ops);
        client.update_user(&downstream_id, &patch).await?;

        info!(
            target = %target.display_name,
            profile_id = %profile_id,
            "user updated in downstream"
        );

        Ok(())
    }

    /// PATCH /Users/{id} active=false — deactivate user in downstream.
    async fn handle_user_deactivated(
        &self,
        target: &ScimOutboundTarget,
        client: &ScimHttpClient,
        event: &Event,
    ) -> Result<(), ScimClientError> {
        let profile_id = extract_profile_id(&event.data)?;

        let downstream_id = match self
            .find_downstream_id(target.id, profile_id.into_uuid(), OutboundEntityType::User)
            .await
        {
            Some(id) => id,
            None => {
                debug!(
                    target = %target.display_name,
                    profile_id = %profile_id,
                    "user not found in downstream, skipping deactivation"
                );
                return Ok(());
            }
        };

        client.deactivate_user(&downstream_id).await?;

        info!(
            target = %target.display_name,
            profile_id = %profile_id,
            "user deactivated in downstream"
        );

        Ok(())
    }

    /// PATCH /Users/{id} active=true — reactivate user in downstream.
    async fn handle_user_reactivated(
        &self,
        target: &ScimOutboundTarget,
        client: &ScimHttpClient,
        event: &Event,
    ) -> Result<(), ScimClientError> {
        let profile_id = extract_profile_id(&event.data)?;

        let downstream_id = match self
            .find_downstream_id(target.id, profile_id.into_uuid(), OutboundEntityType::User)
            .await
        {
            Some(id) => id,
            None => {
                // Not previously provisioned — do a full POST instead
                return self.handle_user_provisioned(target, client, event).await;
            }
        };

        let patch = ScimPatchPayload::reactivate();
        client.update_user(&downstream_id, &patch).await?;

        info!(
            target = %target.display_name,
            profile_id = %profile_id,
            "user reactivated in downstream"
        );

        Ok(())
    }

    /// POST /Groups — create group in downstream.
    async fn handle_group_created(
        &self,
        target: &ScimOutboundTarget,
        client: &ScimHttpClient,
        event: &Event,
    ) -> Result<(), ScimClientError> {
        if !target.group_push.enabled {
            return Ok(());
        }

        let group_id = extract_uuid_field(&event.data, "group_id")?;
        let group_name = event
            .data
            .get("display_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Check if this group is mapped
        if mapper::resolve_group_mapping(group_name, &target.group_push).is_none() {
            return Ok(());
        }

        let payload = mapper::ScimGroupPayload {
            schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:Group".into()],
            display_name: group_name.to_string(),
            members: Vec::new(),
        };

        let response = client.create_group(&payload).await?;

        if let Some(downstream_id) = response.id {
            self.save_outbound_record(
                target.id,
                group_id,
                OutboundEntityType::Group,
                &downstream_id,
            )
            .await;
        }

        Ok(())
    }

    /// PATCH /Groups/{id} — update group members.
    async fn handle_group_updated(
        &self,
        target: &ScimOutboundTarget,
        client: &ScimHttpClient,
        event: &Event,
    ) -> Result<(), ScimClientError> {
        if !target.group_push.enabled {
            return Ok(());
        }

        let group_id = extract_uuid_field(&event.data, "group_id")?;

        let downstream_id = match self
            .find_downstream_id(target.id, group_id, OutboundEntityType::Group)
            .await
        {
            Some(id) => id,
            None => return Ok(()),
        };

        // Build patch from event data
        let mut ops = Vec::new();

        if let Some(add_members) = event.data.get("add_members").and_then(|v| v.as_array()) {
            let member_ids: Vec<String> = add_members
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if !member_ids.is_empty() {
                // Look up downstream IDs for each member
                let mut downstream_member_ids = Vec::new();
                for mid in &member_ids {
                    if let Ok(uuid) = Uuid::parse_str(mid)
                        && let Some(did) = self
                            .find_downstream_id(target.id, uuid, OutboundEntityType::User)
                            .await
                    {
                        downstream_member_ids.push(did);
                    }
                }
                if !downstream_member_ids.is_empty() {
                    let patch = ScimPatchPayload::add_members(downstream_member_ids);
                    ops.extend(patch.operations);
                }
            }
        }

        if let Some(remove_members) = event.data.get("remove_members").and_then(|v| v.as_array()) {
            let member_ids: Vec<String> = remove_members
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if !member_ids.is_empty() {
                let mut downstream_member_ids = Vec::new();
                for mid in &member_ids {
                    if let Ok(uuid) = Uuid::parse_str(mid)
                        && let Some(did) = self
                            .find_downstream_id(target.id, uuid, OutboundEntityType::User)
                            .await
                    {
                        downstream_member_ids.push(did);
                    }
                }
                if !downstream_member_ids.is_empty() {
                    let patch = ScimPatchPayload::remove_members(downstream_member_ids);
                    ops.extend(patch.operations);
                }
            }
        }

        if !ops.is_empty() {
            let patch = ScimPatchPayload::new(ops);
            client.update_group(&downstream_id, &patch).await?;
        }

        Ok(())
    }

    /// DELETE /Groups/{id} — delete group from downstream.
    async fn handle_group_deleted(
        &self,
        target: &ScimOutboundTarget,
        client: &ScimHttpClient,
        event: &Event,
    ) -> Result<(), ScimClientError> {
        if !target.group_push.enabled {
            return Ok(());
        }

        let group_id = extract_uuid_field(&event.data, "group_id")?;

        let downstream_id = match self
            .find_downstream_id(target.id, group_id, OutboundEntityType::Group)
            .await
        {
            Some(id) => id,
            None => return Ok(()),
        };

        client.delete_group(&downstream_id).await?;

        Ok(())
    }

    // ── Failure handling (DLQ, error recording, sid-notify) ──

    /// Handle a failed dispatch: update error tracking, save to DLQ, publish failure event.
    async fn handle_dispatch_failure(
        &self,
        target: &ScimOutboundTarget,
        event: &Event,
        error: &ScimClientError,
    ) {
        let now = Utc::now();

        // G3: Update error tracking on outbound record (if entity exists downstream).
        let sid_entity_id = extract_profile_id(&event.data)
            .map(ProfileId::into_uuid)
            .or_else(|_| extract_uuid_field(&event.data, "group_id"))
            .ok();

        if let Some(entity_id) = sid_entity_id {
            let entity_type = if event.event_type.contains("group") {
                OutboundEntityType::Group
            } else {
                OutboundEntityType::User
            };

            // Counted in place on the stored mapping: a stale copy would undo a
            // concurrent success (its downstream id and cleared error) and lose counts.
            if let Err(e) = self
                .storage
                .record_scim_outbound_failure(
                    target.id,
                    entity_id,
                    entity_type,
                    &error.to_string(),
                    now,
                    AuditEntry::system("scim.outbound.error_recorded", error.to_string()).into(),
                )
                .await
            {
                warn!(error = %e, "failed to update outbound record with error");
            }
        }

        // G2: Save failed event to DLQ for later retry/review.
        let dlq_entry = sid_core::models::OutboundDlqEntry {
            id: Uuid::now_v7(),
            target_id: target.id,
            event_type: event.event_type.clone(),
            payload: event.data.clone(),
            sid_entity_id: sid_entity_id.unwrap_or(Uuid::nil()),
            entity_type: if event.event_type.contains("group") {
                OutboundEntityType::Group
            } else {
                OutboundEntityType::User
            },
            error: error.to_string(),
            attempts: target.sync_config.max_retry_attempts,
            first_attempt: now,
            last_attempt: now,
        };

        // The failure alert (sid-notify tells the admins) is owed by the
        // commit that stores the dead letter.
        let failure_event = Event::new("sid-scim", "sid.scim.outbound_failed.v1")
            .with_subject(format!("target/{}", target.id))
            .with_data(serde_json::json!({
                "target_name": target.display_name,
                "event_type": event.event_type,
                "error": error.to_string(),
                "error_class": error_class(error),
            }));
        let ctx = MutationContext::from(AuditEntry::system(
            "scim.outbound.dlq_saved",
            &event.event_type,
        ))
        .with_work(failure_event.relay());
        if let Err(e) = self
            .storage
            .create_outbound_dlq_entry(&dlq_entry, ctx)
            .await
        {
            warn!(error = %e, "failed to save DLQ entry and its alert");
        }
    }

    // ── Storage helpers ──

    async fn load_profile_data(
        &self,
        profile_id: ProfileId,
    ) -> Result<
        (
            sid_core::models::Profile,
            Vec<sid_core::models::Principal>,
            Vec<sid_core::models::ProfileMetadata>,
        ),
        ScimClientError,
    > {
        let profile = self
            .storage
            .get_profile(profile_id)
            .await
            .map_err(|e| ScimClientError::Unreachable(format!("storage error: {e}")))?
            .ok_or_else(|| {
                ScimClientError::Serialization(format!("profile {profile_id} not found"))
            })?;

        let principals = self
            .storage
            .get_principals_by_profile(profile_id)
            .await
            .map_err(|e| ScimClientError::Unreachable(format!("storage error: {e}")))?;

        let metadata = self
            .storage
            .list_profile_metadata(profile_id)
            .await
            .map_err(|e| ScimClientError::Unreachable(format!("storage error: {e}")))?;

        Ok((profile, principals, metadata))
    }

    /// Look up downstream SCIM resource ID from outbound records.
    async fn find_downstream_id(
        &self,
        target_id: ScimOutboundTargetId,
        sid_entity_id: Uuid,
        entity_type: OutboundEntityType,
    ) -> Option<String> {
        match self
            .storage
            .get_scim_outbound_record(target_id, sid_entity_id, entity_type)
            .await
        {
            Ok(Some(record)) => Some(record.downstream_id),
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "failed to look up outbound record");
                None
            }
        }
    }

    /// Save a mapping record after successful outbound provisioning.
    async fn save_outbound_record(
        &self,
        target_id: ScimOutboundTargetId,
        sid_entity_id: Uuid,
        entity_type: OutboundEntityType,
        downstream_id: &str,
    ) {
        let now = Utc::now();
        let record = ScimOutboundRecord {
            target_id,
            sid_entity_id,
            entity_type,
            downstream_id: downstream_id.to_string(),
            last_synced_at: now,
            last_error: None,
            failure_count: 0,
            created_at: now,
            updated_at: now,
        };

        if let Err(e) = self
            .storage
            .record_scim_outbound_sync(
                &record,
                AuditEntry::system("scim.outbound.record_saved", downstream_id).into(),
            )
            .await
        {
            warn!(
                error = %e,
                downstream_id,
                "failed to save outbound record"
            );
        }
    }
}

// ── Event data extraction helpers ──

fn extract_profile_id(data: &serde_json::Value) -> Result<ProfileId, ScimClientError> {
    let id_str = data
        .get("profile_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ScimClientError::Serialization("missing profile_id in event data".into()))?;

    ProfileId::parse(id_str)
        .map_err(|e| ScimClientError::Serialization(format!("invalid profile_id: {e}")))
}

fn extract_uuid_field(data: &serde_json::Value, field: &str) -> Result<Uuid, ScimClientError> {
    let id_str = data
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| ScimClientError::Serialization(format!("missing {field} in event data")))?;

    Uuid::parse_str(id_str)
        .map_err(|e| ScimClientError::Serialization(format!("invalid {field}: {e}")))
}

/// Classify error for sid-notify alert routing.
fn error_class(error: &ScimClientError) -> &'static str {
    match error {
        ScimClientError::Unreachable(_) => "unreachable",
        ScimClientError::Rejected { .. } => "rejected",
        ScimClientError::RateLimited { .. } => "rate_limited",
        ScimClientError::Conflict { .. } => "conflict",
        ScimClientError::AuthFailed { .. } => "auth_failed",
        ScimClientError::Serialization(_) => "serialization",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_profile_id_valid() {
        let uuid = Uuid::now_v7();
        let data = serde_json::json!({"profile_id": uuid.to_string()});
        let result = extract_profile_id(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().into_uuid(), uuid);
    }

    #[test]
    fn test_extract_profile_id_missing() {
        let data = serde_json::json!({"other": "value"});
        let result = extract_profile_id(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_profile_id_invalid() {
        let data = serde_json::json!({"profile_id": "not-a-uuid"});
        let result = extract_profile_id(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_uuid_field() {
        let uuid = Uuid::now_v7();
        let data = serde_json::json!({"group_id": uuid.to_string()});
        let result = extract_uuid_field(&data, "group_id");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), uuid);
    }

    #[test]
    fn test_extract_uuid_field_missing() {
        let data = serde_json::json!({});
        let result = extract_uuid_field(&data, "group_id");
        assert!(result.is_err());
    }

    #[test]
    fn test_error_class_classification() {
        assert_eq!(
            error_class(&ScimClientError::Unreachable("timeout".into())),
            "unreachable"
        );
        assert_eq!(
            error_class(&ScimClientError::Rejected {
                status: 400,
                body: "bad request".into()
            }),
            "rejected"
        );
        assert_eq!(
            error_class(&ScimClientError::RateLimited {
                retry_after_secs: 30
            }),
            "rate_limited"
        );
        assert_eq!(
            error_class(&ScimClientError::Conflict {
                body: "conflict".into()
            }),
            "conflict"
        );
        assert_eq!(
            error_class(&ScimClientError::AuthFailed { status: 401 }),
            "auth_failed"
        );
        assert_eq!(
            error_class(&ScimClientError::Serialization("bad json".into())),
            "serialization"
        );
    }

    #[test]
    fn test_reactivate_patch_payload() {
        let patch = mapper::ScimPatchPayload::reactivate();
        assert_eq!(patch.operations.len(), 1);
        assert_eq!(patch.operations[0].op, "replace");
        assert_eq!(patch.operations[0].path.as_deref(), Some("active"));
        assert_eq!(patch.operations[0].value, Some(serde_json::json!(true)));
    }
}
