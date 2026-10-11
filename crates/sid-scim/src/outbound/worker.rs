// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM outbound worker.
//!
//! Consumes corporate profile/group change events durably, one at a time in
//! the order they were committed, and dispatches each to every enabled
//! target. A target's outcome (taken, or its failure recorded in the
//! dead-letter store) is recorded per (event, target) in the same commit as
//! anything it stores, so a redelivered event goes only to the targets that
//! have no outcome yet: a target that took it, or whose failure was
//! recorded, never gets it or its dead letter twice.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sid_core::models::{
    AuditEntry, MutationContext, OperationCompletion, OperationKey, OutboundEntityType, ProfileId,
    ScimOutboundRecord, ScimOutboundTarget, ScimOutboundTargetId,
    event::{Event, RequiredReceiver, WorkRecipient, event_types},
};
use sid_plugin::StorageBackend;
use sid_plugin::event_bus::{Delivery, DurableConsumer, EventBus, Settlement};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::client::{ScimClientError, ScimHttpClient};
use super::mapper::{self, ScimPatchPayload};

/// The receiver SCIM outbound work is addressed to.
pub const SCIM_OUTBOUND_RECEIVER: &str = "sid-scim-outbound";

/// The event types outbound provisioning acts on.
const SCIM_EVENTS: &str = "sid.scim.*";

/// Where a target's outcome for an event is recorded.
pub const DISPATCH_OUTCOME_NAMESPACE: &str = "scim.outbound.dispatched";

/// When an event some target's outcome could not be recorded for is
/// delivered again.
const UNRECORDED_RETRY: Duration = Duration::from_secs(30);

/// Namespace of the ids a target's failure records carry for an event.
const FAILURE_NAMESPACE: Uuid = Uuid::from_u128(0x2c6f_91d4_7a30_4e85_b1c9_5d02_e64a_8f17);

/// The key a target's outcome for `event` is recorded under.
pub(crate) fn outcome_key(event: &Event, target: ScimOutboundTargetId) -> OperationKey {
    OperationKey::parse(&format!("{}:{}", event.relay_id(), target.0))
        .expect("two UUIDs make a valid key")
}

/// The record of a target's outcome for `event`, committed with whatever
/// that outcome stores.
fn outcome(event: &Event, target: ScimOutboundTargetId, method: &str) -> OperationCompletion {
    OperationCompletion::new(
        DISPATCH_OUTCOME_NAMESPACE,
        outcome_key(event, target),
        method,
        &[],
        Vec::new(),
    )
}

/// Outbound provisioning as a receiver the deployment requires while
/// targets are configured: every SCIM fact committed meanwhile is owed to it.
pub fn required_receiver() -> RequiredReceiver {
    RequiredReceiver {
        recipient: WorkRecipient::new(SCIM_OUTBOUND_RECEIVER).expect("the receiver is a token"),
        event_types: vec![SCIM_EVENTS.into()],
    }
}

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

    /// Consume the outbound work and process it on a background task. A
    /// consumer that cannot be opened is returned, not logged away.
    pub async fn start(
        self: Arc<Self>,
    ) -> Result<tokio::task::JoinHandle<()>, sid_plugin::event_bus::EventBusError> {
        let receiver = required_receiver();
        let rx = self
            .event_bus
            .consume(DurableConsumer {
                recipient: receiver.recipient,
                event_types: receiver.event_types,
                // An entity's changes reach a target in commit order: an
                // update never overtakes the create whose mapping it needs.
                ordered: true,
            })
            .await?;
        info!(targets = self.targets.len(), "SCIM outbound worker started");
        Ok(tokio::spawn(self.process_events(rx)))
    }

    async fn process_events(self: Arc<Self>, mut rx: mpsc::Receiver<Delivery>) {
        while let Some(delivery) = rx.recv().await {
            let settlement = self.process(&delivery.event).await;
            delivery.settle(settlement);
        }

        info!("SCIM outbound worker stopped (event channel closed)");
    }

    /// Dispatch `event` to every enabled target that has no recorded outcome
    /// for it. It is settled once every target has one, and left with the bus
    /// (delivered again, to those targets only) otherwise.
    pub(crate) async fn process(&self, event: &Event) -> Settlement {
        debug!(
            event_type = %event.event_type,
            subject = ?event.subject,
            "processing SCIM outbound event"
        );
        let mut unrecorded = false;
        for target in self.targets.iter().filter(|t| t.enabled) {
            match self
                .storage
                .get_operation_result(DISPATCH_OUTCOME_NAMESPACE, &outcome_key(event, target.id))
                .await
            {
                Ok(Some(_)) => continue,
                Ok(None) => {}
                Err(e) => {
                    warn!(target = %target.display_name, error = %e, "SCIM outcome not read");
                    unrecorded = true;
                    continue;
                }
            }
            let recorded = match self.dispatch_to_target(target, event).await {
                Ok(()) => self.record_taken(target, event).await,
                Err(e) => {
                    error!(
                        target = %target.display_name,
                        event_type = %event.event_type,
                        error = %e,
                        "SCIM outbound dispatch failed"
                    );
                    self.handle_dispatch_failure(target, event, &e).await
                }
            };
            unrecorded |= !recorded;
        }
        if unrecorded {
            Settlement::Retry(UNRECORDED_RETRY)
        } else {
            Settlement::Done
        }
    }

    /// Record that `target` took `event`. Whether it is recorded: a target
    /// whose record is lost gets the event again on its redelivery.
    async fn record_taken(&self, target: &ScimOutboundTarget, event: &Event) -> bool {
        let ctx = MutationContext::from(AuditEntry::system(
            "scim.outbound.dispatched",
            &event.event_type,
        ))
        .with_operation(outcome(event, target.id, "taken"));
        match self.storage.record_outcome(ctx).await {
            Ok(()) | Err(sid_core::Error::OperationCompleted(_)) => true,
            Err(e) => {
                warn!(target = %target.display_name, error = %e, "SCIM outcome not recorded");
                false
            }
        }
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

    /// Handle a failed dispatch: save the dead letter, owe the failure event
    /// and record the target's outcome in one commit, then count the error.
    /// Whether the failure is recorded (now or by an earlier attempt).
    async fn handle_dispatch_failure(
        &self,
        target: &ScimOutboundTarget,
        event: &Event,
        error: &ScimClientError,
    ) -> bool {
        let now = Utc::now();
        let sid_entity_id = extract_profile_id(&event.data)
            .map(ProfileId::into_uuid)
            .or_else(|_| extract_uuid_field(&event.data, "group_id"))
            .ok();
        // The failure's records carry ids of this (event, target), and commit
        // with its outcome: a repeat of this dispatch finds the outcome and
        // stores no second dead letter or alert.
        let failure_id = Uuid::new_v5(
            &FAILURE_NAMESPACE,
            outcome_key(event, target.id).as_str().as_bytes(),
        );

        // Save the failed event to the dead-letter store for review.
        let dlq_entry = sid_core::models::OutboundDlqEntry {
            id: failure_id,
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
        let mut failure_event = Event::new("sid-scim", event_types::SCIM_OUTBOUND_FAILED)
            .with_subject(format!("target/{}", target.id))
            .with_data(serde_json::json!({
                "target_name": target.display_name,
                "event_type": event.event_type,
                "error": error.to_string(),
                "error_class": error_class(error),
            }));
        failure_event.id = failure_id.to_string();
        let ctx = MutationContext::from(AuditEntry::system(
            "scim.outbound.dlq_saved",
            &event.event_type,
        ))
        .with_work(failure_event.relay())
        .with_operation(outcome(event, target.id, "failed"));
        match self
            .storage
            .create_outbound_dlq_entry(&dlq_entry, ctx)
            .await
        {
            Ok(()) => {}
            // An earlier attempt recorded this failure already.
            Err(sid_core::Error::OperationCompleted(_)) => return true,
            Err(e) => {
                warn!(error = %e, "failed to save DLQ entry and its alert");
                return false;
            }
        }

        // Counted once the failure is recorded, so a repeated dispatch does
        // not count it twice. Counted in place on the stored mapping: a stale
        // copy would undo a concurrent success (its downstream id and cleared
        // error) and lose counts.
        if let Some(entity_id) = sid_entity_id {
            let entity_type = if event.event_type.contains("group") {
                OutboundEntityType::Group
            } else {
                OutboundEntityType::User
            };
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
        true
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
mod tests;
