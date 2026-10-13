// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM outbound worker.
//!
//! Consumes corporate profile/group change events durably and pushes the
//! current state of the resource each one names to every enabled target. An
//! event only says what changed: the push carries what the directory holds
//! now, so a repeated, late or reordered event never restores an older
//! state. Deliveries are taken one at a time across replicas, and a request
//! is sent only while the delivery is certainly still this replica's, so two
//! pushes of one resource do not race.
//!
//! A target's outcome (taken, or its failure recorded in the dead-letter
//! store) is recorded per (event, target) in the same commit as anything it
//! stores, so a redelivered event goes only to the targets without one.
//! Effects on a target are at least once: a create whose response was lost
//! is looked up on the next attempt before it is created again.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sid_core::models::{
    AuditEntry, GroupId, MutationContext, OperationCompletion, OperationKey, OutboundEntityType,
    ProfileId, ScimOutboundRecord, ScimOutboundTarget, ScimOutboundTargetId,
    event::{Event, RequiredReceiver, WorkRecipient, event_types},
};
use sid_plugin::StorageBackend;
use sid_plugin::event_bus::{Delivery, DurableConsumer, EventBus, Hold, Settlement};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::client::{ScimClientError, ScimHttpClient};
use super::mapper::{self, ScimGroupPayload, ScimMemberPayload};

/// The receiver SCIM outbound work is addressed to.
pub const SCIM_OUTBOUND_RECEIVER: &str = "sid-scim-outbound";

/// The event types outbound provisioning acts on, by name: a pattern over
/// `sid.scim.*` would also take its own failure facts back.
const SCIM_EVENTS: [&str; 7] = [
    event_types::SCIM_USER_PROVISIONED,
    event_types::SCIM_USER_UPDATED,
    event_types::SCIM_USER_DEACTIVATED,
    event_types::SCIM_USER_REACTIVATED,
    event_types::SCIM_GROUP_CREATED,
    event_types::SCIM_GROUP_UPDATED,
    event_types::SCIM_GROUP_DELETED,
];

/// Where a target's outcome for an event is recorded.
pub const DISPATCH_OUTCOME_NAMESPACE: &str = "scim.outbound.dispatched";

/// Where each failed attempt at an event for a target is recorded.
const FAILED_ATTEMPT_NAMESPACE: &str = "scim.outbound.attempt_failed";

/// Where a create sent to a target is recorded before it is sent: a later
/// attempt finding no mapping looks the resource up rather than create it
/// twice when the response was lost.
const CREATION_NAMESPACE: &str = "scim.outbound.creating";

/// When an event some target's outcome could not be recorded for is
/// delivered again.
const UNRECORDED_RETRY: Duration = Duration::from_secs(30);

/// When an event whose hold ran out before a request is delivered again.
const NOT_HELD_RETRY: Duration = Duration::from_secs(1);

/// The longest pause before a failed dispatch is tried again.
const MAX_BACKOFF: Duration = Duration::from_secs(60 * 60);

/// The SCIM core Group schema (RFC 7643 §8.7.1).
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

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
        event_types: SCIM_EVENTS.iter().map(|t| (*t).to_string()).collect(),
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
                // One delivery at a time across replicas: two pushes of the
                // same resource never run at once. Their order is not relied
                // on (the relay may publish a later change first): each push
                // carries the current state, so any order converges.
                ordered: true,
            })
            .await?;
        info!(targets = self.targets.len(), "SCIM outbound worker started");
        Ok(tokio::spawn(self.process_events(rx)))
    }

    async fn process_events(self: Arc<Self>, mut rx: mpsc::Receiver<Delivery>) {
        while let Some(delivery) = rx.recv().await {
            let settlement = self
                .process(&delivery.event, delivery.attempt, delivery.hold())
                .await;
            delivery.settle(settlement);
        }

        info!("SCIM outbound worker stopped (event channel closed)");
    }

    /// Dispatch delivery number `attempt` of `event`, held as `hold` says,
    /// to every enabled target that has no recorded outcome for it. A target
    /// failing in a way a later attempt may cure, within its attempts, is
    /// left for the redelivery; any other failure is recorded. The event is
    /// settled once every target has an outcome.
    pub(crate) async fn process(&self, event: &Event, attempt: u64, hold: &Hold) -> Settlement {
        debug!(
            event_type = %event.event_type,
            subject = ?event.subject,
            attempt,
            "processing SCIM outbound event"
        );
        let mut retry: Option<Duration> = None;
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
                    retry = later(retry, UNRECORDED_RETRY);
                    continue;
                }
            }
            let client = ScimHttpClient::new(target, hold.clone());
            let recorded = match self.dispatch(target, &client, event).await {
                Ok(()) => self.record_taken(target, event).await,
                // A lost hold is no failure of the target: it is not counted.
                Err(ScimClientError::NotHeld) => {
                    retry = later(retry, NOT_HELD_RETRY);
                    continue;
                }
                // Neither is a failure of SID's own storage: retried like an
                // outcome that could not be recorded, the target's attempts
                // left for its own failures.
                Err(ScimClientError::Storage(e)) => {
                    warn!(target = %target.display_name, error = %e, "SCIM dispatch stopped by storage");
                    retry = later(retry, UNRECORDED_RETRY);
                    continue;
                }
                Err(e) if e.is_transient() => {
                    // The target's own attempts, not the event's deliveries:
                    // another target's retries do not use them up.
                    let failed = match self.count_failure(event, target).await {
                        Ok(failed) => failed,
                        Err(count) => {
                            warn!(target = %target.display_name, error = %count, "SCIM attempt not counted");
                            retry = later(retry, UNRECORDED_RETRY);
                            continue;
                        }
                    };
                    if failed < target.sync_config.max_retry_attempts {
                        warn!(
                            target = %target.display_name,
                            event_type = %event.event_type,
                            failed,
                            error = %e,
                            "SCIM outbound dispatch will be retried"
                        );
                        retry = later(retry, backoff(&e, u64::from(failed), target));
                        continue;
                    }
                    error!(
                        target = %target.display_name,
                        event_type = %event.event_type,
                        error = %e,
                        "SCIM outbound dispatch failed at its last attempt"
                    );
                    self.handle_dispatch_failure(target, event, &e).await
                }
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
            if !recorded {
                retry = later(retry, UNRECORDED_RETRY);
            }
        }
        retry.map_or(Settlement::Done, Settlement::Retry)
    }

    /// Count a failed attempt at `event` for `target`: its number, from 1.
    /// Each is its own durable record, so replicas share the count and a
    /// delivery repeated for another reason counts nothing.
    async fn count_failure(
        &self,
        event: &Event,
        target: &ScimOutboundTarget,
    ) -> Result<u32, sid_core::Error> {
        let last = target.sync_config.max_retry_attempts.max(1);
        for failed in 1..=last {
            let key = OperationKey::parse(&format!(
                "{}:{failed}",
                outcome_key(event, target.id).as_str()
            ))
            .expect("an outcome key and a number make a valid key");
            let ctx = MutationContext::from(AuditEntry::system(
                "scim.outbound.attempt_failed",
                &event.event_type,
            ))
            .with_operation(OperationCompletion::new(
                FAILED_ATTEMPT_NAMESPACE,
                key,
                "failed",
                &[],
                Vec::new(),
            ));
            match self.storage.record_outcome(ctx).await {
                Ok(()) => return Ok(failed),
                Err(sid_core::Error::OperationCompleted(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(last)
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

    /// Push the current state of the resource `event` names to `target`.
    async fn dispatch(
        &self,
        target: &ScimOutboundTarget,
        client: &ScimHttpClient,
        event: &Event,
    ) -> Result<(), ScimClientError> {
        match event.event_type.as_str() {
            t if t == event_types::SCIM_USER_PROVISIONED
                || t == event_types::SCIM_USER_UPDATED
                || t == event_types::SCIM_USER_DEACTIVATED
                || t == event_types::SCIM_USER_REACTIVATED =>
            {
                let profile_id = extract_profile_id(&event.data)?;
                self.sync_user(target, client, profile_id).await
            }
            t if t == event_types::SCIM_GROUP_CREATED
                || t == event_types::SCIM_GROUP_UPDATED
                || t == event_types::SCIM_GROUP_DELETED =>
            {
                let group_id = GroupId(extract_uuid_field(&event.data, "group_id")?);
                self.sync_group(target, client, group_id).await
            }
            _ => {
                debug!(event_type = %event.event_type, "ignoring unknown event type");
                Ok(())
            }
        }
    }

    /// Push a user's current state: replace every mapped attribute where the
    /// target has the user, create it where it does not and it is active
    /// (an inactive user the target never had needs nothing).
    async fn sync_user(
        &self,
        target: &ScimOutboundTarget,
        client: &ScimHttpClient,
        profile_id: ProfileId,
    ) -> Result<(), ScimClientError> {
        let (profile, principals, metadata) = self.load_profile_data(profile_id).await?;
        let user =
            mapper::build_scim_user(&profile, &principals, &metadata, &target.attribute_mapping);
        let entity = profile_id.into_uuid();
        let kind = OutboundEntityType::User;

        // A create recorded as sent is looked up first; when the lookup
        // finds nothing (the create never landed) `known` stays empty and the
        // create below is sent again.
        let known = match self.find_downstream_id(target.id, entity, kind).await? {
            Some(id) => Some(id),
            None if self.creation_sent(target.id, entity, kind).await? => {
                let found = client.find_user(&user.user_name).await?;
                self.adopt(target.id, entity, kind, found).await?
            }
            None => None,
        };
        if let Some(id) = known {
            let absent = mapper::absent_user_paths(&user, &target.attribute_mapping)?;
            client.replace_user(&id, &user, &absent).await?;
            info!(target = %target.display_name, %profile_id, "user state pushed downstream");
            return Ok(());
        }
        if !user.active {
            return Ok(());
        }
        self.mark_creation(target.id, entity, kind).await?;
        let created = match client.create_user(&user).await? {
            Some(id) => Some(id),
            None => client.find_user(&user.user_name).await?,
        };
        self.adopt(target.id, entity, kind, created)
            .await?
            .ok_or_else(|| ScimClientError::Unreachable("the created user was not found".into()))?;
        info!(target = %target.display_name, %profile_id, "user provisioned downstream");
        // A group pushed before this user existed downstream left the user
        // out: push again each group of the user the target already has.
        for group in self
            .storage
            .list_groups_for_profile(profile_id)
            .await
            .map_err(storage)?
        {
            if self
                .find_downstream_id(target.id, group.id.0, OutboundEntityType::Group)
                .await?
                .is_some()
            {
                self.sync_group(target, client, group.id).await?;
            }
        }
        Ok(())
    }

    /// Push a group's current state when it is pushed to `target`: its name
    /// and its whole membership (members the target has), or its deletion
    /// once it is gone.
    async fn sync_group(
        &self,
        target: &ScimOutboundTarget,
        client: &ScimHttpClient,
        group_id: GroupId,
    ) -> Result<(), ScimClientError> {
        if !target.group_push.enabled {
            return Ok(());
        }
        let entity = group_id.0;
        let kind = OutboundEntityType::Group;
        let known = self.find_downstream_id(target.id, entity, kind).await?;
        let Some(group) = self.storage.get_group(group_id).await.map_err(storage)? else {
            if let Some(id) = known {
                client.delete_group(&id).await?;
            }
            return Ok(());
        };
        // The name mapping decides which groups start being pushed. A group
        // the target already has keeps following its state under its
        // downstream id after a rename (`PUT /Groups/{id}`), whatever its new
        // name: skipping it would leave the old name and removed members on
        // the target.
        if known.is_none()
            && mapper::resolve_group_mapping(&group.name, &target.group_push).is_none()
        {
            return Ok(());
        }
        let mut members = Vec::new();
        for member in self
            .storage
            .list_group_members(group_id)
            .await
            .map_err(storage)?
        {
            let user = member.profile_id.into_uuid();
            if let Some(id) = self
                .find_downstream_id(target.id, user, OutboundEntityType::User)
                .await?
            {
                members.push(ScimMemberPayload {
                    value: id,
                    display: None,
                });
            }
        }
        let payload = ScimGroupPayload {
            schemas: vec![GROUP_SCHEMA.into()],
            display_name: group.name.clone(),
            members,
        };

        // As for a user: a create the lookup does not find is sent again.
        let known = match known {
            Some(id) => Some(id),
            None if self.creation_sent(target.id, entity, kind).await? => {
                let found = client.find_group(&group.name).await?;
                self.adopt(target.id, entity, kind, found).await?
            }
            None => None,
        };
        if let Some(id) = known {
            return client.replace_group(&id, &payload).await;
        }
        self.mark_creation(target.id, entity, kind).await?;
        let created = match client.create_group(&payload).await? {
            Some(id) => Some(id),
            None => client.find_group(&group.name).await?,
        };
        self.adopt(target.id, entity, kind, created)
            .await?
            .ok_or_else(|| {
                ScimClientError::Unreachable("the created group was not found".into())
            })?;
        Ok(())
    }

    /// Whether a create of `entity` was ever sent to `target`.
    async fn creation_sent(
        &self,
        target: ScimOutboundTargetId,
        entity: Uuid,
        kind: OutboundEntityType,
    ) -> Result<bool, ScimClientError> {
        self.storage
            .get_operation_result(CREATION_NAMESPACE, &creation_key(target, entity, kind))
            .await
            .map(|found| found.is_some())
            .map_err(storage)
    }

    /// Record that a create of `entity` is about to be sent to `target`.
    async fn mark_creation(
        &self,
        target: ScimOutboundTargetId,
        entity: Uuid,
        kind: OutboundEntityType,
    ) -> Result<(), ScimClientError> {
        let ctx = MutationContext::from(AuditEntry::system(
            "scim.outbound.creating",
            entity.to_string(),
        ))
        .with_operation(OperationCompletion::new(
            CREATION_NAMESPACE,
            creation_key(target, entity, kind),
            "create",
            &[],
            Vec::new(),
        ));
        match self.storage.record_outcome(ctx).await {
            Ok(()) | Err(sid_core::Error::OperationCompleted(_)) => Ok(()),
            Err(e) => Err(storage(e)),
        }
    }

    /// Map `entity` to the downstream resource `found`, if any.
    async fn adopt(
        &self,
        target: ScimOutboundTargetId,
        entity: Uuid,
        kind: OutboundEntityType,
        found: Option<String>,
    ) -> Result<Option<String>, ScimClientError> {
        if let Some(id) = &found {
            self.save_outbound_record(target, entity, kind, id).await?;
        }
        Ok(found)
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
            .map_err(storage)?
            .ok_or_else(|| {
                ScimClientError::Serialization(format!("profile {profile_id} not found"))
            })?;

        let principals = self
            .storage
            .get_principals_by_profile(profile_id)
            .await
            .map_err(storage)?;

        let metadata = self
            .storage
            .list_profile_metadata(profile_id)
            .await
            .map_err(storage)?;

        Ok((profile, principals, metadata))
    }

    /// The downstream id `target` has for an entity. An unreadable mapping
    /// is an error, never taken for a missing one (that would create the
    /// resource a second time).
    async fn find_downstream_id(
        &self,
        target_id: ScimOutboundTargetId,
        sid_entity_id: Uuid,
        entity_type: OutboundEntityType,
    ) -> Result<Option<String>, ScimClientError> {
        Ok(self
            .storage
            .get_scim_outbound_record(target_id, sid_entity_id, entity_type)
            .await
            .map_err(storage)?
            .map(|record| record.downstream_id))
    }

    /// Save the mapping of an entity to its downstream resource.
    async fn save_outbound_record(
        &self,
        target_id: ScimOutboundTargetId,
        sid_entity_id: Uuid,
        entity_type: OutboundEntityType,
        downstream_id: &str,
    ) -> Result<(), ScimClientError> {
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

        self.storage
            .record_scim_outbound_sync(
                &record,
                AuditEntry::system("scim.outbound.record_saved", downstream_id).into(),
            )
            .await
            .map_err(storage)
    }
}

/// A storage failure, which a later attempt may not meet.
fn storage(e: sid_core::Error) -> ScimClientError {
    ScimClientError::Storage(e.to_string())
}

/// The key a create of `entity` sent to `target` is recorded under.
fn creation_key(
    target: ScimOutboundTargetId,
    entity: Uuid,
    kind: OutboundEntityType,
) -> OperationKey {
    OperationKey::parse(&format!("{}:{}:{}", target.0, entity, kind.as_str()))
        .expect("two UUIDs and a kind make a valid key")
}

/// The later of a pending retry and `delay`.
fn later(pending: Option<Duration>, delay: Duration) -> Option<Duration> {
    Some(pending.map_or(delay, |pending| pending.max(delay)))
}

/// When delivery number `attempt` failing with `error` is tried again: the
/// target's own Retry-After, or its backoff doubling per attempt, at most
/// [`MAX_BACKOFF`].
fn backoff(error: &ScimClientError, attempt: u64, target: &ScimOutboundTarget) -> Duration {
    match error {
        ScimClientError::RateLimited { retry_after_secs } => {
            Duration::from_secs(*retry_after_secs).min(MAX_BACKOFF)
        }
        ScimClientError::NotHeld => NOT_HELD_RETRY,
        _ => u32::try_from(attempt.max(1) - 1)
            .ok()
            .and_then(|doublings| 2u64.checked_pow(doublings))
            .and_then(|factor| {
                target
                    .sync_config
                    .retry_backoff_base_secs
                    .checked_mul(factor)
            })
            .map(Duration::from_secs)
            .filter(|delay| *delay <= MAX_BACKOFF)
            .unwrap_or(MAX_BACKOFF),
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
        ScimClientError::Malformed(_) => "malformed",
        ScimClientError::Storage(_) => "storage",
        ScimClientError::NotHeld => "not_held",
    }
}

#[cfg(test)]
mod tests;
