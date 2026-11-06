// SPDX-License-Identifier: AGPL-3.0-only
//! Outbound SCIM provisioning in CoordiNode: the downstream targets, the
//! mapping of each provisioned entity to its downstream id, and the dead
//! letters of deliveries that failed. Structured settings and payloads are
//! CoordiNode documents.
//!
//! A mapping and a dead letter hold their target for the commit, so a
//! target deleted meanwhile refuses them; a target takes both with it.

use coordinode_core::graph::types::Value;
use sid_core::models::{
    MutationContext, OutboundDlqEntry, OutboundEntityType, ProjectId, ScimOutboundRecord,
    ScimOutboundTarget, ScimOutboundTargetId,
};
use sid_core::{Error as SidError, Result as SidResult};
use uuid::Uuid;

use super::{
    CoordinodeBackend, Params, Row, Statements, document, get_bool, get_document, get_int,
    get_opt_text, get_parsed, get_text, get_time, get_uuid, hold_first, key, opt_text,
    project::project_value, time, uuid,
};

const TARGET: &str = "t.id AS id, t.client_id AS client_id, t.project_id AS project_id,
    t.display_name AS display_name, t.endpoint_url AS endpoint_url, t.auth AS auth,
    t.attribute_mapping AS attribute_mapping, t.group_push AS group_push,
    t.sync_config AS sync_config, t.enabled AS enabled, t.created_at AS created_at,
    t.updated_at AS updated_at";

const RECORD: &str = "r.target_id AS target_id, r.sid_entity_id AS sid_entity_id,
    r.entity_type AS entity_type, r.downstream_id AS downstream_id,
    r.last_synced_at AS last_synced_at, r.last_error AS last_error,
    r.failure_count AS failure_count, r.created_at AS created_at, r.updated_at AS updated_at";

const LETTER: &str = "d.id AS id, d.target_id AS target_id, d.event_type AS event_type,
    d.payload AS payload, d.sid_entity_id AS sid_entity_id, d.entity_type AS entity_type,
    d.error AS error, d.attempts AS attempts, d.first_attempt AS first_attempt,
    d.last_attempt AS last_attempt";

fn count(row: &Row, name: &str) -> SidResult<u32> {
    let value = get_int(row, name)?;
    u32::try_from(value).map_err(|_| SidError::Storage(format!("{name}: {value}")))
}

fn target(row: &Row) -> SidResult<ScimOutboundTarget> {
    Ok(ScimOutboundTarget {
        id: ScimOutboundTargetId(get_uuid(row, "id")?),
        client_id: get_text(row, "client_id")?,
        project_id: ProjectId::from_uuid(get_uuid(row, "project_id")?)
            .map_err(|e| SidError::Storage(format!("project_id: {e}")))?,
        display_name: get_text(row, "display_name")?,
        endpoint_url: get_text(row, "endpoint_url")?,
        auth: get_document(row, "auth")?,
        attribute_mapping: get_document(row, "attribute_mapping")?,
        group_push: get_document(row, "group_push")?,
        sync_config: get_document(row, "sync_config")?,
        enabled: get_bool(row, "enabled")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn record(row: &Row) -> SidResult<ScimOutboundRecord> {
    Ok(ScimOutboundRecord {
        target_id: ScimOutboundTargetId(get_uuid(row, "target_id")?),
        sid_entity_id: get_uuid(row, "sid_entity_id")?,
        entity_type: get_parsed(row, "entity_type")?,
        downstream_id: get_text(row, "downstream_id")?,
        last_synced_at: get_time(row, "last_synced_at")?,
        last_error: get_opt_text(row, "last_error")?,
        failure_count: count(row, "failure_count")?,
        created_at: get_time(row, "created_at")?,
        updated_at: get_time(row, "updated_at")?,
    })
}

fn letter(row: &Row) -> SidResult<OutboundDlqEntry> {
    Ok(OutboundDlqEntry {
        id: get_uuid(row, "id")?,
        target_id: ScimOutboundTargetId(get_uuid(row, "target_id")?),
        event_type: get_text(row, "event_type")?,
        payload: get_document(row, "payload")?,
        sid_entity_id: get_uuid(row, "sid_entity_id")?,
        entity_type: get_parsed(row, "entity_type")?,
        error: get_text(row, "error")?,
        attempts: count(row, "attempts")?,
        first_attempt: get_time(row, "first_attempt")?,
        last_attempt: get_time(row, "last_attempt")?,
    })
}

fn record_key(
    target_id: ScimOutboundTargetId,
    entity: Uuid,
    kind: OutboundEntityType,
) -> SidResult<Value> {
    key(&[
        target_id.0.as_bytes(),
        entity.as_bytes(),
        kind.as_str().as_bytes(),
    ])
}

fn record_chain(target_id: ScimOutboundTargetId, entity: Uuid) -> String {
    format!("scim_outbound_record:{}:{entity}", target_id.0)
}

/// Hold target `id` for the commit, or refuse the reference to it.
fn hold_target(tx: &Statements<'_>, id: ScimOutboundTargetId) -> SidResult<()> {
    let rows = tx.run(
        "MATCH (t:SidScimTarget) WHERE t.id = $id RETURN id(t) AS node",
        Params::default().with("id", uuid(&id.0)),
    )?;
    if !hold_first(tx, &rows)? {
        return Err(SidError::NotFound(format!("SCIM outbound target {}", id.0)));
    }
    Ok(())
}

fn insert_letter(tx: &Statements<'_>, d: &OutboundDlqEntry) -> SidResult<()> {
    hold_target(tx, d.target_id)?;
    let found = tx.run(
        "MATCH (d:SidScimDeadLetter) WHERE d.id = $id RETURN d.id AS id",
        Params::default().with("id", uuid(&d.id)),
    )?;
    if !found.is_empty() {
        return Err(SidError::Conflict(
            "outbound dlq entry already exists".into(),
        ));
    }
    tx.run(
        "CREATE (d:SidScimDeadLetter {id: $id, target_id: $target_id, event_type: $event_type,
            payload: $payload, sid_entity_id: $sid_entity_id, entity_type: $entity_type,
            error: $error, attempts: $attempts, first_attempt: $first_attempt,
            last_attempt: $last_attempt})",
        Params::default()
            .with("id", uuid(&d.id))
            .with("target_id", uuid(&d.target_id.0))
            .with("event_type", Value::String(d.event_type.clone()))
            .with("payload", document(&d.payload, "payload")?)
            .with("sid_entity_id", uuid(&d.sid_entity_id))
            .with("entity_type", Value::String(d.entity_type.as_str().into()))
            .with("error", Value::String(d.error.clone()))
            .with("attempts", Value::Int(i64::from(d.attempts)))
            .with("first_attempt", time(d.first_attempt))
            .with("last_attempt", time(d.last_attempt)),
    )?;
    Ok(())
}

/// Delete target `id` with its mappings and dead letters, in `tx`.
fn delete_target(tx: &Statements<'_>, id: ScimOutboundTargetId) -> SidResult<()> {
    for query in [
        "MATCH (r:SidScimRecord) WHERE r.target_id = $id DETACH DELETE r",
        "MATCH (d:SidScimDeadLetter) WHERE d.target_id = $id DETACH DELETE d",
        "MATCH (t:SidScimTarget) WHERE t.id = $id DETACH DELETE t",
    ] {
        tx.run(query, Params::default().with("id", uuid(&id.0)))?;
    }
    Ok(())
}

/// Delete in `tx` the SCIM outbound targets of `project`.
pub(super) fn delete_project_records(tx: &Statements<'_>, project: ProjectId) -> SidResult<()> {
    let rows = tx.run(
        "MATCH (t:SidScimTarget) WHERE t.project_id = $id RETURN t.id AS id",
        Params::default().with("id", project_value(project)),
    )?;
    for row in &rows {
        delete_target(tx, ScimOutboundTargetId(get_uuid(row, "id")?))?;
    }
    Ok(())
}

impl CoordinodeBackend {
    pub(super) async fn create_scim_outbound_target(
        &self,
        t: &ScimOutboundTarget,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let params = Params::default()
            .with("id", uuid(&t.id.0))
            .with("client_id", Value::String(t.client_id.clone()))
            .with("project_id", project_value(t.project_id))
            .with("display_name", Value::String(t.display_name.clone()))
            .with("endpoint_url", Value::String(t.endpoint_url.clone()))
            .with("auth", document(&t.auth, "auth")?)
            .with(
                "attribute_mapping",
                document(&t.attribute_mapping, "attribute mapping")?,
            )
            .with("group_push", document(&t.group_push, "group push")?)
            .with("sync_config", document(&t.sync_config, "sync config")?)
            .with("enabled", Value::Bool(t.enabled))
            .with("created_at", time(t.created_at))
            .with("updated_at", time(t.updated_at));
        let project = t.project_id;
        self.mutate(format!("scim_outbound_target:{}", t.id.0), ctx, move |tx| {
            let held = tx.run(
                "MATCH (j:SidProject) WHERE j.id = $id RETURN id(j) AS node",
                Params::default().with("id", project_value(project)),
            )?;
            if !hold_first(tx, &held)? {
                return Err(SidError::NotFound(format!("project {project}")));
            }
            let found = tx.run(
                "MATCH (t:SidScimTarget) WHERE t.id = $id RETURN t.id AS id",
                params.clone(),
            )?;
            if !found.is_empty() {
                return Err(SidError::Conflict(
                    "SCIM outbound target already exists".into(),
                ));
            }
            tx.run(
                "CREATE (t:SidScimTarget {id: $id, client_id: $client_id, project_id: $project_id,
                    display_name: $display_name, endpoint_url: $endpoint_url, auth: $auth,
                    attribute_mapping: $attribute_mapping, group_push: $group_push,
                    sync_config: $sync_config, enabled: $enabled, created_at: $created_at,
                    updated_at: $updated_at})",
                params.clone(),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn get_scim_outbound_target(
        &self,
        id: ScimOutboundTargetId,
    ) -> SidResult<Option<ScimOutboundTarget>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (t:SidScimTarget) WHERE t.id = $id RETURN {TARGET}"),
                Params::default().with("id", uuid(&id.0)),
            )?;
            rows.first().map(target).transpose()
        })
        .await
    }

    pub(super) async fn list_scim_outbound_targets(
        &self,
        project: ProjectId,
    ) -> SidResult<Vec<ScimOutboundTarget>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!(
                    "MATCH (t:SidScimTarget) WHERE t.project_id = $id AND t.enabled = true
                     RETURN {TARGET}"
                ),
                Params::default().with("id", project_value(project)),
            )?;
            rows.iter().map(target).collect()
        })
        .await
    }

    pub(super) async fn delete_scim_outbound_target(
        &self,
        id: ScimOutboundTargetId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("scim_outbound_target:{}", id.0), ctx, move |tx| {
            delete_target(tx, id)
        })
        .await
    }

    pub(super) async fn create_scim_outbound_record(
        &self,
        r: &ScimOutboundRecord,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let r = r.clone();
        self.mutate(record_chain(r.target_id, r.sid_entity_id), ctx, move |tx| {
            hold_target(tx, r.target_id)?;
            let pair = record_key(r.target_id, r.sid_entity_id, r.entity_type)?;
            let found = tx.run(
                "MATCH (r:SidScimRecord) WHERE r.pair = $pair RETURN r.pair AS pair",
                Params::default().with("pair", pair.clone()),
            )?;
            if !found.is_empty() {
                return Err(SidError::Conflict(
                    "SCIM outbound record already exists".into(),
                ));
            }
            tx.run(
                "CREATE (r:SidScimRecord {pair: $pair, target_id: $target_id,
                    sid_entity_id: $sid_entity_id, entity_type: $entity_type,
                    downstream_id: $downstream_id, last_synced_at: $last_synced_at,
                    last_error: $last_error, failure_count: $failure_count,
                    created_at: $created_at, updated_at: $updated_at})",
                Params::default()
                    .with("pair", pair)
                    .with("target_id", uuid(&r.target_id.0))
                    .with("sid_entity_id", uuid(&r.sid_entity_id))
                    .with("entity_type", Value::String(r.entity_type.as_str().into()))
                    .with("downstream_id", Value::String(r.downstream_id.clone()))
                    .with("last_synced_at", time(r.last_synced_at))
                    .with("last_error", opt_text(r.last_error.as_deref()))
                    .with("failure_count", Value::Int(i64::from(r.failure_count)))
                    .with("created_at", time(r.created_at))
                    .with("updated_at", time(r.updated_at)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn record_scim_outbound_sync(
        &self,
        r: &ScimOutboundRecord,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let r = r.clone();
        self.mutate(record_chain(r.target_id, r.sid_entity_id), ctx, move |tx| {
            hold_target(tx, r.target_id)?;
            let pair = record_key(r.target_id, r.sid_entity_id, r.entity_type)?;
            let synced = time(r.last_synced_at);
            // Point the mapping at the downstream id just provisioned and
            // clear its error; an existing mapping keeps its creation time.
            let updated = tx.run(
                "MATCH (r:SidScimRecord) WHERE r.pair = $pair
                 SET r.downstream_id = $downstream_id, r.last_synced_at = $synced,
                     r.last_error = null, r.failure_count = 0, r.updated_at = $synced
                 RETURN r.pair AS pair",
                Params::default()
                    .with("pair", pair.clone())
                    .with("downstream_id", Value::String(r.downstream_id.clone()))
                    .with("synced", synced.clone()),
            )?;
            if updated.is_empty() {
                tx.run(
                    "CREATE (r:SidScimRecord {pair: $pair, target_id: $target_id,
                        sid_entity_id: $sid_entity_id, entity_type: $entity_type,
                        downstream_id: $downstream_id, last_synced_at: $synced,
                        last_error: null, failure_count: 0, created_at: $synced,
                        updated_at: $synced})",
                    Params::default()
                        .with("pair", pair)
                        .with("target_id", uuid(&r.target_id.0))
                        .with("sid_entity_id", uuid(&r.sid_entity_id))
                        .with("entity_type", Value::String(r.entity_type.as_str().into()))
                        .with("downstream_id", Value::String(r.downstream_id.clone()))
                        .with("synced", synced),
                )?;
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn record_scim_outbound_dead_letter(
        &self,
        d: &OutboundDlqEntry,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let d = d.clone();
        self.mutate(format!("outbound_dlq:{}", d.id), ctx, move |tx| {
            insert_letter(tx, &d)?;
            // Counted on its entity's mapping, if any, in place.
            tx.run(
                "MATCH (r:SidScimRecord) WHERE r.pair = $pair
                 SET r.last_error = $error, r.failure_count = r.failure_count + 1,
                     r.updated_at = $at",
                Params::default()
                    .with(
                        "pair",
                        record_key(d.target_id, d.sid_entity_id, d.entity_type)?,
                    )
                    .with("error", Value::String(d.error.clone()))
                    .with("at", time(d.last_attempt)),
            )?;
            Ok(())
        })
        .await
    }

    pub(super) async fn get_scim_outbound_record(
        &self,
        target_id: ScimOutboundTargetId,
        entity: Uuid,
        kind: OutboundEntityType,
    ) -> SidResult<Option<ScimOutboundRecord>> {
        let pair = record_key(target_id, entity, kind)?;
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (r:SidScimRecord) WHERE r.pair = $pair RETURN {RECORD}"),
                Params::default().with("pair", pair.clone()),
            )?;
            rows.first().map(record).transpose()
        })
        .await
    }

    pub(super) async fn create_outbound_dlq_entry(
        &self,
        d: &OutboundDlqEntry,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let d = d.clone();
        self.mutate(format!("outbound_dlq:{}", d.id), ctx, move |tx| {
            insert_letter(tx, &d)
        })
        .await
    }

    pub(super) async fn list_outbound_dlq_entries(
        &self,
        target_id: ScimOutboundTargetId,
    ) -> SidResult<Vec<OutboundDlqEntry>> {
        self.read(move |tx| {
            let rows = tx.run(
                &format!("MATCH (d:SidScimDeadLetter) WHERE d.target_id = $id RETURN {LETTER}"),
                Params::default().with("id", uuid(&target_id.0)),
            )?;
            rows.iter().map(letter).collect()
        })
        .await
    }

    pub(super) async fn delete_outbound_dlq_entry(
        &self,
        id: Uuid,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("outbound_dlq:{id}"), ctx, move |tx| {
            tx.run(
                "MATCH (d:SidScimDeadLetter) WHERE d.id = $id DETACH DELETE d",
                Params::default().with("id", uuid(&id)),
            )?;
            Ok(())
        })
        .await
    }
}
