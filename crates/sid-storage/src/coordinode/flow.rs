// SPDX-License-Identifier: AGPL-3.0-only
//! Authentication flows in CoordiNode: one configuration per project and
//! flow type, and the actions hooked into a flow. Content is a CoordiNode
//! document; what a listing selects and orders by (project, flow type, hook
//! point, order) and an action's revision are their own properties.

use coordinode_core::graph::types::Value;
use sid_core::models::{
    ActionPoint, FlowAction, FlowActionId, FlowConfig, FlowType, MutationContext, ProjectId,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{
    CoordinodeBackend, Decision, Params, Row, Statements, claim_first, document, finalize,
    get_document, get_int, key, project::project_value, time, uuid,
};

fn config_key(project: ProjectId, flow_type: FlowType) -> SidResult<Value> {
    key(&[project.as_uuid().as_bytes(), flow_type.as_str().as_bytes()])
}

fn config_chain(project: ProjectId, flow_type: FlowType) -> String {
    format!("flow_config:{project}:{}", flow_type.as_str())
}

/// The revision inside the content is not read: the property is the stored one.
fn action(row: &Row) -> SidResult<FlowAction> {
    let mut action: FlowAction = get_document(row, "content")?;
    let revision = get_int(row, "revision")?;
    action.revision = u64::try_from(revision)
        .map_err(|_| SidError::Storage(format!("flow action revision: {revision}")))?;
    Ok(action)
}

/// Claim project `id` for a record created under it, or refuse it.
fn claim_project(tx: &Statements<'_>, id: ProjectId) -> SidResult<()> {
    let rows = tx.run(
        "MATCH (j:SidProject) WHERE j.id = $id RETURN id(j) AS node",
        Params::default().with("id", project_value(id)),
    )?;
    if !claim_first(tx, &rows)? {
        return Err(SidError::NotFound(format!("project {id}")));
    }
    Ok(())
}

/// Delete in `tx` the flow configurations and actions of `project`.
pub(super) fn delete_project_records(tx: &Statements<'_>, project: ProjectId) -> SidResult<()> {
    for query in [
        "MATCH (c:SidFlowConfig) WHERE c.project_id = $id DETACH DELETE c",
        "MATCH (a:SidFlowAction) WHERE a.project_id = $id DETACH DELETE a",
    ] {
        tx.run(query, Params::default().with("id", project_value(project)))?;
    }
    Ok(())
}

impl CoordinodeBackend {
    pub(super) async fn get_flow_config(
        &self,
        project: ProjectId,
        flow_type: FlowType,
    ) -> SidResult<Option<FlowConfig>> {
        let pair = config_key(project, flow_type)?;
        self.read(move |tx| {
            let rows = tx.run(
                "MATCH (c:SidFlowConfig) WHERE c.pair = $pair RETURN c.content AS content",
                Params::default().with("pair", pair.clone()),
            )?;
            rows.first()
                .map(|row| get_document(row, "content"))
                .transpose()
        })
        .await
    }

    pub(super) async fn save_flow_config(
        &self,
        config: &FlowConfig,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let pair = config_key(config.project_id, config.flow_type)?;
        let params = Params::default()
            .with("pair", pair)
            .with("project_id", project_value(config.project_id))
            .with("flow_type", Value::String(config.flow_type.as_str().into()))
            .with("content", document(config, "flow config")?)
            .with("updated_at", time(config.updated_at));
        let project = config.project_id;
        self.mutate(config_chain(project, config.flow_type), ctx, move |tx| {
            claim_project(tx, project)?;
            // The whole configuration is replaced: one per project and type.
            let updated = tx.run(
                "MATCH (c:SidFlowConfig) WHERE c.pair = $pair
                 SET c.content = $content, c.updated_at = $updated_at
                 RETURN c.pair AS pair",
                params.clone(),
            )?;
            if updated.is_empty() {
                tx.run(
                    "CREATE (c:SidFlowConfig {pair: $pair, project_id: $project_id,
                        flow_type: $flow_type, content: $content, updated_at: $updated_at})",
                    params.clone(),
                )?;
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn list_flow_configs(&self, project: ProjectId) -> SidResult<Vec<FlowConfig>> {
        self.read(move |tx| {
            let rows = tx.run(
                "MATCH (c:SidFlowConfig) WHERE c.project_id = $id
                 RETURN c.content AS content, c.flow_type AS flow_type",
                Params::default().with("id", project_value(project)),
            )?;
            let mut configs = rows
                .iter()
                .map(|row| get_document::<FlowConfig>(row, "content"))
                .collect::<SidResult<Vec<_>>>()?;
            configs.sort_by(|a, b| a.flow_type.as_str().cmp(b.flow_type.as_str()));
            Ok(configs)
        })
        .await
    }

    pub(super) async fn create_flow_action(
        &self,
        action: &FlowAction,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let params = Params::default()
            .with("id", uuid(action.id.as_uuid()))
            .with("project_id", project_value(action.project_id))
            .with("flow_type", Value::String(action.flow_type.as_str().into()))
            .with(
                "action_point",
                Value::String(action.action_point.as_str().into()),
            )
            .with("action_order", Value::Int(i64::from(action.order)))
            .with("content", document(action, "flow action")?)
            .with("created_at", time(action.created_at))
            .with("updated_at", time(action.updated_at));
        let project = action.project_id;
        self.mutate(format!("flow_action:{}", action.id), ctx, move |tx| {
            claim_project(tx, project)?;
            let found = tx.run(
                "MATCH (a:SidFlowAction) WHERE a.id = $id RETURN a.id AS id",
                params.clone(),
            )?;
            if !found.is_empty() {
                return Err(SidError::Conflict("flow action already exists".into()));
            }
            tx.run(
                "CREATE (a:SidFlowAction {id: $id, project_id: $project_id, flow_type: $flow_type,
                    action_point: $action_point, action_order: $action_order,
                    content: $content, revision: 0, created_at: $created_at,
                    updated_at: $updated_at})",
                params.clone(),
            )?;
            Ok(())
        })
        .await
    }

    /// Applies only over the revision `action` was read at; the hook point
    /// and order move with the content.
    pub(super) async fn update_flow_action(
        &self,
        action: &FlowAction,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let revision = i64::try_from(action.revision)
            .map_err(|_| SidError::Validation("flow action revision out of range".into()))?;
        let params = Params::default()
            .with("id", uuid(action.id.as_uuid()))
            .with("revision", Value::Int(revision))
            .with(
                "action_point",
                Value::String(action.action_point.as_str().into()),
            )
            .with("action_order", Value::Int(i64::from(action.order)))
            .with("content", document(action, "flow action")?)
            .with("updated_at", time(action.updated_at));
        let chain = format!("flow_action:{}", action.id);
        self.transaction(move |tx| {
            let updated = tx.run(
                "MATCH (a:SidFlowAction) WHERE a.id = $id AND a.revision = $revision
                 SET a.action_point = $action_point, a.action_order = $action_order,
                     a.content = $content, a.updated_at = $updated_at,
                     a.revision = a.revision + 1
                 RETURN a.id AS id",
                params.clone(),
            )?;
            if updated.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            finalize(tx, &chain, ctx.clone())?;
            Ok(Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn get_flow_action(&self, id: FlowActionId) -> SidResult<Option<FlowAction>> {
        self.read(move |tx| {
            let rows = tx.run(
                "MATCH (a:SidFlowAction) WHERE a.id = $id
                 RETURN a.content AS content, a.revision AS revision",
                Params::default().with("id", uuid(id.as_uuid())),
            )?;
            rows.first().map(action).transpose()
        })
        .await
    }

    pub(super) async fn list_flow_actions(
        &self,
        project: ProjectId,
        flow_type: FlowType,
        point: Option<ActionPoint>,
    ) -> SidResult<Vec<FlowAction>> {
        self.read(move |tx| {
            let rows = tx.run(
                "MATCH (a:SidFlowAction) WHERE a.project_id = $id AND a.flow_type = $flow_type
                 RETURN a.content AS content, a.revision AS revision",
                Params::default()
                    .with("id", project_value(project))
                    .with("flow_type", Value::String(flow_type.as_str().into())),
            )?;
            let mut actions = rows
                .iter()
                .map(action)
                .filter(|a| match (a, point) {
                    (Ok(a), Some(point)) => a.action_point == point,
                    _ => true,
                })
                .collect::<SidResult<Vec<_>>>()?;
            // In execution order: hook point, then order, then id.
            actions.sort_by(|a, b| {
                (a.action_point.as_str(), a.order, a.id).cmp(&(
                    b.action_point.as_str(),
                    b.order,
                    b.id,
                ))
            });
            Ok(actions)
        })
        .await
    }

    pub(super) async fn delete_flow_action(
        &self,
        id: FlowActionId,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.mutate(format!("flow_action:{id}"), ctx, move |tx| {
            tx.run(
                "MATCH (a:SidFlowAction) WHERE a.id = $id DETACH DELETE a",
                Params::default().with("id", uuid(id.as_uuid())),
            )?;
            Ok(())
        })
        .await
    }
}
