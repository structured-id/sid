// SPDX-License-Identifier: AGPL-3.0-only
//! Runtime configuration of the sign-in flows of a project: which steps run
//! and their parameters, the flow timeout, and the webhook actions at the
//! pipeline's hook points. Every operation is instance administration. A
//! keyed operation commits its change, audit and completion together and
//! answers a retry with what the first attempt recorded.

use std::collections::HashMap;
use std::sync::Arc;

use prost::Message;
use sid_authn::caller::{Caller, CallerError};
use sid_authn::operation::{CommandError, Effect, KeyedCommand, OperationError};
use sid_core::Error as SidError;
use sid_core::models::{
    ActionConfig, ActionOnError, ActionPoint, ActionType, AuditEntry, FlowAction, FlowActionId,
    FlowConfig, FlowType, MutationContext, OperationContext, StepConfig,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::keyed::admin::{flow_action_service, flow_config_service};
use sid_proto::sid::v1::{self as pb};

use crate::wire::{FieldError, json_object_to_struct, struct_to_json, to_timestamp, wire_id};

/// The flow timeout a configuration that names none gets.
const DEFAULT_TIMEOUT_SECONDS: u32 = 300;

/// Why a flow operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    /// The caller is not admitted.
    #[error(transparent)]
    Caller(#[from] CallerError),
    /// The keyed command conflicts, is refused its period or its outcome is
    /// unknown.
    #[error(transparent)]
    Operation(#[from] OperationError),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] SidError),
    /// A required field is absent.
    #[error("{0} is required")]
    MissingField(&'static str),
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// The project has no configuration for this flow type.
    #[error("flow config {0} not found")]
    ConfigNotFound(String),
    /// No action with this id in the project and flow type addressed.
    #[error("flow action {0} not found")]
    ActionNotFound(FlowActionId),
    /// The record changed since it was read.
    #[error("changed concurrently")]
    ChangedConcurrently,
}

impl From<FlowError> for Effect<FlowError> {
    fn from(e: FlowError) -> Self {
        Self::Refused(e)
    }
}

impl From<CommandError<FlowError>> for FlowError {
    fn from(e: CommandError<FlowError>) -> Self {
        e.refusal()
    }
}

impl From<FieldError> for FlowError {
    fn from(FieldError { field, reason }: FieldError) -> Self {
        Self::InvalidField { field, reason }
    }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> FlowError {
    FlowError::InvalidField {
        field,
        reason: reason.into(),
    }
}

/// The sign-in flow configuration of one installation's projects.
pub struct Flows {
    storage: Arc<dyn StorageBackend>,
}

impl Flows {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    /// The stored action a request addresses: its project, flow type and id
    /// together. An action of another project or flow type is not found
    /// here, the same answer as one that does not exist.
    async fn scoped_action(
        &self,
        project_id: Option<&pb::ids::ProjectId>,
        flow_type: i32,
        action_id: Option<&pb::ids::FlowActionId>,
    ) -> Result<FlowAction, FlowError> {
        let project_id = wire_id(project_id, "project_id")?;
        let flow_type = flow_type_from_proto(flow_type)?;
        let action_id = wire_id(action_id, "action_id")?;
        match self.storage.get_flow_action(action_id).await? {
            Some(action) if action.project_id == project_id && action.flow_type == flow_type => {
                Ok(action)
            }
            _ => Err(FlowError::ActionNotFound(action_id)),
        }
    }

    pub async fn config(
        &self,
        caller: &Caller,
        req: pb::GetFlowConfigRequest,
    ) -> Result<pb::FlowConfig, FlowError> {
        caller.require_admin()?;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let flow_type = flow_type_from_proto(req.flow_type)?;
        let config = self
            .storage
            .get_flow_config(project_id, flow_type)
            .await?
            .ok_or_else(|| FlowError::ConfigNotFound(format!("{project_id}:{flow_type}")))?;
        Ok(config_to_proto(&config))
    }

    /// Replace a flow's configuration; a timeout of 0 is the default. A
    /// retry of a completed save answers with the configuration that save
    /// wrote and never writes it over a later save.
    pub async fn save_config(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: pb::SaveFlowConfigRequest,
    ) -> Result<pb::FlowConfig, FlowError> {
        caller.require_admin()?;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let flow_type = flow_type_from_proto(req.flow_type)?;
        let command = KeyedCommand::by_profile::<flow_config_service::SaveFlowConfig>(
            caller.profile_id,
            operation,
            &req,
        );
        let steps: HashMap<String, StepConfig> = req.steps.iter().map(step_from_proto).collect();
        let config = FlowConfig {
            project_id,
            flow_type,
            steps,
            timeout_seconds: match req.timeout_seconds {
                0 => DEFAULT_TIMEOUT_SECONDS,
                t => t,
            },
            updated_at: chrono::Utc::now(),
        };
        command
            .execute(&*self.storage, || async {
                let response = config_to_proto(&config);
                let audit = MutationContext::from(AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "flow_config.save",
                    format!("{project_id}:{flow_type}"),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                self.storage.save_flow_config(&config, audit).await?;
                Ok(response)
            })
            .await
            .map_err(CommandError::<FlowError>::refusal)
    }

    pub async fn list_configs(
        &self,
        caller: &Caller,
        req: pb::ListFlowConfigsRequest,
    ) -> Result<pb::ListFlowConfigsResponse, FlowError> {
        caller.require_admin()?;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let configs = self.storage.list_flow_configs(project_id).await?;
        Ok(pb::ListFlowConfigsResponse {
            configs: configs.iter().map(config_to_proto).collect(),
        })
    }

    /// Create an action. A retry of a completed creation answers with the
    /// action it created and creates no second one.
    pub async fn create_action(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: pb::CreateFlowActionRequest,
    ) -> Result<pb::FlowAction, FlowError> {
        caller.require_admin()?;
        let command = KeyedCommand::by_profile::<flow_action_service::CreateFlowAction>(
            caller.profile_id,
            operation,
            &req,
        );
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let flow_type = flow_type_from_proto(req.flow_type)?;
        let action_point = action_point_from_proto(req.action_point)?;
        if req.name.is_empty() {
            return Err(FlowError::MissingField("name"));
        }
        let config = match req.config {
            Some(pb::create_flow_action_request::Config::Webhook(ref wh)) => webhook_from_proto(wh),
            None => return Err(FlowError::MissingField("config")),
        };
        config.validate().map_err(|why| invalid("webhook", why))?;
        let on_error = on_error_from_proto(req.on_error)?;
        let now = chrono::Utc::now();
        let action = FlowAction {
            id: FlowActionId::generate(),
            project_id,
            flow_type,
            action_point,
            name: req.name,
            action_type: ActionType::Webhook,
            config,
            order: req.order,
            on_error,
            enabled: req.enabled,
            revision: 0,
            created_at: now,
            updated_at: now,
        };
        command
            .execute(&*self.storage, || async {
                let response = action_to_proto(&action);
                let audit = MutationContext::from(AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "flow_action.create",
                    action.id.to_string(),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                self.storage.create_flow_action(&action, audit).await?;
                Ok(response)
            })
            .await
            .map_err(CommandError::<FlowError>::refusal)
    }

    pub async fn action(
        &self,
        caller: &Caller,
        req: pb::GetFlowActionRequest,
    ) -> Result<pb::FlowAction, FlowError> {
        caller.require_admin()?;
        let action = self
            .scoped_action(
                req.project_id.as_ref(),
                req.flow_type,
                req.action_id.as_ref(),
            )
            .await?;
        Ok(action_to_proto(&action))
    }

    /// The actions of a flow, at one hook point when the request names one.
    pub async fn list_actions(
        &self,
        caller: &Caller,
        req: pb::ListFlowActionsRequest,
    ) -> Result<pb::ListFlowActionsResponse, FlowError> {
        caller.require_admin()?;
        let project_id = wire_id(req.project_id.as_ref(), "project_id")?;
        let flow_type = flow_type_from_proto(req.flow_type)?;
        let action_point = match req.action_point {
            0 => None,
            point => Some(action_point_from_proto(point)?),
        };
        let actions = self
            .storage
            .list_flow_actions(project_id, flow_type, action_point)
            .await?;
        Ok(pb::ListFlowActionsResponse {
            actions: actions.iter().map(action_to_proto).collect(),
        })
    }

    /// Change the fields given of an action at the revision read: a stale
    /// copy never re-enables a disabled action or recreates a deleted one. A
    /// retry of a completed change answers with the action as that change
    /// left it and never writes it over a later change.
    pub async fn update_action(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: pb::UpdateFlowActionRequest,
    ) -> Result<pb::FlowAction, FlowError> {
        caller.require_admin()?;
        let command = KeyedCommand::by_profile::<flow_action_service::UpdateFlowAction>(
            caller.profile_id,
            operation,
            &req,
        );
        command
            .execute(&*self.storage, || async {
                let mut action = self
                    .scoped_action(
                        req.project_id.as_ref(),
                        req.flow_type,
                        req.action_id.as_ref(),
                    )
                    .await?;
                if let Some(name) = &req.name {
                    if name.is_empty() {
                        return Err(invalid("name", "empty").into());
                    }
                    action.name = name.clone();
                }
                if let Some(point) = req.action_point {
                    action.action_point = action_point_from_proto(point)?;
                }
                if let Some(pb::update_flow_action_request::Config::Webhook(ref wh)) = req.config {
                    let config = webhook_from_proto(wh);
                    config.validate().map_err(|why| invalid("webhook", why))?;
                    action.config = config;
                }
                if let Some(order) = req.order {
                    action.order = order;
                }
                if let Some(on_error) = req.on_error {
                    action.on_error = on_error_from_proto(on_error)?;
                }
                if let Some(enabled) = req.enabled {
                    action.enabled = enabled;
                }
                action.updated_at = chrono::Utc::now();
                let response = action_to_proto(&action);
                let audit = MutationContext::from(AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "flow_action.update",
                    action.id.to_string(),
                ))
                .with_operation(command.completion(response.encode_to_vec()));
                if !self.storage.update_flow_action(&action, audit).await? {
                    return Err(FlowError::ChangedConcurrently.into());
                }
                Ok(response)
            })
            .await
            .map_err(CommandError::<FlowError>::refusal)
    }

    pub async fn delete_action(
        &self,
        caller: &Caller,
        req: pb::DeleteFlowActionRequest,
    ) -> Result<(), FlowError> {
        caller.require_admin()?;
        let action_id = self
            .scoped_action(
                req.project_id.as_ref(),
                req.flow_type,
                req.action_id.as_ref(),
            )
            .await?
            .id;
        let audit: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "flow_action.delete",
            action_id.to_string(),
        )
        .into();
        self.storage.delete_flow_action(action_id, audit).await?;
        Ok(())
    }
}

// ── Messages ──

fn flow_type_from_proto(v: i32) -> Result<FlowType, FlowError> {
    use pb::admin::FlowType as P;
    match P::try_from(v) {
        Ok(P::Authentication) => Ok(FlowType::Authentication),
        Ok(P::Registration) => Ok(FlowType::Registration),
        Ok(P::Recovery) => Ok(FlowType::Recovery),
        Ok(P::DeviceGrant) => Ok(FlowType::DeviceGrant),
        Ok(P::DirectGrant) => Ok(FlowType::DirectGrant),
        Ok(P::Enrollment) => Ok(FlowType::Enrollment),
        Ok(P::Unspecified) | Err(_) => Err(invalid("flow_type", "not a flow type")),
    }
}

fn flow_type_to_proto(ft: &FlowType) -> i32 {
    use pb::admin::FlowType as P;
    let proto = match ft {
        FlowType::Authentication => P::Authentication,
        FlowType::Registration => P::Registration,
        FlowType::Recovery => P::Recovery,
        FlowType::DeviceGrant => P::DeviceGrant,
        FlowType::DirectGrant => P::DirectGrant,
        FlowType::Enrollment => P::Enrollment,
    };
    proto as i32
}

fn action_point_from_proto(v: i32) -> Result<ActionPoint, FlowError> {
    use pb::admin::ActionPoint as P;
    match P::try_from(v) {
        Ok(P::PreAuthentication) => Ok(ActionPoint::PreAuthentication),
        Ok(P::PostAuthentication) => Ok(ActionPoint::PostAuthentication),
        Ok(P::PostMfa) => Ok(ActionPoint::PostMfa),
        Ok(P::PreTokenCreation) => Ok(ActionPoint::PreTokenCreation),
        Ok(P::PostLogin) => Ok(ActionPoint::PostLogin),
        Ok(P::PostRegistration) => Ok(ActionPoint::PostRegistration),
        Ok(P::PreConsent) => Ok(ActionPoint::PreConsent),
        Ok(P::Unspecified) | Err(_) => Err(invalid("action_point", "not an action point")),
    }
}

fn action_point_to_proto(ap: &ActionPoint) -> i32 {
    use pb::admin::ActionPoint as P;
    let proto = match ap {
        ActionPoint::PreAuthentication => P::PreAuthentication,
        ActionPoint::PostAuthentication => P::PostAuthentication,
        ActionPoint::PostMfa => P::PostMfa,
        ActionPoint::PreTokenCreation => P::PreTokenCreation,
        ActionPoint::PostLogin => P::PostLogin,
        ActionPoint::PostRegistration => P::PostRegistration,
        ActionPoint::PreConsent => P::PreConsent,
    };
    proto as i32
}

fn on_error_to_proto(onerr: &ActionOnError) -> i32 {
    use pb::admin::ActionOnError as P;
    let proto = match onerr {
        ActionOnError::Continue => P::Continue,
        ActionOnError::Deny => P::Deny,
    };
    proto as i32
}

/// What a failing action does to the flow. Unspecified keeps the default,
/// continue; a value the enum does not define is refused, never read as
/// continue (which would let a sign-in pass a failed check).
fn on_error_from_proto(v: i32) -> Result<ActionOnError, FlowError> {
    use pb::admin::ActionOnError as P;
    match P::try_from(v) {
        Ok(P::Unspecified | P::Continue) => Ok(ActionOnError::Continue),
        Ok(P::Deny) => Ok(ActionOnError::Deny),
        Err(_) => Err(invalid("on_error", "not an on-error policy")),
    }
}

/// A step's parameters: an object is a protobuf struct, anything else no
/// parameters.
fn step_to_proto(step_type: &str, step: &StepConfig) -> pb::admin::StepConfig {
    pb::admin::StepConfig {
        step_type: step_type.to_string(),
        enabled: step.enabled,
        params: match step.params.clone() {
            serde_json::Value::Object(map) => Some(json_object_to_struct(map)),
            _ => None,
        },
    }
}

fn step_from_proto(step: &pb::admin::StepConfig) -> (String, StepConfig) {
    let params = step
        .params
        .clone()
        .map(struct_to_json)
        .unwrap_or(serde_json::Value::Null);
    (
        step.step_type.clone(),
        StepConfig {
            enabled: step.enabled,
            params,
        },
    )
}

fn config_to_proto(config: &FlowConfig) -> pb::FlowConfig {
    pb::FlowConfig {
        project_id: Some(config.project_id.into()),
        flow_type: flow_type_to_proto(&config.flow_type),
        steps: config
            .steps
            .iter()
            .map(|(k, v)| step_to_proto(k, v))
            .collect(),
        timeout_seconds: config.timeout_seconds,
        updated_at: Some(to_timestamp(config.updated_at)),
    }
}

fn action_to_proto(action: &FlowAction) -> pb::FlowAction {
    let (action_type, config) = match &action.config {
        ActionConfig::Webhook {
            url,
            timeout_seconds,
            retry_count,
            headers,
        } => (
            pb::admin::ActionType::Webhook as i32,
            Some(pb::flow_action::Config::Webhook(pb::WebhookConfig {
                url: url.clone(),
                timeout_seconds: *timeout_seconds,
                retry_count: *retry_count,
                headers: headers.clone(),
            })),
        ),
    };
    pb::FlowAction {
        action_id: Some(action.id.into()),
        project_id: Some(action.project_id.into()),
        flow_type: flow_type_to_proto(&action.flow_type),
        action_point: action_point_to_proto(&action.action_point),
        name: action.name.clone(),
        action_type,
        config,
        order: action.order,
        on_error: on_error_to_proto(&action.on_error),
        enabled: action.enabled,
        created_at: Some(to_timestamp(action.created_at)),
        updated_at: Some(to_timestamp(action.updated_at)),
    }
}

fn webhook_from_proto(wh: &pb::WebhookConfig) -> ActionConfig {
    ActionConfig::Webhook {
        url: wh.url.clone(),
        timeout_seconds: wh.timeout_seconds,
        retry_count: wh.retry_count,
        headers: wh.headers.clone(),
    }
}

#[cfg(test)]
mod tests;
