// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC FlowConfigService and FlowActionService implementation.
//!
//! Runtime configuration for auth flows (step enable/disable, timeouts)
//! and webhook actions at pipeline hook points. Admin role required.

use sid_authn::caller::authenticate;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::grpc_error::ErrorReason;
use sid_core::grpc_error::refuse::{
    changed_concurrently, invalid_field, missing_field, not_found, storage_failure,
};
use sid_core::models::{
    ActionConfig, ActionId, ActionOnError, ActionPoint, ActionType, AuditEntry, FlowAction,
    FlowConfig, FlowType, MutationContext, ProjectId, StepConfig,
};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::flow_action_service_server::FlowActionService;
use sid_proto::sid::v1::flow_config_service_server::FlowConfigService;
use sid_proto::sid::v1::{self as pb};
use std::collections::HashMap;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::instrument;
use uuid::Uuid;

pub struct FlowConfigServiceImpl {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
}

impl FlowConfigServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            storage,
            jwt,
            revocation,
        }
    }
}

pub struct FlowActionServiceImpl {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
}

impl FlowActionServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            storage,
            jwt,
            revocation,
        }
    }
}

// ── Shared Helpers ──

/// Authenticate the caller and require the administrator role; returns the
/// caller's ProfileId as the audit actor.
#[allow(clippy::result_large_err)]
async fn require_admin<T>(
    jwt: &JwtService,
    revocation: &RevocationCache,
    req: &Request<T>,
) -> Result<String, Status> {
    let caller = authenticate(req, jwt.verifier(), revocation).await?;
    caller.require_admin()?;
    Ok(caller.profile_id.to_string())
}

#[allow(clippy::result_large_err)]
fn parse_project_id(s: &str) -> Result<ProjectId, Status> {
    Uuid::parse_str(s)
        .map(ProjectId)
        .map_err(|_| invalid_field("project_id", "not a project identifier"))
}

#[allow(clippy::result_large_err)]
fn parse_action_id(s: &str) -> Result<ActionId, Status> {
    Uuid::parse_str(s)
        .map(ActionId)
        .map_err(|_| invalid_field("action_id", "not a flow action identifier"))
}

#[allow(clippy::result_large_err)]
fn parse_flow_type_str(s: &str) -> Result<FlowType, Status> {
    s.parse::<FlowType>()
        .map_err(|_| invalid_field("flow_type", "not a flow type"))
}

fn flow_action_not_found(id: ActionId) -> Status {
    not_found(
        ErrorReason::FlowActionNotFound,
        "FlowAction",
        id.0.to_string(),
    )
}

fn domain_flow_type_to_proto(ft: &FlowType) -> i32 {
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

#[allow(clippy::result_large_err)]
fn proto_action_point_to_domain(v: i32) -> Result<ActionPoint, Status> {
    use pb::admin::ActionPoint as P;
    match P::try_from(v) {
        Ok(P::PreAuthentication) => Ok(ActionPoint::PreAuthentication),
        Ok(P::PostAuthentication) => Ok(ActionPoint::PostAuthentication),
        Ok(P::PostMfa) => Ok(ActionPoint::PostMfa),
        Ok(P::PreTokenCreation) => Ok(ActionPoint::PreTokenCreation),
        Ok(P::PostLogin) => Ok(ActionPoint::PostLogin),
        Ok(P::PostRegistration) => Ok(ActionPoint::PostRegistration),
        Ok(P::PreConsent) => Ok(ActionPoint::PreConsent),
        Ok(P::Unspecified) | Err(_) => Err(invalid_field("action_point", "not an action point")),
    }
}

fn domain_action_point_to_proto(ap: &ActionPoint) -> i32 {
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

fn domain_action_on_error_to_proto(onerr: &ActionOnError) -> i32 {
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
#[allow(clippy::result_large_err)]
fn proto_action_on_error_to_domain(v: i32) -> Result<ActionOnError, Status> {
    use pb::admin::ActionOnError as P;
    match P::try_from(v) {
        Ok(P::Unspecified | P::Continue) => Ok(ActionOnError::Continue),
        Ok(P::Deny) => Ok(ActionOnError::Deny),
        Err(_) => Err(invalid_field("on_error", "not an on-error policy")),
    }
}

// ── JSON ↔ prost_types::Struct helpers ──

fn json_to_prost_value(v: serde_json::Value) -> prost_types::Value {
    match v {
        serde_json::Value::Null => prost_types::Value {
            kind: Some(prost_types::value::Kind::NullValue(0)),
        },
        serde_json::Value::Bool(b) => prost_types::Value {
            kind: Some(prost_types::value::Kind::BoolValue(b)),
        },
        serde_json::Value::Number(n) => prost_types::Value {
            kind: Some(prost_types::value::Kind::NumberValue(
                n.as_f64().unwrap_or(0.0),
            )),
        },
        serde_json::Value::String(s) => prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(s)),
        },
        serde_json::Value::Array(arr) => prost_types::Value {
            kind: Some(prost_types::value::Kind::ListValue(
                prost_types::ListValue {
                    values: arr.into_iter().map(json_to_prost_value).collect(),
                },
            )),
        },
        serde_json::Value::Object(map) => prost_types::Value {
            kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                fields: map
                    .into_iter()
                    .map(|(k, v)| (k, json_to_prost_value(v)))
                    .collect(),
            })),
        },
    }
}

fn prost_value_to_json(v: prost_types::Value) -> serde_json::Value {
    match v.kind {
        Some(prost_types::value::Kind::NullValue(_)) => serde_json::Value::Null,
        Some(prost_types::value::Kind::BoolValue(b)) => serde_json::Value::Bool(b),
        Some(prost_types::value::Kind::NumberValue(n)) => {
            serde_json::Value::Number(serde_json::Number::from_f64(n).unwrap_or_else(|| 0.into()))
        }
        Some(prost_types::value::Kind::StringValue(s)) => serde_json::Value::String(s),
        Some(prost_types::value::Kind::ListValue(list)) => {
            serde_json::Value::Array(list.values.into_iter().map(prost_value_to_json).collect())
        }
        Some(prost_types::value::Kind::StructValue(s)) => serde_json::Value::Object(
            s.fields
                .into_iter()
                .map(|(k, v)| (k, prost_value_to_json(v)))
                .collect(),
        ),
        None => serde_json::Value::Null,
    }
}

fn json_to_prost_struct(v: serde_json::Value) -> Option<prost_types::Struct> {
    match v {
        serde_json::Value::Object(map) => Some(prost_types::Struct {
            fields: map
                .into_iter()
                .map(|(k, v)| (k, json_to_prost_value(v)))
                .collect(),
        }),
        serde_json::Value::Null => None,
        _ => None,
    }
}

fn prost_struct_to_json(s: &prost_types::Struct) -> serde_json::Value {
    serde_json::Value::Object(
        s.fields
            .iter()
            .map(|(k, v)| (k.clone(), prost_value_to_json(v.clone())))
            .collect(),
    )
}

// ── Domain ↔ Proto Conversions ──

fn domain_step_to_proto(step_type: &str, step: &StepConfig) -> pb::admin::StepConfig {
    pb::admin::StepConfig {
        step_type: step_type.to_string(),
        enabled: step.enabled,
        params: json_to_prost_struct(step.params.clone()),
    }
}

fn proto_step_to_domain(step: &pb::admin::StepConfig) -> (String, StepConfig) {
    let params = step
        .params
        .as_ref()
        .map(prost_struct_to_json)
        .unwrap_or(serde_json::Value::Null);

    (
        step.step_type.clone(),
        StepConfig {
            enabled: step.enabled,
            params,
        },
    )
}

fn domain_config_to_proto(config: &FlowConfig) -> pb::FlowConfig {
    pb::FlowConfig {
        project_id: config.project_id.0.to_string(),
        flow_type: domain_flow_type_to_proto(&config.flow_type),
        steps: config
            .steps
            .iter()
            .map(|(k, v)| domain_step_to_proto(k, v))
            .collect(),
        timeout_seconds: config.timeout_seconds,
        updated_at: Some(prost_types::Timestamp {
            seconds: config.updated_at.timestamp(),
            nanos: config.updated_at.timestamp_subsec_nanos() as i32,
        }),
    }
}

fn domain_action_to_proto(action: &FlowAction) -> pb::FlowAction {
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
        action_id: action.id.0.to_string(),
        project_id: action.project_id.0.to_string(),
        flow_type: domain_flow_type_to_proto(&action.flow_type),
        action_point: domain_action_point_to_proto(&action.action_point),
        name: action.name.clone(),
        action_type,
        config,
        order: action.order,
        on_error: domain_action_on_error_to_proto(&action.on_error),
        enabled: action.enabled,
        created_at: Some(prost_types::Timestamp {
            seconds: action.created_at.timestamp(),
            nanos: action.created_at.timestamp_subsec_nanos() as i32,
        }),
        updated_at: Some(prost_types::Timestamp {
            seconds: action.updated_at.timestamp(),
            nanos: action.updated_at.timestamp_subsec_nanos() as i32,
        }),
    }
}

fn proto_webhook_to_domain(wh: &pb::WebhookConfig) -> ActionConfig {
    ActionConfig::Webhook {
        url: wh.url.clone(),
        timeout_seconds: wh.timeout_seconds,
        retry_count: wh.retry_count,
        headers: wh.headers.clone(),
    }
}

// ── FlowConfigService ──

#[tonic::async_trait]
impl FlowConfigService for FlowConfigServiceImpl {
    #[instrument(skip(self, req))]
    async fn get_flow_config(
        &self,
        req: Request<pb::GetFlowConfigRequest>,
    ) -> Result<Response<pb::FlowConfig>, Status> {
        require_admin(&self.jwt, &self.revocation, &req).await?;
        let inner = req.into_inner();
        let project_id = parse_project_id(&inner.project_id)?;
        let flow_type = parse_flow_type_str(&inner.flow_type)?;

        let config = self
            .storage
            .get_flow_config(project_id, flow_type)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| {
                not_found(
                    ErrorReason::FlowConfigNotFound,
                    "FlowConfig",
                    format!("{}:{flow_type}", project_id.0),
                )
            })?;

        Ok(Response::new(domain_config_to_proto(&config)))
    }

    #[instrument(skip(self, req))]
    async fn save_flow_config(
        &self,
        req: Request<pb::SaveFlowConfigRequest>,
    ) -> Result<Response<pb::FlowConfig>, Status> {
        let admin_sub = require_admin(&self.jwt, &self.revocation, &req).await?;
        let inner = req.into_inner();
        let project_id = parse_project_id(&inner.project_id)?;
        let flow_type = parse_flow_type_str(&inner.flow_type)?;

        let steps: HashMap<String, StepConfig> =
            inner.steps.iter().map(proto_step_to_domain).collect();

        let timeout = if inner.timeout_seconds == 0 {
            300
        } else {
            inner.timeout_seconds
        };

        let now = chrono::Utc::now();
        let config = FlowConfig {
            project_id,
            flow_type,
            steps,
            timeout_seconds: timeout,
            updated_at: now,
        };

        let audit: MutationContext = AuditEntry::admin(
            &admin_sub,
            "flow_config.save",
            format!("{}:{}", project_id.0, flow_type),
        )
        .into();
        self.storage
            .save_flow_config(&config, audit)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(domain_config_to_proto(&config)))
    }

    #[instrument(skip(self, req))]
    async fn list_flow_configs(
        &self,
        req: Request<pb::ListFlowConfigsRequest>,
    ) -> Result<Response<pb::ListFlowConfigsResponse>, Status> {
        require_admin(&self.jwt, &self.revocation, &req).await?;
        let inner = req.into_inner();
        let project_id = parse_project_id(&inner.project_id)?;

        let configs = self
            .storage
            .list_flow_configs(project_id)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(pb::ListFlowConfigsResponse {
            configs: configs.iter().map(domain_config_to_proto).collect(),
        }))
    }
}

// ── FlowActionService ──

#[tonic::async_trait]
impl FlowActionService for FlowActionServiceImpl {
    #[instrument(skip(self, req))]
    async fn create_flow_action(
        &self,
        req: Request<pb::CreateFlowActionRequest>,
    ) -> Result<Response<pb::FlowAction>, Status> {
        let admin_sub = require_admin(&self.jwt, &self.revocation, &req).await?;
        let inner = req.into_inner();
        let project_id = parse_project_id(&inner.project_id)?;
        let flow_type = parse_flow_type_str(&inner.flow_type)?;
        let action_point = proto_action_point_to_domain(inner.action_point)?;

        if inner.name.is_empty() {
            return Err(missing_field("name"));
        }

        let config = match inner.config {
            Some(pb::create_flow_action_request::Config::Webhook(ref wh)) => {
                proto_webhook_to_domain(wh)
            }
            None => return Err(missing_field("config")),
        };

        config
            .validate()
            .map_err(|why| invalid_field("webhook", why))?;
        let on_error = proto_action_on_error_to_domain(inner.on_error)?;

        let now = chrono::Utc::now();
        let action = FlowAction {
            id: ActionId::new(),
            project_id,
            flow_type,
            action_point,
            name: inner.name,
            action_type: ActionType::Webhook,
            config,
            order: inner.order,
            on_error,
            enabled: inner.enabled,
            revision: 0,
            created_at: now,
            updated_at: now,
        };

        let audit: MutationContext =
            AuditEntry::admin(&admin_sub, "flow_action.create", action.id.to_string()).into();
        self.storage
            .create_flow_action(&action, audit)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(domain_action_to_proto(&action)))
    }

    #[instrument(skip(self, req))]
    async fn get_flow_action(
        &self,
        req: Request<pb::GetFlowActionRequest>,
    ) -> Result<Response<pb::FlowAction>, Status> {
        require_admin(&self.jwt, &self.revocation, &req).await?;
        let inner = req.into_inner();
        let action_id = parse_action_id(&inner.action_id)?;

        let action = self
            .storage
            .get_flow_action(action_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| flow_action_not_found(action_id))?;

        Ok(Response::new(domain_action_to_proto(&action)))
    }

    #[instrument(skip(self, req))]
    async fn list_flow_actions(
        &self,
        req: Request<pb::ListFlowActionsRequest>,
    ) -> Result<Response<pb::ListFlowActionsResponse>, Status> {
        require_admin(&self.jwt, &self.revocation, &req).await?;
        let inner = req.into_inner();
        let project_id = parse_project_id(&inner.project_id)?;
        let flow_type = parse_flow_type_str(&inner.flow_type)?;

        let action_point = if inner.action_point != 0 {
            Some(proto_action_point_to_domain(inner.action_point)?)
        } else {
            None
        };

        let actions = self
            .storage
            .list_flow_actions(project_id, flow_type, action_point)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(pb::ListFlowActionsResponse {
            actions: actions.iter().map(domain_action_to_proto).collect(),
        }))
    }

    #[instrument(skip(self, req))]
    async fn update_flow_action(
        &self,
        req: Request<pb::UpdateFlowActionRequest>,
    ) -> Result<Response<pb::FlowAction>, Status> {
        let admin_sub = require_admin(&self.jwt, &self.revocation, &req).await?;
        let inner = req.into_inner();
        let action_id = parse_action_id(&inner.action_id)?;

        let mut action = self
            .storage
            .get_flow_action(action_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| flow_action_not_found(action_id))?;

        if let Some(name) = inner.name {
            if name.is_empty() {
                return Err(invalid_field("name", "empty"));
            }
            action.name = name;
        }

        if let Some(ap) = inner.action_point {
            action.action_point = proto_action_point_to_domain(ap)?;
        }

        if let Some(config) = inner.config {
            let new_config = match config {
                pb::update_flow_action_request::Config::Webhook(ref wh) => {
                    proto_webhook_to_domain(wh)
                }
            };
            new_config
                .validate()
                .map_err(|why| invalid_field("webhook", why))?;
            action.config = new_config;
        }

        if let Some(order) = inner.order {
            action.order = order;
        }

        if let Some(on_error) = inner.on_error {
            action.on_error = proto_action_on_error_to_domain(on_error)?;
        }

        if let Some(enabled) = inner.enabled {
            action.enabled = enabled;
        }

        action.updated_at = chrono::Utc::now();

        let audit: MutationContext =
            AuditEntry::admin(&admin_sub, "flow_action.update", action.id.to_string()).into();
        let updated = self
            .storage
            .update_flow_action(&action, audit)
            .await
            .map_err(storage_failure)?;
        if !updated {
            // Deleted or changed since it was read: a stale copy never
            // re-enables a disabled action or recreates a deleted one.
            return Err(changed_concurrently());
        }
        action.revision += 1;

        Ok(Response::new(domain_action_to_proto(&action)))
    }

    #[instrument(skip(self, req))]
    async fn delete_flow_action(
        &self,
        req: Request<pb::DeleteFlowActionRequest>,
    ) -> Result<Response<()>, Status> {
        let admin_sub = require_admin(&self.jwt, &self.revocation, &req).await?;
        let inner = req.into_inner();
        let action_id = parse_action_id(&inner.action_id)?;

        // Verify action exists
        self.storage
            .get_flow_action(action_id)
            .await
            .map_err(storage_failure)?
            .ok_or_else(|| flow_action_not_found(action_id))?;

        let audit: MutationContext =
            AuditEntry::admin(&admin_sub, "flow_action.delete", action_id.to_string()).into();
        self.storage
            .delete_flow_action(action_id, audit)
            .await
            .map_err(storage_failure)?;

        Ok(Response::new(()))
    }
}

#[cfg(test)]
mod tests;
