// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC FlowConfigService and FlowActionService implementation:
//! authenticates the caller and answers through [`sid::flows`]. Admin role
//! required.

use sid::flows::{FlowError, Flows};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_infra::authn::caller::authenticate;
use sid_infra::grpc_error::refuse::{
    changed_concurrently, invalid_field, missing_field, not_found, storage_failure,
};
use sid_infra::grpc_error::{ErrorReason, IntoStatus};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::flow_action_service_server::FlowActionService;
use sid_proto::sid::v1::flow_config_service_server::FlowConfigService;
use sid_proto::sid::v1::{self as pb};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::instrument;

/// The status a flow refusal answers with.
fn refusal(e: FlowError) -> Status {
    match e {
        FlowError::Caller(e) => e.into_status(),
        FlowError::Store(e) => storage_failure(e),
        FlowError::MissingField(field) => missing_field(field),
        FlowError::InvalidField { field, reason } => invalid_field(field, reason),
        FlowError::ConfigNotFound(name) => {
            not_found(ErrorReason::FlowConfigNotFound, "FlowConfig", name)
        }
        FlowError::ActionNotFound(id) => not_found(
            ErrorReason::FlowActionNotFound,
            "FlowAction",
            id.to_string(),
        ),
        FlowError::ChangedConcurrently => changed_concurrently(),
    }
}

/// The authenticated caller and the flows it manages, shared by both
/// services.
struct Host {
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    flows: Flows,
}

impl Host {
    fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self {
            jwt,
            revocation,
            flows: Flows::new(storage),
        }
    }

    async fn caller<T>(&self, req: &Request<T>) -> Result<Caller, Status> {
        authenticate(req, self.jwt.verifier(), &self.revocation).await
    }
}

pub struct FlowConfigServiceImpl(Host);

impl FlowConfigServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self(Host::new(storage, jwt, revocation))
    }
}

pub struct FlowActionServiceImpl(Host);

impl FlowActionServiceImpl {
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
    ) -> Self {
        Self(Host::new(storage, jwt, revocation))
    }
}

#[tonic::async_trait]
impl FlowConfigService for FlowConfigServiceImpl {
    #[instrument(skip(self, req))]
    async fn get_flow_config(
        &self,
        req: Request<pb::GetFlowConfigRequest>,
    ) -> Result<Response<pb::FlowConfig>, Status> {
        let caller = self.0.caller(&req).await?;
        self.0
            .flows
            .config(&caller, req.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip(self, req))]
    async fn save_flow_config(
        &self,
        req: Request<pb::SaveFlowConfigRequest>,
    ) -> Result<Response<pb::FlowConfig>, Status> {
        let caller = self.0.caller(&req).await?;
        self.0
            .flows
            .save_config(&caller, req.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip(self, req))]
    async fn list_flow_configs(
        &self,
        req: Request<pb::ListFlowConfigsRequest>,
    ) -> Result<Response<pb::ListFlowConfigsResponse>, Status> {
        let caller = self.0.caller(&req).await?;
        self.0
            .flows
            .list_configs(&caller, req.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }
}

#[tonic::async_trait]
impl FlowActionService for FlowActionServiceImpl {
    #[instrument(skip(self, req))]
    async fn create_flow_action(
        &self,
        req: Request<pb::CreateFlowActionRequest>,
    ) -> Result<Response<pb::FlowAction>, Status> {
        let caller = self.0.caller(&req).await?;
        self.0
            .flows
            .create_action(&caller, req.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip(self, req))]
    async fn get_flow_action(
        &self,
        req: Request<pb::GetFlowActionRequest>,
    ) -> Result<Response<pb::FlowAction>, Status> {
        let caller = self.0.caller(&req).await?;
        self.0
            .flows
            .action(&caller, req.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip(self, req))]
    async fn list_flow_actions(
        &self,
        req: Request<pb::ListFlowActionsRequest>,
    ) -> Result<Response<pb::ListFlowActionsResponse>, Status> {
        let caller = self.0.caller(&req).await?;
        self.0
            .flows
            .list_actions(&caller, req.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip(self, req))]
    async fn update_flow_action(
        &self,
        req: Request<pb::UpdateFlowActionRequest>,
    ) -> Result<Response<pb::FlowAction>, Status> {
        let caller = self.0.caller(&req).await?;
        self.0
            .flows
            .update_action(&caller, req.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    #[instrument(skip(self, req))]
    async fn delete_flow_action(
        &self,
        req: Request<pb::DeleteFlowActionRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.0.caller(&req).await?;
        self.0
            .flows
            .delete_action(&caller, req.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }
}

#[cfg(test)]
mod tests;
