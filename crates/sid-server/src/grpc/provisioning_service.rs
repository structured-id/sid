// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC ProvisioningService: authenticates the caller and answers through
//! [`sid::provisioning`], the organization's provisioning connectors and the
//! credentials of its inbound ones.

use std::sync::Arc;

use sid::provisioning::{Provisioning, ProvisioningError};
use sid_authn::caller::Caller;
use sid_authn::jwt::JwtService;
use sid_authn::revocation_cache::RevocationCache;
use sid_core::models::provisioning_connector::MAX_USABLE_CONNECTOR_CREDENTIALS;
use sid_core::models::{OidcIssuer, ProtectedResource};
use sid_infra::authn::caller::authenticate;
use sid_infra::authn::operation::context;
use sid_infra::grpc_error::refuse::{
    changed_concurrently, invalid_field, not_found, storage_failure,
};
use sid_infra::grpc_error::{ApiError, ErrorReason, IntoStatus};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::admin::{self as pb, provisioning_service_server::ProvisioningService};
use tonic::{Request, Response, Status};

/// The status a provisioning refusal answers with.
fn refusal(e: ProvisioningError) -> Status {
    match e {
        ProvisioningError::Caller(e) => e.into_status(),
        ProvisioningError::Operation(e) => e.into_status(),
        ProvisioningError::Store(e) => storage_failure(e),
        ProvisioningError::Internal => ApiError::internal().into(),
        ProvisioningError::InvalidField { field, reason } => invalid_field(field, reason),
        ProvisioningError::ConnectorNotFound(id) => not_found(
            ErrorReason::ProvisioningConnectorNotFound,
            "ProvisioningConnector",
            id.to_string(),
        ),
        ProvisioningError::CredentialNotFound(id) => not_found(
            ErrorReason::CredentialNotFound,
            "ProvisioningCredential",
            id.to_string(),
        ),
        ProvisioningError::Outbound(id) => ApiError::new(
            ErrorReason::InvalidState,
            "an outbound connector presents the credentials its target issues",
        )
        .with_precondition("CONNECTOR_DIRECTION", id.to_string(), "inbound")
        .into(),
        ProvisioningError::ConnectorState { id, state, change } => ApiError::new(
            ErrorReason::InvalidState,
            format!("a {} connector cannot be {change}", state.as_str()),
        )
        .with_precondition("CONNECTOR_STATE", id.to_string(), state.as_str())
        .into(),
        ProvisioningError::CredentialStatus { id, status } => ApiError::new(
            ErrorReason::InvalidState,
            "only an active credential is rotated",
        )
        .with_precondition("CREDENTIAL_STATUS", id.to_string(), status)
        .into(),
        ProvisioningError::QuotaReached(id) => ApiError::new(
            ErrorReason::QuotaExceeded,
            "the connector already holds its most usable credentials",
        )
        .with_quota_violation(
            format!("provisioning_credentials/{id}"),
            format!("at most {MAX_USABLE_CONNECTOR_CREDENTIALS} usable credentials per connector"),
        )
        .into(),
        ProvisioningError::ChangedConcurrently => changed_concurrently(),
    }
}

/// The organization's provisioning connectors, managed by its
/// administrators.
pub struct ProvisioningServiceImpl {
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    provisioning: Provisioning,
}

impl ProvisioningServiceImpl {
    /// The connectors of `issuer`'s organization, whose SCIM directory is
    /// `directory`, served at `scim_base_url`.
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        jwt: Arc<JwtService>,
        revocation: Arc<RevocationCache>,
        issuer: OidcIssuer,
        directory: ProtectedResource,
        scim_base_url: String,
    ) -> Self {
        Self {
            jwt,
            revocation,
            provisioning: Provisioning::new(storage, issuer, directory, scim_base_url),
        }
    }

    async fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        authenticate(request, self.jwt.verifier(), &self.revocation).await
    }

    /// The authenticated administrator: checked before the operation
    /// context, so a refused caller learns nothing more about it.
    async fn admin<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let caller = self.caller(request).await?;
        caller.require_admin().map_err(|e| e.into_status())?;
        Ok(caller)
    }
}

#[tonic::async_trait]
impl ProvisioningService for ProvisioningServiceImpl {
    async fn list_provisioning_connectors(
        &self,
        request: Request<pb::ListProvisioningConnectorsRequest>,
    ) -> Result<Response<pb::ListProvisioningConnectorsResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.provisioning
            .list_connectors(&caller)
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn create_inbound_connector(
        &self,
        request: Request<pb::CreateInboundConnectorRequest>,
    ) -> Result<Response<pb::ProvisioningConnector>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.provisioning
            .create_inbound_connector(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn get_provisioning_connector(
        &self,
        request: Request<pb::GetProvisioningConnectorRequest>,
    ) -> Result<Response<pb::ProvisioningConnector>, Status> {
        let caller = self.caller(&request).await?;
        self.provisioning
            .get_connector(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn rename_provisioning_connector(
        &self,
        request: Request<pb::RenameProvisioningConnectorRequest>,
    ) -> Result<Response<pb::ProvisioningConnector>, Status> {
        let caller = self.caller(&request).await?;
        self.provisioning
            .rename_connector(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn change_provisioning_connector_state(
        &self,
        request: Request<pb::ChangeProvisioningConnectorStateRequest>,
    ) -> Result<Response<pb::ProvisioningConnector>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.provisioning
            .change_connector_state(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn get_scim_inbound_config(
        &self,
        request: Request<pb::GetScimInboundConfigRequest>,
    ) -> Result<Response<pb::ScimInboundConfig>, Status> {
        let caller = self.caller(&request).await?;
        self.provisioning
            .scim_inbound_config(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn list_connector_credentials(
        &self,
        request: Request<pb::ListConnectorCredentialsRequest>,
    ) -> Result<Response<pb::ListConnectorCredentialsResponse>, Status> {
        let caller = self.caller(&request).await?;
        self.provisioning
            .list_credentials(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn create_connector_credential(
        &self,
        request: Request<pb::CreateConnectorCredentialRequest>,
    ) -> Result<Response<pb::IssuedConnectorCredential>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.provisioning
            .create_credential(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn rotate_connector_credential(
        &self,
        request: Request<pb::RotateConnectorCredentialRequest>,
    ) -> Result<Response<pb::IssuedConnectorCredential>, Status> {
        let caller = self.admin(&request).await?;
        let operation = context(&request)?;
        self.provisioning
            .rotate_credential(&caller, operation, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }

    async fn revoke_connector_credential(
        &self,
        request: Request<pb::RevokeConnectorCredentialRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.caller(&request).await?;
        self.provisioning
            .revoke_credential(&caller, request.into_inner())
            .await
            .map(Response::new)
            .map_err(refusal)
    }
}

#[cfg(test)]
mod tests;
