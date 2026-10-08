// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC ProvisioningService: the organization's provisioning connectors and
//! the credentials of its inbound ones. Grants are role assignments on the
//! SCIM directory resource, made through the authorization service; nothing
//! here grants a connector anything.

use std::sync::Arc;

use chrono::Utc;
use prost::Message;
use secrecy::ExposeSecret;
use sid_authn::bearer_secret;
use sid_authn::caller::{Caller, authenticate};
use sid_authn::jwt::JwtService;
use sid_authn::operation::{KeyedCommand, required_key};
use sid_authn::revocation_cache::RevocationCache;
use sid_core::Error as SidError;
use sid_core::grpc_error::refuse::{
    changed_concurrently, invalid_field, not_found, storage_failure,
};
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::machine_user::CredentialStatus;
use sid_core::models::provisioning_connector::rotation_grace;
use sid_core::models::{
    AuditEntry, ConnectorCredentialKind, ConnectorState, MutationContext, OidcIssuer, OrgId,
    ProtectedResource, ProvisioningConnector, ProvisioningConnectorId, ProvisioningCredential,
    ProvisioningCredentialId, ProvisioningDirection,
};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::admin::{self as pb, provisioning_service_server::ProvisioningService};
use sid_proto::sid::v1::ids;
use tonic::{Request, Response, Status};

use super::convert::to_timestamp;

const CREATE_INBOUND_CONNECTOR: &str = "ProvisioningService/CreateInboundConnector";
const CREATE_CONNECTOR_CREDENTIAL: &str = "ProvisioningService/CreateConnectorCredential";
const ROTATE_CONNECTOR_CREDENTIAL: &str = "ProvisioningService/RotateConnectorCredential";

/// The organization's provisioning connectors, managed by its
/// administrators.
pub struct ProvisioningServiceImpl {
    storage: Arc<dyn StorageBackend>,
    jwt: Arc<JwtService>,
    revocation: Arc<RevocationCache>,
    org: OrgId,
    /// The issuer whose tokens the SCIM resource accepts.
    issuer: OidcIssuer,
    /// The SCIM directory resource inbound connectors hold their roles on.
    directory: ProtectedResource,
    /// The SCIM base URL this installation serves.
    scim_base_url: String,
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
            storage,
            jwt,
            revocation,
            org: issuer.recipient_org,
            issuer,
            directory,
            scim_base_url,
        }
    }

    /// Authenticate the caller and require the administrator role: a
    /// connector writes the organization's directory.
    #[allow(clippy::result_large_err)]
    async fn admin<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        let caller = authenticate(request, self.jwt.verifier(), &self.revocation).await?;
        caller.require_admin()?;
        Ok(caller)
    }

    /// The connector `id` of this organization; another organization's is
    /// not found, as an unknown one.
    async fn connector(
        &self,
        id: ProvisioningConnectorId,
    ) -> Result<ProvisioningConnector, Status> {
        self.storage
            .get_provisioning_connector(id)
            .await
            .map_err(storage_failure)?
            .filter(|c| c.org_id == self.org)
            .ok_or_else(|| connector_not_found(id))
    }

    /// The connector `id`, which must be inbound: only an inbound connector
    /// has credentials SID issues.
    async fn inbound(&self, id: ProvisioningConnectorId) -> Result<ProvisioningConnector, Status> {
        let connector = self.connector(id).await?;
        if connector.direction != ProvisioningDirection::Inbound {
            return Err(ApiError::new(
                ErrorReason::InvalidState,
                "an outbound connector presents the credentials its target issues",
            )
            .with_precondition("CONNECTOR_DIRECTION", id.to_string(), "inbound")
            .into());
        }
        Ok(connector)
    }
}

fn connector_not_found(id: ProvisioningConnectorId) -> Status {
    not_found(
        ErrorReason::ProvisioningConnectorNotFound,
        "ProvisioningConnector",
        id.to_string(),
    )
}

fn credential_not_found(id: ProvisioningCredentialId) -> Status {
    not_found(
        ErrorReason::CredentialNotFound,
        "ProvisioningCredential",
        id.to_string(),
    )
}

/// INVALID_STATE: a connector in `state` does not allow `change`.
fn connector_state(id: ProvisioningConnectorId, state: ConnectorState, change: &str) -> Status {
    ApiError::new(
        ErrorReason::InvalidState,
        format!("a {} connector cannot be {change}", state.as_str()),
    )
    .with_precondition("CONNECTOR_STATE", id.to_string(), state.as_str())
    .into()
}

#[allow(clippy::result_large_err)]
fn connector_id(
    field: Option<&ids::ProvisioningConnectorId>,
) -> Result<ProvisioningConnectorId, Status> {
    sid_ids_proto::required(field)
        .map_err(|_| invalid_field("connector_id", "not a provisioning connector identifier"))
}

#[allow(clippy::result_large_err)]
fn credential_id(
    field: Option<&ids::ProvisioningCredentialId>,
) -> Result<ProvisioningCredentialId, Status> {
    sid_ids_proto::required(field)
        .map_err(|_| invalid_field("credential_id", "not a provisioning credential identifier"))
}

/// A label: non-empty after trimming, at most 200 characters.
#[allow(clippy::result_large_err)]
fn display_name(value: &str) -> Result<String, Status> {
    let name = value.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(invalid_field("display_name", "1 to 200 characters"));
    }
    Ok(name.to_owned())
}

fn direction_to_proto(d: ProvisioningDirection) -> pb::ProvisioningDirection {
    match d {
        ProvisioningDirection::Inbound => pb::ProvisioningDirection::Inbound,
        ProvisioningDirection::Outbound => pb::ProvisioningDirection::Outbound,
    }
}

fn state_to_proto(s: ConnectorState) -> pb::ProvisioningConnectorState {
    match s {
        ConnectorState::Active => pb::ProvisioningConnectorState::Active,
        ConnectorState::Disabled => pb::ProvisioningConnectorState::Disabled,
        ConnectorState::Retired => pb::ProvisioningConnectorState::Retired,
    }
}

#[allow(clippy::result_large_err)]
fn state_from_proto(value: i32) -> Result<ConnectorState, Status> {
    match pb::ProvisioningConnectorState::try_from(value) {
        Ok(pb::ProvisioningConnectorState::Active) => Ok(ConnectorState::Active),
        Ok(pb::ProvisioningConnectorState::Disabled) => Ok(ConnectorState::Disabled),
        Ok(pb::ProvisioningConnectorState::Retired) => Ok(ConnectorState::Retired),
        _ => Err(invalid_field("state", "active, disabled or retired")),
    }
}

fn credential_status_to_proto(s: CredentialStatus) -> pb::ConnectorCredentialStatus {
    match s {
        CredentialStatus::Active => pb::ConnectorCredentialStatus::Active,
        CredentialStatus::GracePeriod => pb::ConnectorCredentialStatus::GracePeriod,
        CredentialStatus::Expired => pb::ConnectorCredentialStatus::Expired,
        CredentialStatus::Revoked => pb::ConnectorCredentialStatus::Revoked,
    }
}

fn connector_to_proto(c: &ProvisioningConnector) -> pb::ProvisioningConnector {
    pb::ProvisioningConnector {
        id: Some(c.id.into()),
        direction: direction_to_proto(c.direction).into(),
        display_name: c.display_name.clone(),
        state: state_to_proto(c.state).into(),
        revision: c.revision,
        created_at: Some(to_timestamp(c.created_at)),
        updated_at: Some(to_timestamp(c.updated_at)),
    }
}

fn kind_to_proto(k: ConnectorCredentialKind) -> pb::ConnectorCredentialKind {
    match k {
        ConnectorCredentialKind::ScimBearer => pb::ConnectorCredentialKind::ScimBearer,
        ConnectorCredentialKind::ClientSecret => pb::ConnectorCredentialKind::ClientSecret,
    }
}

#[allow(clippy::result_large_err)]
fn kind_from_proto(value: i32) -> Result<ConnectorCredentialKind, Status> {
    match pb::ConnectorCredentialKind::try_from(value) {
        Ok(pb::ConnectorCredentialKind::ScimBearer) => Ok(ConnectorCredentialKind::ScimBearer),
        Ok(pb::ConnectorCredentialKind::ClientSecret) => Ok(ConnectorCredentialKind::ClientSecret),
        _ => Err(invalid_field("kind", "scim_bearer or client_secret")),
    }
}

fn credential_to_proto(c: &ProvisioningCredential) -> pb::ConnectorCredential {
    pb::ConnectorCredential {
        id: Some(c.id.into()),
        kind: kind_to_proto(c.kind).into(),
        status: credential_status_to_proto(c.status).into(),
        expires_at: c.expires_at.map(to_timestamp),
        created_at: Some(to_timestamp(c.created_at)),
    }
}

/// An expiry that is a valid time in the future, never replaced by another.
#[allow(clippy::result_large_err)]
fn future_expiry(
    ts: Option<prost_types::Timestamp>,
) -> Result<Option<chrono::DateTime<Utc>>, Status> {
    ts.map(|ts| {
        u32::try_from(ts.nanos)
            .ok()
            .and_then(|nanos| chrono::DateTime::from_timestamp(ts.seconds, nanos))
            .filter(|at| *at > Utc::now())
            .ok_or_else(|| invalid_field("expires_at", "not a time in the future"))
    })
    .transpose()
}

/// The recorded result of a keyed issue: the credential without its secret,
/// which SID never keeps.
#[allow(clippy::result_large_err)]
fn replayed_issue(result: &[u8]) -> Result<pb::IssuedConnectorCredential, Status> {
    pb::IssuedConnectorCredential::decode(result).map_err(|e| {
        tracing::warn!("recorded credential issue unreadable: {e}");
        Status::from(ApiError::internal())
    })
}

#[allow(clippy::result_large_err)]
fn replayed_connector(result: &[u8]) -> Result<pb::ProvisioningConnector, Status> {
    pb::ProvisioningConnector::decode(result).map_err(|e| {
        tracing::warn!("recorded connector create unreadable: {e}");
        Status::from(ApiError::internal())
    })
}

/// A newly issued credential of `connector` of `kind`: its secret, and the
/// response recorded for retries (the same, without the secret).
fn issue(
    connector: ProvisioningConnectorId,
    kind: ConnectorCredentialKind,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> (
    ProvisioningCredential,
    String,
    pb::IssuedConnectorCredential,
) {
    let issued = bearer_secret::issue(kind.secret_prefix());
    let mut credential = ProvisioningCredential::new(connector, kind, issued.verifier);
    credential.expires_at = expires_at;
    let recorded = pb::IssuedConnectorCredential {
        credential: Some(credential_to_proto(&credential)),
        secret: String::new(),
    };
    (credential, issued.secret.expose_secret().clone(), recorded)
}

fn quota_reached(connector: ProvisioningConnectorId) -> Status {
    ApiError::new(
        ErrorReason::QuotaExceeded,
        "the connector already holds its most usable credentials",
    )
    .with_quota_violation(
        format!("provisioning_credentials/{connector}"),
        format!(
            "at most {} usable credentials per connector",
            sid_core::models::provisioning_connector::MAX_USABLE_CONNECTOR_CREDENTIALS
        ),
    )
    .into()
}

#[tonic::async_trait]
impl ProvisioningService for ProvisioningServiceImpl {
    async fn list_provisioning_connectors(
        &self,
        request: Request<pb::ListProvisioningConnectorsRequest>,
    ) -> Result<Response<pb::ListProvisioningConnectorsResponse>, Status> {
        self.admin(&request).await?;
        let connectors = self
            .storage
            .list_provisioning_connectors(self.org)
            .await
            .map_err(storage_failure)?;
        Ok(Response::new(pb::ListProvisioningConnectorsResponse {
            connectors: connectors.iter().map(connector_to_proto).collect(),
        }))
    }

    async fn create_inbound_connector(
        &self,
        request: Request<pb::CreateInboundConnectorRequest>,
    ) -> Result<Response<pb::ProvisioningConnector>, Status> {
        let caller = self.admin(&request).await?;
        let key = required_key(request.metadata())?;
        let req = request.into_inner();
        let name = display_name(&req.display_name)?;

        // A retry of a completed create returns the connector it created.
        let command = KeyedCommand::new(
            format!("profile:{}", caller.profile_id),
            key,
            CREATE_INBOUND_CONNECTOR,
            req.encode_to_vec(),
        );
        if let Some(result) = command.completed(&*self.storage).await? {
            return Ok(Response::new(replayed_connector(&result)?));
        }

        let connector = ProvisioningConnector::new(self.org, ProvisioningDirection::Inbound, name);
        let response = connector_to_proto(&connector);
        let ctx: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "provisioning_connector.create",
            connector.id.to_string(),
        )
        .into();
        match self
            .storage
            .create_provisioning_connector(
                &connector,
                ctx.with_operation(command.completion(response.encode_to_vec())),
            )
            .await
        {
            Ok(()) => Ok(Response::new(response)),
            // A concurrent attempt of this command committed first.
            Err(SidError::OperationCompleted(_)) => {
                let result = command.committed_elsewhere(&*self.storage).await?;
                Ok(Response::new(replayed_connector(&result)?))
            }
            Err(e) => Err(storage_failure(e)),
        }
    }

    async fn get_provisioning_connector(
        &self,
        request: Request<pb::GetProvisioningConnectorRequest>,
    ) -> Result<Response<pb::ProvisioningConnector>, Status> {
        self.admin(&request).await?;
        let id = connector_id(request.get_ref().connector_id.as_ref())?;
        Ok(Response::new(connector_to_proto(
            &self.connector(id).await?,
        )))
    }

    async fn rename_provisioning_connector(
        &self,
        request: Request<pb::RenameProvisioningConnectorRequest>,
    ) -> Result<Response<pb::ProvisioningConnector>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let id = connector_id(req.connector_id.as_ref())?;
        let name = display_name(&req.display_name)?;
        let current = self.connector(id).await?;
        if current.state == ConnectorState::Retired {
            return Err(connector_state(id, current.state, "renamed"));
        }
        let renamed = self
            .storage
            .rename_provisioning_connector(
                id,
                req.revision,
                &name,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "provisioning_connector.rename",
                    id.to_string(),
                )
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        let after = self.connector(id).await?;
        if !renamed {
            return Err(if after.state == ConnectorState::Retired {
                connector_state(id, after.state, "renamed")
            } else {
                changed_concurrently()
            });
        }
        Ok(Response::new(connector_to_proto(&after)))
    }

    async fn change_provisioning_connector_state(
        &self,
        request: Request<pb::ChangeProvisioningConnectorStateRequest>,
    ) -> Result<Response<pb::ProvisioningConnector>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let id = connector_id(req.connector_id.as_ref())?;
        let target = state_from_proto(req.state)?;
        let current = self.connector(id).await?;
        if current.state == target {
            return Ok(Response::new(connector_to_proto(&current)));
        }
        if !current.state.may_become(target) {
            return Err(connector_state(
                id,
                current.state,
                &format!("made {}", target.as_str()),
            ));
        }
        let moved = self
            .storage
            .transition_provisioning_connector(
                id,
                current.state,
                target,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "provisioning_connector.state",
                    id.to_string(),
                )
                .with_metadata(serde_json::json!({
                    "from": current.state.as_str(),
                    "to": target.as_str(),
                }))
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        let after = self.connector(id).await?;
        if !moved && after.state != target {
            return Err(changed_concurrently());
        }
        Ok(Response::new(connector_to_proto(&after)))
    }

    async fn get_scim_inbound_config(
        &self,
        request: Request<pb::GetScimInboundConfigRequest>,
    ) -> Result<Response<pb::ScimInboundConfig>, Status> {
        self.admin(&request).await?;
        let id = connector_id(request.get_ref().connector_id.as_ref())?;
        let connector = self.inbound(id).await?;
        Ok(Response::new(pb::ScimInboundConfig {
            connector: Some(connector_to_proto(&connector)),
            base_url: self.scim_base_url.clone(),
            resource_indicator: self.directory.indicator.as_str().to_owned(),
            authentication_methods: vec![
                pb::ScimAuthenticationMethod::StaticBearer.into(),
                pb::ScimAuthenticationMethod::OauthClientCredentials.into(),
            ],
            client_id: connector.client_id.clone(),
            token_endpoint: sid_authn::issuer::token_endpoint(&self.issuer.canonical_url),
            issuer: self.issuer.canonical_url.clone(),
        }))
    }

    async fn list_connector_credentials(
        &self,
        request: Request<pb::ListConnectorCredentialsRequest>,
    ) -> Result<Response<pb::ListConnectorCredentialsResponse>, Status> {
        self.admin(&request).await?;
        let id = connector_id(request.get_ref().connector_id.as_ref())?;
        self.connector(id).await?;
        let credentials = self
            .storage
            .list_provisioning_credentials(id)
            .await
            .map_err(storage_failure)?;
        Ok(Response::new(pb::ListConnectorCredentialsResponse {
            credentials: credentials.iter().map(credential_to_proto).collect(),
        }))
    }

    async fn create_connector_credential(
        &self,
        request: Request<pb::CreateConnectorCredentialRequest>,
    ) -> Result<Response<pb::IssuedConnectorCredential>, Status> {
        let caller = self.admin(&request).await?;
        let key = required_key(request.metadata())?;
        let req = request.into_inner();
        let id = connector_id(req.connector_id.as_ref())?;
        let expires_at = future_expiry(req.expires_at)?;
        let kind = kind_from_proto(req.kind)?;

        let command = KeyedCommand::new(
            format!("profile:{}", caller.profile_id),
            key,
            CREATE_CONNECTOR_CREDENTIAL,
            req.encode_to_vec(),
        );
        if let Some(result) = command.completed(&*self.storage).await? {
            return Ok(Response::new(replayed_issue(&result)?));
        }
        let connector = self.inbound(id).await?;
        if connector.state != ConnectorState::Active {
            return Err(connector_state(id, connector.state, "given a credential"));
        }

        let (credential, secret, recorded) = issue(id, kind, expires_at);
        let ctx: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "provisioning_credential.create",
            credential.id.to_string(),
        )
        .with_metadata(serde_json::json!({ "connector_id": id.to_string() }))
        .into();
        match self
            .storage
            .add_provisioning_credential(
                &credential,
                ctx.with_operation(command.completion(recorded.encode_to_vec())),
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                let now = self.connector(id).await?;
                return Err(connector_state(id, now.state, "given a credential"));
            }
            Err(SidError::ResourceExhausted(_)) => return Err(quota_reached(id)),
            Err(SidError::OperationCompleted(_)) => {
                let result = command.committed_elsewhere(&*self.storage).await?;
                return Ok(Response::new(replayed_issue(&result)?));
            }
            Err(e) => return Err(storage_failure(e)),
        }
        Ok(Response::new(pb::IssuedConnectorCredential {
            credential: recorded.credential,
            secret,
        }))
    }

    async fn rotate_connector_credential(
        &self,
        request: Request<pb::RotateConnectorCredentialRequest>,
    ) -> Result<Response<pb::IssuedConnectorCredential>, Status> {
        let caller = self.admin(&request).await?;
        let key = required_key(request.metadata())?;
        let req = request.into_inner();
        let id = connector_id(req.connector_id.as_ref())?;
        let old = credential_id(req.credential_id.as_ref())?;

        let command = KeyedCommand::new(
            format!("profile:{}", caller.profile_id),
            key,
            ROTATE_CONNECTOR_CREDENTIAL,
            req.encode_to_vec(),
        );
        if let Some(result) = command.completed(&*self.storage).await? {
            return Ok(Response::new(replayed_issue(&result)?));
        }
        let connector = self.inbound(id).await?;
        if connector.state != ConnectorState::Active {
            return Err(connector_state(id, connector.state, "given a credential"));
        }

        // The replacement is of the kind it replaces.
        let replaced = self
            .storage
            .list_provisioning_credentials(id)
            .await
            .map_err(storage_failure)?
            .into_iter()
            .find(|c| c.id == old)
            .ok_or_else(|| credential_not_found(old))?;
        let (credential, secret, recorded) = issue(id, replaced.kind, None);
        let ctx: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "provisioning_credential.rotate",
            old.to_string(),
        )
        .with_metadata(serde_json::json!({
            "connector_id": id.to_string(),
            "replacement": credential.id.to_string(),
        }))
        .into();
        match self
            .storage
            .rotate_provisioning_credential(
                id,
                old,
                &credential,
                Utc::now() + rotation_grace(),
                ctx.with_operation(command.completion(recorded.encode_to_vec())),
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                let held = self
                    .storage
                    .list_provisioning_credentials(id)
                    .await
                    .map_err(storage_failure)?;
                return Err(match held.iter().find(|c| c.id == old) {
                    None => credential_not_found(old),
                    Some(c) => ApiError::new(
                        ErrorReason::InvalidState,
                        "only an active credential is rotated",
                    )
                    .with_precondition("CREDENTIAL_STATUS", old.to_string(), c.status.as_str())
                    .into(),
                });
            }
            Err(SidError::OperationCompleted(_)) => {
                let result = command.committed_elsewhere(&*self.storage).await?;
                return Ok(Response::new(replayed_issue(&result)?));
            }
            Err(e) => return Err(storage_failure(e)),
        }
        Ok(Response::new(pb::IssuedConnectorCredential {
            credential: recorded.credential,
            secret,
        }))
    }

    async fn revoke_connector_credential(
        &self,
        request: Request<pb::RevokeConnectorCredentialRequest>,
    ) -> Result<Response<()>, Status> {
        let caller = self.admin(&request).await?;
        let req = request.into_inner();
        let id = connector_id(req.connector_id.as_ref())?;
        let credential = credential_id(req.credential_id.as_ref())?;
        self.connector(id).await?;
        let revoked = self
            .storage
            .revoke_provisioning_credential(
                id,
                credential,
                AuditEntry::admin(
                    caller.profile_id.to_string(),
                    "provisioning_credential.revoke",
                    credential.to_string(),
                )
                .with_metadata(serde_json::json!({ "connector_id": id.to_string() }))
                .into(),
            )
            .await
            .map_err(storage_failure)?;
        if !revoked {
            // Nothing usable to revoke: an unknown credential is not found;
            // one already unusable needs nothing more.
            let held = self
                .storage
                .list_provisioning_credentials(id)
                .await
                .map_err(storage_failure)?;
            if !held.iter().any(|c| c.id == credential) {
                return Err(credential_not_found(credential));
            }
        }
        Ok(Response::new(()))
    }
}

#[cfg(test)]
mod tests;
