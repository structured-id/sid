// SPDX-License-Identifier: AGPL-3.0-only
//! The organization's provisioning connectors and the credentials of its
//! inbound ones, managed by its administrators. Grants are role assignments
//! on the SCIM directory resource, made through authorization management;
//! nothing here grants a connector anything. A keyed operation commits its
//! change, audit and completion together and answers a retry with what the
//! first attempt recorded; an issued secret is never recorded.

use std::sync::Arc;

use chrono::Utc;
use prost::Message;
use secrecy::ExposeSecret;
use sid_authn::bearer_secret;
use sid_authn::caller::{Caller, CallerError};
use sid_authn::operation::{KeyedCommand, OperationError};
use sid_core::Error as SidError;
use sid_core::models::machine_user::CredentialStatus;
use sid_core::models::provisioning_connector::rotation_grace;
use sid_core::models::{
    AuditEntry, ConnectorCredentialKind, ConnectorState, MutationContext, OidcIssuer,
    OperationContext, OrgId, ProtectedResource, ProvisioningConnector, ProvisioningConnectorId,
    ProvisioningCredential, ProvisioningCredentialId, ProvisioningDirection,
};
use sid_plugin::StorageBackend;
use sid_proto::keyed::admin::provisioning_service as keyed;
use sid_proto::sid::v1::admin as pb;
use sid_proto::sid::v1::ids;

use crate::wire::to_timestamp;

/// Why a provisioning operation was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum ProvisioningError {
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
    /// A failure of this installation (an unreadable recorded result); its
    /// cause is in the log, not the refusal.
    #[error("internal error")]
    Internal,
    /// A field holds a value the operation does not take.
    #[error("{field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    /// No connector with this id in this organization.
    #[error("provisioning connector {0} not found")]
    ConnectorNotFound(ProvisioningConnectorId),
    /// No credential with this id on the connector.
    #[error("provisioning credential {0} not found")]
    CredentialNotFound(ProvisioningCredentialId),
    /// An outbound connector presents the credentials its target issues.
    #[error("connector {0} is outbound")]
    Outbound(ProvisioningConnectorId),
    /// The connector's state does not allow the change.
    #[error("a {} connector cannot be {change}", .state.as_str())]
    ConnectorState {
        id: ProvisioningConnectorId,
        state: ConnectorState,
        change: String,
    },
    /// Only an active credential is rotated.
    #[error("credential {id} is {status}")]
    CredentialStatus {
        id: ProvisioningCredentialId,
        status: &'static str,
    },
    /// The connector holds the most usable credentials allowed.
    #[error("connector {0} holds its most usable credentials")]
    QuotaReached(ProvisioningConnectorId),
    /// The record changed since it was read.
    #[error("changed concurrently")]
    ChangedConcurrently,
}

fn invalid(field: &'static str, reason: &'static str) -> ProvisioningError {
    ProvisioningError::InvalidField { field, reason }
}

fn connector_state(
    id: ProvisioningConnectorId,
    state: ConnectorState,
    change: impl Into<String>,
) -> ProvisioningError {
    ProvisioningError::ConnectorState {
        id,
        state,
        change: change.into(),
    }
}

/// The provisioning connectors of one organization.
pub struct Provisioning {
    storage: Arc<dyn StorageBackend>,
    org: OrgId,
    /// The issuer whose tokens the SCIM resource accepts.
    issuer: OidcIssuer,
    /// The SCIM directory resource inbound connectors hold their roles on.
    directory: ProtectedResource,
    /// The SCIM base URL this installation serves.
    scim_base_url: String,
}

impl Provisioning {
    /// The connectors of `issuer`'s organization, whose SCIM directory is
    /// `directory`, served at `scim_base_url`.
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        issuer: OidcIssuer,
        directory: ProtectedResource,
        scim_base_url: String,
    ) -> Self {
        Self {
            storage,
            org: issuer.recipient_org,
            issuer,
            directory,
            scim_base_url,
        }
    }

    /// The connector `id` of this organization; another organization's is
    /// not found, as an unknown one.
    async fn connector(
        &self,
        id: ProvisioningConnectorId,
    ) -> Result<ProvisioningConnector, ProvisioningError> {
        self.storage
            .get_provisioning_connector(id)
            .await?
            .filter(|c| c.org_id == self.org)
            .ok_or(ProvisioningError::ConnectorNotFound(id))
    }

    /// The connector `id`, which must be inbound: only an inbound connector
    /// has credentials SID issues.
    async fn inbound(
        &self,
        id: ProvisioningConnectorId,
    ) -> Result<ProvisioningConnector, ProvisioningError> {
        let connector = self.connector(id).await?;
        if connector.direction != ProvisioningDirection::Inbound {
            return Err(ProvisioningError::Outbound(id));
        }
        Ok(connector)
    }

    /// A state change `command` that found `connector` already in its target
    /// state: the connector as it is now is the command's outcome, recorded
    /// so a retry after a later change answers the same and moves nothing.
    /// A concurrent attempt that recorded first answers with its outcome.
    async fn already_in_effect(
        &self,
        command: &KeyedCommand,
        caller: &Caller,
        connector: &ProvisioningConnector,
    ) -> Result<pb::ProvisioningConnector, ProvisioningError> {
        let audit = AuditEntry::admin(
            caller.profile_id.to_string(),
            "provisioning_connector.state",
            connector.id.to_string(),
        )
        .with_metadata(serde_json::json!({
            "from": connector.state.as_str(),
            "to": connector.state.as_str(),
        }));
        command
            .unchanged(&*self.storage, audit, || async {
                Ok::<_, ProvisioningError>(connector_to_proto(connector))
            })
            .await
            .map_err(|e| e.refusal())
    }

    pub async fn list_connectors(
        &self,
        caller: &Caller,
    ) -> Result<pb::ListProvisioningConnectorsResponse, ProvisioningError> {
        caller.require_admin()?;
        let connectors = self.storage.list_provisioning_connectors(self.org).await?;
        Ok(pb::ListProvisioningConnectorsResponse {
            connectors: connectors.iter().map(connector_to_proto).collect(),
        })
    }

    /// Create an inbound connector. A retry of a completed create returns
    /// the connector it created.
    pub async fn create_inbound_connector(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: pb::CreateInboundConnectorRequest,
    ) -> Result<pb::ProvisioningConnector, ProvisioningError> {
        caller.require_admin()?;
        let name = display_name(&req.display_name)?;
        let command = KeyedCommand::of::<keyed::CreateInboundConnector>(
            format!("profile:{}", caller.profile_id),
            operation,
            &req,
        );
        if let Some(result) = command.completed(&*self.storage).await? {
            return replayed_connector(&result);
        }
        let connector = ProvisioningConnector::new(self.org, ProvisioningDirection::Inbound, name);
        let response = connector_to_proto(&connector);
        let ctx: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "provisioning_connector.create",
            connector.id.to_string(),
        )
        .into();
        let answer = match self
            .storage
            .create_provisioning_connector(
                &connector,
                ctx.with_operation(command.completion(response.encode_to_vec())),
            )
            .await
        {
            Ok(()) => Ok(response),
            // A concurrent attempt of this command committed first, or its
            // connector took a value this one needs: its answer is this one's.
            Err(SidError::OperationCompleted(_)) => Err(ProvisioningError::ChangedConcurrently),
            Err(e) => Err(e.into()),
        };
        command
            .settle(&*self.storage, answer)
            .await
            .map_err(|e| e.refusal())
    }

    pub async fn get_connector(
        &self,
        caller: &Caller,
        req: pb::GetProvisioningConnectorRequest,
    ) -> Result<pb::ProvisioningConnector, ProvisioningError> {
        caller.require_admin()?;
        let id = connector_id(req.connector_id.as_ref())?;
        Ok(connector_to_proto(&self.connector(id).await?))
    }

    /// Rename a connector at the revision the caller read; a retired one
    /// keeps its name.
    pub async fn rename_connector(
        &self,
        caller: &Caller,
        req: pb::RenameProvisioningConnectorRequest,
    ) -> Result<pb::ProvisioningConnector, ProvisioningError> {
        caller.require_admin()?;
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
            .await?;
        let after = self.connector(id).await?;
        if !renamed {
            return Err(if after.state == ConnectorState::Retired {
                connector_state(id, after.state, "renamed")
            } else {
                ProvisioningError::ChangedConcurrently
            });
        }
        Ok(connector_to_proto(&after))
    }

    /// Move a connector to another lifecycle state. A retry of a completed
    /// change answers with the connector as that change left it, and never
    /// moves it again after a later change (a suspension retried after a
    /// reactivation).
    pub async fn change_connector_state(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: pb::ChangeProvisioningConnectorStateRequest,
    ) -> Result<pb::ProvisioningConnector, ProvisioningError> {
        caller.require_admin()?;
        let command = KeyedCommand::of::<keyed::ChangeProvisioningConnectorState>(
            format!("profile:{}", caller.profile_id),
            operation,
            &req,
        );
        if let Some(result) = command.completed(&*self.storage).await? {
            return replayed_connector(&result);
        }
        let id = connector_id(req.connector_id.as_ref())?;
        let target = state_from_proto(req.state)?;
        let current = self.connector(id).await?;
        if current.state == target {
            return self.already_in_effect(&command, caller, &current).await;
        }
        if !current.state.may_become(target) {
            return Err(connector_state(
                id,
                current.state,
                format!("made {}", target.as_str()),
            ));
        }
        // The connector as the transition leaves it.
        let mut moved = current.clone();
        moved.state = target;
        moved.revision += 1;
        moved.updated_at = Utc::now();
        let response = connector_to_proto(&moved);
        let ctx: MutationContext = AuditEntry::admin(
            caller.profile_id.to_string(),
            "provisioning_connector.state",
            id.to_string(),
        )
        .with_metadata(serde_json::json!({
            "from": current.state.as_str(),
            "to": target.as_str(),
        }))
        .into();
        match self
            .storage
            .transition_provisioning_connector(
                id,
                current.state,
                target,
                ctx.with_operation(command.completion(response.encode_to_vec())),
            )
            .await
        {
            Ok(true) => Ok(response),
            // Another change came first; the connector is answered as it is
            // when that change already made it the target.
            Ok(false) => {
                let after = self.connector(id).await?;
                if after.state != target {
                    return Err(ProvisioningError::ChangedConcurrently);
                }
                self.already_in_effect(&command, caller, &after).await
            }
            // A concurrent attempt of this command committed first.
            Err(SidError::OperationCompleted(_)) => {
                replayed_connector(&command.committed_elsewhere(&*self.storage).await?)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// What an inbound connector's directory client is configured with.
    pub async fn scim_inbound_config(
        &self,
        caller: &Caller,
        req: pb::GetScimInboundConfigRequest,
    ) -> Result<pb::ScimInboundConfig, ProvisioningError> {
        caller.require_admin()?;
        let id = connector_id(req.connector_id.as_ref())?;
        let connector = self.inbound(id).await?;
        Ok(pb::ScimInboundConfig {
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
        })
    }

    pub async fn list_credentials(
        &self,
        caller: &Caller,
        req: pb::ListConnectorCredentialsRequest,
    ) -> Result<pb::ListConnectorCredentialsResponse, ProvisioningError> {
        caller.require_admin()?;
        let id = connector_id(req.connector_id.as_ref())?;
        self.connector(id).await?;
        let credentials = self.storage.list_provisioning_credentials(id).await?;
        Ok(pb::ListConnectorCredentialsResponse {
            credentials: credentials.iter().map(credential_to_proto).collect(),
        })
    }

    /// Issue a credential to an active inbound connector. A retry answers
    /// with the credential the first attempt issued, without its secret.
    pub async fn create_credential(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: pb::CreateConnectorCredentialRequest,
    ) -> Result<pb::IssuedConnectorCredential, ProvisioningError> {
        caller.require_admin()?;
        let id = connector_id(req.connector_id.as_ref())?;
        let expires_at = future_expiry(req.expires_at)?;
        let kind = kind_from_proto(req.kind)?;
        let command = KeyedCommand::of::<keyed::CreateConnectorCredential>(
            format!("profile:{}", caller.profile_id),
            operation,
            &req,
        );
        if let Some(result) = command.completed(&*self.storage).await? {
            return replayed_issue(&result);
        }
        // A refusal a concurrent attempt of this command caused (the slot its
        // credential took) is that attempt's answer.
        let answer: Result<pb::IssuedConnectorCredential, ProvisioningError> = async {
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
                Err(SidError::ResourceExhausted(_)) => {
                    return Err(ProvisioningError::QuotaReached(id));
                }
                Err(SidError::OperationCompleted(_)) => {
                    return Err(ProvisioningError::ChangedConcurrently);
                }
                Err(e) => return Err(e.into()),
            }
            Ok(pb::IssuedConnectorCredential {
                credential: recorded.credential,
                secret,
            })
        }
        .await;
        command
            .settle(&*self.storage, answer)
            .await
            .map_err(|e| e.refusal())
    }

    /// Replace an active credential with a new one of its kind; the old one
    /// stays usable through the rotation grace. A retry answers with the
    /// replacement the first attempt issued, without its secret.
    pub async fn rotate_credential(
        &self,
        caller: &Caller,
        operation: OperationContext,
        req: pb::RotateConnectorCredentialRequest,
    ) -> Result<pb::IssuedConnectorCredential, ProvisioningError> {
        caller.require_admin()?;
        let id = connector_id(req.connector_id.as_ref())?;
        let old = credential_id(req.credential_id.as_ref())?;
        let command = KeyedCommand::of::<keyed::RotateConnectorCredential>(
            format!("profile:{}", caller.profile_id),
            operation,
            &req,
        );
        if let Some(result) = command.completed(&*self.storage).await? {
            return replayed_issue(&result);
        }
        // A refusal a concurrent attempt of this command caused (the
        // credential it rotated is no longer active) is that attempt's answer.
        let answer: Result<pb::IssuedConnectorCredential, ProvisioningError> = async {
            let connector = self.inbound(id).await?;
            if connector.state != ConnectorState::Active {
                return Err(connector_state(id, connector.state, "given a credential"));
            }
            // The replacement is of the kind it replaces.
            let replaced = self
                .storage
                .list_provisioning_credentials(id)
                .await?
                .into_iter()
                .find(|c| c.id == old)
                .ok_or(ProvisioningError::CredentialNotFound(old))?;
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
                    let held = self.storage.list_provisioning_credentials(id).await?;
                    return Err(match held.iter().find(|c| c.id == old) {
                        None => ProvisioningError::CredentialNotFound(old),
                        Some(c) => ProvisioningError::CredentialStatus {
                            id: old,
                            status: c.status.as_str(),
                        },
                    });
                }
                Err(SidError::OperationCompleted(_)) => {
                    return Err(ProvisioningError::ChangedConcurrently);
                }
                Err(e) => return Err(e.into()),
            }
            Ok(pb::IssuedConnectorCredential {
                credential: recorded.credential,
                secret,
            })
        }
        .await;
        command
            .settle(&*self.storage, answer)
            .await
            .map_err(|e| e.refusal())
    }

    /// Revoke a credential. One already unusable needs nothing more; an
    /// unknown one is not found.
    pub async fn revoke_credential(
        &self,
        caller: &Caller,
        req: pb::RevokeConnectorCredentialRequest,
    ) -> Result<(), ProvisioningError> {
        caller.require_admin()?;
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
            .await?;
        if !revoked {
            let held = self.storage.list_provisioning_credentials(id).await?;
            if !held.iter().any(|c| c.id == credential) {
                return Err(ProvisioningError::CredentialNotFound(credential));
            }
        }
        Ok(())
    }
}

fn connector_id(
    field: Option<&ids::ProvisioningConnectorId>,
) -> Result<ProvisioningConnectorId, ProvisioningError> {
    sid_ids_proto::required(field)
        .map_err(|_| invalid("connector_id", "not a provisioning connector identifier"))
}

fn credential_id(
    field: Option<&ids::ProvisioningCredentialId>,
) -> Result<ProvisioningCredentialId, ProvisioningError> {
    sid_ids_proto::required(field)
        .map_err(|_| invalid("credential_id", "not a provisioning credential identifier"))
}

/// A label: non-empty after trimming, at most 200 characters.
fn display_name(value: &str) -> Result<String, ProvisioningError> {
    let name = value.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(invalid("display_name", "1 to 200 characters"));
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

fn state_from_proto(value: i32) -> Result<ConnectorState, ProvisioningError> {
    match pb::ProvisioningConnectorState::try_from(value) {
        Ok(pb::ProvisioningConnectorState::Active) => Ok(ConnectorState::Active),
        Ok(pb::ProvisioningConnectorState::Disabled) => Ok(ConnectorState::Disabled),
        Ok(pb::ProvisioningConnectorState::Retired) => Ok(ConnectorState::Retired),
        _ => Err(invalid("state", "active, disabled or retired")),
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

fn kind_from_proto(value: i32) -> Result<ConnectorCredentialKind, ProvisioningError> {
    match pb::ConnectorCredentialKind::try_from(value) {
        Ok(pb::ConnectorCredentialKind::ScimBearer) => Ok(ConnectorCredentialKind::ScimBearer),
        Ok(pb::ConnectorCredentialKind::ClientSecret) => Ok(ConnectorCredentialKind::ClientSecret),
        _ => Err(invalid("kind", "scim_bearer or client_secret")),
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
fn future_expiry(
    ts: Option<prost_types::Timestamp>,
) -> Result<Option<chrono::DateTime<Utc>>, ProvisioningError> {
    ts.map(|ts| {
        u32::try_from(ts.nanos)
            .ok()
            .and_then(|nanos| chrono::DateTime::from_timestamp(ts.seconds, nanos))
            .filter(|at| *at > Utc::now())
            .ok_or_else(|| invalid("expires_at", "not a time in the future"))
    })
    .transpose()
}

/// The recorded result of a keyed issue: the credential without its secret,
/// which SID never keeps.
fn replayed_issue(result: &[u8]) -> Result<pb::IssuedConnectorCredential, ProvisioningError> {
    pb::IssuedConnectorCredential::decode(result).map_err(|e| {
        tracing::warn!("recorded credential issue unreadable: {e}");
        ProvisioningError::Internal
    })
}

fn replayed_connector(result: &[u8]) -> Result<pb::ProvisioningConnector, ProvisioningError> {
    pb::ProvisioningConnector::decode(result).map_err(|e| {
        tracing::warn!("recorded connector change unreadable: {e}");
        ProvisioningError::Internal
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

#[cfg(test)]
mod tests;
