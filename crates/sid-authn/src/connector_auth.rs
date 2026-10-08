// SPDX-License-Identifier: AGPL-3.0-only
//! Authentication of an inbound SCIM provisioning connector.
//!
//! A connector proves itself in one of two ways, each with its own kind of
//! credential, never accepted for the other:
//!
//! - a dedicated SCIM bearer secret, recognised by its prefix and resolved by
//!   its verifier: an explicit path of the SCIM endpoint, never a fallback
//!   after a JWT failed to verify;
//! - an access token its issuer signed for the SCIM resource after the
//!   connector authenticated at the token endpoint with its client secret
//!   (OAuth client credentials). The token names the connector (`sub`), its
//!   `client_id` and the credential it used (`sid`); every request checks
//!   them again, so a disabled connector or a revoked credential stops its
//!   tokens at once.
//!
//! Every refusal is the same `unauthenticated`, so a caller learns nothing
//! about which check failed.

use chrono::Utc;
use sid_core::grpc_error::refuse::storage_failure;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::provisioning_connector::{
    CONNECTOR_CLIENT_SECRET_PREFIX, SCIM_BEARER_PREFIX,
};
use sid_core::models::{
    ActorFence, ConnectorCredentialKind, OrgId, ProvisioningConnector, ProvisioningCredential,
    ProvisioningCredentialId, ProvisioningDirection,
};
use sid_plugin::StorageBackend;
use tonic::{Request, Status};

use crate::bearer_secret;
use crate::caller::bearer_token;
use crate::jwt::AccessTokenClaims;
use crate::resource_token::ResourceTokenVerifier;

/// An authenticated inbound connector and the credential it presented.
#[derive(Debug, Clone)]
pub struct ConnectorCaller {
    pub connector: ProvisioningConnector,
    /// The credential reference audit records name; never the secret.
    pub credential_id: ProvisioningCredentialId,
    /// The scopes its access token was issued with; `None` for a SCIM
    /// bearer, which is limited by the connector's grants alone.
    pub scopes: Option<Vec<String>>,
}

impl ConnectorCaller {
    /// The authority this caller was authenticated under, for its writes to
    /// commit only while it still holds.
    pub fn fence(&self) -> ActorFence {
        ActorFence::Connector {
            connector: self.connector.id,
            revision: self.connector.revision,
            credential: self.credential_id,
        }
    }

    /// Whether its token allows `action`; a SCIM bearer allows every action
    /// the grants do.
    pub fn may(&self, action: &str) -> bool {
        self.scopes
            .as_ref()
            .is_none_or(|scopes| scopes.iter().any(|s| s == action))
    }
}

fn unauthenticated() -> Status {
    ApiError::new(ErrorReason::TokenInvalid, "authentication required").into()
}

/// Whether `credential` of kind `kind` and `connector` can act now: the
/// credential is the connector's, of that kind and usable, and the connector
/// is an active inbound one.
fn usable(
    kind: ConnectorCredentialKind,
    credential: &ProvisioningCredential,
    connector: &ProvisioningConnector,
) -> bool {
    credential.connector_id == connector.id
        && credential.kind == kind
        && credential.is_usable_at(Utc::now())
        && connector.is_active()
        && connector.direction == ProvisioningDirection::Inbound
}

/// The caller when `credential` of kind `kind` and `connector` may act for
/// `org` now: [`usable`], and the connector is one of `org`.
#[allow(clippy::result_large_err)]
fn admit(
    org: OrgId,
    kind: ConnectorCredentialKind,
    credential: ProvisioningCredential,
    connector: ProvisioningConnector,
    scopes: Option<Vec<String>>,
) -> Result<ConnectorCaller, Status> {
    if !usable(kind, &credential, &connector) || connector.org_id != org {
        return Err(unauthenticated());
    }
    Ok(ConnectorCaller {
        connector,
        credential_id: credential.id,
        scopes,
    })
}

/// Whether an access token stands for an inbound connector, read from the
/// stored records at the moment of asking.
#[derive(Debug)]
pub enum ConnectorTokenState {
    /// Its `client_id` belongs to no connector.
    NotConnector,
    /// It names a connector or a credential that cannot act now: disabled,
    /// retired, outbound, revoked, expired, or not the connector and
    /// credential the token claims.
    Unusable,
    /// The connector and the client credential the token was issued for can
    /// act now.
    Usable(ConnectorCaller),
}

/// The current state of the connector a verified access token was issued to
/// and of the client credential it authenticated with (`sub`, `client_id`,
/// `sid`). A storage failure is an error, never a state.
pub async fn connector_token_state(
    storage: &dyn StorageBackend,
    claims: &AccessTokenClaims,
) -> sid_core::Result<ConnectorTokenState> {
    let Some(client_id) = claims.client_id.as_deref() else {
        return Ok(ConnectorTokenState::NotConnector);
    };
    let Some(connector) = storage
        .get_provisioning_connector_by_client_id(client_id)
        .await?
    else {
        return Ok(ConnectorTokenState::NotConnector);
    };
    if claims.sub != connector.id.to_string() {
        return Ok(ConnectorTokenState::Unusable);
    }
    let Ok(credential_id) = ProvisioningCredentialId::parse(&claims.sid) else {
        return Ok(ConnectorTokenState::Unusable);
    };
    let Some(credential) = storage
        .list_provisioning_credentials(connector.id)
        .await?
        .into_iter()
        .find(|c| c.id == credential_id)
    else {
        return Ok(ConnectorTokenState::Unusable);
    };
    if !usable(
        ConnectorCredentialKind::ClientSecret,
        &credential,
        &connector,
    ) {
        return Ok(ConnectorTokenState::Unusable);
    }
    Ok(ConnectorTokenState::Usable(ConnectorCaller {
        connector,
        credential_id: credential.id,
        scopes: Some(claims.scope.split_whitespace().map(String::from).collect()),
    }))
}

/// The inbound connector of `org` that `request` authenticates, by its SCIM
/// bearer or, when `tokens` verifies the SCIM resource's access tokens, by
/// such a token (RFC 7644 §2 leaves authentication to the service provider).
#[allow(clippy::result_large_err)]
pub async fn authenticate_connector<T>(
    request: &Request<T>,
    storage: &dyn StorageBackend,
    org: OrgId,
    tokens: Option<&ResourceTokenVerifier>,
) -> Result<ConnectorCaller, Status> {
    let presented = bearer_token(request)?;
    if bearer_secret::has_prefix(presented, SCIM_BEARER_PREFIX) {
        let Some((credential, connector)) = storage
            .find_provisioning_credential(&bearer_secret::verifier_of(presented))
            .await
            .map_err(storage_failure)?
        else {
            return Err(unauthenticated());
        };
        if !bearer_secret::matches(presented, &credential.verifier) {
            return Err(unauthenticated());
        }
        return admit(
            org,
            ConnectorCredentialKind::ScimBearer,
            credential,
            connector,
            None,
        );
    }
    let Some(tokens) = tokens else {
        return Err(unauthenticated());
    };
    let claims = match tokens.verify(presented).await {
        Ok(claims) => claims,
        Err(sid_core::Error::AuthenticationFailed(_)) => return Err(unauthenticated()),
        Err(e) => return Err(storage_failure(e)),
    };
    // A sender-constrained token needs its proof, which SCIM does not take
    // (RFC 9449 §7.1); a source ProfileId never rides a connector's token.
    if claims.cnf.is_some() || claims.pid.is_some() {
        return Err(unauthenticated());
    }
    match connector_token_state(storage, &claims)
        .await
        .map_err(storage_failure)?
    {
        ConnectorTokenState::Usable(caller) if caller.connector.org_id == org => Ok(caller),
        _ => Err(unauthenticated()),
    }
}

/// The inbound connector of `org` whose `client_id` and client `secret` a
/// token request presents (client_secret_basic or client_secret_post,
/// RFC 6749 §2.3.1). `None` when no connector has this `client_id`, so the
/// token endpoint tries its other clients; a connector's wrong or unusable
/// secret is refused.
#[allow(clippy::result_large_err)]
pub async fn authenticate_connector_client(
    storage: &dyn StorageBackend,
    org: OrgId,
    client_id: &str,
    secret: &str,
) -> Result<Option<ConnectorCaller>, Status> {
    let Some(connector) = storage
        .get_provisioning_connector_by_client_id(client_id)
        .await
        .map_err(storage_failure)?
    else {
        return Ok(None);
    };
    if !bearer_secret::has_prefix(secret, CONNECTOR_CLIENT_SECRET_PREFIX) {
        return Err(unauthenticated());
    }
    let Some((credential, owner)) = storage
        .find_provisioning_credential(&bearer_secret::verifier_of(secret))
        .await
        .map_err(storage_failure)?
    else {
        return Err(unauthenticated());
    };
    if owner.id != connector.id || !bearer_secret::matches(secret, &credential.verifier) {
        return Err(unauthenticated());
    }
    admit(
        org,
        ConnectorCredentialKind::ClientSecret,
        credential,
        connector,
        None,
    )
    .map(Some)
}

#[cfg(test)]
mod tests;
