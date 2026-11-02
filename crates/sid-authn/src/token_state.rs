// SPDX-License-Identifier: AGPL-3.0-only
//! The current state of a verified resource access token: who it stands for
//! now, read from the stored records at the moment of asking.
//!
//! A valid signature says what was true at issuance. A suspended or expired
//! machine user, a disabled connector, a revoked credential, a deactivated
//! or deleted requesting client, or an ended sign-in makes the token
//! inactive now (developer/resource-sdk.md token-state freshness). Token
//! introspection and permission questions on an original request read the
//! token through this one rule.
//!
//! The Profile a user's token stands for is the one of the stored sign-in it was
//! issued from, never its `sub` read as an identifier: a pairwise `sub` is a
//! BindingId whatever its shape.

use sid_core::models::{MachineUserId, ProfileId, ProvisioningConnectorId, SessionId};
use sid_plugin::StorageBackend;

use crate::connector_auth::{ConnectorTokenState, connector_token_state};
use crate::jwt::AccessTokenClaims;
use crate::machine_auth::{MachineTokenState, machine_token_state};

/// Whom an active token stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenActor {
    /// A machine user acting for itself.
    Machine(MachineUserId),
    /// A provisioning connector acting for itself.
    Connector(ProvisioningConnectorId),
    /// An OAuth client acting for itself, by its `client_id`.
    Client(String),
    /// A Profile, through the sign-in the token was issued from.
    Profile {
        profile: ProfileId,
        session: SessionId,
    },
}

impl TokenActor {
    /// Its subject in the common authorization engine.
    pub fn subject(&self) -> String {
        match self {
            Self::Machine(id) => format!("machine:{id}"),
            Self::Connector(id) => format!("provisioning_connector:{id}"),
            Self::Client(client_id) => format!("oauth_client:{client_id}"),
            Self::Profile { profile, .. } => format!("user:{profile}"),
        }
    }
}

/// What a verified token stands for now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenState {
    /// Nobody can act with it now.
    Inactive,
    /// It stands for this actor now.
    Active(TokenActor),
}

/// The current state of the token `claims` were verified from. A storage
/// failure is an error, never a state.
pub async fn current_state(
    storage: &dyn StorageBackend,
    claims: &AccessTokenClaims,
) -> sid_core::Result<TokenState> {
    match machine_token_state(storage, claims).await? {
        MachineTokenState::Usable { machine, .. } => {
            return Ok(TokenState::Active(TokenActor::Machine(machine.id)));
        }
        MachineTokenState::Unusable => return Ok(TokenState::Inactive),
        MachineTokenState::NotMachine => {}
    }
    match connector_token_state(storage, claims).await? {
        ConnectorTokenState::Usable(caller) => {
            return Ok(TokenState::Active(TokenActor::Connector(
                caller.connector.id,
            )));
        }
        ConnectorTokenState::Unusable => return Ok(TokenState::Inactive),
        ConnectorTokenState::NotConnector => {}
    }
    // Every other resource token was requested by an OAuth client: its grants
    // end when the client is deactivated or gone.
    let Some(client_id) = claims.client_id.as_deref() else {
        return Ok(TokenState::Inactive);
    };
    if !storage
        .get_oauth2_client(client_id)
        .await?
        .is_some_and(|client| client.active)
    {
        return Ok(TokenState::Inactive);
    }
    // The client's own token names the client as subject and credential.
    if claims.sub == client_id && claims.sid == client_id {
        return Ok(TokenState::Active(TokenActor::Client(client_id.to_owned())));
    }
    // A user's token lives as long as its sign-in; an ended one is deleted.
    let Ok(session_id) = SessionId::parse(&claims.sid) else {
        return Ok(TokenState::Inactive);
    };
    Ok(match storage.get_session(session_id).await? {
        Some(session) if !session.is_expired() => TokenState::Active(TokenActor::Profile {
            profile: session.profile_id,
            session: session.id,
        }),
        _ => TokenState::Inactive,
    })
}

#[cfg(test)]
mod tests;
