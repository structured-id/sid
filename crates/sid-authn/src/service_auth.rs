// SPDX-License-Identifier: AGPL-3.0-only
//! A service authenticating as itself with an access token it obtained
//! through OAuth client credentials for one protected API of its issuer,
//! such as the authorization API a permission checker calls (D054).
//!
//! The service is a machine user or an independent confidential OAuth
//! client; each request checks again that it, and the credential its token
//! names, can act now. The token is the service's own: a token issued for a
//! user's sign-in never authenticates a service here, whatever it names.
//!
//! Every refusal is the same `unauthenticated`, so a caller learns nothing
//! about which check failed.

use sid_core::models::MachineUserId;
use sid_plugin::StorageBackend;

use crate::machine_auth::{MachineTokenState, machine_token_state, revoked};
use crate::resource_token::{OwnTokenError, ResourceTokenVerifier};
use crate::revocation_cache::RevocationCache;

/// An authenticated service.
#[derive(Debug, Clone)]
pub enum ServiceCaller {
    /// A machine user, with the `kid` of the credential it used.
    Machine {
        machine: MachineUserId,
        credential: String,
    },
    /// An independent confidential OAuth client, by its `client_id`.
    Client { client_id: String },
}

impl ServiceCaller {
    /// Its authorization subject in the common engine.
    pub fn subject(&self) -> String {
        match self {
            Self::Machine { machine, .. } => format!("machine:{machine}"),
            Self::Client { client_id } => format!("oauth_client:{client_id}"),
        }
    }
}

/// An authenticated service and the scopes its verified token carries.
#[derive(Debug, Clone)]
pub struct AuthenticatedService {
    pub caller: ServiceCaller,
    scopes: Vec<String>,
}

impl AuthenticatedService {
    /// Whether the token was issued for `action`: an action outside its
    /// scopes is refused whatever the service's roles grant (RFC 6749 §3.3).
    pub fn may(&self, action: &str) -> bool {
        self.scopes.iter().any(|s| s == action)
    }
}

/// The service the `presented` token authenticates at the API `tokens`
/// verifies.
pub async fn authenticate_service(
    presented: &str,
    storage: &dyn StorageBackend,
    tokens: &ResourceTokenVerifier,
    revocation: &RevocationCache,
) -> Result<AuthenticatedService, OwnTokenError> {
    let unauthenticated = || OwnTokenError::Unauthenticated;
    let claims = tokens.verify_own(presented).await?;
    let caller = match machine_token_state(storage, &claims)
        .await
        .map_err(OwnTokenError::Storage)?
    {
        MachineTokenState::Usable {
            machine,
            credential,
        } => ServiceCaller::Machine {
            machine: machine.id,
            credential: credential.kid,
        },
        MachineTokenState::Unusable => return Err(unauthenticated()),
        MachineTokenState::NotMachine => {
            // An OAuth client acting for itself names itself as subject and
            // credential; anything else was issued for a user's sign-in.
            let client_id = claims.client_id.as_deref().ok_or_else(unauthenticated)?;
            if claims.sub != client_id || claims.sid != client_id {
                return Err(unauthenticated());
            }
            let client = storage
                .get_oauth2_client(client_id)
                .await
                .map_err(OwnTokenError::Storage)?
                .ok_or_else(unauthenticated)?;
            if !client.active || client.is_public() {
                return Err(unauthenticated());
            }
            ServiceCaller::Client {
                client_id: client.client_id,
            }
        }
    };
    if revoked(revocation, &claims).await? {
        return Err(unauthenticated());
    }
    Ok(AuthenticatedService {
        caller,
        scopes: claims.scope.split_whitespace().map(String::from).collect(),
    })
}

#[cfg(test)]
mod tests;
