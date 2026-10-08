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

use sid_core::grpc_error::refuse::storage_failure;
use sid_core::grpc_error::{ApiError, ErrorReason};
use sid_core::models::MachineUserId;
use sid_plugin::StorageBackend;
use tonic::{Request, Status};

use crate::caller::bearer_token;
use crate::machine_auth::{MachineTokenState, machine_token_state};
use crate::resource_token::ResourceTokenVerifier;
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

fn unauthenticated() -> Status {
    ApiError::new(ErrorReason::TokenInvalid, "authentication required").into()
}

/// The service `request`'s bearer token authenticates at the API `tokens`
/// verifies.
#[allow(clippy::result_large_err)]
pub async fn authenticate_service<T>(
    request: &Request<T>,
    storage: &dyn StorageBackend,
    tokens: &ResourceTokenVerifier,
    revocation: &RevocationCache,
) -> Result<ServiceCaller, Status> {
    let presented = bearer_token(request)?;
    let claims = match tokens.verify(presented).await {
        Ok(claims) => claims,
        Err(sid_core::Error::AuthenticationFailed(_)) => return Err(unauthenticated()),
        Err(e) => return Err(storage_failure(e)),
    };
    // A sender-constrained token needs its proof, which a service call does
    // not carry (RFC 9449 §7.1); a ProfileId never rides a service's token.
    if claims.cnf.is_some() || claims.pid.is_some() {
        return Err(unauthenticated());
    }
    let caller = match machine_token_state(storage, &claims)
        .await
        .map_err(storage_failure)?
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
                .map_err(storage_failure)?
                .ok_or_else(unauthenticated)?;
            if !client.active || client.is_public() {
                return Err(unauthenticated());
            }
            ServiceCaller::Client {
                client_id: client.client_id,
            }
        }
    };
    // Revocation reaches every replica through the shared cache.
    if revocation
        .is_revoked(&claims.jti, &claims.sid)
        .await
        .map_err(|e| storage_failure(sid_core::Error::Storage(e.to_string())))?
    {
        return Err(unauthenticated());
    }
    Ok(caller)
}

#[cfg(test)]
mod tests;
