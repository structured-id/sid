// SPDX-License-Identifier: AGPL-3.0-only
//! A protected resource's authentication of a machine user calling it with
//! an access token it obtained through OAuth client credentials.
//!
//! The token must be signed by the resource's trusted issuer for exactly this
//! resource; it names the machine user (`sub`), its `client_id` and the
//! credential it authenticated with (`sid`). Each request checks them again
//! against the stored machine user, so suspending it, expiring it or revoking
//! that credential stops tokens already issued. What the machine may do is
//! decided afterwards from its current RoleAssignments, never from the token.
//!
//! Every refusal is the same `unauthenticated`, so a caller learns nothing
//! about which check failed.

use chrono::Utc;
use sid_core::models::{MachineUser, MachineUserCredential};
use sid_plugin::StorageBackend;

use crate::jwt::AccessTokenClaims;
use crate::resource_token::{OwnTokenError, ResourceTokenVerifier};
use crate::revocation_cache::RevocationCache;

/// An authenticated machine user and the credential its token was issued for.
#[derive(Debug, Clone)]
pub struct MachineCaller {
    pub machine: MachineUser,
    /// The `kid` of the credential the machine authenticated with; audit
    /// records name it, never a secret.
    pub credential: String,
    /// The scopes its token was issued with.
    pub scopes: Vec<String>,
}

impl MachineCaller {
    /// Its authorization subject in the common engine.
    pub fn subject(&self) -> String {
        format!("machine:{}", self.machine.id)
    }

    /// Whether its token allows `scope`.
    pub fn may(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Whether a token stands for a machine user, read from the stored records
/// at the moment of asking.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "returned once and destructured at once; boxing would add a heap allocation to every token check"
)]
pub enum MachineTokenState {
    /// Its `client_id` belongs to no machine user.
    NotMachine,
    /// It names a machine user that, or a credential that, cannot act now:
    /// suspended, expired, revoked, or not the machine and credential the
    /// token claims.
    Unusable,
    /// The machine and the credential it was issued for can act now.
    Usable {
        machine: MachineUser,
        credential: MachineUserCredential,
    },
}

/// The current state of the machine user a verified token was issued to and
/// of the credential it authenticated with (`sub`, `client_id`, `sid`). The
/// token's signature says what was true at issuance; this says what is true
/// now. A storage failure is an error, never a state.
pub async fn machine_token_state(
    storage: &dyn StorageBackend,
    claims: &AccessTokenClaims,
) -> sid_core::Result<MachineTokenState> {
    let Some(client_id) = claims.client_id.as_deref() else {
        return Ok(MachineTokenState::NotMachine);
    };
    let Some(machine) = storage.get_machine_user_by_client_id(client_id).await? else {
        return Ok(MachineTokenState::NotMachine);
    };
    if claims.sub != machine.id.to_string() || !machine.can_authenticate() {
        return Ok(MachineTokenState::Unusable);
    }
    let Some(credential) = storage.get_machine_credential_by_kid(&claims.sid).await? else {
        return Ok(MachineTokenState::Unusable);
    };
    let usable = credential.machine_user_id == machine.id
        && credential.status.is_usable()
        && credential.expires_at.is_none_or(|at| at > Utc::now());
    if !usable {
        return Ok(MachineTokenState::Unusable);
    }
    Ok(MachineTokenState::Usable {
        machine,
        credential,
    })
}

/// Whether the token `claims` were verified from was revoked; revocation
/// reaches every replica through the shared cache.
pub(crate) async fn revoked(
    revocation: &RevocationCache,
    claims: &AccessTokenClaims,
) -> Result<bool, OwnTokenError> {
    revocation
        .is_revoked(&claims.jti, &claims.sid)
        .await
        .map_err(|e| OwnTokenError::Storage(sid_core::Error::Storage(e.to_string())))
}

/// The machine user the `presented` token authenticates at the resource
/// `tokens` verifies.
pub async fn authenticate_machine(
    presented: &str,
    storage: &dyn StorageBackend,
    tokens: &ResourceTokenVerifier,
    revocation: &RevocationCache,
) -> Result<MachineCaller, OwnTokenError> {
    let claims = tokens.verify_own(presented).await?;
    let MachineTokenState::Usable {
        machine,
        credential,
    } = machine_token_state(storage, &claims)
        .await
        .map_err(OwnTokenError::Storage)?
    else {
        return Err(OwnTokenError::Unauthenticated);
    };
    if revoked(revocation, &claims).await? {
        return Err(OwnTokenError::Unauthenticated);
    }
    Ok(MachineCaller {
        machine,
        credential: credential.kid,
        scopes: claims.scope.split_whitespace().map(String::from).collect(),
    })
}

#[cfg(test)]
mod tests;
