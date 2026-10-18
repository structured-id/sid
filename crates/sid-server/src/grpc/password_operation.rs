// SPDX-License-Identifier: AGPL-3.0-only
//! This installation's password operations: the shared operation
//! ([`sid_authn::password_operation`]) over the CE store, for its own
//! purposes (registration, change, reset), and the purge a profile's
//! deletion owes the history evaluator.

use serde::{Deserialize, Serialize};
use sid_core::models::{CredentialId, NewWork, OwnerPurge, ProfileId, ResetSessionId};
use sid_plugin::storage::StorageBackend;

use super::auth_service::PendingRegistration;

pub use sid_authn::password_operation::{
    cleanup_consumer, consume_cleanup_settlements, consume_relayed_cleanup, settlement_consumer,
};

/// The purge the deletion of `profile` owes the evaluator, to be committed
/// with the deletion; `None` when the installation has no authority yet, and
/// so no history domain any key could be under.
pub(crate) async fn owner_purge(
    storage: &dyn StorageBackend,
    profile: ProfileId,
) -> sid_core::Result<Option<NewWork>> {
    Ok(storage.instance_organization().await?.map(|org| {
        OwnerPurge {
            owner_domain: sid_authn::password_history::owner_domain(org.id.as_bytes(), profile),
        }
        .work()
    }))
}

/// What an operation installs a password for, and the authority it rests on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum OperationPurpose {
    /// A self-registration; an existing identifier's start is a decoy that
    /// commits nothing.
    Registration { pending: PendingRegistration },
    /// A password change of the caller's own credential.
    Change {
        profile_id: ProfileId,
        credential_id: CredentialId,
        /// The OPRF credential identifier of the password the change began
        /// on: each password has its own, so it names that version.
        password: [u8; 16],
    },
    /// A reset under a verified reset session.
    Reset { session: ResetSessionId },
}

impl sid_authn::password_operation::OperationPurpose for OperationPurpose {
    fn method(&self) -> &'static str {
        match self {
            Self::Registration { .. } => "registration",
            Self::Change { .. } => "change",
            Self::Reset { .. } => "reset",
        }
    }
}

/// The shared operation over this installation's store, for its purposes.
pub(crate) type PasswordOperations =
    sid_authn::password_operation::PasswordOperations<dyn StorageBackend, OperationPurpose>;

/// An operation of this installation between its steps.
pub(crate) type PendingOperation =
    sid_authn::password_operation::PendingOperation<ProfileId, OperationPurpose>;

/// The outcome of one of this installation's finishes.
pub(crate) type Finish = sid_authn::password_operation::Finish<ProfileId, OperationPurpose>;

#[cfg(test)]
mod tests;
