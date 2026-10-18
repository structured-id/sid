// SPDX-License-Identifier: AGPL-3.0-only
//! This installation's password operations: the shared operation
//! ([`sid_authn::password_operation`]) over the CE store, for its own
//! purposes (registration, change, reset), and the workers that end what an
//! operation leaves behind (abandoned first enrollments, purged owners, the
//! cleanup a separate evaluator is told about).

use serde::{Deserialize, Serialize};
use sid_core::models::{CredentialId, ProfileId, ResetSessionId};
use sid_plugin::storage::StorageBackend;

use super::auth_service::PendingRegistration;

mod enrollment;
mod purge;
mod relayed;
pub(crate) use enrollment::{EnrollmentHandler, EvaluatorDelivery, compact_enrollments};
pub(crate) use purge::{OwnerPurgeHandler, owner_purge};
pub use relayed::{
    cleanup_consumer, consume_cleanup_settlements, consume_relayed_cleanup, settlement_consumer,
};

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
