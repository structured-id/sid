// SPDX-License-Identifier: AGPL-3.0-only
//! What a storage mutation commits besides its own state: the audit record
//! of the action and the required work it creates, all in one transaction.

use super::audit::AuditEntry;
use super::durable_work::NewWork;
use super::operation::OperationCompletion;
use super::provisioning_connector::{ProvisioningConnectorId, ProvisioningCredentialId};

/// The audit entry, the owed work and the command completion a mutation
/// commits with its state. A backend writes all of them in one transaction,
/// or none of them.
#[derive(Debug, Clone)]
pub struct MutationContext {
    pub audit: AuditEntry,
    /// Required work the mutation creates (delivery intents, relays); empty
    /// when the mutation owes nothing asynchronous.
    pub work: Vec<NewWork>,
    /// The completion of the caller's keyed command. When another commit
    /// already recorded that key, the backend commits nothing and returns
    /// `Error::OperationCompleted`.
    pub operation: Option<OperationCompletion>,
    /// The authority the mutation was authorized under, rechecked in the
    /// same transaction: when it changed since, the backend commits nothing
    /// and returns `Error::Fenced`.
    pub fence: Option<ActorFence>,
}

/// An acting principal as it stood when its request was authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorFence {
    /// A provisioning connector at `revision`, acting with `credential`. The
    /// write holds only while the connector is still active at that revision
    /// (its grants, state and credentials move the revision) and the
    /// credential is still usable.
    Connector {
        connector: ProvisioningConnectorId,
        revision: i64,
        credential: ProvisioningCredentialId,
    },
}

impl MutationContext {
    /// Commit only while `fence` still holds.
    pub fn fenced_by(mut self, fence: ActorFence) -> Self {
        self.fence = Some(fence);
        self
    }

    /// Add work the mutation owes.
    pub fn with_work(mut self, work: NewWork) -> Self {
        self.work.push(work);
        self
    }

    /// Record the completion of the caller's keyed command with the effect.
    pub fn with_operation(mut self, operation: OperationCompletion) -> Self {
        self.operation = Some(operation);
        self
    }
}

/// A mutation that owes no asynchronous work.
impl From<AuditEntry> for MutationContext {
    fn from(audit: AuditEntry) -> Self {
        Self {
            audit,
            work: Vec::new(),
            operation: None,
            fence: None,
        }
    }
}
