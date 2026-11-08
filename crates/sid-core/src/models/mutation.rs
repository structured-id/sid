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
    /// The ceremony state the mutation completes, removed in the same
    /// transaction: when it is no longer live and exactly as read, the
    /// backend commits nothing and returns `Error::Expired`.
    pub ceremony: Option<CeremonyConsumption>,
    /// The credential state the mutation spends, replaced in the same
    /// transaction: when the credential is no longer active and exactly as
    /// read, the backend commits nothing and returns `Error::Fenced`.
    pub spend: Option<CredentialSpend>,
    /// The first refresh generation of a native session the mutation
    /// commits, stored in the same transaction: a session and its
    /// generation exist together or not at all.
    pub generation: Option<super::NativeGeneration>,
}

/// A credential's data replaced as part of a mutation: a single-use secret
/// of a set (a recovery code) is spent only by the effect it pays for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSpend {
    pub credential: super::CredentialId,
    /// The data as read, which the credential must still hold.
    pub read: Vec<u8>,
    /// The data it holds after the spend.
    pub left: Vec<u8>,
}

/// Ceremony state a mutation consumes: its namespace and key and the stored
/// form it was read in, so the mutation completes exactly that ceremony
/// once, whichever replica finishes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyConsumption {
    pub namespace: &'static str,
    pub key: String,
    pub stored: Vec<u8>,
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
    /// The installation's login policy at `epoch`: a session or code decided
    /// under it holds only while no policy write has advanced the epoch since.
    LoginPolicy { epoch: i64 },
    /// The administrative authority that authorized the write.
    Authority(super::AuthorityBasis),
    /// A Profile's own sign-in: the write holds only while `session` is
    /// still `profile`'s and unexpired, the Profile can still sign in, and,
    /// when `fresh_until` is given, the commit happens before it.
    Session {
        session: super::SessionId,
        profile: super::ProfileId,
        fresh_until: Option<chrono::DateTime<chrono::Utc>>,
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

    /// Consume `ceremony` in the same transaction.
    pub fn consuming(mut self, ceremony: CeremonyConsumption) -> Self {
        self.ceremony = Some(ceremony);
        self
    }

    /// Spend `spend` in the same transaction.
    pub fn spending(mut self, spend: CredentialSpend) -> Self {
        self.spend = Some(spend);
        self
    }

    /// Store `generation`, the first of the session this mutation commits,
    /// in the same transaction.
    pub fn issuing(mut self, generation: super::NativeGeneration) -> Self {
        self.generation = Some(generation);
        self
    }

    /// Record the completion of the caller's keyed command with the effect.
    pub fn with_operation(mut self, operation: OperationCompletion) -> Self {
        self.operation = Some(operation);
        self
    }

    /// Record `effect`, the state the mutation leaves as its store reads it
    /// inside the transaction, as the keyed command's result: a retry then
    /// returns exactly what this commit made, never a state read before or
    /// after it. Nothing to record without a keyed command.
    pub fn record_effect<T: serde::Serialize>(&mut self, effect: &T) -> crate::Result<()> {
        if let Some(operation) = &mut self.operation {
            operation.result = serde_json::to_vec(effect)
                .map_err(|e| crate::Error::Storage(format!("operation result: {e}")))?;
        }
        Ok(())
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
            ceremony: None,
            spend: None,
            generation: None,
        }
    }
}
