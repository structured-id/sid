// SPDX-License-Identifier: AGPL-3.0-only
//! Audit log types for tamper-evident logging.
//!
//! Append-only audit records with parallel hash chains per entity.
//! Hash chain provides tamper-evidence without requiring full event sourcing.

use chrono::{DateTime, Utc};
use core::net::IpAddr;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Input provided by services when logging an auditable action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Who performed the action (profile_id, admin_id, or "system").
    pub actor_id: String,

    /// Actor type.
    pub actor_type: ActorType,

    /// What action was performed (e.g., "profile.email_changed").
    pub action: String,

    /// What resource was affected (e.g., profile_id, session_id).
    pub resource: String,

    /// Outcome of the action.
    pub outcome: AuditOutcome,

    /// Action-specific metadata (NO PII values — only field names, IDs).
    #[serde(default)]
    pub metadata: serde_json::Value,

    /// Source address.
    pub ip_address: Option<IpAddr>,

    /// Device identifier (if applicable).
    pub device_id: Option<String>,
}

impl AuditEntry {
    /// An entry for the actor `actor_id` of `actor_type`.
    pub fn by_actor(
        actor_id: impl Into<String>,
        actor_type: ActorType,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self::of(actor_id, actor_type, action, resource)
    }

    /// An entry of `actor_type` with no metadata, address or device.
    fn of(
        actor_id: impl Into<String>,
        actor_type: ActorType,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            actor_id: actor_id.into(),
            actor_type,
            action: action.into(),
            resource: resource.into(),
            outcome: AuditOutcome::Success,
            metadata: serde_json::Value::Null,
            ip_address: None,
            device_id: None,
        }
    }

    /// Create an audit entry for a system-initiated action.
    pub fn system(action: impl Into<String>, resource: impl Into<String>) -> Self {
        Self::of("system", ActorType::System, action, resource)
    }

    /// Create an audit entry for a user-initiated action.
    pub fn user(
        actor_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self::of(actor_id, ActorType::User, action, resource)
    }

    /// Create an audit entry for an admin-initiated action.
    pub fn admin(
        actor_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self::of(actor_id, ActorType::Admin, action, resource)
    }

    /// Create an audit entry for a machine user (service account) action.
    pub fn machine(
        actor_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self::of(actor_id, ActorType::Machine, action, resource)
    }

    /// Create an audit entry for a provisioning connector's action.
    pub fn connector(
        actor_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self::of(actor_id, ActorType::Connector, action, resource)
    }

    /// Set metadata on this entry.
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set the source address of this entry.
    pub fn with_ip(mut self, ip: Option<IpAddr>) -> Self {
        self.ip_address = ip;
        self
    }

    /// Set outcome on this entry.
    pub fn with_outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome;
        self
    }
}

/// Stored audit record with hash chain fields.
///
/// Immutable once written — no UPDATE or DELETE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique record ID (ULID — time-ordered).
    pub id: String,

    /// When the event was recorded.
    pub timestamp: DateTime<Utc>,

    /// Chain this record belongs to (e.g., "profile:prof_01J8K...", "site:site_01J8K...").
    pub chain_id: String,

    /// Monotonic sequence number within the chain.
    pub sequence: u64,

    /// Who performed the action.
    pub actor_id: String,

    /// Actor type.
    pub actor_type: ActorType,

    /// What action was performed.
    pub action: String,

    /// What resource was affected.
    pub resource: String,

    /// Outcome of the action.
    pub outcome: AuditOutcome,

    /// Action-specific metadata (NO PII values).
    #[serde(default)]
    pub metadata: serde_json::Value,

    /// Source address.
    pub ip_address: Option<IpAddr>,

    /// Device identifier.
    pub device_id: Option<String>,

    /// Digest of the previous record in this chain ([`AuditDigest::GENESIS`]
    /// for the first record).
    pub prev_hash: AuditDigest,

    /// This record's digest ([`compute_record_hash`]).
    pub hash: AuditDigest,
}

/// The SHA-256 digest that links an audit record into its chain.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditDigest(pub [u8; 32]);

impl AuditDigest {
    /// What the first record of a chain links to. No SHA-256 output is all
    /// zeros in practice, so it is never a record's digest.
    pub const GENESIS: Self = Self([0; 32]);

    /// The digest as stored: its 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A stored digest; `None` unless `bytes` is exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }

    /// The digest a store holds as `what`; one that is not 32 bytes is a
    /// damaged record, refused rather than read as another value.
    pub fn stored(bytes: &[u8], what: &str) -> Result<Self, AuditError> {
        Self::from_slice(bytes)
            .ok_or_else(|| AuditError::Other(format!("stored {what} is not a 32-byte digest")))
    }
}

impl fmt::Debug for AuditDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuditDigest({})", hex::encode(self.0))
    }
}

/// Type of actor performing the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorType {
    User,
    Admin,
    /// External service (third-party integration).
    Service,
    /// Machine user (service account, automated client).
    Machine,
    /// Provisioning connector (SCIM), identified by its connector ID.
    Connector,
    System,
}

impl fmt::Display for ActorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Admin => write!(f, "admin"),
            Self::Service => write!(f, "service"),
            Self::Machine => write!(f, "machine"),
            Self::Connector => write!(f, "connector"),
            Self::System => write!(f, "system"),
        }
    }
}

/// Outcome of an auditable action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

impl fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
            Self::Denied => write!(f, "denied"),
        }
    }
}

/// Where a chain resumes after retention removed its oldest records: the
/// sequence and hash of the last removed record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainCheckpoint {
    pub sequence: u64,
    pub hash: AuditDigest,
    /// Records before this time were removed.
    pub cut_before: DateTime<Utc>,
}

/// A hash chain as stored, for a move between stores: its head, the
/// checkpoint retention left and its records in sequence order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditChain {
    pub head: ChainHead,
    pub checkpoint: Option<ChainCheckpoint>,
    pub records: Vec<AuditRecord>,
}

impl AuditChain {
    /// Check the chain as a whole: its records follow the checkpoint (or
    /// genesis) without a gap, each links to the one before and hashes to
    /// its stored hash, all are of the head's chain, and the head names the
    /// last of them.
    pub fn check(&self) -> Result<(), AuditError> {
        let broken = |record_id: &str| AuditError::IntegrityViolation {
            record_id: record_id.to_owned(),
        };
        let (mut sequence, mut hash) = match &self.checkpoint {
            Some(c) => (c.sequence, c.hash),
            None => (0, AuditDigest::GENESIS),
        };
        for record in &self.records {
            let next = sequence.checked_add(1).ok_or_else(|| broken(&record.id))?;
            if record.chain_id != self.head.chain_id
                || record.sequence != next
                || record.prev_hash != hash
                || !verify_record_hash(record)
            {
                return Err(broken(&record.id));
            }
            sequence = next;
            hash = record.hash;
        }
        let head_ok = match self.records.last() {
            Some(last) => {
                self.head.last_record_id == last.id
                    && self.head.last_hash == last.hash
                    && self.head.sequence == last.sequence
            }
            // Retention removed every record: the head is where the chain
            // was cut.
            None => self.head.sequence == sequence && self.head.last_hash == hash,
        };
        if head_ok {
            Ok(())
        } else {
            Err(broken(&self.head.last_record_id))
        }
    }

    /// Whether this stored chain holds `given`: the same checkpoint and
    /// every record of `given`, possibly followed by later ones.
    pub fn holds(&self, given: &AuditChain) -> bool {
        self.head.chain_id == given.head.chain_id
            && self.checkpoint == given.checkpoint
            && self.head.sequence >= given.head.sequence
            && self.records.starts_with(&given.records)
    }
}

/// State of a hash chain head (for tracking the latest record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHead {
    /// Chain identifier (e.g., "profile:prof_01J8K...").
    pub chain_id: String,

    /// ID of the last record in the chain.
    pub last_record_id: String,

    /// Digest of the last record ([`AuditDigest::GENESIS`] before the first).
    pub last_hash: AuditDigest,

    /// Current sequence number.
    pub sequence: u64,
}

/// Errors from audit operations.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit write failed: {0}")]
    WriteFailed(String),

    #[error("chain integrity violation at record {record_id}")]
    IntegrityViolation { record_id: String },

    #[error("chain not found: {0}")]
    ChainNotFound(String),

    /// The store holds another chain under the same id.
    #[error("audit chain conflict: {0}")]
    Conflict(String),

    #[error("audit error: {0}")]
    Other(String),
}

/// Domain of the record digest, so it never equals a SHA-256 taken for
/// another purpose over the same bytes.
const RECORD_DIGEST_DOMAIN: &[u8] = b"sid.audit.record.v1";

/// The digest that links `record` into its chain: SHA-256 over the domain,
/// then chain id, record id, sequence, timestamp, actor, action, outcome and
/// the previous digest. Each text field is length-prefixed (u32 BE), so no
/// content of one field can be read as a boundary of the next; the sequence
/// is a u64 BE and the previous digest its 32 bytes.
pub fn compute_record_hash(record: &AuditRecord) -> AuditDigest {
    use sha2::{Digest, Sha256};

    fn text(hasher: &mut Sha256, value: &str) {
        // Audit fields are bounded far below 4 GiB; a longer one would be a
        // record no store accepts.
        let len = u32::try_from(value.len()).expect("an audit field shorter than 4 GiB");
        hasher.update(len.to_be_bytes());
        hasher.update(value.as_bytes());
    }

    let mut hasher = Sha256::new();
    hasher.update(RECORD_DIGEST_DOMAIN);
    text(&mut hasher, &record.chain_id);
    text(&mut hasher, &record.id);
    hasher.update(record.sequence.to_be_bytes());
    text(&mut hasher, &record.timestamp.to_rfc3339());
    text(&mut hasher, &record.actor_id);
    text(&mut hasher, &record.action);
    text(&mut hasher, &record.outcome.to_string());
    hasher.update(record.prev_hash.as_bytes());
    AuditDigest(hasher.finalize().into())
}

/// Verify that a record's hash matches its content.
pub fn verify_record_hash(record: &AuditRecord) -> bool {
    compute_record_hash(record) == record.hash
}

#[cfg(test)]
mod tests;
