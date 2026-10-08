// SPDX-License-Identifier: AGPL-3.0-only
//! Audit log types for tamper-evident logging.
//!
//! Append-only audit records with parallel hash chains per entity.
//! Hash chain provides tamper-evidence without requiring full event sourcing.

use chrono::{DateTime, Utc};
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

    /// Source IP address.
    pub ip_address: Option<String>,

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

    /// Set IP address on this entry.
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Source IP address.
    pub ip_address: Option<String>,

    /// Device identifier.
    pub device_id: Option<String>,

    /// Hash of the previous record in this chain ("genesis" for first record).
    pub prev_hash: String,

    /// SHA-256(chain_id + id + sequence + timestamp + actor_id + action + outcome + prev_hash).
    pub hash: String,
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

/// State of a hash chain head (for tracking the latest record).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainHead {
    /// Chain identifier (e.g., "profile:prof_01J8K...").
    pub chain_id: String,

    /// ID of the last record in the chain.
    pub last_record_id: String,

    /// Hash of the last record.
    pub last_hash: String,

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

    #[error("audit error: {0}")]
    Other(String),
}

/// Compute the hash for an audit record.
///
/// SHA-256(chain_id | id | sequence | timestamp | actor_id | action | outcome | prev_hash)
///
/// Produces a hex-encoded SHA-256 digest suitable for tamper-evident hash chains.
pub fn compute_record_hash(record: &AuditRecord) -> String {
    use sha2::{Digest, Sha256};

    let input = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        record.chain_id,
        record.id,
        record.sequence,
        record.timestamp.to_rfc3339(),
        record.actor_id,
        record.action,
        record.outcome,
        record.prev_hash,
    );

    let digest = Sha256::digest(input.as_bytes());
    hex::encode(digest)
}

/// Verify that a record's hash matches its content.
pub fn verify_record_hash(record: &AuditRecord) -> bool {
    compute_record_hash(record) == record.hash
}

#[cfg(test)]
mod tests;
