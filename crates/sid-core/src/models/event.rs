// SPDX-License-Identifier: AGPL-3.0-only
//! Domain event types following CloudEvents 1.0 specification (CNCF).
//!
//! All SID events use CloudEvents envelope for transport-agnostic
//! serialization over gRPC, NATS JetStream, and HTTP webhooks.
//!
//! Hybrid approach: custom `Event` struct for SID-specific fields +
//! `cloudevents-sdk` interop via `From`/`TryFrom` conversions.

use chrono::{DateTime, Utc};
use cloudevents::EventBuilder;
use serde::{Deserialize, Serialize};

use super::durable_work::{NewWork, WorkId, WorkKind};

/// CloudEvents 1.0 spec version constant.
pub const CLOUDEVENTS_SPEC_VERSION: &str = "1.0";

/// Work kind publishing a committed event to the event bus.
pub const EVENT_RELAY_KIND: &str = "event.relay";

/// Relay attempts before the event is recorded failed: with the relay's
/// schedule this outlasts a broker outage of more than a day.
pub const EVENT_RELAY_ATTEMPTS: u32 = 40;

/// Namespace of relay ids for events whose id is not a UUID.
const EVENT_RELAY_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x3b8f_0c21_9e47_4d5a_b612_7f0e_a95c_2d18);

/// SID-specific extension attribute name for monotonic sequence.
const EXT_SEQUENCE: &str = "sequence";

/// Validation errors for CloudEvents envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventValidationError {
    /// Required field `specversion` is missing or empty.
    MissingSpecVersion,
    /// Unsupported spec version (only "1.0" is supported).
    UnsupportedSpecVersion(String),
    /// Required field `id` is missing or empty.
    MissingId,
    /// Required field `source` is missing or empty.
    MissingSource,
    /// Required field `type` is missing or empty.
    MissingType,
    /// JSON structure is not a valid CloudEvents envelope.
    InvalidStructure(String),
}

impl std::fmt::Display for EventValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSpecVersion => write!(f, "missing required field: specversion"),
            Self::UnsupportedSpecVersion(v) => {
                write!(f, "unsupported specversion: {v} (expected 1.0)")
            }
            Self::MissingId => write!(f, "missing required field: id"),
            Self::MissingSource => write!(f, "missing required field: source"),
            Self::MissingType => write!(f, "missing required field: type"),
            Self::InvalidStructure(msg) => write!(f, "invalid CloudEvents structure: {msg}"),
        }
    }
}

impl std::error::Error for EventValidationError {}

/// CloudEvents 1.0 envelope for all SID domain events.
///
/// See: <https://cloudevents.io/>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// CloudEvents spec version (always "1.0").
    pub specversion: String,

    /// Unique event ID (ULID or UUIDv7).
    pub id: String,

    /// Event source identifier (e.g., "sid-identity.acme.com").
    pub source: String,

    /// Event type following reverse-DNS convention (e.g., "sid.user.created.v1").
    #[serde(rename = "type")]
    pub event_type: String,

    /// Resource identifier that the event relates to.
    pub subject: Option<String>,

    /// When the event occurred.
    pub time: DateTime<Utc>,

    /// Content type of the data payload.
    #[serde(default = "default_content_type")]
    pub datacontenttype: String,

    /// Event-specific payload (serialized per datacontenttype).
    #[serde(default)]
    pub data: serde_json::Value,

    /// Monotonic sequence number for ordering within a stream.
    #[serde(default)]
    pub sequence: u64,
}

fn default_content_type() -> String {
    "application/json".to_string()
}

impl Event {
    /// Create a new event with required fields.
    pub fn new(source: impl Into<String>, event_type: impl Into<String>) -> Self {
        Self {
            specversion: CLOUDEVENTS_SPEC_VERSION.to_string(),
            id: uuid::Uuid::now_v7().to_string(),
            source: source.into(),
            event_type: event_type.into(),
            subject: None,
            time: Utc::now(),
            datacontenttype: default_content_type(),
            data: serde_json::Value::Null,
            sequence: 0,
        }
    }

    /// Set the subject (resource identifier).
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Set the data payload.
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = data;
        self
    }

    /// Set the sequence number.
    pub fn with_sequence(mut self, seq: u64) -> Self {
        self.sequence = seq;
        self
    }

    /// The durable work that publishes this event once the mutation carrying
    /// it commits (transactional outbox). Its id follows from the event id,
    /// so the same event is owed once however often the mutation is retried.
    pub fn relay(&self) -> NewWork {
        let kind = WorkKind::new(EVENT_RELAY_KIND).expect("the relay kind is valid");
        let payload = serde_json::to_vec(self).expect("an event serializes");
        let mut work = NewWork::new(kind, payload);
        work.id =
            WorkId(uuid::Uuid::parse_str(&self.id).unwrap_or_else(|_| {
                uuid::Uuid::new_v5(&EVENT_RELAY_NAMESPACE, self.id.as_bytes())
            }));
        work.max_attempts = EVENT_RELAY_ATTEMPTS;
        work
    }

    /// Validate that this Event is a conforming CloudEvents 1.0 envelope.
    ///
    /// Checks all REQUIRED CloudEvents attributes:
    /// - `specversion` must be "1.0"
    /// - `id` must be non-empty
    /// - `source` must be non-empty
    /// - `type` must be non-empty
    pub fn validate(&self) -> Result<(), EventValidationError> {
        if self.specversion.is_empty() {
            return Err(EventValidationError::MissingSpecVersion);
        }
        if self.specversion != CLOUDEVENTS_SPEC_VERSION {
            return Err(EventValidationError::UnsupportedSpecVersion(
                self.specversion.clone(),
            ));
        }
        if self.id.is_empty() {
            return Err(EventValidationError::MissingId);
        }
        if self.source.is_empty() {
            return Err(EventValidationError::MissingSource);
        }
        if self.event_type.is_empty() {
            return Err(EventValidationError::MissingType);
        }
        Ok(())
    }
}

/// Parse and validate a CloudEvents 1.0 JSON envelope into an `Event`.
///
/// Validates all REQUIRED CloudEvents fields (specversion, id, source, type).
/// Returns `EventValidationError` if any required field is missing or invalid.
impl TryFrom<serde_json::Value> for Event {
    type Error = EventValidationError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        let event: Event = serde_json::from_value(value)
            .map_err(|e| EventValidationError::InvalidStructure(e.to_string()))?;
        event.validate()?;
        Ok(event)
    }
}

// ── cloudevents-sdk interop ─────────────────────────────────────────

/// Convert SID Event → cloudevents::Event for ecosystem interop.
///
/// Maps all CloudEvents required + optional attributes.
/// SID `sequence` extension is stored as CE extension attribute.
impl From<&Event> for cloudevents::Event {
    fn from(sid: &Event) -> Self {
        let mut builder = cloudevents::EventBuilderV10::new()
            .id(&sid.id)
            .source(&sid.source)
            .ty(&sid.event_type)
            .time(sid.time);

        if let Some(ref subject) = sid.subject {
            builder = builder.subject(subject);
        }

        if sid.data != serde_json::Value::Null {
            builder = builder.data(sid.datacontenttype.clone(), sid.data.clone());
        }

        let mut ce = builder.build().expect("required CE fields are set");

        if sid.sequence > 0 {
            ce.set_extension(
                EXT_SEQUENCE,
                cloudevents::event::ExtensionValue::Integer(sid.sequence as i64),
            );
        }

        ce
    }
}

/// Convert cloudevents::Event → SID Event for inbound interop.
///
/// Extracts all CloudEvents attributes + SID `sequence` extension.
impl TryFrom<cloudevents::Event> for Event {
    type Error = EventValidationError;

    fn try_from(ce: cloudevents::Event) -> Result<Self, Self::Error> {
        use cloudevents::event::AttributesReader;

        let id = ce.id().to_string();
        let source = ce.source().to_string();
        let event_type = ce.ty().to_string();
        let specversion = match ce.specversion() {
            cloudevents::event::SpecVersion::V10 => CLOUDEVENTS_SPEC_VERSION.to_string(),
            other => other.to_string(),
        };

        if id.is_empty() {
            return Err(EventValidationError::MissingId);
        }
        if source.is_empty() {
            return Err(EventValidationError::MissingSource);
        }
        if event_type.is_empty() {
            return Err(EventValidationError::MissingType);
        }

        let subject = ce.subject().map(|s| s.to_string());
        let time = ce.time().copied().unwrap_or_else(Utc::now);
        let datacontenttype = ce
            .datacontenttype()
            .unwrap_or("application/json")
            .to_string();

        let data = match ce.data() {
            Some(cloudevents::Data::Json(v)) => v.clone(),
            Some(cloudevents::Data::String(s)) => serde_json::Value::String(s.clone()),
            Some(cloudevents::Data::Binary(b)) => {
                // Try to parse binary as JSON, fallback to hex-encoded string.
                serde_json::from_slice(b)
                    .unwrap_or_else(|_| serde_json::Value::String(hex::encode(b)))
            }
            None => serde_json::Value::Null,
        };

        let sequence = ce
            .extension(EXT_SEQUENCE)
            .and_then(|v| match v {
                cloudevents::event::ExtensionValue::Integer(i) => Some(*i as u64),
                cloudevents::event::ExtensionValue::String(s) => s.parse().ok(),
                _ => None,
            })
            .unwrap_or(0);

        Ok(Event {
            specversion,
            id,
            source,
            event_type,
            subject,
            time,
            datacontenttype,
            data,
            sequence,
        })
    }
}

/// Well-known event type constants.
pub mod event_types {
    // User lifecycle
    pub const USER_CREATED: &str = "sid.user.created.v1";
    pub const USER_DEACTIVATED: &str = "sid.user.deactivated.v1";
    pub const USER_LOCKED: &str = "sid.user.locked.v1";
    pub const USER_UNLOCKED: &str = "sid.user.unlocked.v1";
    pub const USER_DELETED: &str = "sid.user.deleted.v1";

    // Profile
    pub const PROFILE_CLAIM_CHANGED: &str = "sid.profile.claim_changed.v1";
    pub const PROFILE_EMAIL_CHANGED: &str = "sid.profile.email_changed.v1";

    // Session
    pub const SESSION_CREATED: &str = "sid.session.created.v1";
    pub const SESSION_REVOKED: &str = "sid.session.revoked.v1";

    // MFA
    pub const MFA_ENROLLED: &str = "sid.mfa.enrolled.v1";
    pub const MFA_DISABLED: &str = "sid.mfa.disabled.v1";
    pub const MFA_RECOVERY_CODE_USED: &str = "sid.mfa.recovery_code_used.v1";

    // Security
    pub const SECURITY_BRUTE_FORCE: &str = "sid.security.brute_force.v1";
    pub const SECURITY_SUSPICIOUS_LOGIN: &str = "sid.security.suspicious_login.v1";
    pub const SECURITY_CREDENTIAL_ROTATED: &str = "sid.security.credential_rotated.v1";
    pub const SECURITY_COUNTRY_BLOCKED: &str = "sid.security.country_blocked.v1";
    pub const SECURITY_TOR_BLOCKED: &str = "sid.security.tor_blocked.v1";
    pub const SECURITY_DATACENTER_IP: &str = "sid.security.datacenter_ip.v1";
    pub const SECURITY_LOCATION_SWITCH: &str = "sid.security.location_switch.v1";

    // Admin
    pub const ADMIN_CREATED: &str = "sid.admin.created.v1";
    pub const ADMIN_POLICY_CHANGED: &str = "sid.admin.policy_changed.v1";

    // Federation
    pub const FEDERATION_PEER_CONNECTED: &str = "sid.federation.peer_connected.v1";
    pub const FEDERATION_PEER_DISCONNECTED: &str = "sid.federation.peer_disconnected.v1";
    pub const FEDERATION_SYNC_COMPLETED: &str = "sid.federation.sync_completed.v1";

    // Revocation
    pub const CREDENTIAL_REVOKED: &str = "sid.credential.revoked.v1";
    pub const REFRESH_TOKEN_REVOKED: &str = "sid.token.refresh_revoked.v1";
    pub const PROFILE_SUSPENDED: &str = "sid.profile.suspended.v1";
    pub const PROFILE_CLOSED: &str = "sid.profile.closed.v1";

    // Consent
    pub const CONSENT_GRANTED: &str = "sid.consent.granted.v1";
    pub const CONSENT_REVOKED: &str = "sid.consent.revoked.v1";

    // Notification
    pub const NOTIFY_DLQ: &str = "sid.notify.dlq.v1";

    // Certificate
    pub const CERT_EXPIRING: &str = "sid.cert.expiring.v1";
    pub const CERT_ROTATED: &str = "sid.cert.rotated.v1";

    // Closure lifecycle
    pub const CLOSURE_REQUESTED: &str = "sid.closure.requested.v1";
    pub const CLOSURE_EXPORT_READY: &str = "sid.closure.export_ready.v1";
    pub const CLOSURE_GRACE_PERIOD: &str = "sid.closure.grace_period.v1";
    pub const CLOSURE_CANCELLED: &str = "sid.closure.cancelled.v1";
    pub const CLOSURE_PURGED: &str = "sid.closure.purged.v1";

    // PAT (Personal Access Token)
    pub const PAT_CREATED: &str = "sid.pat.created.v1";
    pub const PAT_REVOKED: &str = "sid.pat.revoked.v1";
    pub const PAT_EXPIRED: &str = "sid.pat.expired.v1";

    // Machine User / Service Account
    pub const MACHINE_USER_CREATED: &str = "sid.machine_user.created.v1";
    pub const MACHINE_USER_SUSPENDED: &str = "sid.machine_user.suspended.v1";
    pub const MACHINE_USER_CREDENTIAL_ROTATED: &str = "sid.machine_user.credential_rotated.v1";
    pub const MACHINE_USER_CREDENTIAL_EXPIRING: &str = "sid.machine_user.credential_expiring.v1";
    pub const MACHINE_USER_CREDENTIAL_EXPIRED: &str = "sid.machine_user.credential_expired.v1";

    // Profile Grant
    pub const PROFILE_GRANT_CREATED: &str = "sid.profile_grant.created.v1";
    pub const PROFILE_GRANT_REVOKED: &str = "sid.profile_grant.revoked.v1";
    pub const PROFILE_GRANT_UPDATED: &str = "sid.profile_grant.updated.v1";

    // Governance
    pub const GOVERNANCE_ROLE_EXPIRING: &str = "sid.governance.role_expiring.v1";
    pub const GOVERNANCE_ROLE_EXPIRED: &str = "sid.governance.role_expired.v1";

    // Organization (SaaS)
    pub const ORG_TRIAL_ACTIVATED: &str = "sid.organization.trial_activated.v1";

    // Principal contestation
    /// A second profile has bound this principal — all existing holders are notified.
    /// Recipients: profiles that already held this principal (not the new claimer).
    /// Channels: email + push.
    pub const PRINCIPAL_CONTESTED: &str = "sid.principal.contested.v1";
    /// A profile lost eligibility on a contested principal (another profile verified ownership).
    /// Recipients: the profile that lost eligibility.
    /// Channels: push only — the contested address cannot reliably reach the losing profile.
    pub const PRINCIPAL_LOST: &str = "sid.principal.lost.v1";
    /// A profile's verified ownership of a principal was superseded by another profile.
    /// Recipients: the profile that was the previous verified owner.
    /// Channels: push only.
    pub const PRINCIPAL_OWNERSHIP_SUPERSEDED: &str = "sid.principal.ownership_superseded.v1";

    // SCIM provisioning
    pub const SCIM_USER_PROVISIONED: &str = "sid.scim.user_provisioned.v1";
    pub const SCIM_USER_UPDATED: &str = "sid.scim.user_updated.v1";
    pub const SCIM_USER_DEACTIVATED: &str = "sid.scim.user_deactivated.v1";
    pub const SCIM_USER_REACTIVATED: &str = "sid.scim.user_reactivated.v1";
    pub const SCIM_GROUP_CREATED: &str = "sid.scim.group_created.v1";
    pub const SCIM_GROUP_UPDATED: &str = "sid.scim.group_updated.v1";
    pub const SCIM_GROUP_DELETED: &str = "sid.scim.group_deleted.v1";
}

/// Filter for event subscriptions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    /// Event type patterns to subscribe to (e.g., "sid.user.*", "sid.security.brute_force.v1").
    /// Empty = all events.
    pub event_types: Vec<String>,

    /// Attribute filters (key=value pairs). All must match.
    pub attributes: std::collections::HashMap<String, String>,

    /// Queue group name for load-balanced consumption.
    ///
    /// When set, NATS JetStream creates a durable consumer with this queue group.
    /// Among N instances subscribing with the same queue_group, each event is
    /// delivered to exactly ONE instance (load balanced, not broadcast).
    ///
    /// When `None`, the consumer is ephemeral and each instance receives ALL events
    /// (fan-out / broadcast mode). This is correct for notification-style consumers
    /// but WRONG for work queues (leads to N× processing).
    ///
    /// Convention: use service binary name as queue group (e.g., "sid-notify", "sid-scim-worker").
    pub queue_group: Option<String>,
}

impl EventFilter {
    /// Check if an event matches this filter.
    pub fn matches(&self, event: &Event) -> bool {
        // Check event type patterns
        if !self.event_types.is_empty() {
            let type_match = self.event_types.iter().any(|pattern| {
                if pattern.ends_with(".*") {
                    let prefix = &pattern[..pattern.len() - 2];
                    event.event_type.starts_with(prefix)
                } else if pattern.ends_with(".>") {
                    // NATS-style wildcard: matches any suffix
                    let prefix = &pattern[..pattern.len() - 2];
                    event.event_type.starts_with(prefix)
                } else {
                    event.event_type == *pattern
                }
            });
            if !type_match {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests;
