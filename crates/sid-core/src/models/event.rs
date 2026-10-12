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

/// Work kind relaying a committed fact: it owes the fact to each required
/// receiver of its type and publishes it to the retained history.
pub const EVENT_RELAY_KIND: &str = "event.relay";

/// Work kind handing an event to one addressed receiver.
pub const EVENT_DELIVERY_KIND: &str = "event.deliver";

/// Work kind carrying a relayed fact's fixed plan: the receivers it is owed
/// to, then its history publication.
pub const EVENT_FANOUT_KIND: &str = "event.fanout";

/// Namespace of fan-out plan ids, one per relayed fact.
const EVENT_FANOUT_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x5e81_c3a0_2d74_4b9f_86e1_0af2_93c7_4d58);

/// Attempts at handing a committed fact on (relay, plan, delivery): as many
/// as every store can count (a signed 32-bit column). A broker that is down
/// or a work stream that is full leaves the handoff pending, not failed, so
/// it goes on once the broker is back; a refusal no attempt can cure (an
/// unroutable type, a malformed payload) still ends it at once.
pub const EVENT_RELAY_ATTEMPTS: u32 = i32::MAX.unsigned_abs();

/// Namespace of relay ids, one per `(source, id)`.
const EVENT_RELAY_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x3b8f_0c21_9e47_4d5a_b612_7f0e_a95c_2d18);

/// Namespace of delivery ids, one per `(source, id, receiver)`.
const EVENT_DELIVERY_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x9d26_47e1_0b8c_4f35_a7e2_51c9_6d08_3fa4);

/// `parts` encoded so that no two different sequences give the same bytes:
/// each part is prefixed with its length.
fn identity_key(parts: &[&[u8]]) -> Vec<u8> {
    let mut key = Vec::with_capacity(parts.iter().map(|p| p.len() + 8).sum());
    for part in parts {
        key.extend_from_slice(&(part.len() as u64).to_be_bytes());
        key.extend_from_slice(part);
    }
    key
}

/// The transport family that carries an event type. Families never share
/// transport subjects; which family a type belongs to is fixed by
/// [`event_route`], never inferred from the type's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventFamily {
    /// Facts and work of the identity engine (CE, EE and SaaS tenants).
    Identity,
    /// Management facts of the private SaaS platform.
    Platform,
}

impl EventFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Platform => "platform",
        }
    }
}

/// How an event type travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventRoute {
    /// A fact: kept in the family's retained history for replay and
    /// observers, and owed to every receiver the deployment requires for
    /// its type.
    Fact(EventFamily),
    /// Work between named services: handed only to the receiver its producer
    /// addresses, never kept in history.
    Addressed(EventFamily),
}

impl EventRoute {
    pub const fn family(self) -> EventFamily {
        match self {
            Self::Fact(family) | Self::Addressed(family) => family,
        }
    }
}

/// The route of `event_type`; `None` for a type the registry does not know,
/// which is refused rather than routed anywhere.
pub fn event_route(event_type: &str) -> Option<EventRoute> {
    use event_types::{IDENTITY_ADDRESSED, IDENTITY_FACTS, PLATFORM_FACTS};
    if IDENTITY_FACTS.contains(&event_type) {
        Some(EventRoute::Fact(EventFamily::Identity))
    } else if IDENTITY_ADDRESSED.contains(&event_type) {
        Some(EventRoute::Addressed(EventFamily::Identity))
    } else if PLATFORM_FACTS.contains(&event_type) {
        Some(EventRoute::Fact(EventFamily::Platform))
    } else {
        None
    }
}

/// A logical service that receives addressed work: stable across restarts,
/// shared by its replicas, distinct per independent receiver. It is a
/// transport address token: ASCII letters, digits, `-` and `_`, 1-128
/// characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WorkRecipient(String);

impl WorkRecipient {
    pub fn new(name: impl Into<String>) -> crate::Result<Self> {
        let name = name.into();
        let valid = (1..=128).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if valid {
            Ok(Self(name))
        } else {
            Err(crate::Error::Validation(format!(
                "invalid work recipient: {name:?}"
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for WorkRecipient {
    type Error = crate::Error;

    fn try_from(name: String) -> crate::Result<Self> {
        Self::new(name)
    }
}

impl From<WorkRecipient> for String {
    fn from(recipient: WorkRecipient) -> Self {
        recipient.0
    }
}

impl std::fmt::Display for WorkRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A receiver the deployment requires for some fact types: every committed
/// fact whose type matches is owed to it, whether or not it is running.
#[derive(Debug, Clone)]
pub struct RequiredReceiver {
    pub recipient: WorkRecipient,
    /// Type patterns (exact, `prefix.*` or `prefix.>`); empty is every fact.
    pub event_types: Vec<String>,
}

impl RequiredReceiver {
    /// The receivers a deployment lists (comma-separated names, or `none`),
    /// each owed every fact: its own routing decides what it acts on. A name
    /// that is not an address token, or an empty one, is refused.
    pub fn parse_list(list: &str) -> crate::Result<Vec<Self>> {
        match list.trim() {
            "none" => Ok(Vec::new()),
            list => list
                .split(',')
                .map(|name| {
                    WorkRecipient::new(name.trim()).map(|recipient| Self {
                        recipient,
                        event_types: Vec::new(),
                    })
                })
                .collect(),
        }
    }

    pub fn requires(&self, event_type: &str) -> bool {
        self.event_types.is_empty()
            || self
                .event_types
                .iter()
                .any(|pattern| type_matches(pattern, event_type))
    }
}

/// The input of [`EVENT_FANOUT_KIND`] work: a fact and the receivers it is
/// owed to, fixed when the plan is first stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFanout {
    pub event: Event,
    pub receivers: Vec<WorkRecipient>,
}

/// The input of [`EVENT_DELIVERY_KIND`] work: one event for one receiver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDelivery {
    pub recipient: WorkRecipient,
    pub event: Event,
}

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

    /// The durable work that relays this fact once the mutation carrying it
    /// commits (transactional outbox). Its id follows from the event's
    /// `(source, id)`, so the same event is owed once however often the
    /// mutation is retried, and two producers' events never share it.
    pub fn relay(&self) -> NewWork {
        let kind = WorkKind::new(EVENT_RELAY_KIND).expect("the relay kind is valid");
        let payload = serde_json::to_vec(self).expect("an event serializes");
        let mut work = NewWork::new(kind, payload);
        work.id = self.relay_id();
        work.max_attempts = EVENT_RELAY_ATTEMPTS;
        work
    }

    /// The stable identity of this event's relay, one per `(source, id)`. It
    /// is also the transport's message id for the history publication.
    pub fn relay_id(&self) -> WorkId {
        WorkId(uuid::Uuid::new_v5(
            &EVENT_RELAY_NAMESPACE,
            &identity_key(&[self.source.as_bytes(), self.id.as_bytes()]),
        ))
    }

    /// The fan-out plan owing this fact to `receivers`. Its id follows from
    /// the event alone, not from the receivers, so the store keeps the plan
    /// first written: a retry under another configuration changes nothing.
    pub fn fanout(&self, receivers: &[WorkRecipient]) -> NewWork {
        /// [`EventFanout`] as written, borrowing what it carries.
        #[derive(Serialize)]
        struct Written<'a> {
            event: &'a Event,
            receivers: &'a [WorkRecipient],
        }
        let kind = WorkKind::new(EVENT_FANOUT_KIND).expect("the fan-out kind is valid");
        let payload = serde_json::to_vec(&Written {
            event: self,
            receivers,
        })
        .expect("a plan serializes");
        let mut work = NewWork::new(kind, payload);
        work.id = WorkId(uuid::Uuid::new_v5(
            &EVENT_FANOUT_NAMESPACE,
            self.relay_id().0.as_bytes(),
        ));
        work.max_attempts = EVENT_RELAY_ATTEMPTS;
        work
    }

    /// The stable identity of this event's handoff to `recipient`: the same
    /// across retries, distinct per receiver and per `(source, id)`. It is
    /// also the transport's message id for the handoff.
    pub fn delivery_id(&self, recipient: &WorkRecipient) -> WorkId {
        WorkId(uuid::Uuid::new_v5(
            &EVENT_DELIVERY_NAMESPACE,
            &identity_key(&[
                EVENT_DELIVERY_KIND.as_bytes(),
                self.source.as_bytes(),
                self.id.as_bytes(),
                recipient.as_str().as_bytes(),
            ]),
        ))
    }

    /// The durable work that hands this event to `recipient`, identified by
    /// [`Event::delivery_id`].
    pub fn deliver(&self, recipient: &WorkRecipient) -> NewWork {
        /// [`EventDelivery`] as written, borrowing what it carries.
        #[derive(Serialize)]
        struct Written<'a> {
            recipient: &'a WorkRecipient,
            event: &'a Event,
        }
        let kind = WorkKind::new(EVENT_DELIVERY_KIND).expect("the delivery kind is valid");
        let payload = serde_json::to_vec(&Written {
            recipient,
            event: self,
        })
        .expect("a delivery serializes");
        let mut work = NewWork::new(kind, payload);
        work.id = self.delivery_id(recipient);
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

    // Password history
    /// A first enrollment was aborted before it committed: the evaluator may
    /// reclaim the key it created for that operation. Internal to the
    /// credential authority and its evaluator; carries the operation and the
    /// owner's history input domain only.
    pub const PASSWORD_HISTORY_ENROLLMENT_ABORTED: &str =
        "sid.password_history.enrollment_aborted.v1";
    /// An owner's profile was deleted: the evaluator destroys the owner's
    /// history keys and lifecycle. Internal to the credential authority and
    /// its evaluator; carries the owner's history input domain only.
    pub const PASSWORD_HISTORY_OWNER_PURGED: &str = "sid.password_history.owner_purged.v1";
    /// A separate evaluator acted on a relayed cleanup (an aborted enrollment
    /// or a purged owner) and recorded it: the credential authority stops
    /// owing it. Carries the authority, the operation or the owner's history
    /// input domain only.
    pub const PASSWORD_HISTORY_CLEANUP_SETTLED: &str = "sid.password_history.cleanup_settled.v1";

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

    // Password reset
    pub const PASSWORD_RESET_REQUESTED: &str = "sid.auth.password_reset_requested.v1";
    pub const PASSWORD_RESET_COMPLETED: &str = "sid.auth.password_reset_completed.v1";

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
    pub const SCIM_OUTBOUND_FAILED: &str = "sid.scim.outbound_failed.v1";

    /// Facts of the identity engine.
    pub const IDENTITY_FACTS: &[&str] = &[
        USER_CREATED,
        USER_DEACTIVATED,
        USER_LOCKED,
        USER_UNLOCKED,
        USER_DELETED,
        PROFILE_CLAIM_CHANGED,
        PROFILE_EMAIL_CHANGED,
        SESSION_CREATED,
        SESSION_REVOKED,
        MFA_ENROLLED,
        MFA_DISABLED,
        MFA_RECOVERY_CODE_USED,
        SECURITY_BRUTE_FORCE,
        SECURITY_SUSPICIOUS_LOGIN,
        SECURITY_CREDENTIAL_ROTATED,
        SECURITY_COUNTRY_BLOCKED,
        SECURITY_TOR_BLOCKED,
        SECURITY_DATACENTER_IP,
        SECURITY_LOCATION_SWITCH,
        ADMIN_CREATED,
        ADMIN_POLICY_CHANGED,
        FEDERATION_PEER_CONNECTED,
        FEDERATION_PEER_DISCONNECTED,
        FEDERATION_SYNC_COMPLETED,
        CREDENTIAL_REVOKED,
        REFRESH_TOKEN_REVOKED,
        PROFILE_SUSPENDED,
        PROFILE_CLOSED,
        CONSENT_GRANTED,
        CONSENT_REVOKED,
        NOTIFY_DLQ,
        CERT_EXPIRING,
        CERT_ROTATED,
        CLOSURE_REQUESTED,
        CLOSURE_EXPORT_READY,
        CLOSURE_GRACE_PERIOD,
        CLOSURE_CANCELLED,
        CLOSURE_PURGED,
        PAT_CREATED,
        PAT_REVOKED,
        PAT_EXPIRED,
        MACHINE_USER_CREATED,
        MACHINE_USER_SUSPENDED,
        MACHINE_USER_CREDENTIAL_ROTATED,
        MACHINE_USER_CREDENTIAL_EXPIRING,
        MACHINE_USER_CREDENTIAL_EXPIRED,
        PROFILE_GRANT_CREATED,
        PROFILE_GRANT_REVOKED,
        PROFILE_GRANT_UPDATED,
        GOVERNANCE_ROLE_EXPIRING,
        GOVERNANCE_ROLE_EXPIRED,
        PRINCIPAL_CONTESTED,
        PRINCIPAL_LOST,
        PRINCIPAL_OWNERSHIP_SUPERSEDED,
        SCIM_USER_PROVISIONED,
        SCIM_USER_UPDATED,
        SCIM_USER_DEACTIVATED,
        SCIM_USER_REACTIVATED,
        SCIM_GROUP_CREATED,
        SCIM_GROUP_UPDATED,
        SCIM_GROUP_DELETED,
        SCIM_OUTBOUND_FAILED,
        PASSWORD_RESET_REQUESTED,
        PASSWORD_RESET_COMPLETED,
    ];

    /// Identity work addressed to a named receiver: the password-history
    /// cleanup between a credential authority and its separate evaluator.
    pub const IDENTITY_ADDRESSED: &[&str] = &[
        PASSWORD_HISTORY_ENROLLMENT_ABORTED,
        PASSWORD_HISTORY_OWNER_PURGED,
        PASSWORD_HISTORY_CLEANUP_SETTLED,
    ];

    /// Facts of the private SaaS platform; an identity runtime never
    /// publishes them.
    pub const PLATFORM_FACTS: &[&str] = &[ORG_TRIAL_ACTIVATED];
}

/// Whether the type pattern `pattern` (exact, `prefix.*` or `prefix.>`)
/// matches `event_type`.
fn type_matches(pattern: &str, event_type: &str) -> bool {
    match pattern
        .strip_suffix(".*")
        .or_else(|| pattern.strip_suffix(".>"))
    {
        Some(prefix) => event_type
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('.')),
        None => event_type == pattern,
    }
}

/// Filter of an observing subscription: each subscriber sees every matching
/// fact published while it is subscribed, and nothing is kept for it. Work
/// a receiver must not lose is consumed durably instead.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    /// Event type patterns to subscribe to (e.g., "sid.user.*", "sid.security.brute_force.v1").
    /// Empty = all events.
    pub event_types: Vec<String>,

    /// Attribute filters (key=value pairs). All must match.
    pub attributes: std::collections::HashMap<String, String>,
}

impl EventFilter {
    /// Check if an event matches this filter.
    pub fn matches(&self, event: &Event) -> bool {
        self.event_types.is_empty()
            || self
                .event_types
                .iter()
                .any(|pattern| type_matches(pattern, &event.event_type))
    }
}

#[cfg(test)]
mod tests;
