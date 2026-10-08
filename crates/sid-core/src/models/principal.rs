// SPDX-License-Identifier: AGPL-3.0-only
//! Principal domain model.
//!
//! A Principal is a **singleton entity** per (type, value) — e.g., there is exactly
//! one `Principal(Email, "alice@example.com")` in the system, regardless of how many
//! profiles reference it.
//!
//! **Every Principal is login-capable by design.** Contact-only data
//! (shared mailbox, display email) is a Profile Field, not a Principal.
//!
//! ## Entity vs Binding (Contestation Model)
//!
//! - **Principal** = the identifier entity. One per (type, value). Carries the one
//!   explicit assignment (`assigned_profile_id` + `assignment_revision`) that routes
//!   login, and the channel proof held by the assigned Profile.
//! - **PrincipalBinding** = a claim by a Profile. Several Profiles may claim one
//!   email; a claim alone never routes login.
//!
//! ## Assignment Rules
//!
//! - First use assigns a never-used principal to its sole claimant (routing only)
//! - A later claim changes neither the assignment nor its proof
//! - Proof expiry clears `verified` and keeps the assignment
//! - The assigned Profile releasing its claim clears the assignment without
//!   electing another claimant; the advanced revision keeps first use closed
//! - Transfer to another claimant needs fresh proof bound to the revision
//!
//! ## Data Projection
//!
//! When loaded via `get_principals_by_profile()`, binding-specific fields
//! (`profile_id`, `is_primary`, `source_field`, `source_email_id`, `source_phone_id`)
//! are projected from the JOIN onto the Principal struct for convenience.
//!

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ProfileEmailId, ProfileId, ProfilePhoneId};

/// The revision of an installation's own email policy (the fixed Personal
/// equality over its managed accounts) that email keys are derived under
/// now. Storage refuses an email principal written under any other revision.
pub const INSTALLATION_EMAIL_POLICY_REVISION: i64 = 1;

/// Unique identifier for a Principal record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalId(pub Uuid);

impl PrincipalId {
    /// Create a new random Principal ID (UUIDv7, time-ordered).
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for PrincipalId {
    fn default() -> Self {
        Self::new()
    }
}

/// Type of Principal (login handle).
///
/// 5 types, each with distinct auth flow and syntax:
/// - Email: contains `@`, federation-global, contestable
/// - Phone: starts with `+` (E.164), federation-global, contestable
/// - Username: no `@`/`+`, global (short) or federated (`user#domain`)
/// - FaceEmbedding: biometric, device-initiated, profile-scoped
/// - NfcTag: physical credential, device-initiated, profile-scoped
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    /// Email address (federation-global, contestable).
    Email,
    /// Phone number in E.164 format (federation-global, contestable).
    Phone,
    /// Username — global (`alice`, SaaS-curated) or federated (`alice#acme.corp`).
    /// Same type for both forms. `#` presence distinguishes them at login resolution.
    Username,
    /// Face embedding (biometric, profile-scoped).
    FaceEmbedding,
    /// NFC tag identifier (physical credential, profile-scoped).
    NfcTag,
}

impl PrincipalType {
    /// Whether several subjects may claim one value (email, phone). Every
    /// other type is a login handle held by one subject only.
    pub fn is_contestable(self) -> bool {
        matches!(self, Self::Email | Self::Phone)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Username => "username",
            Self::FaceEmbedding => "face_embedding",
            Self::NfcTag => "nfc_tag",
        }
    }
}

impl std::fmt::Display for PrincipalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for PrincipalType {
    type Err = UnknownPrincipalType;

    /// The inverse of [`as_str`](Self::as_str); nothing else is accepted.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "email" => Ok(Self::Email),
            "phone" => Ok(Self::Phone),
            "username" => Ok(Self::Username),
            "face_embedding" => Ok(Self::FaceEmbedding),
            "nfc_tag" => Ok(Self::NfcTag),
            other => Err(UnknownPrincipalType(other.to_owned())),
        }
    }
}

/// A stored or supplied principal type that names no [`PrincipalType`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown principal type {0:?}")]
pub struct UnknownPrincipalType(pub String);

/// A login handle — singleton entity per (type, value).
///
/// There is exactly ONE Principal per (type, value) in the system.
/// Multiple profiles can reference it via `PrincipalBinding`.
/// Contestation rules determine who can use it for login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,

    /// The Profile whose claim this is: populated from PrincipalBinding when
    /// loaded via `get_principals_by_profile()`.
    pub profile_id: ProfileId,

    pub principal_type: PrincipalType,

    /// The principal value (email address, phone number, username, etc.).
    /// Unique per principal_type.
    pub value: String,

    /// Whether this principal has been verified (OTP confirmed, KYC, etc.).
    pub verified: bool,

    /// When the last successful verification occurred (OTP confirmed, KYC passed, etc.).
    /// Used for: TTL computation, contestation (later verified_at wins), audit trail.
    /// None = never verified.
    pub verified_at: Option<DateTime<Utc>>,

    /// When the current verification expires (verified_at + policy TTL).
    /// After this time, background job sets `verified = false`.
    /// None = never expires (or never verified).
    /// Default TTL: email = 0 (never), phone = 180 days.
    pub verification_expires: Option<DateTime<Utc>>,

    /// The profile this principal routes login to. `None` once released;
    /// a claim alone never sets it.
    pub assigned_profile_id: Option<ProfileId>,

    /// Generation of the assignment: 0 before first use, advanced by every
    /// assignment change. A proof is bound to the revision it was issued for.
    pub assignment_revision: i64,

    /// For an email principal, the email policy revision its key was derived
    /// under (0: written before revisions, provenance unknown); `None` for
    /// every other type.
    pub email_policy_revision: Option<i64>,

    /// Whether this is the primary principal for its type within the binding.
    /// Populated from PrincipalBinding when loaded by profile.
    pub is_primary: bool,

    /// Legacy free-text source field reference ("email", "phone").
    /// Populated from PrincipalBinding when loaded by profile.
    pub source_field: Option<String>,

    /// FK to profile_emails entry this Principal was created from.
    /// Populated from PrincipalBinding when loaded by profile.
    pub source_email_id: Option<ProfileEmailId>,

    /// FK to profile_phones entry this Principal was created from.
    /// Populated from PrincipalBinding when loaded by profile.
    pub source_phone_id: Option<ProfilePhoneId>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The identifier entity alone: the `principals` row without any binding context.
///
/// Loaded by (type, value) for contestation checks, where the caller inspects
/// the bindings separately. Names no claiming Profile because the entity is
/// shared by every Profile that binds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalEntity {
    pub id: PrincipalId,
    pub principal_type: PrincipalType,
    pub value: String,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub verification_expires: Option<DateTime<Utc>>,
    pub assigned_profile_id: Option<ProfileId>,
    pub assignment_revision: i64,
    /// See [`Principal::email_policy_revision`].
    pub email_policy_revision: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl PrincipalEntity {
    /// Check if verification has expired.
    pub fn is_verification_expired(&self) -> bool {
        match self.verification_expires {
            Some(expires) => Utc::now() > expires,
            None => false, // no expiry set = never expires
        }
    }
}

impl From<&Principal> for PrincipalEntity {
    fn from(p: &Principal) -> Self {
        Self {
            id: p.id,
            principal_type: p.principal_type,
            value: p.value.clone(),
            verified: p.verified,
            verified_at: p.verified_at,
            verification_expires: p.verification_expires,
            assigned_profile_id: p.assigned_profile_id,
            assignment_revision: p.assignment_revision,
            email_policy_revision: p.email_policy_revision,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

/// Unique identifier for a PrincipalBinding record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalBindingId(pub Uuid);

impl PrincipalBindingId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for PrincipalBindingId {
    fn default() -> Self {
        Self::new()
    }
}

/// M:N relationship between a Principal entity and the Profiles claiming it.
///
/// Multiple profiles can bind the same Principal (email/phone).
/// Contestation rules (see `PrincipalEligibility`) determine which
/// bindings allow login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalBinding {
    pub id: PrincipalBindingId,

    /// Which Principal entity this binding references.
    pub principal_id: PrincipalId,

    /// The Profile claiming this principal.
    pub profile_id: ProfileId,

    /// Whether this is the primary principal for its type within the Profile.
    pub is_primary: bool,

    /// Which Profile Field this principal was derived from ("email", "phone").
    pub source_field: Option<String>,

    /// FK to profile_emails entry this binding was created from.
    pub source_email_id: Option<ProfileEmailId>,

    /// FK to profile_phones entry this binding was created from.
    pub source_phone_id: Option<ProfilePhoneId>,

    pub created_at: DateTime<Utc>,
}

impl PrincipalBinding {
    /// Create a new binding of `principal_id` to `profile_id`.
    pub fn new(principal_id: PrincipalId, profile_id: ProfileId) -> Self {
        Self {
            id: PrincipalBindingId::new(),
            principal_id,
            profile_id,
            is_primary: false,
            source_field: None,
            source_email_id: None,
            source_phone_id: None,
            created_at: Utc::now(),
        }
    }

    /// Create a binding with source field info (for email/phone principals).
    pub fn with_source(mut self, source_field: &str) -> Self {
        self.source_field = Some(source_field.to_string());
        self
    }

    /// Create a binding marked as primary.
    pub fn as_primary(mut self) -> Self {
        self.is_primary = true;
        self
    }
}

/// Whether a Profile may route login through a Principal.
///
/// Only the route: the Profile's own credentials, account status and access
/// policy (including proof freshness) still apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalEligibility {
    /// The Profile holds the assignment.
    Eligible,
    /// The Profile holds only a pending or displaced claim.
    NotAssigned,
    /// The Profile holds no claim on the principal.
    NotBound,
    /// An email key derived under another policy revision than the lookup's:
    /// kept reserved, never routed, until its address is established again.
    KeyNotCurrent,
}

impl PrincipalEligibility {
    /// Whether login may route to the Profile.
    pub fn is_eligible(&self) -> bool {
        matches!(self, PrincipalEligibility::Eligible)
    }
}

/// Check whether `profile_id` may route login through `principal`.
///
/// The explicit assignment decides; the number of other claims and the age
/// of the proof do not. `has_binding` guards the invariant that the assigned
/// Profile still holds its claim. `key_revision` is the email policy revision
/// the lookup key was derived under (`None` for other types): an email key of
/// another revision routes nowhere.
pub fn check_principal_eligibility(
    principal: &PrincipalEntity,
    profile_id: ProfileId,
    has_binding: bool,
    key_revision: Option<i64>,
) -> PrincipalEligibility {
    if principal.email_policy_revision != key_revision {
        return PrincipalEligibility::KeyNotCurrent;
    }
    if !has_binding {
        return PrincipalEligibility::NotBound;
    }
    if principal.assigned_profile_id == Some(profile_id) {
        PrincipalEligibility::Eligible
    } else {
        PrincipalEligibility::NotAssigned
    }
}

impl Principal {
    /// Create a new unverified principal claimed by `profile_id`.
    pub fn new(
        profile_id: ProfileId,
        principal_type: PrincipalType,
        value: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: PrincipalId::new(),
            profile_id,
            principal_type,
            value: value.into(),
            verified: false,
            verified_at: None,
            verification_expires: None,
            assigned_profile_id: None,
            assignment_revision: 0,
            // An email key is derived under the installation's policy.
            email_policy_revision: (principal_type == PrincipalType::Email)
                .then_some(INSTALLATION_EMAIL_POLICY_REVISION),
            is_primary: false,
            source_field: None,
            source_email_id: None,
            source_phone_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a new primary email principal (profile-bound).
    pub fn new_email(profile_id: ProfileId, email: impl Into<String>) -> Self {
        let mut p = Self::new(profile_id, PrincipalType::Email, email);
        p.is_primary = true;
        p.source_field = Some("email".to_string());
        p
    }

    /// Create a new phone principal (profile-bound).
    pub fn new_phone(profile_id: ProfileId, phone: impl Into<String>) -> Self {
        let mut p = Self::new(profile_id, PrincipalType::Phone, phone);
        p.source_field = Some("phone".to_string());
        p
    }

    /// Create a new username principal (profile-bound, global or federated).
    pub fn new_username(profile_id: ProfileId, username: impl Into<String>) -> Self {
        Self::new(profile_id, PrincipalType::Username, username)
    }

    /// Record channel proof for a principal about to be first bound by its
    /// subject. `ttl_days = 0` means the proof never expires. Storage takes
    /// this proof only when it creates the entity; an existing entity keeps
    /// its assignment and proof.
    pub fn verify(&mut self, ttl_days: u32) {
        let now = Utc::now();
        self.verified = true;
        self.verified_at = Some(now);
        self.verification_expires = if ttl_days > 0 {
            Some(now + chrono::Duration::days(i64::from(ttl_days)))
        } else {
            None
        };
        self.assigned_profile_id = Some(self.profile_id);
        self.updated_at = now;
    }

    /// This principal as seen by its loaded Profile: the entity's proof is
    /// the assigned Profile's, so any other claimant sees none.
    pub fn as_seen_by_subject(mut self) -> Self {
        if self.assigned_profile_id != Some(self.profile_id) {
            self.verified = false;
            self.verified_at = None;
            self.verification_expires = None;
        }
        self
    }

    /// Clear the proof after its lifetime; the assignment stays.
    pub fn expire_verification(&mut self) {
        self.verified = false;
        self.updated_at = Utc::now();
    }

    /// Check if verification has expired.
    pub fn is_verification_expired(&self) -> bool {
        match self.verification_expires {
            Some(expires) => Utc::now() > expires,
            None => false, // no expiry set = never expires
        }
    }

    /// The identifier entity without binding context.
    pub fn entity(&self) -> PrincipalEntity {
        PrincipalEntity::from(self)
    }

    /// Whether this is a federated username (contains `#`).
    pub fn is_federated_username(&self) -> bool {
        self.principal_type == PrincipalType::Username && self.value.contains('#')
    }

    /// Whether this is a global (short) username (no `#`).
    pub fn is_global_username(&self) -> bool {
        self.principal_type == PrincipalType::Username && !self.value.contains('#')
    }
}

#[cfg(test)]
mod tests;
