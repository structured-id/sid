// SPDX-License-Identifier: AGPL-3.0-only
//! Profile domain model.
//!
//! In StructuredID CE: Profile IS the user (no separate User entity).
//! CE instance IS the organization (implicit).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Validated UUIDv7 identifier of a profile; construction and decoding go through `sid_ids`.
pub use sid_ids::ProfileId;

/// Profile type.
///
/// Determines ownership model and identifier binding rules.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileType {
    /// Owned by its user, not by an organization.
    #[default]
    Personal,
    /// Corporate profile owned by an organization.
    Corporate,
}

impl ProfileType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Corporate => "corporate",
        }
    }
}

impl std::fmt::Display for ProfileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Profile status — full lifecycle including closure flow.
///
/// ```text
/// Provisioned (SCIM) → Active (the user claims via secure channel)
///                  ↓
/// Active → Suspended (admin, reversible)
///   ↓                    ↓
/// ClosureRequested → ExportAvailable → GracePeriod → Closed → Purged
///   ↑ (cancel)                ↑ (cancel)      ↑ (cancel)
///
/// Any non-terminal state → LegalHold (litigation freeze)
/// LegalHold → previous state (when hold lifted)
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileStatus {
    /// Normal operating state.
    #[default]
    Active,
    /// Corporate profile provisioned via SCIM but not yet claimed by its user.
    /// Org owns all fields. The user hasn't participated yet.
    /// Transitions: Provisioned → Active (claim), Provisioned → Suspended (admin).
    Provisioned,
    /// Temporarily disabled by admin. Can be re-activated.
    Suspended,
    /// Profile owner requested closure. Export may be in progress.
    ClosureRequested,
    /// Data export is ready for download.
    ExportAvailable,
    /// Grace period before permanent closure (data still accessible).
    GracePeriod,
    /// Litigation hold — freezes closure, prevents data deletion.
    LegalHold,
    /// Permanently closed. Identifiers quarantined. Data retained for legal.
    Closed,
    /// All data cryptographically shredded. Terminal state.
    Purged,
}

impl ProfileStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Provisioned => "provisioned",
            Self::Suspended => "suspended",
            Self::ClosureRequested => "closure_requested",
            Self::ExportAvailable => "export_available",
            Self::GracePeriod => "grace_period",
            Self::LegalHold => "legal_hold",
            Self::Closed => "closed",
            Self::Purged => "purged",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether the profile is provisioned but not yet claimed by its user.
    pub fn is_provisioned(&self) -> bool {
        matches!(self, Self::Provisioned)
    }

    /// Whether the profile can create NEW sessions (login).
    /// Provisioned profiles cannot authenticate: the user must claim first.
    /// All closure states block new sessions per arch spec.
    pub fn can_authenticate(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether the profile has read-only access (e.g. export download, cancellation).
    pub fn can_access_read_only(&self) -> bool {
        matches!(
            self,
            Self::Active | Self::ClosureRequested | Self::ExportAvailable | Self::GracePeriod
        )
    }

    /// Whether the profile is in a closure flow (not yet terminal).
    pub fn is_closing(&self) -> bool {
        matches!(
            self,
            Self::ClosureRequested | Self::ExportAvailable | Self::GracePeriod
        )
    }

    /// Whether this is a terminal state (no further transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed | Self::Purged)
    }

    /// Whether data deletion is blocked (legal hold or terminal).
    pub fn is_frozen(&self) -> bool {
        matches!(self, Self::LegalHold)
    }

    /// Validate state transition. Returns Ok(new_state) if allowed.
    pub fn transition_to(&self, target: ProfileStatus) -> Result<ProfileStatus, &'static str> {
        match (self, target) {
            // Provisioned → Active (the user claims), Suspended (admin deactivates)
            (Self::Provisioned, Self::Active) => Ok(target),
            (Self::Provisioned, Self::Suspended) => Ok(target),
            // Active → Suspended, ClosureRequested
            (Self::Active, Self::Suspended) => Ok(target),
            (Self::Active, Self::ClosureRequested) => Ok(target),
            // Suspended → Active (re-activate), ClosureRequested
            (Self::Suspended, Self::Active) => Ok(target),
            (Self::Suspended, Self::ClosureRequested) => Ok(target),
            // ClosureRequested → Active (cancel), ExportAvailable, GracePeriod
            (Self::ClosureRequested, Self::Active) => Ok(target),
            (Self::ClosureRequested, Self::ExportAvailable) => Ok(target),
            (Self::ClosureRequested, Self::GracePeriod) => Ok(target),
            // ExportAvailable → Active (cancel), GracePeriod
            (Self::ExportAvailable, Self::Active) => Ok(target),
            (Self::ExportAvailable, Self::GracePeriod) => Ok(target),
            // GracePeriod → Active (cancel), Closed
            (Self::GracePeriod, Self::Active) => Ok(target),
            (Self::GracePeriod, Self::Closed) => Ok(target),
            // Closed → Purged
            (Self::Closed, Self::Purged) => Ok(target),
            // Any non-terminal → LegalHold
            (from, Self::LegalHold) if !from.is_terminal() => Ok(target),
            // LegalHold → any non-terminal state (restore previous)
            (Self::LegalHold, to) if !to.is_terminal() => Ok(to),
            // Same state = no-op
            (from, to) if *from == to => Ok(target),
            // Everything else is invalid
            _ => Err("invalid profile status transition"),
        }
    }
}

/// Reason for account closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosureMode {
    /// User voluntarily closes their account.
    Voluntary,
    /// GDPR Article 17 — Right to Erasure.
    GdprErasure,
    /// Admin-initiated termination.
    AdminTermination,
    /// Regulatory or legal order.
    RegulatoryOrder,
}

impl ClosureMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Voluntary => "voluntary",
            Self::GdprErasure => "gdpr_erasure",
            Self::AdminTermination => "admin_termination",
            Self::RegulatoryOrder => "regulatory_order",
        }
    }

    /// CE hardcoded grace period (days) per closure mode.
    pub fn max_grace_period_days(&self) -> u32 {
        match self {
            Self::Voluntary => 30,
            Self::GdprErasure => 30,
            Self::AdminTermination => 7,
            Self::RegulatoryOrder => 0,
        }
    }

    /// Whether this mode allows cancellation.
    pub fn is_cancellable(&self) -> bool {
        matches!(self, Self::Voluntary | Self::GdprErasure)
    }
}

impl std::str::FromStr for ClosureMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "voluntary" => Ok(Self::Voluntary),
            "gdpr_erasure" => Ok(Self::GdprErasure),
            "admin_termination" => Ok(Self::AdminTermination),
            "regulatory_order" => Ok(Self::RegulatoryOrder),
            other => Err(format!("unknown closure mode: {other}")),
        }
    }
}

impl std::fmt::Display for ClosureMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Export status for account closure data portability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportStatus {
    /// Export not yet started.
    #[default]
    NotStarted,
    /// Export is being prepared.
    Preparing,
    /// Export ready for download.
    Ready,
    /// Export downloaded by user.
    Downloaded,
    /// Export expired (download window closed).
    Expired,
}

impl ExportStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Preparing => "preparing",
            Self::Ready => "ready",
            Self::Downloaded => "downloaded",
            Self::Expired => "expired",
        }
    }
}

impl std::str::FromStr for ExportStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "not_started" => Ok(Self::NotStarted),
            "preparing" => Ok(Self::Preparing),
            "ready" => Ok(Self::Ready),
            "downloaded" => Ok(Self::Downloaded),
            "expired" => Ok(Self::Expired),
            other => Err(format!("unknown export status: {other}")),
        }
    }
}

/// Export format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    #[default]
    Json,
}

impl ExportFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
        }
    }
}

impl std::str::FromStr for ExportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::Json),
            other => Err(format!("unknown export format: {other}")),
        }
    }
}

/// Export download window duration (72 hours).
pub const EXPORT_DOWNLOAD_WINDOW_HOURS: u32 = 72;

/// Data export job — tracks async export preparation and download.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportJob {
    /// Unique export job ID.
    pub id: uuid::Uuid,
    /// Profile requesting the export.
    pub profile_id: ProfileId,
    /// Export format.
    pub format: ExportFormat,
    /// Current status.
    pub status: ExportStatus,
    /// Path to the export archive on disk/blob store.
    pub archive_path: Option<String>,
    /// Size of the export archive in bytes.
    pub size_bytes: Option<i64>,
    /// SHA-256 checksum of the archive.
    pub checksum_sha256: Option<String>,
    /// When the export was requested.
    pub created_at: DateTime<Utc>,
    /// When the export became ready.
    pub ready_at: Option<DateTime<Utc>>,
    /// When the download window expires.
    pub expires_at: Option<DateTime<Utc>>,
}

impl ExportJob {
    pub fn new(profile_id: ProfileId, format: ExportFormat) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            profile_id,
            format,
            status: ExportStatus::Preparing,
            archive_path: None,
            size_bytes: None,
            checksum_sha256: None,
            created_at: Utc::now(),
            ready_at: None,
            expires_at: None,
        }
    }

    /// Mark export as ready with archive metadata.
    pub fn mark_ready(&mut self, archive_path: String, size_bytes: i64, checksum: String) {
        self.status = ExportStatus::Ready;
        self.archive_path = Some(archive_path);
        self.size_bytes = Some(size_bytes);
        self.checksum_sha256 = Some(checksum);
        self.ready_at = Some(Utc::now());
        self.expires_at =
            Some(Utc::now() + chrono::Duration::hours(i64::from(EXPORT_DOWNLOAD_WINDOW_HOURS)));
    }

    /// Mark as downloaded.
    pub fn mark_downloaded(&mut self) {
        self.status = ExportStatus::Downloaded;
    }

    /// Check if download window has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Utc::now() >= exp)
    }
}

/// Legal hold information — freezes account closure for litigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalHold {
    /// Court case or legal reference.
    pub court_reference: String,

    /// Reason for the hold.
    pub reason: Option<String>,

    /// When the hold was placed.
    pub placed_at: DateTime<Utc>,

    /// Expected duration (informational, hold stays until explicitly lifted).
    pub expected_end: Option<DateTime<Utc>>,

    /// Who placed the hold (admin profile_id).
    pub placed_by: ProfileId,

    /// Contact for status inquiries (e.g., legal counsel email).
    pub reviewing_counsel: Option<String>,

    /// Profile status before the hold was placed (restored when lifted).
    pub previous_status: ProfileStatus,
}

/// Tracks an in-progress account closure request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosureRequest {
    /// Profile being closed.
    pub profile_id: ProfileId,

    /// Why the account is being closed.
    pub mode: ClosureMode,

    /// Human-readable closure reason (for audit trail).
    pub closure_reason: Option<String>,

    /// Who initiated the closure (profile_id of admin, or self).
    pub requested_by: ProfileId,

    /// When closure was requested.
    pub requested_at: DateTime<Utc>,

    /// When the grace period ends (after which Closed transition happens).
    pub grace_period_end: Option<DateTime<Utc>>,

    /// Data export status.
    pub export_status: ExportStatus,

    /// Active legal hold (if any). Freezes closure progression.
    pub legal_hold: Option<LegalHold>,

    /// Number of times closure was cancelled and re-requested.
    pub cancel_count: u32,
}

impl ClosureRequest {
    pub fn new(profile_id: ProfileId, mode: ClosureMode, requested_by: ProfileId) -> Self {
        Self {
            profile_id,
            mode,
            closure_reason: None,
            requested_by,
            requested_at: Utc::now(),
            grace_period_end: None,
            export_status: ExportStatus::NotStarted,
            legal_hold: None,
            cancel_count: 0,
        }
    }

    /// Whether the grace period has elapsed.
    pub fn grace_period_elapsed(&self) -> bool {
        match self.grace_period_end {
            Some(end) => Utc::now() >= end,
            None => false,
        }
    }

    /// Set grace period from now.
    pub fn with_grace_period_days(mut self, days: u32) -> Self {
        self.grace_period_end = Some(self.requested_at + chrono::Duration::days(days as i64));
        self
    }
}

impl std::fmt::Display for ProfileStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Profile identity assurance level — how thoroughly identity claims are verified.
///
/// This is a DERIVED value (computed from the highest currently valid verification).
/// Different from `AuthLevel` (session authentication assurance).
///
/// Trust is relational: same profile may be accepted by one consumer and rejected
/// by another based on their acceptance policies.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ProfileAssurance {
    /// No verification. Pseudonymous identity.
    #[default]
    Anonymous,
    /// Email or phone verified (OTP confirmation).
    SelfDeclared,
    /// Third-party attestation (employer, edu, social login provider).
    Attested,
    /// Government ID or equivalent KYC (passport, NFC ePassport, eID).
    Verified,
    /// Notarized / in-person verification + continuous monitoring.
    Certified,
}

impl ProfileAssurance {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::SelfDeclared => "self_declared",
            Self::Attested => "attested",
            Self::Verified => "verified",
            Self::Certified => "certified",
        }
    }

    /// Whether this level satisfies a minimum requirement.
    pub fn satisfies(&self, min: ProfileAssurance) -> bool {
        *self >= min
    }
}

impl std::fmt::Display for ProfileAssurance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Max closure cancel/re-request cycles per calendar year.
pub const MAX_CANCEL_CYCLES_PER_YEAR: u32 = 3;

/// Identifier quarantine duration after closure (days) — email and phone.
pub const IDENTIFIER_QUARANTINE_DAYS: u32 = 90;

/// Profile visibility.
///
/// Controls whether the profile is discoverable by other entities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileVisibility {
    /// Discoverable by other profiles/sites.
    #[default]
    Public,
    /// Hidden; requires PIN or direct link.
    Private,
}

impl ProfileVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

impl std::fmt::Display for ProfileVisibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

parse_stored!(ProfileType, "profile type", [Personal, Corporate]);
parse_stored!(
    ProfileStatus,
    "profile status",
    [
        Active,
        Provisioned,
        Suspended,
        ClosureRequested,
        ExportAvailable,
        GracePeriod,
        LegalHold,
        Closed,
        Purged,
    ]
);
parse_stored!(
    ProfileAssurance,
    "profile assurance",
    [Anonymous, SelfDeclared, Attested, Verified, Certified]
);
parse_stored!(ProfileVisibility, "profile visibility", [Public, Private]);

/// Profile represents a user identity in StructuredID.
///
/// A Profile IS the user (no separate User entity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: ProfileId,

    /// Profile type (personal or corporate).
    pub profile_type: ProfileType,

    /// Username (CE: local login handle). None = registered via email/phone only.
    /// Username is a valuable identity — never auto-generated. User claims it explicitly.
    pub username: Option<String>,

    // Email and phone are multi-valued: see profile_emails / profile_phones tables.
    // OIDC email/phone_number claims read from primary verified entry.

    // ─── Structured name (OIDC + SCIM compliant) ────────────────────
    /// Given name(s) / first name(s). Space-separated for multiple.
    pub given_name: Option<String>,
    /// Family name(s) / surname(s). OPTIONAL — supports mononyms.
    pub family_name: Option<String>,
    /// Middle name(s), patronymic, or generational suffix (space-separated).
    pub middle_name: Option<String>,
    /// Honorific prefix: "Dr.", "Prof.", "Sheikh", "Haji".
    pub honorific_prefix: Option<String>,
    /// Honorific suffix: "Jr.", "III", "PhD", "Esq.".
    pub honorific_suffix: Option<String>,

    /// Roles (e.g. ["admin"]).
    pub roles: Vec<String>,

    /// Account status (active / suspended / closed).
    pub status: ProfileStatus,

    /// Identity assurance level (derived from verifications, used as fast gate).
    pub max_assurance: ProfileAssurance,

    /// Profile visibility (public / private).
    pub visibility: ProfileVisibility,

    /// Manager profile (SCIM `manager` attribute, org chart reference).
    pub manager_id: Option<ProfileId>,

    // ─── Migration tracking (INTEG-008) ─────────────────────────────
    /// Whether this profile has a pending password migration (legacy hash → OPAQUE).
    #[serde(default)]
    pub migration_pending: bool,
    /// When the migration was first initiated (profile imported with legacy hash).
    pub migration_started_at: Option<DateTime<Utc>>,
    /// When the migration was completed (OPAQUE registration finished).
    pub migration_completed_at: Option<DateTime<Utc>>,

    /// Stored revision: 0 for a new profile, moved on by every update. An
    /// update applies only over the revision it was read at, so a stale copy
    /// never writes back a status, role or name changed since.
    pub revision: u64,

    /// Timestamps.
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Profile {
    /// Compute the OIDC `name` claim from structured name components.
    ///
    /// Western default order: [prefix] given [middle] family [suffix].
    /// Returns `None` if no name components are set.
    pub fn formatted_name(&self) -> Option<String> {
        let parts: Vec<&str> = [
            self.honorific_prefix.as_deref(),
            self.given_name.as_deref(),
            self.middle_name.as_deref(),
            self.family_name.as_deref(),
            self.honorific_suffix.as_deref(),
        ]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .collect();

        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn is_admin(&self) -> bool {
        self.has_role("admin")
    }

    /// Create a new personal profile with an optional username.
    /// Username is None when user registers via email or phone only.
    pub fn new(username: Option<impl Into<String>>) -> Self {
        let now = Utc::now();
        Self {
            id: ProfileId::generate(),
            profile_type: ProfileType::Personal,
            username: username.map(|u| u.into()),
            given_name: None,
            family_name: None,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
            roles: vec![],
            status: ProfileStatus::Active,
            max_assurance: ProfileAssurance::Anonymous,
            visibility: ProfileVisibility::Public,
            manager_id: None,
            migration_pending: false,
            migration_started_at: None,
            migration_completed_at: None,
            revision: 0,
            created_at: now,
            updated_at: now,
        }
    }
}

// ── Transition Gateway wrappers ──────────────────────────────────────

/// Typed wrapper for a profile in Active state.
///
/// All transition methods consume `self`, preventing:
/// - Calling both `suspend()` and `request_closure()` on the same profile
/// - Transitioning from a non-Active state
pub struct ActiveProfile<'a>(&'a mut Profile);

impl<'a> ActiveProfile<'a> {
    /// Suspend this profile (admin action). Consumes the wrapper.
    pub fn suspend(self) {
        self.0.status = ProfileStatus::Suspended;
        self.0.updated_at = Utc::now();
    }

    /// Request account closure. Consumes the wrapper.
    pub fn request_closure(self) {
        self.0.status = ProfileStatus::ClosureRequested;
        self.0.updated_at = Utc::now();
    }

    /// Place a legal hold. Consumes the wrapper.
    pub fn place_legal_hold(self) {
        self.0.status = ProfileStatus::LegalHold;
        self.0.updated_at = Utc::now();
    }

    /// Read-only access to the inner profile.
    pub fn inner(&self) -> &Profile {
        self.0
    }
}

/// Typed wrapper for a profile in Suspended state.
pub struct SuspendedProfile<'a>(&'a mut Profile);

impl<'a> SuspendedProfile<'a> {
    /// Re-activate this profile. Consumes the wrapper.
    pub fn reactivate(self) {
        self.0.status = ProfileStatus::Active;
        self.0.updated_at = Utc::now();
    }

    /// Request closure while suspended. Consumes the wrapper.
    pub fn request_closure(self) {
        self.0.status = ProfileStatus::ClosureRequested;
        self.0.updated_at = Utc::now();
    }

    /// Read-only access to the inner profile.
    pub fn inner(&self) -> &Profile {
        self.0
    }
}

/// Typed wrapper for a profile in a closure flow
/// (ClosureRequested, ExportAvailable, or GracePeriod).
pub struct ClosingProfile<'a>(&'a mut Profile);

impl<'a> ClosingProfile<'a> {
    /// Cancel closure — restore to Active. Consumes the wrapper.
    pub fn cancel(self) {
        self.0.status = ProfileStatus::Active;
        self.0.updated_at = Utc::now();
    }

    /// Advance to ExportAvailable. Consumes the wrapper.
    ///
    /// Only valid from ClosureRequested.
    pub fn export_available(self) -> Result<(), &'static str> {
        let new = self
            .0
            .status
            .transition_to(ProfileStatus::ExportAvailable)?;
        self.0.status = new;
        self.0.updated_at = Utc::now();
        Ok(())
    }

    /// Advance to GracePeriod. Consumes the wrapper.
    ///
    /// Valid from ClosureRequested or ExportAvailable.
    pub fn start_grace_period(self) -> Result<(), &'static str> {
        let new = self.0.status.transition_to(ProfileStatus::GracePeriod)?;
        self.0.status = new;
        self.0.updated_at = Utc::now();
        Ok(())
    }

    /// Close the profile. Consumes the wrapper.
    ///
    /// Only valid from GracePeriod.
    pub fn close(self) -> Result<(), &'static str> {
        let new = self.0.status.transition_to(ProfileStatus::Closed)?;
        self.0.status = new;
        self.0.updated_at = Utc::now();
        Ok(())
    }

    /// Place a legal hold. Consumes the wrapper.
    pub fn place_legal_hold(self) {
        self.0.status = ProfileStatus::LegalHold;
        self.0.updated_at = Utc::now();
    }

    /// Read-only access to the inner profile.
    pub fn inner(&self) -> &Profile {
        self.0
    }
}

/// Typed wrapper for a profile in Closed state.
pub struct ClosedProfile<'a>(&'a mut Profile);

impl<'a> ClosedProfile<'a> {
    /// Purge all data (terminal transition). Consumes the wrapper.
    pub fn purge(self) {
        self.0.status = ProfileStatus::Purged;
        self.0.updated_at = Utc::now();
    }

    /// Read-only access to the inner profile.
    pub fn inner(&self) -> &Profile {
        self.0
    }
}

impl Profile {
    /// Gateway: obtain typed wrapper if profile is Active.
    pub fn as_active(&mut self) -> Option<ActiveProfile<'_>> {
        if self.status == ProfileStatus::Active {
            Some(ActiveProfile(self))
        } else {
            None
        }
    }

    /// Gateway: obtain typed wrapper if profile is Suspended.
    pub fn as_suspended(&mut self) -> Option<SuspendedProfile<'_>> {
        if self.status == ProfileStatus::Suspended {
            Some(SuspendedProfile(self))
        } else {
            None
        }
    }

    /// Gateway: obtain typed wrapper if profile is in a closure flow.
    pub fn as_closing(&mut self) -> Option<ClosingProfile<'_>> {
        if self.status.is_closing() {
            Some(ClosingProfile(self))
        } else {
            None
        }
    }

    /// Gateway: obtain typed wrapper if profile is Closed.
    pub fn as_closed(&mut self) -> Option<ClosedProfile<'_>> {
        if self.status == ProfileStatus::Closed {
            Some(ClosedProfile(self))
        } else {
            None
        }
    }

    /// Admin override: transition status with validation.
    ///
    /// Uses `ProfileStatus::transition_to()` validation. Prefer gateway
    /// wrappers for normal code paths — this is for admin APIs that accept
    /// arbitrary target status strings.
    pub fn transition_status(&mut self, target: ProfileStatus) -> Result<(), &'static str> {
        let new = self.status.transition_to(target)?;
        self.status = new;
        self.updated_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
