// SPDX-License-Identifier: AGPL-3.0-only
//! Consent and Claim Grant domain models.
//!
//! Tracks user consent for data sharing with external sites/services.
//! Every claim shared requires explicit consent; users can revoke at any time.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ProfileId;

/// Unique identifier for a consent record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsentId(pub Uuid);

impl ConsentId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ConsentId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a claim grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClaimGrantId(pub Uuid);

impl ClaimGrantId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ClaimGrantId {
    fn default() -> Self {
        Self::new()
    }
}

/// Claim requirement level — how important this claim is to the site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimLevel {
    /// Login impossible without this claim.
    Mandatory,
    /// Site strongly wants this claim with justification.
    HighlyDemanded,
    /// User may freely skip.
    Optional,
}

impl ClaimLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mandatory => "mandatory",
            Self::HighlyDemanded => "highly_demanded",
            Self::Optional => "optional",
        }
    }
}

impl std::fmt::Display for ClaimLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether the site requests the actual data or just an attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimType {
    /// Site receives the actual value (e.g., `email: alice@example.com`).
    Data,
    /// Site receives only verification status (e.g., `passport_verified: true`).
    Attestation,
}

impl ClaimType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Attestation => "attestation",
        }
    }
}

impl std::str::FromStr for ClaimType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "data" => Ok(Self::Data),
            "attestation" => Ok(Self::Attestation),
            other => Err(format!("unknown claim type: {other}")),
        }
    }
}

impl std::fmt::Display for ClaimType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Consent status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentStatus {
    /// Consent requested by site — awaiting user decision.
    #[default]
    Requested,
    /// User granted consent — claims are being shared.
    Active,
    /// User revoked consent — site must delete data.
    Revoked,
    /// Consent expired (TTL-based).
    Expired,
}

impl ConsentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_requested(&self) -> bool {
        matches!(self, Self::Requested)
    }
}

impl std::str::FromStr for ConsentStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "requested" => Ok(Self::Requested),
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            other => Err(format!("unknown consent status: {other}")),
        }
    }
}

impl std::fmt::Display for ConsentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Claim request — what a site asks for during OIDC client registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// Claim name (e.g., "email", "phone", "passport_verified").
    pub claim_name: String,

    /// How important this claim is.
    pub level: ClaimLevel,

    /// Whether this is a data request or attestation request.
    pub claim_type: ClaimType,

    /// Site-provided justification (required for HighlyDemanded).
    pub justification: Option<String>,
}

impl ClaimRequest {
    pub fn mandatory(name: impl Into<String>, claim_type: ClaimType) -> Self {
        Self {
            claim_name: name.into(),
            level: ClaimLevel::Mandatory,
            claim_type,
            justification: None,
        }
    }

    pub fn optional(name: impl Into<String>, claim_type: ClaimType) -> Self {
        Self {
            claim_name: name.into(),
            level: ClaimLevel::Optional,
            claim_type,
            justification: None,
        }
    }

    pub fn highly_demanded(
        name: impl Into<String>,
        claim_type: ClaimType,
        justification: impl Into<String>,
    ) -> Self {
        Self {
            claim_name: name.into(),
            level: ClaimLevel::HighlyDemanded,
            claim_type,
            justification: Some(justification.into()),
        }
    }
}

/// Claim grant — user's decision to share a specific claim with a site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimGrant {
    pub id: ClaimGrantId,

    /// Consent record this grant belongs to.
    pub consent_id: ConsentId,

    /// Claim name being granted.
    pub claim_name: String,

    /// Whether this grants data or attestation access.
    pub claim_type: ClaimType,

    /// When this grant was given.
    pub granted_at: DateTime<Utc>,

    /// When this grant was revoked (if revoked).
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ClaimGrant {
    pub fn new(
        consent_id: ConsentId,
        claim_name: impl Into<String>,
        claim_type: ClaimType,
    ) -> Self {
        Self {
            id: ClaimGrantId::new(),
            consent_id,
            claim_name: claim_name.into(),
            claim_type,
            granted_at: Utc::now(),
            revoked_at: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }

    pub fn revoke(&mut self) {
        if self.revoked_at.is_none() {
            self.revoked_at = Some(Utc::now());
        }
    }
}

/// Consent record — top-level consent decision for a profile→site relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub id: ConsentId,

    /// Profile granting consent.
    pub profile_id: ProfileId,

    /// OIDC client_id of the site receiving data.
    pub client_id: String,

    pub status: ConsentStatus,

    /// Individual claim grants within this consent.
    pub grants: Vec<ClaimGrant>,

    /// When consent was first given.
    pub consented_at: DateTime<Utc>,

    /// When consent was fully revoked (all claims).
    pub revoked_at: Option<DateTime<Utc>>,

    /// When consent was last updated (new grants or revocations).
    pub updated_at: DateTime<Utc>,
}

impl ConsentRecord {
    pub fn new(profile_id: ProfileId, client_id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: ConsentId::new(),
            profile_id,
            client_id: client_id.into(),
            status: ConsentStatus::Requested,
            grants: vec![],
            consented_at: now,
            revoked_at: None,
            updated_at: now,
        }
    }

    /// Grant a claim. A claim has one grant: granting a revoked claim again
    /// renews that grant, granting an active one changes nothing.
    pub fn grant_claim(&mut self, claim_name: impl Into<String>, claim_type: ClaimType) {
        let claim_name = claim_name.into();
        let now = Utc::now();
        match self.grants.iter_mut().find(|g| g.claim_name == claim_name) {
            Some(grant) if grant.is_active() => return,
            Some(grant) => {
                grant.claim_type = claim_type;
                grant.granted_at = now;
                grant.revoked_at = None;
            }
            None => self
                .grants
                .push(ClaimGrant::new(self.id, claim_name, claim_type)),
        }
        self.updated_at = now;
    }

    /// Gateway: obtain typed wrapper if consent is Requested (awaiting user decision).
    pub fn as_requested(&mut self) -> Option<RequestedConsent<'_>> {
        if self.status == ConsentStatus::Requested {
            Some(RequestedConsent(self))
        } else {
            None
        }
    }

    /// Gateway: obtain typed wrapper if consent is Active.
    pub fn as_active(&mut self) -> Option<ActiveConsent<'_>> {
        if self.status == ConsentStatus::Active {
            Some(ActiveConsent(self))
        } else {
            None
        }
    }

    /// Active (non-revoked) grants.
    pub fn active_grants(&self) -> Vec<&ClaimGrant> {
        self.grants.iter().filter(|g| g.is_active()).collect()
    }

    /// Whether this consent has any active grants.
    pub fn has_active_grants(&self) -> bool {
        self.grants.iter().any(|g| g.is_active())
    }

    /// Read-only accessor for status.
    pub fn status(&self) -> ConsentStatus {
        self.status
    }
}

/// A user's decision on one claim of an active consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimDecision {
    /// Share the claim, as data or as an attestation.
    Grant(ClaimType),
    /// Stop sharing it.
    Revoke,
}

/// Outcome of a [`ClaimDecision`] on a stored consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimGrantChange {
    /// The claim was granted or revoked.
    Changed,
    /// It already was: nothing written and nothing owed.
    Unchanged,
    /// The consent is gone or not active (awaiting a decision, revoked,
    /// expired): no claim of it changes.
    ConsentNotActive,
}

/// Typed wrapper for a Requested consent record (awaiting user decision).
pub struct RequestedConsent<'a>(&'a mut ConsentRecord);

impl<'a> RequestedConsent<'a> {
    /// User grants consent — transition to Active. Consumes wrapper.
    pub fn grant(self) {
        self.0.status = ConsentStatus::Active;
        self.0.updated_at = Utc::now();
    }

    /// User denies consent — transition to Revoked. Consumes wrapper.
    pub fn deny(self) {
        self.0.status = ConsentStatus::Revoked;
        self.0.revoked_at = Some(Utc::now());
        self.0.updated_at = Utc::now();
    }

    pub fn inner(&self) -> &ConsentRecord {
        self.0
    }
}

/// Typed wrapper for an Active consent record.
pub struct ActiveConsent<'a>(&'a mut ConsentRecord);

impl<'a> ActiveConsent<'a> {
    /// Revoke all claims — fully disconnect from site. Consumes wrapper.
    pub fn revoke_all(self) {
        for grant in &mut self.0.grants {
            grant.revoke();
        }
        self.0.status = ConsentStatus::Revoked;
        self.0.revoked_at = Some(Utc::now());
        self.0.updated_at = Utc::now();
    }

    /// Revoke a specific claim by name.
    pub fn revoke_claim(&mut self, claim_name: &str) {
        for grant in &mut self.0.grants {
            if grant.claim_name == claim_name && grant.is_active() {
                grant.revoke();
            }
        }
        self.0.updated_at = Utc::now();
    }

    pub fn inner(&self) -> &ConsentRecord {
        self.0
    }
}

#[cfg(test)]
mod tests;
