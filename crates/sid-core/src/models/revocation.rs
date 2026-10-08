// SPDX-License-Identifier: AGPL-3.0-only
//! Revocation cascade domain model.
//!
//! Tracks revocation requests and their cascading effects across entities.
//! Used for audit trail and ensuring complete revocation of dependent resources.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a revocation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RevocationId(pub Uuid);

impl RevocationId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for RevocationId {
    fn default() -> Self {
        Self::new()
    }
}

/// What kind of entity is being revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationTarget {
    /// User profile (account closure).
    Profile,
    /// Active session.
    Session,
    /// Authentication credential.
    Credential,
    /// Personal access token.
    Pat,
    /// Machine user (service account).
    MachineUser,
    /// Device trust.
    Device,
    /// Consent / claim grant.
    Consent,
    /// OAuth2 refresh token.
    RefreshToken,
    /// Role assignment / profile grant.
    ProfileGrant,
    /// OIDC application (triggers back-channel logout).
    Application,
}

impl RevocationTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Session => "session",
            Self::Credential => "credential",
            Self::Pat => "pat",
            Self::MachineUser => "machine_user",
            Self::Device => "device",
            Self::Consent => "consent",
            Self::RefreshToken => "refresh_token",
            Self::ProfileGrant => "profile_grant",
            Self::Application => "application",
        }
    }
}

impl std::fmt::Display for RevocationTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why revocation was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// User requested (voluntary).
    UserRequested,
    /// Admin action (suspension, termination).
    Admin,
    /// Anomaly detected (suspicious activity, impossible travel).
    AnomalyDetected,
    /// Emergency response (breach, compromise).
    Emergency,
    /// Expiration (TTL exceeded).
    Expired,
    /// Cascade from parent entity revocation.
    Cascade,
    /// GDPR erasure request.
    GdprErasure,
    /// Regulatory order (court, government).
    RegulatoryOrder,
    /// A newer session of the profile took its place under the
    /// concurrent-session limit.
    SessionLimit,
}

impl RevocationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserRequested => "user_requested",
            Self::Admin => "admin",
            Self::AnomalyDetected => "anomaly_detected",
            Self::Emergency => "emergency",
            Self::Expired => "expired",
            Self::Cascade => "cascade",
            Self::GdprErasure => "gdpr_erasure",
            Self::RegulatoryOrder => "regulatory_order",
            Self::SessionLimit => "session_limit",
        }
    }

    /// Whether this reason requires immediate revocation (no grace period).
    pub fn is_immediate(&self) -> bool {
        matches!(
            self,
            Self::Emergency | Self::AnomalyDetected | Self::RegulatoryOrder
        )
    }
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Revocation mode — how aggressively to revoke.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationMode {
    /// Immediate and complete. No grace period. All dependent entities revoked.
    #[default]
    Hard,
    /// Allow grace period for dependent entities to wind down.
    Graceful,
    /// Mark as revoked but don't cascade — entity-level only.
    Soft,
}

impl RevocationMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hard => "hard",
            Self::Graceful => "graceful",
            Self::Soft => "soft",
        }
    }
}

impl std::fmt::Display for RevocationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Cascade propagation tier — how fast the revocation propagates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CascadeTier {
    /// Tier 1: Immediate (sessions, active tokens) — sub-second.
    Immediate,
    /// Tier 2: Fast (credentials, PATs, devices) — seconds.
    Fast,
    /// Tier 3: CRL/OCSP (certificates, federated assertions) — minutes.
    Crl,
    /// Tier 4: Federated (downstream IdPs, SCIM deprovisioning) — hours.
    Federated,
}

impl CascadeTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::Fast => "fast",
            Self::Crl => "crl",
            Self::Federated => "federated",
        }
    }
}

impl std::fmt::Display for CascadeTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single entity affected by cascade revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CascadeEntry {
    /// What was revoked.
    pub target: RevocationTarget,
    /// ID of the revoked entity.
    pub entity_id: String,
    /// Which tier this revocation falls into.
    pub tier: CascadeTier,
    /// When this entity was revoked.
    pub revoked_at: DateTime<Utc>,
}

/// Revocation request — tracks a revocation and its cascade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    pub id: RevocationId,

    /// Primary entity being revoked.
    pub target: RevocationTarget,
    /// ID of the primary entity.
    pub entity_id: String,

    pub reason: RevocationReason,
    pub mode: RevocationMode,

    /// Who initiated the revocation (profile ID, admin ID, or "system").
    pub initiated_by: String,

    /// Entities revoked as part of the cascade.
    pub cascade_entries: Vec<CascadeEntry>,

    pub created_at: DateTime<Utc>,
    /// When all cascade tiers completed.
    pub completed_at: Option<DateTime<Utc>>,
}

impl RevocationRequest {
    pub fn new(
        target: RevocationTarget,
        entity_id: impl Into<String>,
        reason: RevocationReason,
        initiated_by: impl Into<String>,
    ) -> Self {
        Self {
            id: RevocationId::new(),
            target,
            entity_id: entity_id.into(),
            reason,
            mode: if reason.is_immediate() {
                RevocationMode::Hard
            } else {
                RevocationMode::Graceful
            },
            initiated_by: initiated_by.into(),
            cascade_entries: vec![],
            created_at: Utc::now(),
            completed_at: None,
        }
    }

    /// Record a cascaded revocation.
    pub fn add_cascade(
        &mut self,
        target: RevocationTarget,
        entity_id: impl Into<String>,
        tier: CascadeTier,
    ) {
        self.cascade_entries.push(CascadeEntry {
            target,
            entity_id: entity_id.into(),
            tier,
            revoked_at: Utc::now(),
        });
    }

    /// Mark the cascade as fully completed.
    pub fn complete(&mut self) {
        self.completed_at = Some(Utc::now());
    }

    /// Total number of entities revoked (primary + cascade).
    pub fn total_revoked(&self) -> usize {
        1 + self.cascade_entries.len()
    }

    /// Whether all tiers have completed.
    pub fn is_complete(&self) -> bool {
        self.completed_at.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_revocation() -> RevocationRequest {
        RevocationRequest::new(
            RevocationTarget::Profile,
            "profile-uuid-123",
            RevocationReason::UserRequested,
            "profile-uuid-123",
        )
    }

    #[test]
    fn test_revocation_new() {
        let r = make_revocation();
        assert_eq!(r.target, RevocationTarget::Profile);
        assert_eq!(r.entity_id, "profile-uuid-123");
        assert_eq!(r.reason, RevocationReason::UserRequested);
        assert_eq!(r.mode, RevocationMode::Graceful); // Not immediate.
        assert!(r.cascade_entries.is_empty());
        assert!(!r.is_complete());
        assert_eq!(r.total_revoked(), 1);
    }

    #[test]
    fn test_emergency_is_hard() {
        let r = RevocationRequest::new(
            RevocationTarget::Profile,
            "id",
            RevocationReason::Emergency,
            "admin",
        );
        assert_eq!(r.mode, RevocationMode::Hard);
    }

    #[test]
    fn test_anomaly_is_hard() {
        let r = RevocationRequest::new(
            RevocationTarget::Session,
            "id",
            RevocationReason::AnomalyDetected,
            "system",
        );
        assert_eq!(r.mode, RevocationMode::Hard);
    }

    #[test]
    fn test_add_cascade() {
        let mut r = make_revocation();
        r.add_cascade(
            RevocationTarget::Session,
            "session-1",
            CascadeTier::Immediate,
        );
        r.add_cascade(RevocationTarget::Pat, "pat-1", CascadeTier::Fast);
        r.add_cascade(
            RevocationTarget::Consent,
            "consent-1",
            CascadeTier::Federated,
        );

        assert_eq!(r.cascade_entries.len(), 3);
        assert_eq!(r.total_revoked(), 4); // 1 primary + 3 cascade.
    }

    #[test]
    fn test_complete() {
        let mut r = make_revocation();
        assert!(!r.is_complete());
        r.complete();
        assert!(r.is_complete());
        assert!(r.completed_at.is_some());
    }

    #[test]
    fn test_reason_is_immediate() {
        assert!(!RevocationReason::UserRequested.is_immediate());
        assert!(!RevocationReason::Admin.is_immediate());
        assert!(!RevocationReason::Expired.is_immediate());
        assert!(!RevocationReason::GdprErasure.is_immediate());

        assert!(RevocationReason::Emergency.is_immediate());
        assert!(RevocationReason::AnomalyDetected.is_immediate());
        assert!(RevocationReason::RegulatoryOrder.is_immediate());
    }

    #[test]
    fn test_revocation_target_serde() {
        let t = RevocationTarget::MachineUser;
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"machine_user\"");
        let parsed: RevocationTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, RevocationTarget::MachineUser);
    }

    #[test]
    fn test_revocation_reason_serde() {
        let r = RevocationReason::GdprErasure;
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "\"gdpr_erasure\"");
        let parsed: RevocationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, RevocationReason::GdprErasure);
    }

    #[test]
    fn test_revocation_mode_serde() {
        let m = RevocationMode::Graceful;
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"graceful\"");
        let parsed: RevocationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, RevocationMode::Graceful);
    }

    #[test]
    fn test_cascade_tier_serde() {
        let t = CascadeTier::Crl;
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"crl\"");
        let parsed: CascadeTier = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CascadeTier::Crl);
    }

    #[test]
    fn test_revocation_serde_roundtrip() {
        let mut r = make_revocation();
        r.add_cascade(RevocationTarget::Session, "s1", CascadeTier::Immediate);

        let json = serde_json::to_string(&r).unwrap();
        let parsed: RevocationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entity_id, "profile-uuid-123");
        assert_eq!(parsed.cascade_entries.len(), 1);
        assert_eq!(parsed.cascade_entries[0].target, RevocationTarget::Session);
    }

    #[test]
    fn test_revocation_id_unique() {
        let id1 = RevocationId::new();
        let id2 = RevocationId::new();
        assert_ne!(id1, id2);
    }
}
