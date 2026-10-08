// SPDX-License-Identifier: AGPL-3.0-only
//! Incident Response models.
//!
//! Type-state pattern for incident lifecycle:
//! Detected → Triaging/Contained → Investigating → Resolved → PostMortem.
//!
//! Classification: P1 (Critical) → P4 (Low).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use uuid::Uuid;

use super::ProfileId;

/// Unique identifier for an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IncidentId(pub Uuid);

impl IncidentId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for IncidentId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for IncidentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Incident severity (P1=Critical through P4=Low).
///
/// Ordered: P1 > P2 > P3 > P4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// P1: acknowledge ≤15min, contain ≤1h. Auto-containment.
    P1,
    /// P2: acknowledge ≤1h, contain ≤4h. Auto-containment.
    P2,
    /// P3: acknowledge ≤4h, contain ≤24h. Alerts only.
    P3,
    /// P4: acknowledge ≤24h, resolve ≤7d. Informational.
    P4,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::P1 => "p1",
            Self::P2 => "p2",
            Self::P3 => "p3",
            Self::P4 => "p4",
        }
    }

    /// Whether auto-containment should trigger for this severity.
    pub fn auto_contain(&self) -> bool {
        matches!(self, Self::P1 | Self::P2)
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Incident category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentCategory {
    CredentialCompromise,
    AccountTakeover,
    PrivilegeEscalation,
    DataExfiltration,
    CryptoCompromise,
    ConfigTampering,
    AvailabilityAttack,
}

impl IncidentCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CredentialCompromise => "credential_compromise",
            Self::AccountTakeover => "account_takeover",
            Self::PrivilegeEscalation => "privilege_escalation",
            Self::DataExfiltration => "data_exfiltration",
            Self::CryptoCompromise => "crypto_compromise",
            Self::ConfigTampering => "config_tampering",
            Self::AvailabilityAttack => "availability_attack",
        }
    }
}

impl std::fmt::Display for IncidentCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the incident was detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum DetectionSource {
    /// Triggered by an anomaly detection rule.
    AnomalyRule { rule_id: String },
    /// Triggered by an observability alert.
    ObservabilityAlert { alert_name: String },
    /// Reported externally (user or customer).
    ExternalReport,
    /// Discovered manually by an administrator.
    ManualDiscovery,
    /// Matched against a threat intelligence feed.
    ThreatIntelFeed,
}

/// Impact assessment for an affected entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    Compromised,
    PotentiallyCompromised,
    Unaffected,
}

/// Type of entity affected by the incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AffectedEntityType {
    Profile,
    Session,
    ApiKey,
    Device,
}

/// An entity affected by an incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedEntity {
    pub entity_type: AffectedEntityType,
    pub entity_id: String,
    pub impact: Impact,
}

/// Automated containment action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum ContainmentAction {
    RevokeAllSessions {
        profile_ids: Vec<ProfileId>,
    },
    LockProfile {
        profile_id: ProfileId,
        reason: String,
    },
    BlockIpRange {
        cidr: String,
        duration_hours: u32,
    },
    ForcePasswordChange {
        profile_ids: Vec<ProfileId>,
    },
}

/// Post-mortem report for a resolved incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMortemReport {
    pub summary: String,
    pub root_cause: String,
    pub timeline: Vec<TimelineEntry>,
    pub remediation_steps: Vec<String>,
    pub created_by: ProfileId,
    pub created_at: DateTime<Utc>,
}

/// Entry in an incident timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub description: String,
    pub actor: Option<String>,
}

// ── Type-state markers ──

/// Marker trait for incident states.
pub trait IncidentState: sealed::Sealed {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Detected {}
    impl Sealed for super::Triaging {}
    impl Sealed for super::Contained {}
    impl Sealed for super::Investigating {}
    impl Sealed for super::Resolved {}
    impl Sealed for super::PostMortemState {}
}

/// Initial detection state.
pub struct Detected;
impl IncidentState for Detected {}

/// Manual triage in progress (P3/P4).
pub struct Triaging;
impl IncidentState for Triaging {}

/// Containment actions applied.
pub struct Contained;
impl IncidentState for Contained {}

/// Under investigation.
pub struct Investigating;
impl IncidentState for Investigating {}

/// Root cause identified and remediated.
pub struct Resolved;
impl IncidentState for Resolved {}

/// Post-mortem completed.
pub struct PostMortemState;
impl IncidentState for PostMortemState {}

/// Core incident data shared across all states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentData {
    pub id: IncidentId,
    pub severity: Severity,
    pub category: IncidentCategory,
    pub detected_at: DateTime<Utc>,
    pub detection_source: DetectionSource,
    pub affected_entities: Vec<AffectedEntity>,
    pub correlation_id: String,
    pub containment_actions: Vec<ContainmentAction>,
    pub assignee: Option<ProfileId>,
    pub root_cause: Option<String>,
    pub remediation: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub post_mortem: Option<PostMortemReport>,
}

/// Type-state incident.
///
/// Invalid state transitions are compilation errors.
pub struct Incident<S: IncidentState> {
    pub data: IncidentData,
    _state: PhantomData<S>,
}

impl Incident<Detected> {
    /// Create a newly detected incident.
    pub fn new(
        severity: Severity,
        category: IncidentCategory,
        detection_source: DetectionSource,
        affected_entities: Vec<AffectedEntity>,
        correlation_id: String,
    ) -> Self {
        Self {
            data: IncidentData {
                id: IncidentId::new(),
                severity,
                category,
                detected_at: Utc::now(),
                detection_source,
                affected_entities,
                correlation_id,
                containment_actions: Vec::new(),
                assignee: None,
                root_cause: None,
                remediation: None,
                resolved_at: None,
                post_mortem: None,
            },
            _state: PhantomData,
        }
    }

    /// Auto-contain (P1/P2): apply containment actions and transition.
    pub fn auto_contain(mut self, actions: Vec<ContainmentAction>) -> Incident<Contained> {
        self.data.containment_actions = actions;
        Incident {
            data: self.data,
            _state: PhantomData,
        }
    }

    /// Manual triage (P3/P4): assign to investigator.
    pub fn triage(mut self, assignee: ProfileId) -> Incident<Triaging> {
        self.data.assignee = Some(assignee);
        Incident {
            data: self.data,
            _state: PhantomData,
        }
    }
}

impl Incident<Triaging> {
    /// Apply containment during triage.
    pub fn contain(mut self, actions: Vec<ContainmentAction>) -> Incident<Contained> {
        self.data.containment_actions = actions;
        Incident {
            data: self.data,
            _state: PhantomData,
        }
    }

    /// Downgrade severity after triage assessment.
    pub fn downgrade(mut self, new_severity: Severity) -> Self {
        self.data.severity = new_severity;
        self
    }

    /// Mark as false positive → resolve immediately.
    pub fn false_positive(mut self, reason: &str) -> Incident<Resolved> {
        self.data.root_cause = Some(format!("False positive: {reason}"));
        self.data.resolved_at = Some(Utc::now());
        Incident {
            data: self.data,
            _state: PhantomData,
        }
    }
}

impl Incident<Contained> {
    /// Begin investigation.
    pub fn investigate(self) -> Incident<Investigating> {
        Incident {
            data: self.data,
            _state: PhantomData,
        }
    }
}

impl Incident<Investigating> {
    /// Resolve with root cause and remediation.
    pub fn resolve(mut self, root_cause: &str, remediation: &str) -> Incident<Resolved> {
        self.data.root_cause = Some(root_cause.to_string());
        self.data.remediation = Some(remediation.to_string());
        self.data.resolved_at = Some(Utc::now());
        Incident {
            data: self.data,
            _state: PhantomData,
        }
    }
}

impl Incident<Resolved> {
    /// Attach post-mortem report.
    pub fn post_mortem(mut self, report: PostMortemReport) -> Incident<PostMortemState> {
        self.data.post_mortem = Some(report);
        Incident {
            data: self.data,
            _state: PhantomData,
        }
    }
}

/// Read-only access to incident data from any state.
impl<S: IncidentState> Incident<S> {
    pub fn id(&self) -> IncidentId {
        self.data.id
    }

    pub fn severity(&self) -> Severity {
        self.data.severity
    }

    pub fn category(&self) -> IncidentCategory {
        self.data.category
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detected_p1() -> Incident<Detected> {
        Incident::new(
            Severity::P1,
            IncidentCategory::AccountTakeover,
            DetectionSource::AnomalyRule {
                rule_id: "impossible_travel".to_string(),
            },
            vec![AffectedEntity {
                entity_type: AffectedEntityType::Profile,
                entity_id: "prof_123".to_string(),
                impact: Impact::Compromised,
            }],
            "corr_001".to_string(),
        )
    }

    fn detected_p3() -> Incident<Detected> {
        Incident::new(
            Severity::P3,
            IncidentCategory::ConfigTampering,
            DetectionSource::ManualDiscovery,
            vec![],
            "corr_002".to_string(),
        )
    }

    #[test]
    fn test_p1_auto_contain_flow() {
        let incident = detected_p1();
        assert_eq!(incident.severity(), Severity::P1);
        assert!(incident.severity().auto_contain());

        let contained = incident.auto_contain(vec![ContainmentAction::RevokeAllSessions {
            profile_ids: vec![ProfileId::generate()],
        }]);

        assert_eq!(contained.data.containment_actions.len(), 1);

        let investigating = contained.investigate();
        let resolved = investigating.resolve("Stolen session token", "Rotated all tokens");

        assert!(resolved.data.root_cause.is_some());
        assert!(resolved.data.resolved_at.is_some());
    }

    #[test]
    fn test_p3_triage_flow() {
        let incident = detected_p3();
        assert!(!incident.severity().auto_contain());

        let assignee = ProfileId::generate();
        let triaging = incident.triage(assignee);

        assert_eq!(triaging.data.assignee, Some(assignee));

        let contained = triaging.contain(vec![]);
        let investigating = contained.investigate();
        let resolved = investigating.resolve("Config drift", "Restored config");

        assert_eq!(resolved.data.root_cause.as_deref(), Some("Config drift"));
    }

    #[test]
    fn test_false_positive() {
        let incident = detected_p3();
        let triaging = incident.triage(ProfileId::generate());
        let resolved = triaging.false_positive("Automated test triggered alert");

        assert!(
            resolved
                .data
                .root_cause
                .as_ref()
                .unwrap()
                .starts_with("False positive:")
        );
        assert!(resolved.data.resolved_at.is_some());
    }

    #[test]
    fn test_downgrade_severity() {
        let incident = detected_p3();
        let triaging = incident.triage(ProfileId::generate());
        let downgraded = triaging.downgrade(Severity::P4);

        assert_eq!(downgraded.severity(), Severity::P4);
    }

    #[test]
    fn test_post_mortem() {
        let incident = detected_p1();
        let contained = incident.auto_contain(vec![]);
        let investigating = contained.investigate();
        let resolved = investigating.resolve("Root cause", "Fix applied");

        let report = PostMortemReport {
            summary: "Account takeover via stolen cookie".to_string(),
            root_cause: "Weak session binding".to_string(),
            timeline: vec![TimelineEntry {
                timestamp: Utc::now(),
                description: "Anomaly detected".to_string(),
                actor: Some("system".to_string()),
            }],
            remediation_steps: vec!["Enable device binding".to_string()],
            created_by: ProfileId::generate(),
            created_at: Utc::now(),
        };

        let post_mortem = resolved.post_mortem(report);
        assert!(post_mortem.data.post_mortem.is_some());
    }

    #[test]
    fn test_severity_auto_contain() {
        assert!(Severity::P1.auto_contain());
        assert!(Severity::P2.auto_contain());
        assert!(!Severity::P3.auto_contain());
        assert!(!Severity::P4.auto_contain());
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(Severity::P1.as_str(), "p1");
        assert_eq!(Severity::P2.as_str(), "p2");
        assert_eq!(Severity::P3.as_str(), "p3");
        assert_eq!(Severity::P4.as_str(), "p4");
    }

    #[test]
    fn test_category_as_str() {
        assert_eq!(
            IncidentCategory::CredentialCompromise.as_str(),
            "credential_compromise"
        );
        assert_eq!(
            IncidentCategory::AccountTakeover.as_str(),
            "account_takeover"
        );
        assert_eq!(
            IncidentCategory::AvailabilityAttack.as_str(),
            "availability_attack"
        );
    }

    #[test]
    fn test_incident_id_unique() {
        let id1 = IncidentId::new();
        let id2 = IncidentId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_containment_action_serde() {
        let action = ContainmentAction::LockProfile {
            profile_id: ProfileId::generate(),
            reason: "Credential compromise".to_string(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let parsed: ContainmentAction = serde_json::from_str(&json).unwrap();
        if let ContainmentAction::LockProfile { reason, .. } = parsed {
            assert_eq!(reason, "Credential compromise");
        } else {
            panic!("wrong variant");
        }
    }
}
