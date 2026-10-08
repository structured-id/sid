// SPDX-License-Identifier: AGPL-3.0-only
//! CE access request model — profile requests role access, admin approves/denies.
//!
//! 1-step approval. Optional temporary duration with auto-expiry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::profile::ProfileId;
use super::project::ProjectId;

/// Unique identifier for an access request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccessRequestId(pub Uuid);

impl AccessRequestId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for AccessRequestId {
    fn default() -> Self {
        Self::new()
    }
}

/// Access request status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessRequestStatus {
    Pending,
    Approved,
    Denied,
    Cancelled,
    Expired,
}

impl AccessRequestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Pending)
    }

    /// Parse from string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "cancelled" => Some(Self::Cancelled),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

impl std::fmt::Display for AccessRequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CE access request — profile requests a role within a project.
///
/// 1-step approval: submitted → pending → approved/denied.
/// Optional duration → creates temporary role assignment on approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    pub id: AccessRequestId,
    pub requester_id: ProfileId,
    pub project_id: ProjectId,
    pub role_key: String,
    pub justification: Option<String>,
    /// Requested duration in hours (None = permanent).
    pub requested_duration_hours: Option<u32>,
    pub status: AccessRequestStatus,
    pub reviewed_by: Option<ProfileId>,
    pub review_comment: Option<String>,
    pub created_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
    /// Request auto-expires if admin doesn't act.
    pub expires_at: Option<DateTime<Utc>>,
}

impl AccessRequest {
    pub fn new(
        requester_id: ProfileId,
        project_id: ProjectId,
        role_key: impl Into<String>,
    ) -> Self {
        Self {
            id: AccessRequestId::new(),
            requester_id,
            project_id,
            role_key: role_key.into(),
            justification: None,
            requested_duration_hours: None,
            status: AccessRequestStatus::Pending,
            reviewed_by: None,
            review_comment: None,
            created_at: Utc::now(),
            reviewed_at: None,
            expires_at: None,
        }
    }

    /// This request as a decision recorded without a role: an approval is
    /// recorded only together with the role it grants.
    pub fn check_plain_decision(&self) -> crate::Result<()> {
        if self.status == AccessRequestStatus::Approved {
            return Err(crate::Error::Validation(format!(
                "access request {} is approved only with its role assignment",
                self.id.0
            )));
        }
        Ok(())
    }

    /// `grant` as the assignment this approved request makes: the request is
    /// approved and the assignment is the requester's.
    pub fn check_approval(&self, grant: &super::RoleAssignment) -> crate::Result<()> {
        if self.status != AccessRequestStatus::Approved {
            return Err(crate::Error::Validation(format!(
                "access request {} is not approved",
                self.id.0
            )));
        }
        if grant.principal != super::RoleAssignmentPrincipal::Profile(self.requester_id) {
            return Err(crate::Error::Validation(format!(
                "the assignment of access request {} is not its requester's",
                self.id.0
            )));
        }
        Ok(())
    }

    /// Approve this request. Errors if not pending.
    pub fn approve(
        &mut self,
        reviewer_id: ProfileId,
        comment: Option<String>,
    ) -> Result<(), &'static str> {
        if self.status != AccessRequestStatus::Pending {
            return Err("can only approve pending requests");
        }
        self.status = AccessRequestStatus::Approved;
        self.reviewed_by = Some(reviewer_id);
        self.review_comment = comment;
        self.reviewed_at = Some(Utc::now());
        Ok(())
    }

    /// Deny this request. Errors if not pending.
    pub fn deny(
        &mut self,
        reviewer_id: ProfileId,
        comment: Option<String>,
    ) -> Result<(), &'static str> {
        if self.status != AccessRequestStatus::Pending {
            return Err("can only deny pending requests");
        }
        self.status = AccessRequestStatus::Denied;
        self.reviewed_by = Some(reviewer_id);
        self.review_comment = comment;
        self.reviewed_at = Some(Utc::now());
        Ok(())
    }

    /// Cancel this request (by the requester). Errors if not pending.
    pub fn cancel(&mut self) -> Result<(), &'static str> {
        if self.status != AccessRequestStatus::Pending {
            return Err("can only cancel pending requests");
        }
        self.status = AccessRequestStatus::Cancelled;
        Ok(())
    }

    /// Check if this request has expired. Returns true if status changed to Expired.
    pub fn check_expired(&mut self) -> bool {
        if self.status == AccessRequestStatus::Pending
            && let Some(exp) = self.expires_at
            && Utc::now() > exp
        {
            self.status = AccessRequestStatus::Expired;
            return true;
        }
        false
    }

    /// Calculate role expiry based on requested duration. None for permanent.
    pub fn role_expires_at(&self) -> Option<DateTime<Utc>> {
        self.requested_duration_hours
            .map(|hours| Utc::now() + chrono::Duration::hours(hours as i64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_access_request() {
        let requester = ProfileId::generate();
        let project = ProjectId::new();
        let request = AccessRequest::new(requester, project, "editor");

        assert_eq!(request.requester_id, requester);
        assert_eq!(request.project_id, project);
        assert_eq!(request.role_key, "editor");
        assert_eq!(request.status, AccessRequestStatus::Pending);
        assert!(!request.status.is_terminal());
    }

    #[test]
    fn test_approve_request() {
        let mut request = AccessRequest::new(ProfileId::generate(), ProjectId::new(), "admin");
        let reviewer = ProfileId::generate();
        request
            .approve(reviewer, Some("Approved per policy".into()))
            .unwrap();
        assert_eq!(request.status, AccessRequestStatus::Approved);
        assert_eq!(request.reviewed_by, Some(reviewer));
        assert!(request.reviewed_at.is_some());
        assert!(request.status.is_terminal());
    }

    #[test]
    fn test_deny_request() {
        let mut request = AccessRequest::new(ProfileId::generate(), ProjectId::new(), "admin");
        let reviewer = ProfileId::generate();
        request
            .deny(reviewer, Some("Not justified".into()))
            .unwrap();
        assert_eq!(request.status, AccessRequestStatus::Denied);
    }

    #[test]
    fn test_cancel_request() {
        let mut request = AccessRequest::new(ProfileId::generate(), ProjectId::new(), "viewer");
        request.cancel().unwrap();
        assert_eq!(request.status, AccessRequestStatus::Cancelled);
    }

    #[test]
    fn test_cannot_approve_non_pending() {
        let mut request = AccessRequest::new(ProfileId::generate(), ProjectId::new(), "admin");
        request.deny(ProfileId::generate(), None).unwrap();
        assert!(request.approve(ProfileId::generate(), None).is_err());
    }

    #[test]
    fn test_cannot_deny_non_pending() {
        let mut request = AccessRequest::new(ProfileId::generate(), ProjectId::new(), "admin");
        request.approve(ProfileId::generate(), None).unwrap();
        assert!(request.deny(ProfileId::generate(), None).is_err());
    }

    #[test]
    fn test_cannot_cancel_non_pending() {
        let mut request = AccessRequest::new(ProfileId::generate(), ProjectId::new(), "admin");
        request.approve(ProfileId::generate(), None).unwrap();
        assert!(request.cancel().is_err());
    }

    #[test]
    fn test_check_expired() {
        let mut request = AccessRequest::new(ProfileId::generate(), ProjectId::new(), "admin");
        request.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        assert!(request.check_expired());
        assert_eq!(request.status, AccessRequestStatus::Expired);
    }

    #[test]
    fn test_not_expired() {
        let mut request = AccessRequest::new(ProfileId::generate(), ProjectId::new(), "admin");
        request.expires_at = Some(Utc::now() + chrono::Duration::hours(24));
        assert!(!request.check_expired());
        assert_eq!(request.status, AccessRequestStatus::Pending);
    }

    #[test]
    fn test_role_expires_at_permanent() {
        let request = AccessRequest::new(ProfileId::generate(), ProjectId::new(), "admin");
        assert!(request.role_expires_at().is_none());
    }

    #[test]
    fn test_role_expires_at_temporary() {
        let mut request = AccessRequest::new(ProfileId::generate(), ProjectId::new(), "viewer");
        request.requested_duration_hours = Some(24);
        let expires = request.role_expires_at().unwrap();
        let expected = Utc::now() + chrono::Duration::hours(24);
        assert!((expires - expected).num_seconds().abs() < 1);
    }

    #[test]
    fn test_status_as_str() {
        assert_eq!(AccessRequestStatus::Pending.as_str(), "pending");
        assert_eq!(AccessRequestStatus::Approved.as_str(), "approved");
        assert_eq!(AccessRequestStatus::Denied.as_str(), "denied");
        assert_eq!(AccessRequestStatus::Cancelled.as_str(), "cancelled");
        assert_eq!(AccessRequestStatus::Expired.as_str(), "expired");
    }

    #[test]
    fn test_status_terminal() {
        assert!(!AccessRequestStatus::Pending.is_terminal());
        assert!(AccessRequestStatus::Approved.is_terminal());
        assert!(AccessRequestStatus::Denied.is_terminal());
        assert!(AccessRequestStatus::Cancelled.is_terminal());
        assert!(AccessRequestStatus::Expired.is_terminal());
    }

    #[test]
    fn test_from_str_loose() {
        assert_eq!(
            AccessRequestStatus::from_str_loose("PENDING"),
            Some(AccessRequestStatus::Pending)
        );
        assert_eq!(AccessRequestStatus::from_str_loose("invalid"), None);
    }

    #[test]
    fn test_id_unique() {
        let id1 = AccessRequestId::new();
        let id2 = AccessRequestId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut request = AccessRequest::new(ProfileId::generate(), ProjectId::new(), "editor");
        request.justification = Some("Need to edit docs".into());
        request.requested_duration_hours = Some(72);
        let json = serde_json::to_string(&request).unwrap();
        let parsed: AccessRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.role_key, "editor");
        assert_eq!(parsed.justification.as_deref(), Some("Need to edit docs"));
        assert_eq!(parsed.requested_duration_hours, Some(72));
    }
}
