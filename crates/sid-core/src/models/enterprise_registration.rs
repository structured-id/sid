// SPDX-License-Identifier: AGPL-3.0-only
//! Enterprise registration model for Level 2 federation.
//!
//! Enterprises register via direct certificate exchange (no DNS required).
//! After verification, they receive a Scoped CA for issuing binding certificates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::CertificateId;

/// Unique identifier for an enterprise registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseId(pub Uuid);

impl EnterpriseId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for EnterpriseId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EnterpriseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Enrollment status for enterprise federation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentStatus {
    /// CSR submitted, awaiting verification and Scoped CA issuance.
    Pending,
    /// Scoped CA issued, enterprise can create corporate profiles.
    Verified,
    /// Enterprise is actively issuing binding certificates.
    Active,
    /// Enterprise enrollment suspended (e.g., contract issues).
    Suspended,
    /// Enterprise enrollment revoked, all certs invalidated.
    Revoked,
}

impl std::fmt::Display for EnrollmentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => f.write_str("pending"),
            Self::Verified => f.write_str("verified"),
            Self::Active => f.write_str("active"),
            Self::Suspended => f.write_str("suspended"),
            Self::Revoked => f.write_str("revoked"),
        }
    }
}

/// Enterprise registration record for Level 2 federation.
///
/// Enterprises exchange certificates directly (no DNS TXT needed).
/// After verification, they receive a Scoped CA to issue binding certs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseRegistration {
    pub id: EnterpriseId,

    /// Organization name.
    pub org_name: String,

    /// Organization identifier (e.g., domain or tax ID).
    pub org_id: String,

    /// Current enrollment status.
    pub enrollment_status: EnrollmentStatus,

    /// Scoped CA certificate ID (issued after verification).
    pub scoped_ca_cert_id: Option<CertificateId>,

    /// Domains the enterprise is allowed to bind services for.
    pub allowed_domains: Vec<String>,

    /// DER-encoded public key from initial CSR exchange.
    pub public_key_der: Vec<u8>,

    /// Enrollment request token for CSR handshake.
    pub enrollment_token: String,

    /// When the enterprise was verified.
    pub verified_at: Option<DateTime<Utc>>,

    /// When the enrollment was revoked.
    pub revoked_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
}

impl EnterpriseRegistration {
    /// Create a new pending enterprise registration.
    pub fn new(
        org_name: String,
        org_id: String,
        allowed_domains: Vec<String>,
        public_key_der: Vec<u8>,
        enrollment_token: String,
    ) -> Self {
        Self {
            id: EnterpriseId::new(),
            org_name,
            org_id,
            enrollment_status: EnrollmentStatus::Pending,
            scoped_ca_cert_id: None,
            allowed_domains,
            public_key_der,
            enrollment_token,
            verified_at: None,
            revoked_at: None,
            created_at: Utc::now(),
        }
    }

    /// Whether this enterprise can issue binding certificates.
    pub fn can_issue_bindings(&self) -> bool {
        matches!(
            self.enrollment_status,
            EnrollmentStatus::Verified | EnrollmentStatus::Active
        )
    }

    /// Whether a domain is in the enterprise's allowed list.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        self.allowed_domains.iter().any(|d| d == domain)
    }

    /// Mark as verified after Scoped CA issuance.
    pub fn mark_verified(&mut self, scoped_ca_cert_id: CertificateId) {
        self.enrollment_status = EnrollmentStatus::Verified;
        self.scoped_ca_cert_id = Some(scoped_ca_cert_id);
        self.verified_at = Some(Utc::now());
    }

    /// Activate (after first binding cert issued).
    pub fn mark_active(&mut self) {
        self.enrollment_status = EnrollmentStatus::Active;
    }

    /// Suspend enrollment.
    pub fn mark_suspended(&mut self) {
        self.enrollment_status = EnrollmentStatus::Suspended;
    }

    /// Revoke enrollment.
    pub fn mark_revoked(&mut self) {
        self.enrollment_status = EnrollmentStatus::Revoked;
        self.revoked_at = Some(Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_reg() -> EnterpriseRegistration {
        EnterpriseRegistration::new(
            "Acme Corp".to_string(),
            "acme.corp".to_string(),
            vec!["app.acme.com".to_string(), "portal.acme.com".to_string()],
            vec![1, 2, 3],
            "enroll_token_123".to_string(),
        )
    }

    #[test]
    fn test_new_registration() {
        let reg = make_reg();
        assert_eq!(reg.org_name, "Acme Corp");
        assert_eq!(reg.enrollment_status, EnrollmentStatus::Pending);
        assert!(!reg.can_issue_bindings());
        assert!(reg.scoped_ca_cert_id.is_none());
    }

    #[test]
    fn test_mark_verified() {
        let mut reg = make_reg();
        let cert_id = CertificateId::new();
        reg.mark_verified(cert_id);
        assert_eq!(reg.enrollment_status, EnrollmentStatus::Verified);
        assert_eq!(reg.scoped_ca_cert_id, Some(cert_id));
        assert!(reg.verified_at.is_some());
        assert!(reg.can_issue_bindings());
    }

    #[test]
    fn test_mark_active() {
        let mut reg = make_reg();
        reg.mark_verified(CertificateId::new());
        reg.mark_active();
        assert_eq!(reg.enrollment_status, EnrollmentStatus::Active);
        assert!(reg.can_issue_bindings());
    }

    #[test]
    fn test_mark_suspended() {
        let mut reg = make_reg();
        reg.mark_verified(CertificateId::new());
        reg.mark_suspended();
        assert_eq!(reg.enrollment_status, EnrollmentStatus::Suspended);
        assert!(!reg.can_issue_bindings());
    }

    #[test]
    fn test_mark_revoked() {
        let mut reg = make_reg();
        reg.mark_verified(CertificateId::new());
        reg.mark_revoked();
        assert_eq!(reg.enrollment_status, EnrollmentStatus::Revoked);
        assert!(!reg.can_issue_bindings());
        assert!(reg.revoked_at.is_some());
    }

    #[test]
    fn test_domain_allowed() {
        let reg = make_reg();
        assert!(reg.is_domain_allowed("app.acme.com"));
        assert!(reg.is_domain_allowed("portal.acme.com"));
        assert!(!reg.is_domain_allowed("other.acme.com"));
    }

    #[test]
    fn test_enrollment_status_serde() {
        let status = EnrollmentStatus::Verified;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"verified\"");
        let parsed: EnrollmentStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EnrollmentStatus::Verified);
    }

    #[test]
    fn test_enterprise_id_unique() {
        let id1 = EnterpriseId::new();
        let id2 = EnterpriseId::new();
        assert_ne!(id1, id2);
    }
}
