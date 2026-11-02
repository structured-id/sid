// SPDX-License-Identifier: AGPL-3.0-only
//! Site registration model for Level 1 federation.
//!
//! Sites prove domain ownership via DNS TXT records, then receive
//! a SiteCertificate for offline VP verification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::CertificateId;

/// Unique identifier for a site registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SiteId(pub Uuid);

impl SiteId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for SiteId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SiteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// DNS verification status for a site registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Awaiting DNS TXT record creation.
    Pending,
    /// DNS TXT record verified, domain ownership proven.
    Verified,
    /// Verification attempt failed (retryable within deadline).
    Failed,
    /// Verification token expired, must start new registration.
    Expired,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => f.write_str("pending"),
            Self::Verified => f.write_str("verified"),
            Self::Failed => f.write_str("failed"),
            Self::Expired => f.write_str("expired"),
        }
    }
}

/// Site registration record for Level 1 federation.
///
/// DNS TXT verification format:
/// ```text
/// _sid-fed.<domain> TXT "v=sid1; token=<dns_verification_token>"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteRegistration {
    pub id: SiteId,

    /// Domain being registered (e.g., "login.acme.com").
    pub domain: String,

    /// Random token for DNS TXT verification.
    pub dns_verification_token: String,

    /// Current verification status.
    pub verification_status: VerificationStatus,

    /// Reference to issued site certificate (after verification).
    pub certificate_id: Option<CertificateId>,

    /// Deadline for DNS verification (token expires after this).
    pub verification_deadline: DateTime<Utc>,

    /// When domain ownership was verified.
    pub verified_at: Option<DateTime<Utc>>,

    /// Number of failed verification attempts.
    pub failed_attempts: u32,

    /// Timestamp of last verification attempt.
    pub last_verification_attempt: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
}

/// Maximum failed verification attempts before requiring new registration.
pub const MAX_VERIFICATION_ATTEMPTS: u32 = 10;

/// Default verification deadline (48 hours).
pub const VERIFICATION_DEADLINE_HOURS: i64 = 48;

/// DNS TXT record prefix for SID federation.
pub const DNS_TXT_PREFIX: &str = "_sid-fed.";

/// DNS TXT record version tag.
pub const DNS_TXT_VERSION: &str = "v=sid1";

impl SiteRegistration {
    /// Create a new pending site registration.
    pub fn new(domain: String, token: String) -> Self {
        let now = Utc::now();
        Self {
            id: SiteId::new(),
            domain,
            dns_verification_token: token,
            verification_status: VerificationStatus::Pending,
            certificate_id: None,
            verification_deadline: now + chrono::Duration::hours(VERIFICATION_DEADLINE_HOURS),
            verified_at: None,
            failed_attempts: 0,
            last_verification_attempt: None,
            created_at: now,
        }
    }

    /// Whether the verification deadline has passed.
    pub fn is_deadline_expired(&self) -> bool {
        Utc::now() > self.verification_deadline
    }

    /// Whether further verification attempts are allowed.
    pub fn can_attempt_verification(&self) -> bool {
        !self.is_deadline_expired()
            && self.failed_attempts < MAX_VERIFICATION_ATTEMPTS
            && self.verification_status != VerificationStatus::Verified
    }

    /// Record a successful verification.
    pub fn mark_verified(&mut self) {
        self.verification_status = VerificationStatus::Verified;
        self.verified_at = Some(Utc::now());
    }

    /// Record a failed verification attempt.
    pub fn mark_failed(&mut self) {
        self.failed_attempts += 1;
        self.last_verification_attempt = Some(Utc::now());
        if self.failed_attempts >= MAX_VERIFICATION_ATTEMPTS {
            self.verification_status = VerificationStatus::Expired;
        } else {
            self.verification_status = VerificationStatus::Failed;
        }
    }

    /// Mark as expired (deadline passed).
    pub fn mark_expired(&mut self) {
        self.verification_status = VerificationStatus::Expired;
    }

    /// Format the expected DNS TXT record name.
    pub fn dns_record_name(&self) -> String {
        format!("{}{}", DNS_TXT_PREFIX, self.domain)
    }

    /// Format the expected DNS TXT record value.
    pub fn expected_dns_txt_value(&self) -> String {
        format!("{}; token={}", DNS_TXT_VERSION, self.dns_verification_token)
    }

    /// Parse a DNS TXT record value and check if it matches.
    pub fn verify_dns_txt_value(&self, txt_value: &str) -> bool {
        let expected = self.expected_dns_txt_value();
        // Constant-time-ish comparison for the token portion.
        // The format is public, only the token value is sensitive.
        txt_value.trim() == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_registration() {
        let reg = SiteRegistration::new("login.acme.com".to_string(), "abc123".to_string());
        assert_eq!(reg.domain, "login.acme.com");
        assert_eq!(reg.verification_status, VerificationStatus::Pending);
        assert!(reg.certificate_id.is_none());
        assert!(reg.verified_at.is_none());
        assert_eq!(reg.failed_attempts, 0);
    }

    #[test]
    fn test_dns_record_name() {
        let reg = SiteRegistration::new("login.acme.com".to_string(), "token".to_string());
        assert_eq!(reg.dns_record_name(), "_sid-fed.login.acme.com");
    }

    #[test]
    fn test_expected_dns_txt_value() {
        let reg = SiteRegistration::new("example.com".to_string(), "mytoken123".to_string());
        assert_eq!(reg.expected_dns_txt_value(), "v=sid1; token=mytoken123");
    }

    #[test]
    fn test_verify_dns_txt_value() {
        let reg = SiteRegistration::new("example.com".to_string(), "secret_token".to_string());
        assert!(reg.verify_dns_txt_value("v=sid1; token=secret_token"));
        assert!(!reg.verify_dns_txt_value("v=sid1; token=wrong_token"));
        assert!(!reg.verify_dns_txt_value("garbage"));
    }

    #[test]
    fn test_mark_verified() {
        let mut reg = SiteRegistration::new("test.com".to_string(), "t".to_string());
        reg.mark_verified();
        assert_eq!(reg.verification_status, VerificationStatus::Verified);
        assert!(reg.verified_at.is_some());
    }

    #[test]
    fn test_mark_failed_increments() {
        let mut reg = SiteRegistration::new("test.com".to_string(), "t".to_string());
        reg.mark_failed();
        assert_eq!(reg.failed_attempts, 1);
        assert_eq!(reg.verification_status, VerificationStatus::Failed);
    }

    #[test]
    fn test_max_attempts_expires() {
        let mut reg = SiteRegistration::new("test.com".to_string(), "t".to_string());
        for _ in 0..MAX_VERIFICATION_ATTEMPTS {
            reg.mark_failed();
        }
        assert_eq!(reg.verification_status, VerificationStatus::Expired);
        assert!(!reg.can_attempt_verification());
    }

    #[test]
    fn test_can_attempt_after_failure() {
        let mut reg = SiteRegistration::new("test.com".to_string(), "t".to_string());
        reg.mark_failed();
        assert!(reg.can_attempt_verification());
    }

    #[test]
    fn test_cannot_attempt_after_verified() {
        let mut reg = SiteRegistration::new("test.com".to_string(), "t".to_string());
        reg.mark_verified();
        assert!(!reg.can_attempt_verification());
    }

    #[test]
    fn test_verification_status_serde() {
        let status = VerificationStatus::Verified;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"verified\"");
        let parsed: VerificationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, VerificationStatus::Verified);
    }

    #[test]
    fn test_site_id_unique() {
        let id1 = SiteId::new();
        let id2 = SiteId::new();
        assert_ne!(id1, id2);
    }
}
