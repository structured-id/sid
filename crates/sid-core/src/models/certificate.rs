// SPDX-License-Identifier: AGPL-3.0-only
//! X.509 certificate domain model for federation PKI.
//!
//! Certificate hierarchy: RootCA → InstanceCA → BindingCertificate / ScopedCA / SiteCertificate.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::RevocationReason;

/// Unique identifier for a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificateId(pub Uuid);

impl CertificateId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for CertificateId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for CertificateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type of certificate in the PKI hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateType {
    /// Self-signed root certificate authority.
    RootCa,
    /// Instance-level CA, signed by RootCA.
    InstanceCa,
    /// Per-service user binding certificate, signed by InstanceCA.
    BindingCertificate,
    /// Enterprise-scoped CA for corporate bindings, signed by InstanceCA.
    ScopedCa,
    /// Federation site certificate for offline VP verification.
    SiteCertificate,
}

impl CertificateType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RootCa => "root_ca",
            Self::InstanceCa => "instance_ca",
            Self::BindingCertificate => "binding_certificate",
            Self::ScopedCa => "scoped_ca",
            Self::SiteCertificate => "site_certificate",
        }
    }

    /// Whether this certificate type can sign other certificates.
    pub fn is_ca(&self) -> bool {
        matches!(self, Self::RootCa | Self::InstanceCa | Self::ScopedCa)
    }
}

impl std::fmt::Display for CertificateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Certificate record — metadata stored in DB alongside PEM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: CertificateId,

    /// Certificate type in the hierarchy.
    pub cert_type: CertificateType,

    /// X.509 serial number (hex string).
    pub serial_hex: String,

    /// X.509 Subject Distinguished Name (RFC 4514).
    pub subject_dn: String,

    /// X.509 Issuer Distinguished Name.
    pub issuer_dn: String,

    /// Parent certificate ID (None for self-signed RootCA).
    pub parent_id: Option<CertificateId>,

    /// DER-encoded certificate bytes.
    pub der: Vec<u8>,

    /// Validity: not before.
    pub not_before: DateTime<Utc>,

    /// Validity: not after.
    pub not_after: DateTime<Utc>,

    /// For InstanceCA: instance identifier.
    pub instance_id: Option<String>,

    /// For ScopedCA: organization ID.
    pub org_id: Option<String>,

    /// For SiteCertificate: domain.
    pub site_domain: Option<String>,

    /// For BindingCertificate: binding ID.
    pub binding_id: Option<String>,

    /// Revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,

    /// Revocation reason.
    pub revocation_reason: Option<RevocationReason>,

    pub created_at: DateTime<Utc>,
}

impl Certificate {
    /// Whether this certificate is currently valid (not expired, not revoked).
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        self.revoked_at.is_none() && now >= self.not_before && now <= self.not_after
    }

    /// Whether this certificate has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Whether this certificate has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    /// Days until expiry (negative if expired).
    pub fn days_until_expiry(&self) -> i64 {
        (self.not_after - Utc::now()).num_days()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cert(cert_type: CertificateType) -> Certificate {
        let now = Utc::now();
        Certificate {
            id: CertificateId::new(),
            cert_type,
            serial_hex: "01".to_string(),
            subject_dn: "CN=Test".to_string(),
            issuer_dn: "CN=Test".to_string(),
            parent_id: None,
            der: vec![],
            not_before: now - chrono::Duration::hours(1),
            not_after: now + chrono::Duration::days(365),
            instance_id: None,
            org_id: None,
            site_domain: None,
            binding_id: None,
            revoked_at: None,
            revocation_reason: None,
            created_at: now,
        }
    }

    #[test]
    fn test_certificate_is_valid() {
        let cert = make_cert(CertificateType::RootCa);
        assert!(cert.is_valid());
        assert!(!cert.is_expired());
        assert!(!cert.is_revoked());
    }

    #[test]
    fn test_certificate_expired() {
        let mut cert = make_cert(CertificateType::InstanceCa);
        cert.not_after = Utc::now() - chrono::Duration::hours(1);
        assert!(!cert.is_valid());
        assert!(cert.is_expired());
    }

    #[test]
    fn test_certificate_revoked() {
        let mut cert = make_cert(CertificateType::BindingCertificate);
        cert.revoked_at = Some(Utc::now());
        cert.revocation_reason = Some(RevocationReason::Emergency);
        assert!(!cert.is_valid());
        assert!(cert.is_revoked());
    }

    #[test]
    fn test_certificate_not_yet_valid() {
        let mut cert = make_cert(CertificateType::SiteCertificate);
        cert.not_before = Utc::now() + chrono::Duration::hours(1);
        assert!(!cert.is_valid());
    }

    #[test]
    fn test_certificate_type_is_ca() {
        assert!(CertificateType::RootCa.is_ca());
        assert!(CertificateType::InstanceCa.is_ca());
        assert!(CertificateType::ScopedCa.is_ca());
        assert!(!CertificateType::BindingCertificate.is_ca());
        assert!(!CertificateType::SiteCertificate.is_ca());
    }

    #[test]
    fn test_certificate_type_serde() {
        let ct = CertificateType::InstanceCa;
        let json = serde_json::to_string(&ct).unwrap();
        assert_eq!(json, "\"instance_ca\"");
        let parsed: CertificateType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CertificateType::InstanceCa);
    }

    #[test]
    fn test_certificate_id_unique() {
        let id1 = CertificateId::new();
        let id2 = CertificateId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_days_until_expiry() {
        let cert = make_cert(CertificateType::RootCa);
        assert!(cert.days_until_expiry() > 360);
    }
}
