// SPDX-License-Identifier: AGPL-3.0-only
//! Federation enrollment service for Level 2 enterprise registration.
//!
//! Handles the enterprise enrollment flow:
//! 1. Enterprise submits registration (org details + public key)
//! 2. Admin verifies and issues Scoped CA certificate
//! 3. Enterprise uses Scoped CA to issue binding certificates

use sid_core::models::CertificateId;
#[cfg(test)]
use sid_core::models::CertificateType;
use sid_core::models::enterprise_registration::{EnrollmentStatus, EnterpriseRegistration};

use crate::cert_builder::{self, GeneratedCert};
use crate::chain_validator;
use crate::error::PkiError;

/// Result of enterprise enrollment verification.
pub struct EnrollmentResult {
    /// The issued Scoped CA certificate.
    pub scoped_ca: GeneratedCert,
    /// Updated enterprise registration.
    pub enterprise_id: sid_core::models::enterprise_registration::EnterpriseId,
}

/// Verify an enterprise enrollment and issue a Scoped CA.
///
/// Prerequisites:
/// - Enterprise registration exists with status `Pending`
/// - Instance CA cert and key are available for signing
/// - Admin has approved the enrollment
pub fn issue_scoped_ca_for_enterprise(
    registration: &mut EnterpriseRegistration,
    instance_ca_der: &[u8],
    instance_ca_key: &rcgen::KeyPair,
    instance_ca_cert_id: CertificateId,
    validity_years: u32,
) -> Result<EnrollmentResult, PkiError> {
    // Verify enrollment is pending.
    if registration.enrollment_status != EnrollmentStatus::Pending {
        return Err(PkiError::Enrollment(format!(
            "enterprise enrollment must be pending, got {}",
            registration.enrollment_status
        )));
    }

    // Verify the instance CA is actually a CA.
    let cn = chain_validator::extract_subject_cn(instance_ca_der)?;
    if cn.is_none() {
        return Err(PkiError::ChainInvalid(
            "instance CA has no subject CN".to_string(),
        ));
    }

    // Issue a Scoped CA for the enterprise.
    let scoped_ca = cert_builder::build_scoped_ca(
        &registration.org_name,
        &registration.org_id,
        validity_years,
        instance_ca_der,
        instance_ca_key,
        instance_ca_cert_id,
    )?;

    // Update registration status.
    registration.mark_verified(scoped_ca.certificate.id);

    Ok(EnrollmentResult {
        enterprise_id: registration.id,
        scoped_ca,
    })
}

/// Issue a binding certificate for an enterprise's service user.
///
/// The enterprise must be verified or active (have a valid Scoped CA).
#[allow(clippy::too_many_arguments)]
pub fn issue_binding_for_enterprise(
    registration: &EnterpriseRegistration,
    binding_id: &str,
    sector: &str,
    assurance_level: &str,
    validity_days: u32,
    scoped_ca_der: &[u8],
    scoped_ca_key: &rcgen::KeyPair,
    scoped_ca_cert_id: CertificateId,
) -> Result<GeneratedCert, PkiError> {
    // Verify enterprise can issue bindings.
    if !registration.can_issue_bindings() {
        return Err(PkiError::Enrollment(format!(
            "enterprise cannot issue bindings in {} status",
            registration.enrollment_status
        )));
    }

    // Verify the sector domain is allowed for this enterprise.
    if !registration.is_domain_allowed(sector) {
        return Err(PkiError::Enrollment(format!(
            "domain '{}' is not in enterprise's allowed domains",
            sector
        )));
    }

    cert_builder::build_binding_cert(
        binding_id,
        sector,
        assurance_level,
        validity_days,
        scoped_ca_der,
        scoped_ca_key,
        scoped_ca_cert_id,
    )
}

/// Revoke an enterprise's enrollment and cascade to its certificates.
///
/// Returns the list of certificate IDs that should be added to the CRL.
pub fn revoke_enterprise(registration: &mut EnterpriseRegistration) -> Vec<CertificateId> {
    registration.mark_revoked();

    // The Scoped CA cert should be revoked (cascade to all bindings).
    let mut revoked = Vec::new();
    if let Some(cert_id) = registration.scoped_ca_cert_id {
        revoked.push(cert_id);
    }
    revoked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_root_and_instance() -> (GeneratedCert, GeneratedCert) {
        let root = cert_builder::build_root_ca("Test Root CA", 10).unwrap();
        let instance = cert_builder::build_instance_ca(
            "Test Instance CA",
            "test_inst_1",
            3,
            &root.certificate.der,
            &root.key_pair,
            root.certificate.id,
        )
        .unwrap();
        (root, instance)
    }

    fn make_enterprise_reg() -> EnterpriseRegistration {
        EnterpriseRegistration::new(
            "Acme Corp".to_string(),
            "acme.corp".to_string(),
            vec!["app.acme.com".to_string(), "portal.acme.com".to_string()],
            vec![1, 2, 3],
            "enroll_token_123".to_string(),
        )
    }

    #[test]
    fn test_issue_scoped_ca_success() {
        let (_root, instance) = setup_root_and_instance();
        let mut reg = make_enterprise_reg();

        let result = issue_scoped_ca_for_enterprise(
            &mut reg,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
            2,
        );
        assert!(result.is_ok());
        let enrollment = result.unwrap();
        assert_eq!(reg.enrollment_status, EnrollmentStatus::Verified);
        assert!(reg.scoped_ca_cert_id.is_some());
        assert_eq!(
            enrollment.scoped_ca.certificate.cert_type,
            CertificateType::ScopedCa
        );
    }

    #[test]
    fn test_issue_scoped_ca_rejects_non_pending() {
        let (_root, instance) = setup_root_and_instance();
        let mut reg = make_enterprise_reg();
        reg.mark_revoked();

        let result = issue_scoped_ca_for_enterprise(
            &mut reg,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
            2,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_issue_binding_success() {
        let (_root, instance) = setup_root_and_instance();
        let mut reg = make_enterprise_reg();

        let enrollment = issue_scoped_ca_for_enterprise(
            &mut reg,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
            2,
        )
        .unwrap();

        let binding = issue_binding_for_enterprise(
            &reg,
            "bind_001",
            "app.acme.com",
            "loa2",
            30,
            &enrollment.scoped_ca.certificate.der,
            &enrollment.scoped_ca.key_pair,
            enrollment.scoped_ca.certificate.id,
        );
        assert!(binding.is_ok());
        let cert = binding.unwrap();
        assert_eq!(
            cert.certificate.cert_type,
            CertificateType::BindingCertificate
        );
    }

    #[test]
    fn test_issue_binding_wrong_domain() {
        let (_root, instance) = setup_root_and_instance();
        let mut reg = make_enterprise_reg();

        let enrollment = issue_scoped_ca_for_enterprise(
            &mut reg,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
            2,
        )
        .unwrap();

        let result = issue_binding_for_enterprise(
            &reg,
            "bind_001",
            "unauthorized.com",
            "loa2",
            30,
            &enrollment.scoped_ca.certificate.der,
            &enrollment.scoped_ca.key_pair,
            enrollment.scoped_ca.certificate.id,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_issue_binding_suspended_enterprise() {
        let (_root, instance) = setup_root_and_instance();
        let mut reg = make_enterprise_reg();

        let enrollment = issue_scoped_ca_for_enterprise(
            &mut reg,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
            2,
        )
        .unwrap();

        reg.mark_suspended();

        let result = issue_binding_for_enterprise(
            &reg,
            "bind_001",
            "app.acme.com",
            "loa2",
            30,
            &enrollment.scoped_ca.certificate.der,
            &enrollment.scoped_ca.key_pair,
            enrollment.scoped_ca.certificate.id,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_enterprise() {
        let (_root, instance) = setup_root_and_instance();
        let mut reg = make_enterprise_reg();

        issue_scoped_ca_for_enterprise(
            &mut reg,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
            2,
        )
        .unwrap();

        let revoked_ids = revoke_enterprise(&mut reg);
        assert_eq!(reg.enrollment_status, EnrollmentStatus::Revoked);
        assert_eq!(revoked_ids.len(), 1);
    }

    #[test]
    fn test_full_chain_verification() {
        let (root, instance) = setup_root_and_instance();
        let mut reg = make_enterprise_reg();

        let enrollment = issue_scoped_ca_for_enterprise(
            &mut reg,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
            2,
        )
        .unwrap();

        let binding = issue_binding_for_enterprise(
            &reg,
            "bind_full",
            "app.acme.com",
            "loa2",
            30,
            &enrollment.scoped_ca.certificate.der,
            &enrollment.scoped_ca.key_pair,
            enrollment.scoped_ca.certificate.id,
        )
        .unwrap();

        // Verify full chain: binding → scoped CA → instance CA → root.
        let result = crate::chain_validator::verify_chain(&[
            &binding.certificate.der,
            &enrollment.scoped_ca.certificate.der,
            &instance.certificate.der,
            &root.certificate.der,
        ]);
        assert!(result.is_ok());
        let vr = result.unwrap();
        assert_eq!(vr.chain_length, 4);
        assert!(!vr.is_ca);
    }
}
