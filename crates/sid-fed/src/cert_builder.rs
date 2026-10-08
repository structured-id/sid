// SPDX-License-Identifier: AGPL-3.0-only
//! X.509 certificate builder for SID federation PKI.
//!
//! Uses `rcgen` for certificate generation. Supports all 5 certificate types:
//! RootCA, InstanceCA, BindingCertificate, ScopedCA, SiteCertificate.

use chrono::{Duration, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SerialNumber,
};
use sid_core::models::{Certificate, CertificateId, CertificateType};

use crate::error::PkiError;
use crate::oid;

/// Result of certificate generation: the signed DER bytes + the key pair.
pub struct GeneratedCert {
    /// The domain model certificate record.
    pub certificate: Certificate,
    /// The key pair (caller must store the private key securely).
    pub key_pair: KeyPair,
}

/// Build a self-signed Root CA certificate.
pub fn build_root_ca(subject_cn: &str, validity_years: u32) -> Result<GeneratedCert, PkiError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| PkiError::Generation(e.to_string()))?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| PkiError::Generation(e.to_string()))?;
    params
        .distinguished_name
        .push(DnType::CommonName, subject_cn);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "StructuredID");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(generate_serial());

    let now = Utc::now();
    let duration_days = 365 * validity_years as i64;
    params.not_before = chrono_to_time(now);
    params.not_after = chrono_to_time(now + Duration::days(duration_days));

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| PkiError::Generation(e.to_string()))?;

    let der = cert.der().to_vec();
    let subject_dn = format!("CN={},O=StructuredID", subject_cn);

    Ok(GeneratedCert {
        certificate: Certificate {
            id: CertificateId::new(),
            cert_type: CertificateType::RootCa,
            serial_hex: format_serial(&params.serial_number),
            subject_dn: subject_dn.clone(),
            issuer_dn: subject_dn,
            parent_id: None,
            der,
            not_before: now,
            not_after: now + Duration::days(duration_days),
            instance_id: None,
            org_id: None,
            site_domain: None,
            binding_id: None,
            revoked_at: None,
            revocation_reason: None,
            created_at: now,
        },
        key_pair,
    })
}

/// Build an Instance CA certificate, signed by a Root CA.
pub fn build_instance_ca(
    subject_cn: &str,
    instance_id: &str,
    validity_years: u32,
    issuer_cert_der: &[u8],
    issuer_key: &KeyPair,
    parent_cert_id: CertificateId,
) -> Result<GeneratedCert, PkiError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| PkiError::Generation(e.to_string()))?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| PkiError::Generation(e.to_string()))?;
    params
        .distinguished_name
        .push(DnType::CommonName, subject_cn);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "StructuredID");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(generate_serial());
    params
        .custom_extensions
        .push(oid::instance_id_extension(instance_id));

    let now = Utc::now();
    let duration_days = 365 * validity_years as i64;
    params.not_before = chrono_to_time(now);
    params.not_after = chrono_to_time(now + Duration::days(duration_days));

    let issuer = make_issuer(issuer_cert_der, issuer_key)?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .map_err(|e| PkiError::Generation(e.to_string()))?;

    let der = cert.der().to_vec();
    let subject_dn = format!("CN={},O=StructuredID", subject_cn);

    Ok(GeneratedCert {
        certificate: Certificate {
            id: CertificateId::new(),
            cert_type: CertificateType::InstanceCa,
            serial_hex: format_serial(&params.serial_number),
            subject_dn,
            issuer_dn: format!("(parent:{})", parent_cert_id),
            parent_id: Some(parent_cert_id),
            der,
            not_before: now,
            not_after: now + Duration::days(duration_days),
            instance_id: Some(instance_id.to_string()),
            org_id: None,
            site_domain: None,
            binding_id: None,
            revoked_at: None,
            revocation_reason: None,
            created_at: now,
        },
        key_pair,
    })
}

/// Build a Binding Certificate for a per-service user identity.
pub fn build_binding_cert(
    binding_id_str: &str,
    service_sector: &str,
    assurance_level: &str,
    ttl_days: u32,
    issuer_cert_der: &[u8],
    issuer_key: &KeyPair,
    parent_cert_id: CertificateId,
) -> Result<GeneratedCert, PkiError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| PkiError::Generation(e.to_string()))?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| PkiError::Generation(e.to_string()))?;
    params
        .distinguished_name
        .push(DnType::CommonName, binding_id_str);
    params
        .distinguished_name
        .push(DnType::OrganizationalUnitName, "Pairwise Binding");
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
    ];
    params.serial_number = Some(generate_serial());
    params
        .custom_extensions
        .push(oid::binding_sector_extension(service_sector));
    params
        .custom_extensions
        .push(oid::assurance_level_extension(assurance_level));

    let now = Utc::now();
    params.not_before = chrono_to_time(now);
    params.not_after = chrono_to_time(now + Duration::days(ttl_days as i64));

    let issuer = make_issuer(issuer_cert_der, issuer_key)?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .map_err(|e| PkiError::Generation(e.to_string()))?;

    let der = cert.der().to_vec();

    Ok(GeneratedCert {
        certificate: Certificate {
            id: CertificateId::new(),
            cert_type: CertificateType::BindingCertificate,
            serial_hex: format_serial(&params.serial_number),
            subject_dn: format!("CN={},OU=Pairwise Binding", binding_id_str),
            issuer_dn: format!("(parent:{})", parent_cert_id),
            parent_id: Some(parent_cert_id),
            der,
            not_before: now,
            not_after: now + Duration::days(ttl_days as i64),
            instance_id: None,
            org_id: None,
            site_domain: None,
            binding_id: Some(binding_id_str.to_string()),
            revoked_at: None,
            revocation_reason: None,
            created_at: now,
        },
        key_pair,
    })
}

/// Build a Scoped CA for enterprise-scoped corporate bindings.
pub fn build_scoped_ca(
    subject_cn: &str,
    org_id: &str,
    validity_years: u32,
    issuer_cert_der: &[u8],
    issuer_key: &KeyPair,
    parent_cert_id: CertificateId,
) -> Result<GeneratedCert, PkiError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| PkiError::Generation(e.to_string()))?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| PkiError::Generation(e.to_string()))?;
    params
        .distinguished_name
        .push(DnType::CommonName, subject_cn);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "StructuredID");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(generate_serial());
    params
        .custom_extensions
        .push(oid::scoped_ca_org_extension(org_id));

    let now = Utc::now();
    let duration_days = 365 * validity_years as i64;
    params.not_before = chrono_to_time(now);
    params.not_after = chrono_to_time(now + Duration::days(duration_days));

    let issuer = make_issuer(issuer_cert_der, issuer_key)?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .map_err(|e| PkiError::Generation(e.to_string()))?;

    let der = cert.der().to_vec();

    Ok(GeneratedCert {
        certificate: Certificate {
            id: CertificateId::new(),
            cert_type: CertificateType::ScopedCa,
            serial_hex: format_serial(&params.serial_number),
            subject_dn: format!("CN={},O=StructuredID", subject_cn),
            issuer_dn: format!("(parent:{})", parent_cert_id),
            parent_id: Some(parent_cert_id),
            der,
            not_before: now,
            not_after: now + Duration::days(duration_days),
            instance_id: None,
            org_id: Some(org_id.to_string()),
            site_domain: None,
            binding_id: None,
            revoked_at: None,
            revocation_reason: None,
            created_at: now,
        },
        key_pair,
    })
}

/// Build a Site Certificate for federation member offline VP verification.
pub fn build_site_cert(
    domain: &str,
    validity_days: u32,
    issuer_cert_der: &[u8],
    issuer_key: &KeyPair,
    parent_cert_id: CertificateId,
) -> Result<GeneratedCert, PkiError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| PkiError::Generation(e.to_string()))?;

    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| PkiError::Generation(e.to_string()))?;
    params
        .distinguished_name
        .push(DnType::CommonName, format!("{} Federation Site", domain));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.serial_number = Some(generate_serial());

    let now = Utc::now();
    params.not_before = chrono_to_time(now);
    params.not_after = chrono_to_time(now + Duration::days(validity_days as i64));

    let issuer = make_issuer(issuer_cert_der, issuer_key)?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .map_err(|e| PkiError::Generation(e.to_string()))?;

    let der = cert.der().to_vec();

    Ok(GeneratedCert {
        certificate: Certificate {
            id: CertificateId::new(),
            cert_type: CertificateType::SiteCertificate,
            serial_hex: format_serial(&params.serial_number),
            subject_dn: format!("CN={} Federation Site", domain),
            issuer_dn: format!("(parent:{})", parent_cert_id),
            parent_id: Some(parent_cert_id),
            der,
            not_before: now,
            not_after: now + Duration::days(validity_days as i64),
            instance_id: None,
            org_id: None,
            site_domain: Some(domain.to_string()),
            binding_id: None,
            revoked_at: None,
            revocation_reason: None,
            created_at: now,
        },
        key_pair,
    })
}

// --- Helpers ---

/// Create an `Issuer` from DER-encoded CA cert + key pair.
///
/// KeyPair is not Clone, so we reconstruct from serialized DER.
fn make_issuer(
    issuer_cert_der: &[u8],
    issuer_key: &KeyPair,
) -> Result<Issuer<'static, KeyPair>, PkiError> {
    let cert_der = rustls_pki_types::CertificateDer::from(issuer_cert_der.to_vec());
    let key_der_bytes = issuer_key.serialized_der();
    let private_key_der = rustls_pki_types::PrivateKeyDer::try_from(key_der_bytes.to_vec())
        .map_err(|e| PkiError::Generation(format!("key DER: {}", e)))?;
    let reconstructed =
        KeyPair::from_der_and_sign_algo(&private_key_der, &rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| PkiError::Generation(format!("key reconstruction: {}", e)))?;
    Issuer::from_ca_cert_der(&cert_der, reconstructed)
        .map_err(|e| PkiError::Generation(format!("issuer: {}", e)))
}

fn generate_serial() -> SerialNumber {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    // Ensure high bit is 0 (serial must be positive integer per X.509).
    bytes[0] &= 0x7F;
    SerialNumber::from_slice(&bytes)
}

fn format_serial(serial: &Option<SerialNumber>) -> String {
    match serial {
        Some(s) => hex::encode(s.as_ref()),
        None => "unknown".to_string(),
    }
}

fn chrono_to_time(dt: chrono::DateTime<Utc>) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(dt.timestamp()).expect("valid timestamp")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_root_ca() {
        let result = build_root_ca("Test Root CA", 10);
        assert!(result.is_ok());
        let issued = result.unwrap();
        assert_eq!(issued.certificate.cert_type, CertificateType::RootCa);
        assert!(issued.certificate.parent_id.is_none());
        assert!(!issued.certificate.der.is_empty());
        assert!(issued.certificate.is_valid());
    }

    #[test]
    fn test_build_instance_ca() {
        let root = build_root_ca("Root CA", 10).unwrap();
        let result = build_instance_ca(
            "Instance CA Gen-1",
            "instance_abc",
            3,
            &root.certificate.der,
            &root.key_pair,
            root.certificate.id,
        );
        assert!(result.is_ok());
        let issued = result.unwrap();
        assert_eq!(issued.certificate.cert_type, CertificateType::InstanceCa);
        assert_eq!(issued.certificate.parent_id, Some(root.certificate.id));
        assert_eq!(
            issued.certificate.instance_id.as_deref(),
            Some("instance_abc")
        );
    }

    #[test]
    fn test_build_binding_cert() {
        let root = build_root_ca("Root CA", 10).unwrap();
        let instance = build_instance_ca(
            "Instance CA",
            "inst_1",
            3,
            &root.certificate.der,
            &root.key_pair,
            root.certificate.id,
        )
        .unwrap();

        let result = build_binding_cert(
            "bind_01HY9K",
            "acme.corp",
            "loa2",
            30,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
        );
        assert!(result.is_ok());
        let issued = result.unwrap();
        assert_eq!(
            issued.certificate.cert_type,
            CertificateType::BindingCertificate
        );
        assert_eq!(
            issued.certificate.binding_id.as_deref(),
            Some("bind_01HY9K")
        );
        assert_eq!(issued.certificate.parent_id, Some(instance.certificate.id));
    }

    #[test]
    fn test_build_scoped_ca() {
        let root = build_root_ca("Root CA", 10).unwrap();
        let instance = build_instance_ca(
            "Instance CA",
            "inst_1",
            3,
            &root.certificate.der,
            &root.key_pair,
            root.certificate.id,
        )
        .unwrap();

        let result = build_scoped_ca(
            "Acme Corp Scoped CA",
            "org_123",
            2,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
        );
        assert!(result.is_ok());
        let issued = result.unwrap();
        assert_eq!(issued.certificate.cert_type, CertificateType::ScopedCa);
        assert_eq!(issued.certificate.org_id.as_deref(), Some("org_123"));
    }

    #[test]
    fn test_build_site_cert() {
        let root = build_root_ca("Root CA", 10).unwrap();
        let instance = build_instance_ca(
            "Instance CA",
            "inst_1",
            3,
            &root.certificate.der,
            &root.key_pair,
            root.certificate.id,
        )
        .unwrap();

        let result = build_site_cert(
            "example.com",
            365,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
        );
        assert!(result.is_ok());
        let issued = result.unwrap();
        assert_eq!(
            issued.certificate.cert_type,
            CertificateType::SiteCertificate
        );
        assert_eq!(
            issued.certificate.site_domain.as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn test_serial_uniqueness() {
        let s1 = generate_serial();
        let s2 = generate_serial();
        assert_ne!(s1.as_ref(), s2.as_ref());
    }
}
