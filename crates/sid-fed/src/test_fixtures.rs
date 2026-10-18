// SPDX-License-Identifier: AGPL-3.0-only
//! Fixed certificates for the verification tests: a root, an instance CA under
//! it, a binding certificate under that, and an unrelated root (ECDSA P-256,
//! valid until 2126). Verification is tested on certificates as they arrive,
//! never on ones this crate issues.

use sid_core::models::{Certificate, CertificateId, CertificateType};
use x509_parser::prelude::*;

pub const ROOT: &str = include_str!("../fixtures/root.pem");
pub const OTHER_ROOT: &str = include_str!("../fixtures/other_root.pem");
pub const INSTANCE_CA: &str = include_str!("../fixtures/instance_ca.pem");
pub const BINDING: &str = include_str!("../fixtures/binding.pem");

/// The DER of a PEM fixture.
pub fn der(pem: &str) -> Vec<u8> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
    pem.contents
}

/// The certificate record of a fixture, as storage would hold it.
pub fn record(
    pem: &str,
    cert_type: CertificateType,
    parent_id: Option<CertificateId>,
) -> Certificate {
    let der = der(pem);
    let (_, cert) = X509Certificate::from_der(&der).unwrap();
    let at = |t: ASN1Time| chrono::DateTime::from_timestamp(t.timestamp(), 0).unwrap();
    Certificate {
        id: CertificateId::new(),
        cert_type,
        serial_hex: hex::encode(cert.raw_serial()),
        subject_dn: cert.subject().to_string(),
        issuer_dn: cert.issuer().to_string(),
        parent_id,
        not_before: at(cert.validity().not_before),
        not_after: at(cert.validity().not_after),
        der,
        instance_id: None,
        org_id: None,
        site_domain: None,
        binding_id: None,
        revoked_at: None,
        revocation_reason: None,
        created_at: chrono::Utc::now(),
    }
}
