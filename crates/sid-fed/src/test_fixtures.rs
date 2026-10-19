// SPDX-License-Identifier: AGPL-3.0-only
//! Fixed certificates for the verification tests (ECDSA P-256): a root, an
//! instance CA under it, a binding certificate under that, an organization CA
//! under the instance CA with its own leaf, and an unrelated root. For the
//! refusals: the instance CA again with a validity that ended in 2021, and
//! the root again with `pathLenConstraint` 0 (same name and key). Verification
//! is tested on certificates as they arrive, never on ones this crate issues.

use sid_core::models::{Certificate, CertificateId, CertificateType};
use x509_parser::prelude::*;

pub const ROOT: &str = include_str!("../fixtures/root.pem");
pub const OTHER_ROOT: &str = include_str!("../fixtures/other_root.pem");
pub const INSTANCE_CA: &str = include_str!("../fixtures/instance_ca.pem");
pub const BINDING: &str = include_str!("../fixtures/binding.pem");
pub const ORG_CA: &str = include_str!("../fixtures/org_ca.pem");
pub const ORG_LEAF: &str = include_str!("../fixtures/org_leaf.pem");
pub const EXPIRED_INSTANCE_CA: &str = include_str!("../fixtures/expired_instance_ca.pem");
pub const ROOT_PATHLEN_0: &str = include_str!("../fixtures/root_pathlen0.pem");

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
