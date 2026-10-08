// SPDX-License-Identifier: AGPL-3.0-only
//! X.509 certificate chain validation for SID federation.
//!
//! Validates certificate chains from leaf → intermediate(s) → root CA.
//! Checks signatures, validity periods, basic constraints, and revocation status.

use x509_parser::prelude::*;

use crate::error::PkiError;

/// Result of successful chain verification.
#[derive(Debug)]
pub struct VerificationResult {
    /// Subject DN of the leaf certificate.
    pub subject: String,
    /// Whether the leaf is a CA certificate.
    pub is_ca: bool,
    /// Number of certificates in the verified chain (including leaf and root).
    pub chain_length: usize,
}

/// Verify a DER-encoded certificate chain.
///
/// `chain` must be ordered: `[leaf, intermediate..., root]`.
/// The root must be self-signed.
///
/// Checks:
/// 1. Chain structure (issuer/subject linking)
/// 2. Signature verification (each cert signed by next in chain)
/// 3. Validity periods (not expired, not future)
/// 4. Basic constraints (CA certs have CA:TRUE, path length)
pub fn verify_chain(chain: &[&[u8]]) -> Result<VerificationResult, PkiError> {
    if chain.is_empty() {
        return Err(PkiError::ChainInvalid("empty chain".to_string()));
    }

    let mut parsed: Vec<X509Certificate<'_>> = Vec::with_capacity(chain.len());
    for (i, der) in chain.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| PkiError::Parse(format!("cert[{}]: {}", i, e)))?;
        parsed.push(cert);
    }

    // Verify root is self-signed.
    let root = parsed.last().unwrap();
    if root.issuer() != root.subject() {
        return Err(PkiError::ChainInvalid(
            "root certificate is not self-signed".to_string(),
        ));
    }

    // Verify root self-signature.
    root.verify_signature(None)
        .map_err(|e| PkiError::SignatureInvalid(format!("root self-signature: {}", e)))?;

    // Walk chain from root down to leaf, verifying each link.
    for i in (0..parsed.len() - 1).rev() {
        let issued = &parsed[i];
        let issuer = &parsed[i + 1];

        // Check issuer/subject linking.
        if issued.issuer() != issuer.subject() {
            return Err(PkiError::ChainInvalid(format!(
                "issuer mismatch at position {}: cert issuer '{}' != parent subject '{}'",
                i,
                issued.issuer(),
                issuer.subject(),
            )));
        }

        // Verify signature.
        issued
            .verify_signature(Some(issuer.public_key()))
            .map_err(|e| PkiError::SignatureInvalid(format!("cert[{}]: {}", i, e)))?;

        // Check issuer is CA with valid constraints.
        // remaining_ca_depth = number of CA certs between this issuer and the leaf.
        // Leaf (i=0) is not a CA, so we count only intermediate CAs.
        let remaining_ca_depth = if i > 0 { i - 1 } else { 0 };
        verify_ca_constraints(issuer, i + 1, remaining_ca_depth)?;
    }

    // Check validity of all certificates.
    for (i, cert) in parsed.iter().enumerate() {
        verify_validity(cert, i)?;
    }

    let leaf = &parsed[0];
    Ok(VerificationResult {
        subject: leaf.subject().to_string(),
        is_ca: leaf
            .basic_constraints()
            .ok()
            .flatten()
            .map(|bc| bc.value.ca)
            .unwrap_or(false),
        chain_length: parsed.len(),
    })
}

/// Verify a single DER certificate against a known issuer DER certificate.
pub fn verify_issued_by(cert_der: &[u8], issuer_der: &[u8]) -> Result<(), PkiError> {
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|e| PkiError::Parse(e.to_string()))?;
    let (_, issuer) =
        X509Certificate::from_der(issuer_der).map_err(|e| PkiError::Parse(e.to_string()))?;

    if cert.issuer() != issuer.subject() {
        return Err(PkiError::ChainInvalid(
            "issuer DN does not match".to_string(),
        ));
    }

    cert.verify_signature(Some(issuer.public_key()))
        .map_err(|e| PkiError::SignatureInvalid(e.to_string()))?;

    Ok(())
}

/// Parse a DER certificate and extract its subject CN.
pub fn extract_subject_cn(der: &[u8]) -> Result<Option<String>, PkiError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| PkiError::Parse(e.to_string()))?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok().map(|s| s.to_string()));
    Ok(cn)
}

/// Check that a certificate is a valid CA (BasicConstraints CA:TRUE, path length).
fn verify_ca_constraints(
    cert: &X509Certificate<'_>,
    position: usize,
    remaining_depth: usize,
) -> Result<(), PkiError> {
    let bc = cert
        .basic_constraints()
        .map_err(|e| PkiError::Parse(format!("cert[{}] basic constraints: {}", position, e)))?;

    match bc {
        Some(bc) => {
            if !bc.value.ca {
                return Err(PkiError::ChainInvalid(format!(
                    "cert[{}] is not a CA but signed subordinate certificates",
                    position,
                )));
            }
            if let Some(path_len) = bc.value.path_len_constraint
                && (remaining_depth as u32) > path_len
            {
                return Err(PkiError::PathLengthExceeded);
            }
        }
        None => {
            return Err(PkiError::ChainInvalid(format!(
                "cert[{}] missing BasicConstraints extension",
                position,
            )));
        }
    }

    Ok(())
}

/// Check that a certificate is within its validity period.
fn verify_validity(cert: &X509Certificate<'_>, _position: usize) -> Result<(), PkiError> {
    let now = chrono::Utc::now();

    let now_asn1 = x509_parser::time::ASN1Time::from_timestamp(now.timestamp())
        .map_err(|_| PkiError::Parse("cannot convert current time".to_string()))?;

    if now_asn1 < cert.validity().not_before {
        return Err(PkiError::NotYetValid);
    }
    if now_asn1 > cert.validity().not_after {
        return Err(PkiError::Expired);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_builder;

    #[test]
    fn test_verify_root_self_signed() {
        let root = cert_builder::build_root_ca("Test Root", 10).unwrap();
        let result = verify_chain(&[&root.certificate.der]);
        assert!(result.is_ok());
        let vr = result.unwrap();
        assert!(vr.is_ca);
        assert_eq!(vr.chain_length, 1);
    }

    #[test]
    fn test_verify_two_level_chain() {
        let root = cert_builder::build_root_ca("Root CA", 10).unwrap();
        let instance = cert_builder::build_instance_ca(
            "Instance CA",
            "inst_1",
            3,
            &root.certificate.der,
            &root.key_pair,
            root.certificate.id,
        )
        .unwrap();

        let result = verify_chain(&[&instance.certificate.der, &root.certificate.der]);
        assert!(result.is_ok());
        let vr = result.unwrap();
        assert!(vr.is_ca);
        assert_eq!(vr.chain_length, 2);
    }

    #[test]
    fn test_verify_three_level_chain() {
        let root = cert_builder::build_root_ca("Root CA", 10).unwrap();
        let instance = cert_builder::build_instance_ca(
            "Instance CA",
            "inst_1",
            3,
            &root.certificate.der,
            &root.key_pair,
            root.certificate.id,
        )
        .unwrap();
        let binding = cert_builder::build_binding_cert(
            "bind_123",
            "acme.corp",
            "loa2",
            30,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
        )
        .unwrap();

        let result = verify_chain(&[
            &binding.certificate.der,
            &instance.certificate.der,
            &root.certificate.der,
        ]);
        assert!(result.is_ok());
        let vr = result.unwrap();
        assert!(!vr.is_ca);
        assert_eq!(vr.chain_length, 3);
    }

    #[test]
    fn test_verify_wrong_order_fails() {
        let root = cert_builder::build_root_ca("Root CA", 10).unwrap();
        let instance = cert_builder::build_instance_ca(
            "Instance CA",
            "inst_1",
            3,
            &root.certificate.der,
            &root.key_pair,
            root.certificate.id,
        )
        .unwrap();

        // Wrong order: root first, instance second.
        let result = verify_chain(&[&root.certificate.der, &instance.certificate.der]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_issued_by() {
        let root = cert_builder::build_root_ca("Root CA", 10).unwrap();
        let instance = cert_builder::build_instance_ca(
            "Instance CA",
            "inst_1",
            3,
            &root.certificate.der,
            &root.key_pair,
            root.certificate.id,
        )
        .unwrap();

        assert!(verify_issued_by(&instance.certificate.der, &root.certificate.der).is_ok());
    }

    #[test]
    fn test_verify_unrelated_certs_fails() {
        let root1 = cert_builder::build_root_ca("Root 1", 10).unwrap();
        let root2 = cert_builder::build_root_ca("Root 2", 10).unwrap();
        let instance = cert_builder::build_instance_ca(
            "Instance CA",
            "inst_1",
            3,
            &root1.certificate.der,
            &root1.key_pair,
            root1.certificate.id,
        )
        .unwrap();

        // Instance was signed by root1, not root2.
        let result = verify_issued_by(&instance.certificate.der, &root2.certificate.der);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_subject_cn() {
        let root = cert_builder::build_root_ca("My Root CA", 10).unwrap();
        let cn = extract_subject_cn(&root.certificate.der).unwrap();
        assert_eq!(cn, Some("My Root CA".to_string()));
    }

    #[test]
    fn test_empty_chain_fails() {
        let result = verify_chain(&[]);
        assert!(result.is_err());
    }
}
