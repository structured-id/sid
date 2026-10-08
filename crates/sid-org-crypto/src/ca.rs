// SPDX-License-Identifier: AGPL-3.0-only
//! CA generation: self-signed root certificate for an organization.
//!
//! Generates an Ed25519 self-signed root cert + matching private key. No
//! post-quantum component is generated here.
//!
//! ## What this module produces
//!
//! For a given org domain (e.g. `acme.corp`):
//!   - X.509 v3 self-signed root certificate (DER-encoded)
//!   - Ed25519 private key in PKCS#8 DER form
//!
//! ## Validity
//!
//! Default 10 years for root CA. Caller may override via `CaParams::valid_for`.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use secrecy::SecretBox;
use time::{Duration, OffsetDateTime};

use crate::error::OrgCryptoError;

/// Parameters for generating a per-org self-signed root CA.
pub struct CaParams<'a> {
    /// Org domain — used as Subject CN and SAN DNS.
    pub domain: &'a str,
    /// Organization name shown in cert Subject (default: domain).
    pub organization_name: Option<&'a str>,
    /// Validity duration. Default: 10 years.
    pub valid_for: Duration,
}

impl<'a> CaParams<'a> {
    pub fn new(domain: &'a str) -> Self {
        Self {
            domain,
            organization_name: None,
            valid_for: Duration::days(365 * 10),
        }
    }
}

/// Generated CA material. Caller wraps `private_key_pkcs8_der` with the org
/// DEK before persisting to `shared.organizations.ca_classical_priv_wrapped`.
pub struct GeneratedCa {
    /// X.509 v3 self-signed root cert in DER form. Persist plaintext.
    pub cert_der: Vec<u8>,
    /// Ed25519 private key in PKCS#8 v2 DER form. **Wrap with DEK before persisting.**
    pub private_key_pkcs8_der: SecretBox<Vec<u8>>,
}

/// Generate a self-signed Ed25519 root CA for an org.
pub fn generate_classical_ca(params: &CaParams<'_>) -> Result<GeneratedCa, OrgCryptoError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| OrgCryptoError::Aes(format!("rcgen keypair: {e}")))?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, params.domain);
    dn.push(
        DnType::OrganizationName,
        params.organization_name.unwrap_or(params.domain),
    );

    let mut cert_params = CertificateParams::new(vec![params.domain.to_string()])
        .map_err(|e| OrgCryptoError::Aes(format!("rcgen params: {e}")))?;
    cert_params.distinguished_name = dn;
    cert_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    cert_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let now = OffsetDateTime::now_utc();
    cert_params.not_before = now;
    cert_params.not_after = now + params.valid_for;

    let cert = cert_params
        .self_signed(&key_pair)
        .map_err(|e| OrgCryptoError::Aes(format!("rcgen self-sign: {e}")))?;

    let cert_der = cert.der().to_vec();
    let pkcs8_der = key_pair.serialize_der();

    Ok(GeneratedCa {
        cert_der,
        private_key_pkcs8_der: SecretBox::new(Box::new(pkcs8_der)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn generate_ca_for_domain() {
        let params = CaParams::new("acme.corp");
        let ca = generate_classical_ca(&params).expect("generate");
        assert!(!ca.cert_der.is_empty());
        assert!(!ca.private_key_pkcs8_der.expose_secret().is_empty());
    }

    #[test]
    fn cert_starts_with_der_sequence() {
        let params = CaParams::new("test.example");
        let ca = generate_classical_ca(&params).unwrap();
        // X.509 DER always starts with SEQUENCE (0x30).
        assert_eq!(ca.cert_der[0], 0x30);
    }

    #[test]
    fn validity_can_be_overridden() {
        let mut params = CaParams::new("short.example");
        params.valid_for = Duration::days(30);
        let ca = generate_classical_ca(&params).unwrap();
        assert!(!ca.cert_der.is_empty());
    }

    #[test]
    fn org_name_falls_back_to_domain() {
        // Ensures we don't panic when organization_name is None.
        let params = CaParams::new("dummy.example");
        let _ = generate_classical_ca(&params).unwrap();
    }

    #[test]
    fn generates_distinct_keys_each_call() {
        let params = CaParams::new("x.example");
        let a = generate_classical_ca(&params).unwrap();
        let b = generate_classical_ca(&params).unwrap();
        // Vanishingly unlikely to collide.
        assert_ne!(
            a.private_key_pkcs8_der.expose_secret(),
            b.private_key_pkcs8_der.expose_secret()
        );
    }
}
