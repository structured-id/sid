// SPDX-License-Identifier: AGPL-3.0-only
//! Trust anchor management for federation certificate verification.
//!
//! A trust anchor holds the root CA(s) and instance CAs that this node trusts,
//! along with a revocation cache for binding-level and profile-level revocation.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use sid_core::models::Certificate;

use crate::chain_validator;
use crate::error::PkiError;

/// Trust anchor — the set of trusted CAs for chain verification.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// Root CAs (keyed by certificate ID hex string).
    root_cas: HashMap<String, Certificate>,

    /// Instance CAs from federated peers (keyed by instance_id).
    instance_cas: HashMap<String, Certificate>,

    /// Scoped CAs for enterprise federation (keyed by org_id).
    scoped_cas: HashMap<String, Certificate>,

    /// Revocation cache.
    crl: CrlCache,
}

/// Revocation list cache.
#[derive(Debug, Clone, Default)]
pub struct CrlCache {
    /// Revoked certificate serial numbers (hex).
    pub revoked_serials: HashSet<String>,

    /// Revoked binding IDs.
    pub revoked_binding_ids: HashSet<String>,

    /// Last update timestamp.
    pub last_updated: Option<DateTime<Utc>>,
}

impl CrlCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a serial number is revoked.
    pub fn is_serial_revoked(&self, serial_hex: &str) -> bool {
        self.revoked_serials.contains(serial_hex)
    }

    /// Check if a binding ID is revoked.
    pub fn is_binding_revoked(&self, binding_id: &str) -> bool {
        self.revoked_binding_ids.contains(binding_id)
    }

    /// Add a revoked serial.
    pub fn revoke_serial(&mut self, serial_hex: String) {
        self.revoked_serials.insert(serial_hex);
    }

    /// Add a revoked binding.
    pub fn revoke_binding(&mut self, binding_id: String) {
        self.revoked_binding_ids.insert(binding_id);
    }
}

impl TrustAnchor {
    /// Create an empty trust anchor.
    pub fn new() -> Self {
        Self {
            root_cas: HashMap::new(),
            instance_cas: HashMap::new(),
            scoped_cas: HashMap::new(),
            crl: CrlCache::new(),
        }
    }

    /// Add a root CA. Verifies it is self-signed.
    pub fn add_root_ca(&mut self, cert: Certificate) -> Result<(), PkiError> {
        // Verify self-signed.
        chain_validator::verify_chain(&[&cert.der])?;
        let key = cert.id.0.to_string();
        self.root_cas.insert(key, cert);
        Ok(())
    }

    /// Add an instance CA. Verifies it chains to a known root CA.
    pub fn add_instance_ca(&mut self, cert: Certificate) -> Result<(), PkiError> {
        let instance_id = cert
            .instance_id
            .as_deref()
            .ok_or_else(|| PkiError::MissingExtension("instance_id".to_string()))?
            .to_string();

        // Find the parent root CA.
        let parent_id = cert.parent_id.ok_or(PkiError::IssuerNotFound)?;
        let root = self
            .root_cas
            .get(&parent_id.0.to_string())
            .ok_or(PkiError::IssuerNotFound)?;

        // Verify chain.
        chain_validator::verify_issued_by(&cert.der, &root.der)?;

        self.instance_cas.insert(instance_id, cert);
        Ok(())
    }

    /// Add a scoped CA. Verifies it chains to a known instance CA.
    pub fn add_scoped_ca(&mut self, cert: Certificate) -> Result<(), PkiError> {
        let org_id = cert
            .org_id
            .as_deref()
            .ok_or_else(|| PkiError::MissingExtension("org_id".to_string()))?
            .to_string();

        // Find parent instance CA.
        let parent_id = cert.parent_id.ok_or(PkiError::IssuerNotFound)?;
        let issuer = self.find_ca_by_id(parent_id)?;

        chain_validator::verify_issued_by(&cert.der, &issuer.der)?;

        self.scoped_cas.insert(org_id, cert);
        Ok(())
    }

    /// Verify a leaf certificate against this trust anchor.
    ///
    /// Builds the chain from leaf → issuer → root and validates.
    pub fn verify_leaf(&self, cert: &Certificate) -> Result<(), PkiError> {
        // Check CRL first.
        if self.crl.is_serial_revoked(&cert.serial_hex) {
            return Err(PkiError::Revoked);
        }
        if let Some(ref bid) = cert.binding_id
            && self.crl.is_binding_revoked(bid)
        {
            return Err(PkiError::Revoked);
        }

        // Find the issuer CA.
        let parent_id = cert.parent_id.ok_or(PkiError::IssuerNotFound)?;
        let issuer = self.find_ca_by_id(parent_id)?;

        // Verify signature.
        chain_validator::verify_issued_by(&cert.der, &issuer.der)?;

        // If issuer is instance CA, verify it chains to root.
        if let Some(ref issuer_parent_id) = issuer.parent_id {
            let root = self
                .root_cas
                .get(&issuer_parent_id.0.to_string())
                .ok_or(PkiError::IssuerNotFound)?;
            chain_validator::verify_issued_by(&issuer.der, &root.der)?;
        }

        Ok(())
    }

    /// Get a mutable reference to the CRL cache.
    pub fn crl_mut(&mut self) -> &mut CrlCache {
        &mut self.crl
    }

    /// Get the CRL cache.
    pub fn crl(&self) -> &CrlCache {
        &self.crl
    }

    /// Number of root CAs.
    pub fn root_ca_count(&self) -> usize {
        self.root_cas.len()
    }

    /// Number of instance CAs.
    pub fn instance_ca_count(&self) -> usize {
        self.instance_cas.len()
    }

    /// Get an instance CA by instance ID.
    pub fn get_instance_ca(&self, instance_id: &str) -> Option<&Certificate> {
        self.instance_cas.get(instance_id)
    }

    /// Find a CA certificate by its CertificateId (searches all CA collections).
    fn find_ca_by_id(&self, id: sid_core::models::CertificateId) -> Result<&Certificate, PkiError> {
        let id_str = id.0.to_string();

        if let Some(c) = self.root_cas.get(&id_str) {
            return Ok(c);
        }
        for c in self.instance_cas.values() {
            if c.id == id {
                return Ok(c);
            }
        }
        for c in self.scoped_cas.values() {
            if c.id == id {
                return Ok(c);
            }
        }

        Err(PkiError::IssuerNotFound)
    }
}

impl Default for TrustAnchor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_builder;

    fn setup_pki() -> (cert_builder::GeneratedCert, cert_builder::GeneratedCert) {
        let root = cert_builder::build_root_ca("Test Root CA", 10).unwrap();
        let instance = cert_builder::build_instance_ca(
            "Test Instance CA",
            "test_instance",
            3,
            &root.certificate.der,
            &root.key_pair,
            root.certificate.id,
        )
        .unwrap();
        (root, instance)
    }

    #[test]
    fn test_add_root_ca() {
        let root = cert_builder::build_root_ca("Root CA", 10).unwrap();
        let mut ta = TrustAnchor::new();
        assert!(ta.add_root_ca(root.certificate).is_ok());
        assert_eq!(ta.root_ca_count(), 1);
    }

    #[test]
    fn test_add_instance_ca() {
        let (root, instance) = setup_pki();
        let mut ta = TrustAnchor::new();
        ta.add_root_ca(root.certificate).unwrap();
        assert!(ta.add_instance_ca(instance.certificate).is_ok());
        assert_eq!(ta.instance_ca_count(), 1);
        assert!(ta.get_instance_ca("test_instance").is_some());
    }

    #[test]
    fn test_add_instance_ca_without_root_fails() {
        let (_, instance) = setup_pki();
        let mut ta = TrustAnchor::new();
        // No root CA added.
        assert!(ta.add_instance_ca(instance.certificate).is_err());
    }

    #[test]
    fn test_verify_binding_cert() {
        let (root, instance) = setup_pki();
        let binding = cert_builder::build_binding_cert(
            "bind_xyz",
            "example.com",
            "loa1",
            30,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
        )
        .unwrap();

        let mut ta = TrustAnchor::new();
        ta.add_root_ca(root.certificate).unwrap();
        ta.add_instance_ca(instance.certificate).unwrap();

        assert!(ta.verify_leaf(&binding.certificate).is_ok());
    }

    #[test]
    fn test_verify_revoked_binding() {
        let (root, instance) = setup_pki();
        let binding = cert_builder::build_binding_cert(
            "bind_revoked",
            "example.com",
            "loa1",
            30,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
        )
        .unwrap();

        let mut ta = TrustAnchor::new();
        ta.add_root_ca(root.certificate).unwrap();
        ta.add_instance_ca(instance.certificate).unwrap();

        // Revoke the binding.
        ta.crl_mut().revoke_binding("bind_revoked".to_string());
        let result = ta.verify_leaf(&binding.certificate);
        assert!(matches!(result, Err(PkiError::Revoked)));
    }

    #[test]
    fn test_verify_revoked_serial() {
        let (root, instance) = setup_pki();
        let binding = cert_builder::build_binding_cert(
            "bind_ser",
            "example.com",
            "loa1",
            30,
            &instance.certificate.der,
            &instance.key_pair,
            instance.certificate.id,
        )
        .unwrap();

        let mut ta = TrustAnchor::new();
        ta.add_root_ca(root.certificate).unwrap();
        ta.add_instance_ca(instance.certificate).unwrap();

        ta.crl_mut()
            .revoke_serial(binding.certificate.serial_hex.clone());
        let result = ta.verify_leaf(&binding.certificate);
        assert!(matches!(result, Err(PkiError::Revoked)));
    }

    #[test]
    fn test_crl_cache() {
        let mut crl = CrlCache::new();
        assert!(!crl.is_serial_revoked("abc"));
        crl.revoke_serial("abc".to_string());
        assert!(crl.is_serial_revoked("abc"));

        assert!(!crl.is_binding_revoked("bind_1"));
        crl.revoke_binding("bind_1".to_string());
        assert!(crl.is_binding_revoked("bind_1"));
    }
}
