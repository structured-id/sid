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

/// The longest chain the anchor follows: leaf, its issuers and the root.
const MAX_CHAIN_LENGTH: usize = 8;

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

    /// Add an instance CA. Verifies it is a CA directly under a held root,
    /// on the whole chain (signature, validity, constraints, revocation).
    pub fn add_instance_ca(&mut self, cert: Certificate) -> Result<(), PkiError> {
        let instance_id = cert
            .instance_id
            .as_deref()
            .ok_or_else(|| PkiError::MissingExtension("instance_id".to_string()))?
            .to_string();
        let parent_id = cert.parent_id.ok_or(PkiError::IssuerNotFound)?;
        if !self.root_cas.contains_key(&parent_id.0.to_string()) {
            return Err(PkiError::IssuerNotFound);
        }
        self.verify_ca(&cert)?;
        self.instance_cas.insert(instance_id, cert);
        Ok(())
    }

    /// Add a scoped CA. Verifies it is a CA under a held CA, on the whole
    /// chain to a held root.
    pub fn add_scoped_ca(&mut self, cert: Certificate) -> Result<(), PkiError> {
        let org_id = cert
            .org_id
            .as_deref()
            .ok_or_else(|| PkiError::MissingExtension("org_id".to_string()))?
            .to_string();
        self.verify_ca(&cert)?;
        self.scoped_cas.insert(org_id, cert);
        Ok(())
    }

    /// Verify a leaf certificate against this trust anchor: the chain from it
    /// through every issuer the anchor holds to a held root, verified as a
    /// whole, with no certificate in it revoked.
    pub fn verify_leaf(&self, cert: &Certificate) -> Result<(), PkiError> {
        cert.parent_id.ok_or(PkiError::IssuerNotFound)?;
        self.verify_path(&self.chain_to_root(cert)?)?;
        Ok(())
    }

    /// `cert` verifies as a CA on its chain to a held root.
    fn verify_ca(&self, cert: &Certificate) -> Result<(), PkiError> {
        cert.parent_id.ok_or(PkiError::IssuerNotFound)?;
        let verified = self.verify_path(&self.chain_to_root(cert)?)?;
        if !verified.is_ca {
            return Err(PkiError::ChainInvalid(
                "the certificate is not a CA".to_string(),
            ));
        }
        Ok(())
    }

    /// `[cert, issuer, ..., root]`: the issuers of `cert` the anchor holds,
    /// ending at a held root. A chain that loops or exceeds the anchor's
    /// depth is refused, as is one that ends anywhere but a root.
    fn chain_to_root<'a>(
        &'a self,
        cert: &'a Certificate,
    ) -> Result<Vec<&'a Certificate>, PkiError> {
        let mut chain = vec![cert];
        let mut current = cert;
        while let Some(parent) = current.parent_id {
            if chain.len() >= MAX_CHAIN_LENGTH || chain.iter().any(|c| c.id == parent) {
                return Err(PkiError::ChainInvalid(
                    "the issuer chain loops or is too long".to_string(),
                ));
            }
            current = self.find_ca_by_id(parent)?;
            chain.push(current);
        }
        if !self.root_cas.contains_key(&current.id.0.to_string()) {
            return Err(PkiError::IssuerNotFound);
        }
        Ok(chain)
    }

    /// Verify `chain` as a whole (signatures, validity, basic constraints and
    /// path length of every issuer), refusing it if any certificate in it is
    /// revoked.
    fn verify_path(
        &self,
        chain: &[&Certificate],
    ) -> Result<chain_validator::VerificationResult, PkiError> {
        let revoked = |c: &Certificate| {
            self.crl.is_serial_revoked(&c.serial_hex)
                || c.binding_id
                    .as_deref()
                    .is_some_and(|b| self.crl.is_binding_revoked(b))
        };
        if chain.iter().any(|c| revoked(c)) {
            return Err(PkiError::Revoked);
        }
        let ders: Vec<&[u8]> = chain.iter().map(|c| c.der.as_slice()).collect();
        chain_validator::verify_chain(&ders)
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
mod tests;
