// SPDX-License-Identifier: AGPL-3.0-only
//! SID-specific X.509v3 extension OIDs and builders.
//!
//! Uses private enterprise OID arc: 1.3.6.1.4.1.XXXXX (placeholder until IANA assignment).
//! Subdivisions:
//!   .1.0 — Instance ID
//!   .2.0 — Binding sector
//!   .2.3 — Assurance level
//!   .3.0 — Scoped CA organization ID

use rcgen::CustomExtension;

/// Base OID arc for SID custom extensions (placeholder PEN).
/// Format: iso(1).identified-organization(3).dod(6).internet(1).private(4).enterprise(1).SID(59281)
const SID_OID_BASE: &[u64] = &[1, 3, 6, 1, 4, 1, 59281];

/// OID: sid.instance_id (1.3.6.1.4.1.59281.1.0)
fn instance_id_oid() -> Vec<u64> {
    let mut oid = SID_OID_BASE.to_vec();
    oid.extend_from_slice(&[1, 0]);
    oid
}

/// OID: sid.binding.sector (1.3.6.1.4.1.59281.2.0)
fn binding_sector_oid() -> Vec<u64> {
    let mut oid = SID_OID_BASE.to_vec();
    oid.extend_from_slice(&[2, 0]);
    oid
}

/// OID: sid.binding.assurance_level (1.3.6.1.4.1.59281.2.3)
fn assurance_level_oid() -> Vec<u64> {
    let mut oid = SID_OID_BASE.to_vec();
    oid.extend_from_slice(&[2, 3]);
    oid
}

/// OID: sid.scoped_ca.org_id (1.3.6.1.4.1.59281.3.0)
fn scoped_ca_org_oid() -> Vec<u64> {
    let mut oid = SID_OID_BASE.to_vec();
    oid.extend_from_slice(&[3, 0]);
    oid
}

/// Build a custom extension with UTF-8 string value.
fn string_extension(oid: Vec<u64>, value: &str) -> CustomExtension {
    // Encode as DER UTF8String: tag 0x0C + length + value bytes.
    let value_bytes = value.as_bytes();
    let mut der = Vec::with_capacity(2 + value_bytes.len());
    der.push(0x0C); // UTF8String tag
    if value_bytes.len() < 128 {
        der.push(value_bytes.len() as u8);
    } else {
        // Long form length encoding.
        let len = value_bytes.len();
        if len <= 0xFF {
            der.push(0x81);
            der.push(len as u8);
        } else {
            der.push(0x82);
            der.push((len >> 8) as u8);
            der.push((len & 0xFF) as u8);
        }
    }
    der.extend_from_slice(value_bytes);

    CustomExtension::from_oid_content(&oid, der)
}

/// Instance ID extension for InstanceCA certificates.
pub(crate) fn instance_id_extension(instance_id: &str) -> CustomExtension {
    string_extension(instance_id_oid(), instance_id)
}

/// Binding sector extension for BindingCertificates.
pub(crate) fn binding_sector_extension(sector: &str) -> CustomExtension {
    string_extension(binding_sector_oid(), sector)
}

/// Assurance level extension for BindingCertificates.
pub(crate) fn assurance_level_extension(level: &str) -> CustomExtension {
    string_extension(assurance_level_oid(), level)
}

/// Organization ID extension for ScopedCA certificates.
pub(crate) fn scoped_ca_org_extension(org_id: &str) -> CustomExtension {
    string_extension(scoped_ca_org_oid(), org_id)
}

/// OID string constants for parsing (dotted notation).
/// Used by chain_validator when extracting SID-specific extensions.
#[allow(dead_code)]
pub(crate) const INSTANCE_ID_OID_STR: &str = "1.3.6.1.4.1.59281.1.0";
#[allow(dead_code)]
pub(crate) const BINDING_SECTOR_OID_STR: &str = "1.3.6.1.4.1.59281.2.0";
#[allow(dead_code)]
pub(crate) const ASSURANCE_LEVEL_OID_STR: &str = "1.3.6.1.4.1.59281.2.3";
#[allow(dead_code)]
pub(crate) const SCOPED_CA_ORG_OID_STR: &str = "1.3.6.1.4.1.59281.3.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instance_id_oid() {
        let oid = instance_id_oid();
        assert_eq!(oid, vec![1, 3, 6, 1, 4, 1, 59281, 1, 0]);
    }

    #[test]
    fn test_binding_sector_oid() {
        let oid = binding_sector_oid();
        assert_eq!(oid, vec![1, 3, 6, 1, 4, 1, 59281, 2, 0]);
    }

    #[test]
    fn test_string_extension_short() {
        let ext = string_extension(vec![1, 2, 3], "hello");
        // Just verify it doesn't panic.
        let _ = ext;
    }
}
