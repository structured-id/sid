use super::*;
use crate::test_fixtures::{
    BINDING, EXPIRED_INSTANCE_CA, INSTANCE_CA, ORG_CA, ORG_LEAF, OTHER_ROOT, ROOT, ROOT_PATHLEN_0,
    record,
};
use sid_core::models::CertificateType;

/// The anchor's organization CA under the fixture instance CA.
fn org_ca(instance: &Certificate) -> Certificate {
    let mut org = record(ORG_CA, CertificateType::ScopedCa, Some(instance.id));
    org.org_id = Some("org_1".into());
    org
}

// A leaf under an organization CA under the instance CA under the root
// verifies through every issuer to the held root.
#[test]
fn test_verify_leaf_under_organization_ca() {
    let (mut ta, instance) = anchor();
    let org = org_ca(&instance);
    ta.add_scoped_ca(org.clone()).unwrap();
    let mut leaf = record(ORG_LEAF, CertificateType::BindingCertificate, Some(org.id));
    leaf.binding_id = Some("bind_org".into());
    ta.verify_leaf(&leaf).unwrap();
}

// A revoked intermediate refuses every leaf below it.
#[test]
fn test_revoked_intermediate_refuses_the_leaf() {
    let (mut ta, instance) = anchor();
    ta.crl_mut().revoke_serial(instance.serial_hex.clone());
    assert!(matches!(
        ta.verify_leaf(&binding(&instance, "bind_xyz")),
        Err(PkiError::Revoked)
    ));
}

// A revoked organization CA refuses its leaf too, two levels below the root.
#[test]
fn test_revoked_organization_ca_refuses_its_leaf() {
    let (mut ta, instance) = anchor();
    let org = org_ca(&instance);
    ta.add_scoped_ca(org.clone()).unwrap();
    ta.crl_mut().revoke_serial(org.serial_hex.clone());
    let leaf = record(ORG_LEAF, CertificateType::BindingCertificate, Some(org.id));
    assert!(matches!(ta.verify_leaf(&leaf), Err(PkiError::Revoked)));
}

// An expired instance CA is not admitted.
#[test]
fn test_expired_instance_ca_is_not_admitted() {
    let root = record(ROOT, CertificateType::RootCa, None);
    let mut expired = record(
        EXPIRED_INSTANCE_CA,
        CertificateType::InstanceCa,
        Some(root.id),
    );
    expired.instance_id = Some("expired".into());
    let mut ta = TrustAnchor::new();
    ta.add_root_ca(root).unwrap();
    assert!(matches!(
        ta.add_instance_ca(expired),
        Err(PkiError::Expired)
    ));
}

// Under a root with pathLenConstraint 0 the instance CA is admitted, but no
// leaf below it verifies (RFC 5280 §4.2.1.9).
#[test]
fn test_leaf_beyond_the_root_path_length_is_refused() {
    let root = record(ROOT_PATHLEN_0, CertificateType::RootCa, None);
    let mut instance = record(INSTANCE_CA, CertificateType::InstanceCa, Some(root.id));
    instance.instance_id = Some("test_instance".into());
    let mut ta = TrustAnchor::new();
    ta.add_root_ca(root).unwrap();
    ta.add_instance_ca(instance.clone()).unwrap();
    assert!(matches!(
        ta.verify_leaf(&binding(&instance, "bind_xyz")),
        Err(PkiError::PathLengthExceeded)
    ));
}

// A record whose issuer chain loops never reaches a root and is refused.
#[test]
fn test_issuer_loop_is_refused() {
    let (mut ta, instance) = anchor();
    let mut org = org_ca(&instance);
    ta.add_scoped_ca(org.clone()).unwrap();
    // A forged record naming itself as its own parent.
    org.parent_id = Some(org.id);
    assert!(ta.verify_leaf(&org).is_err());
}

/// The fixture root and its instance CA as records, the instance CA naming
/// the root as parent.
fn setup_pki() -> (Certificate, Certificate) {
    let root = record(ROOT, CertificateType::RootCa, None);
    let mut instance = record(INSTANCE_CA, CertificateType::InstanceCa, Some(root.id));
    instance.instance_id = Some("test_instance".into());
    (root, instance)
}

/// The fixture binding certificate under `instance`, with `binding_id`.
fn binding(instance: &Certificate, binding_id: &str) -> Certificate {
    let mut binding = record(
        BINDING,
        CertificateType::BindingCertificate,
        Some(instance.id),
    );
    binding.binding_id = Some(binding_id.into());
    binding
}

/// A trust anchor holding the fixture root and instance CA.
fn anchor() -> (TrustAnchor, Certificate) {
    let (root, instance) = setup_pki();
    let mut ta = TrustAnchor::new();
    ta.add_root_ca(root).unwrap();
    ta.add_instance_ca(instance.clone()).unwrap();
    (ta, instance)
}

#[test]
fn test_add_root_ca() {
    let mut ta = TrustAnchor::new();
    assert!(
        ta.add_root_ca(record(ROOT, CertificateType::RootCa, None))
            .is_ok()
    );
    assert_eq!(ta.root_ca_count(), 1);
}

#[test]
fn test_add_instance_ca() {
    let (root, instance) = setup_pki();
    let mut ta = TrustAnchor::new();
    ta.add_root_ca(root).unwrap();
    assert!(ta.add_instance_ca(instance).is_ok());
    assert_eq!(ta.instance_ca_count(), 1);
    assert!(ta.get_instance_ca("test_instance").is_some());
}

// An instance CA is admitted only under a root the anchor holds.
#[test]
fn test_add_instance_ca_without_root_fails() {
    let (_, instance) = setup_pki();
    let mut ta = TrustAnchor::new();
    assert!(ta.add_instance_ca(instance).is_err());
}

// An instance CA that names a held root as parent but was signed by another
// is refused.
#[test]
fn test_add_instance_ca_under_another_root_fails() {
    let other = record(OTHER_ROOT, CertificateType::RootCa, None);
    let mut instance = record(INSTANCE_CA, CertificateType::InstanceCa, Some(other.id));
    instance.instance_id = Some("test_instance".into());
    let mut ta = TrustAnchor::new();
    ta.add_root_ca(other).unwrap();
    assert!(matches!(
        ta.add_instance_ca(instance),
        Err(PkiError::SignatureInvalid(_) | PkiError::ChainInvalid(_))
    ));
}

#[test]
fn test_verify_binding_cert() {
    let (ta, instance) = anchor();
    assert!(ta.verify_leaf(&binding(&instance, "bind_xyz")).is_ok());
}

#[test]
fn test_verify_revoked_binding() {
    let (mut ta, instance) = anchor();
    ta.crl_mut().revoke_binding("bind_revoked".to_string());
    let result = ta.verify_leaf(&binding(&instance, "bind_revoked"));
    assert!(matches!(result, Err(PkiError::Revoked)));
}

#[test]
fn test_verify_revoked_serial() {
    let (mut ta, instance) = anchor();
    let leaf = binding(&instance, "bind_ser");
    ta.crl_mut().revoke_serial(leaf.serial_hex.clone());
    assert!(matches!(ta.verify_leaf(&leaf), Err(PkiError::Revoked)));
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
