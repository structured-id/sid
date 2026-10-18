use super::*;
use crate::test_fixtures::{BINDING, INSTANCE_CA, OTHER_ROOT, ROOT, record};
use sid_core::models::CertificateType;

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
