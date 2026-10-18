use super::*;
use crate::test_fixtures::{BINDING, INSTANCE_CA, OTHER_ROOT, ROOT, der};

// A self-signed root verifies on its own and is a CA.
#[test]
fn test_verify_root_self_signed() {
    let root = der(ROOT);
    let vr = verify_chain(&[&root]).unwrap();
    assert!(vr.is_ca);
    assert_eq!(vr.chain_length, 1);
}

// An instance CA verifies under the root that signed it.
#[test]
fn test_verify_two_level_chain() {
    let (root, instance) = (der(ROOT), der(INSTANCE_CA));
    let vr = verify_chain(&[&instance, &root]).unwrap();
    assert!(vr.is_ca);
    assert_eq!(vr.chain_length, 2);
}

// A binding certificate verifies through its instance CA to the root and is
// not a CA.
#[test]
fn test_verify_three_level_chain() {
    let (root, instance, binding) = (der(ROOT), der(INSTANCE_CA), der(BINDING));
    let vr = verify_chain(&[&binding, &instance, &root]).unwrap();
    assert!(!vr.is_ca);
    assert_eq!(vr.chain_length, 3);
}

// The chain is leaf first: root first is refused.
#[test]
fn test_verify_wrong_order_fails() {
    let (root, instance) = (der(ROOT), der(INSTANCE_CA));
    assert!(verify_chain(&[&root, &instance]).is_err());
}

// A certificate verifies under its issuer.
#[test]
fn test_verify_issued_by() {
    assert!(verify_issued_by(&der(INSTANCE_CA), &der(ROOT)).is_ok());
}

// A certificate does not verify under an unrelated root.
#[test]
fn test_verify_unrelated_certs_fails() {
    assert!(verify_issued_by(&der(INSTANCE_CA), &der(OTHER_ROOT)).is_err());
}

// A chain that ends in another root is refused.
#[test]
fn test_verify_chain_under_another_root_fails() {
    let (other, instance) = (der(OTHER_ROOT), der(INSTANCE_CA));
    assert!(verify_chain(&[&instance, &other]).is_err());
}

#[test]
fn test_extract_subject_cn() {
    let cn = extract_subject_cn(&der(ROOT)).unwrap();
    assert_eq!(cn, Some("Test Root CA".to_string()));
}

#[test]
fn test_empty_chain_fails() {
    assert!(verify_chain(&[]).is_err());
}
