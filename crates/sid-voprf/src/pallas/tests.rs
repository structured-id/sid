use ff::{Field, PrimeField};
use group::GroupEncoding;
use pasta_curves::pallas;

use super::*;

fn hex(bytes: &[u8]) -> alloc::string::String {
    bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
}

/// The values the published TypeScript client reproduces (its
/// `hash-to-curve.json` fixture): moving the suite must not change one bit.
#[test]
fn hash_to_curve_matches_the_published_vector() {
    let (point, u, offset) = hash_to_curve_native(b"Str0ngP@ssword!");
    let coords = point.coordinates().unwrap();
    assert_eq!(
        hex(u.to_repr().as_ref()),
        "0e06d86167c3e8564a6aed401e3a23650bcd5c43df79350eb279ed55c29dd23d"
    );
    assert_eq!(offset, pallas::Base::ZERO);
    assert_eq!(
        hex(coords.x().to_repr().as_ref()),
        "0e06d86167c3e8564a6aed401e3a23650bcd5c43df79350eb279ed55c29dd23d"
    );
    assert_eq!(
        hex(coords.y().to_repr().as_ref()),
        "1289644e798c301f400854bc8435147247e6f0e03be397a148b641cb09355e01"
    );
}

/// The OPRF element is the native hash of the padded password, the buffer a
/// proof commits to, and the DST takes no part in it.
#[test]
fn the_group_hashes_the_padded_password() {
    let password = b"Str0ngP@ssword!";
    let (native, _, _) = hash_to_curve_native(&padded_password(password));
    let a = PallasGroup::hash_to_curve::<sha2::Sha256>(&[password], &[b"dst-1"]).unwrap();
    let b = PallasGroup::hash_to_curve::<sha2::Sha256>(&[password], &[b"dst-2"]).unwrap();
    assert_eq!(a.0, native.to_curve());
    assert_eq!(a.0, b.0);
    let other = PallasGroup::hash_to_curve::<sha2::Sha256>(&[b"Different-1"], &[b"dst-1"]).unwrap();
    assert!(!bool::from(a.ct_eq(&other)));
}

#[test]
fn an_empty_input_is_refused() {
    assert!(PallasGroup::hash_to_curve::<sha2::Sha256>(&[b""], &[b"dst"]).is_err());
    assert!(PallasGroup::hash_to_scalar::<sha2::Sha256>(&[b""], &[b"dst"]).is_err());
}

/// The padded password is the circuit's buffer; a longer one stays as given.
#[test]
fn passwords_are_padded_to_the_circuit_length() {
    assert_eq!(padded_password(b"abc").len(), MAX_PASSWORD_LEN);
    assert_eq!(&padded_password(b"abc")[..3], b"abc");
    let long = [b'a'; MAX_PASSWORD_LEN + 2];
    assert_eq!(padded_password(&long), long);
}

#[test]
fn field_elements_pack_31_bytes() {
    assert_eq!(bytes_to_field_elements(&[0u8; 128]).len(), 5);
    assert_eq!(bytes_to_field_elements(&[1u8; 31]).len(), 1);
    assert_eq!(bytes_to_field_elements(&[1u8]), [pallas::Base::ONE]);
}

#[test]
fn identity_and_zero_are_refused() {
    let identity = pallas::Point::identity().to_bytes();
    assert!(PallasGroup::deserialize_elem(&identity).is_err());
    assert!(PallasGroup::deserialize_scalar(&pallas::Scalar::ZERO.to_repr()).is_err());
    let base = PallasGroup::serialize_elem(PallasGroup::base_elem());
    assert!(PallasGroup::deserialize_elem(&base[..31]).is_err());
    assert!(bool::from(
        PallasGroup::deserialize_elem(&base)
            .unwrap()
            .ct_eq(&PallasGroup::base_elem())
    ));
}
