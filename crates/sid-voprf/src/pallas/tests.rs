use ff::{Field, PrimeField};
use group::GroupEncoding;
use pasta_curves::pallas;

use super::*;

fn hex(bytes: &[u8]) -> alloc::string::String {
    bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
}

/// The values the proof crate's circuit computes for this password (its
/// `circuit_vectors` example, `hash-to-curve.json`), which the TypeScript
/// client reproduces: the suite and the circuit hash alike.
#[test]
fn hash_to_curve_matches_the_circuit_vector() {
    let (point, u, offset) = hash_to_curve_native(b"Str0ngP@ssword!");
    let coords = point.coordinates().unwrap();
    assert_eq!(
        hex(u.to_repr().as_ref()),
        "41c16d0decf874c6948613891d6c3507646197b4058deede6038eeae2cb6a423"
    );
    assert_eq!(offset, pallas::Base::ONE);
    assert_eq!(
        hex(coords.x().to_repr().as_ref()),
        "42c16d0decf874c6948613891d6c3507646197b4058deede6038eeae2cb6a423"
    );
    assert_eq!(
        hex(coords.y().to_repr().as_ref()),
        "2ce0bbc4ca40ecffa3bfd4efb1772501a78aadb756e8f0405f841ac9aca79338"
    );
}

/// The OPRF element is the native hash of the password, the one a proof
/// commits to, and the DST takes no part in it.
#[test]
fn the_group_hashes_the_password() {
    let password = b"Str0ngP@ssword!";
    let (native, _, _) = hash_to_curve_native(password);
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

/// A password that fits is absorbed as the circuit's padded buffer; a longer
/// one as given.
#[test]
fn passwords_are_packed_as_the_circuit_packs_them() {
    let mut padded = [0u8; MAX_PASSWORD_LEN];
    padded[..3].copy_from_slice(b"abc");
    assert_eq!(password_elements(b"abc"), bytes_to_field_elements(&padded));
    let long = [b'a'; MAX_PASSWORD_LEN + 2];
    assert_eq!(password_elements(&long), bytes_to_field_elements(&long));
}

#[test]
fn field_elements_pack_31_bytes() {
    assert_eq!(bytes_to_field_elements(&[0u8; 128]).len(), 5);
    assert_eq!(bytes_to_field_elements(&[1u8; 31]).len(), 1);
    assert_eq!(bytes_to_field_elements(&[1u8]), [pallas::Base::ONE]);
}

fn group_point(password: &[u8]) -> pallas::Point {
    PallasGroup::hash_to_curve::<sha2::Sha256>(&[password], &[b"dst"])
        .unwrap()
        .0
}

/// `value` as one 31-byte little-endian chunk, the unit the password is
/// packed in.
fn chunk(value: pallas::Base) -> [u8; 31] {
    let repr = value.to_repr();
    assert_eq!(repr[31], 0, "the value fits 31 bytes");
    repr[..31].try_into().unwrap()
}

/// A password and the same bytes with a trailing NUL are different inputs:
/// one OPRF evaluation must not answer for both (RFC 9497 §4.6).
#[test]
fn trailing_nul_is_another_password() {
    assert_ne!(group_point(b"a"), group_point(b"a\0"));
    let mut padded = b"Str0ngP@ss".to_vec();
    padded.resize(MAX_PASSWORD_LEN, 0);
    assert_ne!(group_point(b"Str0ngP@ss"), group_point(&padded));
}

/// The chain over a long input cannot be shortened: replacing its first two
/// elements by their hash, which fits one chunk, is another password.
#[test]
fn long_input_chain_does_not_compress() {
    let values: Vec<pallas::Base> = [173u64, 1, 2, 3, 4, 5]
        .into_iter()
        .map(pallas::Base::from)
        .collect();
    let head = poseidon_hash_2(&[values[0], values[1]]);
    let long: Vec<u8> = values.iter().flat_map(|v| chunk(*v)).collect();
    let short: Vec<u8> = core::iter::once(head)
        .chain(values[2..].iter().copied())
        .flat_map(chunk)
        .collect();
    assert_eq!((long.len(), short.len()), (186, 155));
    assert_ne!(group_point(&long), group_point(&short));
}

/// Inputs at the packing and circuit boundaries each hash to their own point.
#[test]
fn boundary_lengths_hash_apart() {
    let lengths = [1usize, 30, 31, 32, 62, 127, 128, 129, 155, 186];
    let points: Vec<_> = lengths
        .iter()
        .map(|&n| group_point(&alloc::vec![b'x'; n]))
        .collect();
    for (i, a) in points.iter().enumerate() {
        for b in &points[i + 1..] {
            assert_ne!(a, b);
        }
    }
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
