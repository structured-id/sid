use std::vec::Vec;

use ff::{Field, PrimeField};
use group::GroupEncoding;

use super::*;

#[test]
fn diffie_hellman_agrees() {
    let mut rng = rand::rng();
    let a = <Pallas as Group>::random_sk(&mut rng);
    let b = <Pallas as Group>::random_sk(&mut rng);
    let pa = <Pallas as Group>::public_key(&a);
    let pb = <Pallas as Group>::public_key(&b);
    assert_eq!(a.diffie_hellman(&pb), b.diffie_hellman(&pa));
}

/// Deserialization reads its own field and leaves the rest for the next one.
#[test]
fn keys_round_trip_and_leave_trailing_bytes() {
    let mut rng = rand::rng();
    let sk = <Pallas as Group>::random_sk(&mut rng);
    let mut buf: Vec<u8> = <Pallas as Group>::serialize_sk(&sk).to_vec();
    buf.extend_from_slice(b"next");
    let mut reader: &[u8] = &buf;
    let back = <Pallas as Group>::deserialize_take_sk(&mut reader).unwrap();
    assert!(bool::from(sk.ct_eq(&back)));
    assert_eq!(reader, b"next");

    let pk = <Pallas as Group>::public_key(&sk);
    let bytes = <Pallas as Group>::serialize_pk(&pk);
    let mut reader: &[u8] = &bytes;
    let back = <Pallas as Group>::deserialize_take_pk(&mut reader).unwrap();
    assert!(bool::from(pk.ct_eq(&back)));
}

/// RFC 9807 §6.4.1: the identity is no public key, zero no secret key, and
/// a short field is not read past.
#[test]
fn degenerate_keys_are_refused() {
    let identity = pallas::Point::identity().to_bytes();
    assert!(<Pallas as Group>::deserialize_take_pk(&mut identity.as_slice()).is_err());
    let zero = pallas::Scalar::ZERO.to_repr();
    assert!(<Pallas as Group>::deserialize_take_sk(&mut zero.as_slice()).is_err());
    assert!(<Pallas as Group>::deserialize_take_sk(&mut [7u8; 31].as_slice()).is_err());
}

/// The same seed always derives the same key pair, or a restart would
/// invalidate every credential derived from it.
#[test]
fn derivation_is_deterministic() {
    let a = <Pallas as Group>::derive_scalar(Array::from([7u8; 32])).unwrap();
    let b = <Pallas as Group>::derive_scalar(Array::from([7u8; 32])).unwrap();
    let c = <Pallas as Group>::derive_scalar(Array::from([8u8; 32])).unwrap();
    assert!(bool::from(a.ct_eq(&b)));
    assert!(!bool::from(a.ct_eq(&c)));
}
