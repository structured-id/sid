//! The Pallas group, its VOPRF cipher suite and the native primitives the
//! suite hashes passwords with.
//!
//! Hash-to-curve is Poseidon based, so a Halo2 circuit over the Pallas base
//! field can recompute it: the password, zero-padded to [`MAX_PASSWORD_LEN`],
//! is packed into field elements of 31 bytes, hashed with a Poseidon chain to
//! `u`, and mapped to the first `x = u + offset` (`offset < 2^HTC_TRY_BITS`)
//! with `y² = x³ + 5`, taking the even root. A circuit that proves statements
//! about the hashed password must use these functions and parameters.

use alloc::vec::Vec;
use core::num::NonZeroU16;
use core::ops::{Add, Mul, Sub};

use digest::block_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker};
use ff::{Field, FromUniformBytes, PrimeField};
use group::{CurveAffine as _, Group as _, GroupEncoding};
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
use hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use hybrid_array::Array;
use hybrid_array::typenum::{
    IsGreaterOrEqual, IsLess, IsLessOrEqual, Prod, True, U2, U16, U32, U256,
};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;
use rand_core::{TryCryptoRng, TryRng};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::{Error, Group, InternalError, Result};

/// The longest password the suite hashes as the circuit does; a longer one is
/// hashed as given and cannot be proven about.
pub const MAX_PASSWORD_LEN: usize = 128;

/// Hash-to-curve tries `2^HTC_TRY_BITS` offsets.
pub const HTC_TRY_BITS: usize = 8;

/// Poseidon spec: 128-bit security, Pow5 S-box, width 3 (the Orchard spec).
pub type PoseidonSpec = poseidon::P128Pow5T3;

/// Poseidon absorption rate (field elements per permutation).
pub const POSEIDON_RATE: usize = 2;

/// Poseidon state width.
pub const POSEIDON_WIDTH: usize = 3;

/// Poseidon over two field elements.
pub fn poseidon_hash_2(inputs: &[pallas::Base; 2]) -> pallas::Base {
    poseidon::Hash::<_, PoseidonSpec, ConstantLength<2>, POSEIDON_WIDTH, POSEIDON_RATE>::init()
        .hash(*inputs)
}

/// Poseidon over one field element.
pub fn poseidon_hash_1(inputs: &[pallas::Base; 1]) -> pallas::Base {
    poseidon::Hash::<_, PoseidonSpec, ConstantLength<1>, POSEIDON_WIDTH, POSEIDON_RATE>::init()
        .hash(*inputs)
}

/// Bytes packed into Pallas base field elements, 31 little-endian bytes each,
/// the last one zero-padded.
pub fn bytes_to_field_elements(bytes: &[u8]) -> Vec<pallas::Base> {
    const BYTES_PER_FE: usize = 31;
    bytes
        .chunks(BYTES_PER_FE)
        .map(|chunk| {
            let mut repr = [0u8; 32];
            repr[..chunk.len()].copy_from_slice(chunk);
            // 31 bytes stay below the field modulus.
            pallas::Base::from_repr(repr).unwrap()
        })
        .collect()
}

/// Poseidon chain `H(H(H(e0, e1), e2), e3) …`; one element is hashed alone.
///
/// # Panics
/// On empty input.
pub fn poseidon_hash_chain(elements: &[pallas::Base]) -> pallas::Base {
    assert!(!elements.is_empty(), "Cannot hash empty input");
    if elements.len() == 1 {
        return poseidon_hash_1(&[elements[0]]);
    }
    let mut acc = poseidon_hash_2(&[elements[0], elements[1]]);
    for element in &elements[2..] {
        acc = poseidon_hash_2(&[acc, *element]);
    }
    acc
}

/// The password hashed to the curve: the point, `u = Poseidon(password)` and
/// the offset that found it. The scan always makes `2^HTC_TRY_BITS` constant-
/// time tries, so its duration does not depend on the password (RFC 9380
/// §10.1).
///
/// # Panics
/// If no offset gives a point, which happens with negligible probability.
pub fn hash_to_curve_native(password: &[u8]) -> (pallas::Affine, pallas::Base, pallas::Base) {
    let u = poseidon_hash_chain(&bytes_to_field_elements(password));
    let b = pallas::Base::from(5u64);
    let mut found = Choice::from(0u8);
    let mut sel_x = pallas::Base::ZERO;
    let mut sel_y = pallas::Base::ZERO;
    let mut sel_offset = pallas::Base::ZERO;
    for i in 0u64..(1 << HTC_TRY_BITS) {
        let offset = pallas::Base::from(i);
        let x = u + offset;
        let y = (x * x * x + b).sqrt();
        let is_square = y.is_some();
        let take = is_square & !found;
        sel_x = pallas::Base::conditional_select(&sel_x, &x, take);
        sel_y = pallas::Base::conditional_select(&sel_y, &y.unwrap_or(pallas::Base::ZERO), take);
        sel_offset = pallas::Base::conditional_select(&sel_offset, &offset, take);
        found |= is_square;
    }
    assert!(
        bool::from(found),
        "hash_to_curve: no valid point found in 256 tries"
    );
    // The even root (sgn0 of RFC 9380 §4.1), so the root is a rule and not
    // one `sqrt`'s choice.
    let odd = Choice::from(sel_y.to_repr()[0] & 1);
    let sel_y = pallas::Base::conditional_select(&sel_y, &-sel_y, odd);
    let point = pallas::Affine::from_xy(sel_x, sel_y).unwrap();
    (point, u, sel_offset)
}

/// The password as the suite hashes it: zero-padded to [`MAX_PASSWORD_LEN`].
/// A longer password is hashed as given.
pub fn padded_password(password: &[u8]) -> Vec<u8> {
    let mut bytes = password.to_vec();
    if bytes.len() < MAX_PASSWORD_LEN {
        bytes.resize(MAX_PASSWORD_LEN, 0);
    }
    bytes
}

/// A Pallas point as a VOPRF group element.
#[derive(Clone, Copy, Debug)]
pub struct PallasElem(pub pallas::Point);

/// A Pallas scalar as a VOPRF scalar.
#[derive(Clone, Copy, Debug)]
pub struct PallasScalar(pub pallas::Scalar);

impl ConstantTimeEq for PallasElem {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConstantTimeEq for PallasScalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Zeroize for PallasElem {
    fn zeroize(&mut self) {
        self.0 = pallas::Point::identity();
    }
}

impl Zeroize for PallasScalar {
    fn zeroize(&mut self) {
        self.0 = pallas::Scalar::ZERO;
    }
}

impl Add<&PallasElem> for PallasElem {
    type Output = PallasElem;
    fn add(self, rhs: &PallasElem) -> PallasElem {
        PallasElem(self.0 + rhs.0)
    }
}

impl Mul<&PallasScalar> for PallasElem {
    type Output = PallasElem;
    fn mul(self, rhs: &PallasScalar) -> PallasElem {
        PallasElem(self.0 * rhs.0)
    }
}

impl Add<&PallasScalar> for PallasScalar {
    type Output = PallasScalar;
    fn add(self, rhs: &PallasScalar) -> PallasScalar {
        PallasScalar(self.0 + rhs.0)
    }
}

impl Mul<&PallasScalar> for PallasScalar {
    type Output = PallasScalar;
    fn mul(self, rhs: &PallasScalar) -> PallasScalar {
        PallasScalar(self.0 * rhs.0)
    }
}

impl Sub<&PallasScalar> for PallasScalar {
    type Output = PallasScalar;
    fn sub(self, rhs: &PallasScalar) -> PallasScalar {
        PallasScalar(self.0 - rhs.0)
    }
}

/// The Pallas group.
#[derive(Debug)]
pub struct PallasGroup;

impl Group for PallasGroup {
    type Elem = PallasElem;
    type ElemLen = U32;
    type Scalar = PallasScalar;
    type ScalarLen = U32;
    // Pallas targets the 128-bit security level.
    type SecurityLevel = U16;

    fn hash_to_curve<H>(input: &[&[u8]], _dst: &[&[u8]]) -> Result<Self::Elem, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256, Output = True>
            + IsLessOrEqual<H::BlockSize, Output = True>
            + IsGreaterOrEqual<Prod<Self::SecurityLevel, U2>, Output = True>,
    {
        // The DST is not part of the Poseidon hash a circuit recomputes; the
        // protocol above separates its domains itself.
        let bytes: Vec<u8> = input.concat();
        if bytes.is_empty() {
            return Err(InternalError::Input);
        }
        let (point, _u, _offset) = hash_to_curve_native(&padded_password(&bytes));
        Ok(PallasElem(point.to_curve()))
    }

    fn hash_to_scalar<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256, Output = True>
            + IsLessOrEqual<H::BlockSize, Output = True>
            + IsGreaterOrEqual<Prod<Self::SecurityLevel, U2>, Output = True>,
    {
        const WIDE: NonZeroU16 = NonZeroU16::new(64).unwrap();
        if input.iter().all(|part| part.is_empty()) {
            return Err(InternalError::Input);
        }
        // RFC 9380 section 5.3.1 expand_message_xmd to 64 uniform bytes,
        // reduced mod q (RFC 9380 section 5.2 hash_to_field with L = 64).
        let mut wide = [0u8; 64];
        <ExpandMsgXmd<H> as ExpandMsg<Self::SecurityLevel>>::expand_message(input, dst, WIDE)
            .map_err(|_| InternalError::Input)?
            .fill_bytes(&mut wide)
            .map_err(|_| InternalError::Input)?;
        Ok(PallasScalar(pallas::Scalar::from_uniform_bytes(&wide)))
    }

    fn base_elem() -> Self::Elem {
        PallasElem(pallas::Point::generator())
    }

    fn identity_elem() -> Self::Elem {
        PallasElem(pallas::Point::identity())
    }

    fn serialize_elem(elem: Self::Elem) -> Array<u8, Self::ElemLen> {
        Array::from(elem.0.to_bytes())
    }

    fn deserialize_elem(bytes: &[u8]) -> Result<Self::Elem> {
        let repr: [u8; 32] = bytes.try_into().map_err(|_| Error::Deserialization)?;
        let point: pallas::Point =
            Option::from(pallas::Point::from_bytes(&repr)).ok_or(Error::Deserialization)?;
        if bool::from(point.ct_eq(&pallas::Point::identity())) {
            return Err(Error::Deserialization);
        }
        Ok(PallasElem(point))
    }

    fn random_scalar<R: TryRng + TryCryptoRng>(rng: &mut R) -> Result<Self::Scalar> {
        pallas::Scalar::try_random(rng)
            .map(PallasScalar)
            .map_err(|_| Error::Rng)
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        let inv: Option<pallas::Scalar> = scalar.0.invert().into();
        PallasScalar(inv.expect("invert_scalar called on zero"))
    }

    fn is_zero_scalar(scalar: Self::Scalar) -> Choice {
        scalar.0.ct_eq(&pallas::Scalar::ZERO)
    }

    #[cfg(test)]
    fn zero_scalar() -> Self::Scalar {
        PallasScalar(pallas::Scalar::ZERO)
    }

    fn serialize_scalar(scalar: Self::Scalar) -> Array<u8, Self::ScalarLen> {
        Array::from(scalar.0.to_repr())
    }

    fn deserialize_scalar(bytes: &[u8]) -> Result<Self::Scalar> {
        let repr: [u8; 32] = bytes.try_into().map_err(|_| Error::Deserialization)?;
        let scalar: pallas::Scalar =
            Option::from(pallas::Scalar::from_repr(repr)).ok_or(Error::Deserialization)?;
        if bool::from(scalar.ct_eq(&pallas::Scalar::ZERO)) {
            return Err(Error::Deserialization);
        }
        Ok(PallasScalar(scalar))
    }
}

/// The VOPRF suite: Pallas with Poseidon hash-to-curve and SHA-256 framing.
#[derive(Debug)]
pub struct PallasVoprf;

impl crate::CipherSuite for PallasVoprf {
    const ID: &'static str = "Pallas-Poseidon-SHA256";
    type Group = PallasGroup;
    type Hash = sha2::Sha256;
}

#[cfg(test)]
mod tests;
