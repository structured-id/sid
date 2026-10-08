// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use core::num::NonZeroU16;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use digest::block_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker};
use hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use hybrid_array::Array;
use hybrid_array::typenum::{
    IsGreaterOrEqual, IsLess, IsLessOrEqual, Prod, True, U2, U16, U32, U256,
};
use rand_core::{TryCryptoRng, TryRng};
use subtle::ConstantTimeEq;

use super::Group;
use crate::{Error, InternalError, Result};

/// [`Group`] implementation for Ristretto255.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ristretto255;

#[cfg(feature = "ristretto255-ciphersuite")]
impl crate::CipherSuite for Ristretto255 {
    const ID: &'static str = "ristretto255-SHA512";

    type Group = Ristretto255;

    type Hash = sha2::Sha512;
}

/// `expand_message_xmd` to 64 uniform bytes, the input of both the
/// ristretto255 element map and the wide scalar reduction.
fn expand_64<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<[u8; 64], InternalError>
where
    H: BlockSizeUser + Default + FixedOutput + HashMarker,
    H::OutputSize:
        IsLessOrEqual<H::BlockSize, Output = True> + IsGreaterOrEqual<Prod<U16, U2>, Output = True>,
{
    const LEN: NonZeroU16 = NonZeroU16::new(64).unwrap();
    let mut uniform_bytes = [0u8; 64];
    <ExpandMsgXmd<H> as ExpandMsg<U16>>::expand_message(input, dst, LEN)
        .map_err(|_| InternalError::Input)?
        .fill_bytes(&mut uniform_bytes)
        .map_err(|_| InternalError::Input)?;
    Ok(uniform_bytes)
}

impl Group for Ristretto255 {
    type Elem = RistrettoPoint;

    type ElemLen = U32;

    type Scalar = Scalar;

    type ScalarLen = U32;

    // ristretto255 targets the 128-bit security level (RFC 9380 appendix B).
    type SecurityLevel = U16;

    // Implements the `hash_to_ristretto255()` function from
    // https://www.rfc-editor.org/rfc/rfc9380.html#appendix-B
    fn hash_to_curve<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Elem, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256, Output = True>
            + IsLessOrEqual<H::BlockSize, Output = True>
            + IsGreaterOrEqual<Prod<Self::SecurityLevel, U2>, Output = True>,
    {
        Ok(RistrettoPoint::from_uniform_bytes(&expand_64::<H>(
            input, dst,
        )?))
    }

    // Implements the `HashToScalar()` function from
    // https://www.rfc-editor.org/rfc/rfc9497#section-4.1
    fn hash_to_scalar<H>(input: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar, InternalError>
    where
        H: BlockSizeUser + Default + FixedOutput + HashMarker,
        H::OutputSize: IsLess<U256, Output = True>
            + IsLessOrEqual<H::BlockSize, Output = True>
            + IsGreaterOrEqual<Prod<Self::SecurityLevel, U2>, Output = True>,
    {
        Ok(Scalar::from_bytes_mod_order_wide(&expand_64::<H>(
            input, dst,
        )?))
    }

    fn base_elem() -> Self::Elem {
        RISTRETTO_BASEPOINT_POINT
    }

    fn identity_elem() -> Self::Elem {
        RistrettoPoint::identity()
    }

    // serialization of a group element
    fn serialize_elem(elem: Self::Elem) -> Array<u8, Self::ElemLen> {
        elem.compress().to_bytes().into()
    }

    fn deserialize_elem(element_bits: &[u8]) -> Result<Self::Elem> {
        CompressedRistretto::from_slice(element_bits)
            .map_err(|_| Error::Deserialization)?
            .decompress()
            .filter(|point| point != &RistrettoPoint::identity())
            .ok_or(Error::Deserialization)
    }

    fn random_scalar<R: TryRng + TryCryptoRng>(rng: &mut R) -> Result<Self::Scalar> {
        loop {
            let mut scalar_bytes = [0u8; 32];
            rng.try_fill_bytes(&mut scalar_bytes)
                .map_err(|_| Error::Rng)?;

            if let Ok(scalar) = Self::deserialize_scalar(&scalar_bytes) {
                break Ok(scalar);
            }
        }
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    fn is_zero_scalar(scalar: Self::Scalar) -> subtle::Choice {
        scalar.ct_eq(&Scalar::ZERO)
    }

    #[cfg(test)]
    fn zero_scalar() -> Self::Scalar {
        Scalar::ZERO
    }

    fn serialize_scalar(scalar: Self::Scalar) -> Array<u8, Self::ScalarLen> {
        scalar.to_bytes().into()
    }

    fn deserialize_scalar(scalar_bits: &[u8]) -> Result<Self::Scalar> {
        scalar_bits
            .try_into()
            .ok()
            .and_then(|bytes| Scalar::from_canonical_bytes(bytes).into())
            .filter(|scalar| scalar != &Scalar::ZERO)
            .ok_or(Error::Deserialization)
    }
}
