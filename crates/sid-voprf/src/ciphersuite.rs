// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Defines the CipherSuite trait to specify the underlying primitives for VOPRF

use digest::block_api::BlockSizeUser;
use digest::{FixedOutput, HashMarker, OutputSizeUser};
use hash2curve::{ExpandMsg, OprfParameters};
use hybrid_array::ArraySize;
use hybrid_array::typenum::{IsGreaterOrEqual, IsLess, IsLessOrEqual, Prod, True, U2, U256};

use crate::Group;

/// Configures the underlying primitives used in VOPRF
pub trait CipherSuite
where
    <Self::Hash as OutputSizeUser>::OutputSize: ArraySize
        + IsLess<U256, Output = True>
        + IsLessOrEqual<<Self::Hash as BlockSizeUser>::BlockSize, Output = True>
        + IsGreaterOrEqual<Prod<<Self::Group as Group>::SecurityLevel, U2>, Output = True>,
{
    /// The ciphersuite identifier as dictated by
    /// <https://www.rfc-editor.org/rfc/rfc9497>
    const ID: &'static str;

    /// A finite cyclic group along with a point representation that allows some
    /// customization on how to hash an input to a curve point. See [`Group`].
    type Group: Group;

    /// The main hash function to use (for HKDF computations and hashing
    /// transcripts).
    type Hash: BlockSizeUser + Default + FixedOutput + HashMarker;
}

/// The suite identifier of an RFC 9497 curve, which RustCrypto states as bytes.
const fn suite_id(id: &'static [u8]) -> &'static str {
    match core::str::from_utf8(id) {
        Ok(id) => id,
        Err(_) => panic!("RFC 9497 suite identifiers are ASCII"),
    }
}

type OprfHash<T> = <<T as hash2curve::GroupDigest>::ExpandMsg as ExpandMsg<
    <T as hash2curve::MapToCurve>::SecurityLevel,
>>::Hash;

impl<T: OprfParameters> CipherSuite for T
where
    T: Group,
    OprfHash<T>: BlockSizeUser + Default + FixedOutput + HashMarker,
    <OprfHash<T> as OutputSizeUser>::OutputSize: ArraySize
        + IsLess<U256, Output = True>
        + IsLessOrEqual<<OprfHash<T> as BlockSizeUser>::BlockSize, Output = True>
        + IsGreaterOrEqual<Prod<<T as Group>::SecurityLevel, U2>, Output = True>,
{
    const ID: &'static str = suite_id(<T as OprfParameters>::ID);

    type Group = T;

    type Hash = OprfHash<T>;
}
