// SPDX-License-Identifier: AGPL-3.0-only
//! sid-crypto: server-side cryptographic primitives (authenticated encryption,
//! key derivation, curve operations) behind the `CryptoPrimitives` trait of
//! `sid-keys`, with an aws-lc-rs backend.
//!
//! The ZKPP policy and proof types live with the circuit in `sid-pake-core`.

#[cfg(feature = "primitives")]
pub mod primitives;

#[cfg(feature = "aws-lc")]
pub use primitives::AwsLcPrimitives;
