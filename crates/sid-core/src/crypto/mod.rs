// SPDX-License-Identifier: Apache-2.0
//! Cryptographic primitives for StructuredID.

pub mod bip39;
#[cfg(feature = "recovery")]
pub mod recovery;
pub mod shamir;
