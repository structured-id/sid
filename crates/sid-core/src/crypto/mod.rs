// SPDX-License-Identifier: AGPL-3.0-only
//! Cryptographic primitives for StructuredID.

pub mod bip39;
#[cfg(feature = "recovery")]
pub mod recovery;
pub mod shamir;
