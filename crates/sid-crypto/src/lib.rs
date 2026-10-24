// SPDX-License-Identifier: Apache-2.0
//! Host-selected cryptographic operations and independent TLS/JWT adapters.
//! Providers do not install process defaults or choose application policy.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod operations;
pub use operations::{CryptoError, CryptoPrimitives};

#[cfg(any(feature = "primitives", feature = "aws-lc"))]
mod symmetric;
#[cfg(feature = "primitives")]
pub use symmetric::rustcrypto::RustCryptoPrimitives;

#[cfg(feature = "jwt")]
pub mod jwt;
#[cfg(feature = "aws-lc")]
pub use symmetric::aws_lc::AwsLcPrimitives;
