// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod operations;
pub use operations::{CryptoError, CryptoPrimitives};

#[cfg(any(feature = "tls-rustcrypto", feature = "jwt-rustcrypto"))]
mod public_key;
#[cfg(any(feature = "tls-rustcrypto", feature = "tls-aws-lc"))]
pub mod tls;

#[cfg(any(feature = "primitives", feature = "aws-lc"))]
mod symmetric;
#[cfg(feature = "primitives")]
pub use symmetric::rustcrypto::RustCryptoPrimitives;

#[cfg(any(feature = "jwt", feature = "jwt-rustcrypto"))]
pub mod jwt;
#[cfg(feature = "aws-lc")]
pub use symmetric::aws_lc::AwsLcPrimitives;
