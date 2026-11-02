// SPDX-License-Identifier: Apache-2.0
//! StructuredID Core
//!
//! Domain models, errors, and shared types for the StructuredID identity provider.

pub mod crypto;
pub mod embedded;
pub mod enrollment;
pub mod error;
#[cfg(feature = "grpc")]
pub mod grpc_error;
pub mod models;

pub use error::{Error, Result};
