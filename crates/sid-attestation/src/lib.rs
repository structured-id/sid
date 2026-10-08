// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Device Attestation Service — library crate.
//!
//! Manages device keys, platform attestation, and device-bound credentials.
//! Attestation data is stored without cryptographic verification.

pub mod config;
pub mod handler;
pub mod server;
