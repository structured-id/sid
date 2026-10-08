// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Device Attestation Service — library crate.
//!
//! Manages device keys, platform attestation, and device-bound credentials.
//! CE stores attestation data without cryptographic verification.
//! EE extends with chain validation and AAGUID policy enforcement.

pub mod config;
pub mod handler;
pub mod server;
