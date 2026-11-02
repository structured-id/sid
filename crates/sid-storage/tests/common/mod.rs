// SPDX-License-Identifier: AGPL-3.0-only
//! The harness of the storage conformance scenarios: what reaches past the
//! trait to an engine, or runs a capability suite on this crate's backends.
//! The scenarios themselves are `sid_plugin::conformance::backend`.

pub use sid_plugin::conformance::backend::*;

pub mod credential_conformance;
pub mod grant_conformance;
pub mod issuer_conformance;
pub mod password_history;
pub mod principal_conformance;
pub mod registry_conformance;
pub mod sign_in_history_conformance;
