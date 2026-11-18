// SPDX-License-Identifier: AGPL-3.0-only
//! Conformance scenarios of the storage capabilities: what every backend owes
//! its caller, whatever engine and account type it uses. A backend's test
//! harness constructs that backend and runs every scenario against it.

pub mod backend;
pub mod blob_store;
pub mod cache;
pub mod ceremony_state;
pub mod client_registry;
pub mod credential_store;
pub mod entry_connection_store;
pub mod grant_store;
pub mod history_key_store;
pub mod instance_secret_store;
pub mod issuer_store;
pub mod key_manager;
pub mod operation_result_store;
pub mod platform_ca_store;
pub mod principal_store;
pub mod sign_in_history;
pub mod work_store;

/// `n` days of 24 hours: the scenarios' unit for lifetimes and ages.
fn days(n: i64) -> jiff::SignedDuration {
    jiff::SignedDuration::from_hours(n * 24)
}

/// `at` truncated to `unit`, the precision a scenario compares stored
/// instants at.
fn trunc(at: jiff::Timestamp, unit: jiff::Unit) -> jiff::Timestamp {
    at.round(
        jiff::TimestampRound::new()
            .smallest(unit)
            .mode(jiff::RoundMode::Trunc),
    )
    .expect("truncating an instant stays representable")
}

/// A history epoch's public key: `(n + 1)·G` on Pallas, so each `n` gives a
/// distinct valid point and none is the identity.
fn history_public_key(n: u8) -> [u8; 32] {
    use group::{Curve, Group, GroupEncoding};
    use pasta_curves::pallas;
    (pallas::Point::generator() * pallas::Scalar::from(u64::from(n) + 1))
        .to_affine()
        .to_bytes()
}
