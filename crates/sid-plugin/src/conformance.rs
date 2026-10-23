// SPDX-License-Identifier: AGPL-3.0-only
//! Conformance scenarios of the storage capabilities: what every backend owes
//! its caller, whatever engine and account type it uses. A backend's test
//! harness constructs that backend and runs every scenario against it.

pub mod cache;
pub mod client_registry;
pub mod credential_store;
pub mod grant_store;
pub mod history_key_store;
pub mod instance_secret_store;
pub mod issuer_store;
pub mod operation_result_store;
pub mod principal_store;
pub mod sign_in_history;
pub mod work_store;

/// A history epoch's public key: `(n + 1)·G` on Pallas, so each `n` gives a
/// distinct valid point and none is the identity.
fn history_public_key(n: u8) -> [u8; 32] {
    use group::{Curve, Group, GroupEncoding};
    use pasta_curves::pallas;
    (pallas::Point::generator() * pallas::Scalar::from(u64::from(n) + 1))
        .to_affine()
        .to_bytes()
}
