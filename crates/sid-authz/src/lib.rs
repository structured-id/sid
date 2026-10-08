// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Authorization
//!
//! CE authorization: RBAC + flat groups + 1-step access requests.
//! All checks = flat SQL queries. No recursion. No graph. No ReBAC.

pub mod access_request;
pub mod admin;
pub mod approval;
pub mod builtin;
pub mod cedar;
pub mod conditional_access;
pub mod config;
pub mod engine;
#[cfg(feature = "grpc")]
pub mod governance_grpc;
pub mod group;
#[cfg(feature = "grpc")]
pub mod grpc;
pub mod rbac;
pub mod request_verifier;
pub mod simulator;
pub mod sod;

#[cfg(test)]
mod test_mock;

pub use access_request::{AccessRequest, AccessRequestId, AccessRequestStatus};
pub use engine::CeAuthzEngine;
pub use group::GroupService;
pub use rbac::{AuthzDecision, RbacService};
