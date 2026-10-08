// SPDX-License-Identifier: AGPL-3.0-only
//! gRPC service implementations for StructuredID.
//!
//! Each module implements a tonic-generated server trait, reusing
//! the same business logic and storage layer as the REST handlers.

pub mod account_service;
pub mod admin_service;
mod application_view;
pub mod auth_service;
pub mod branding_service;
mod client_metadata;
pub(crate) mod convert;
pub mod enrollment_service;
pub mod event_stream_service;
pub mod flow_service;
pub mod identity_service;
#[allow(dead_code)]
pub mod machine_user_service;
mod oauth_http;
pub mod oidc_issuer_service;
pub mod oidc_provider_service;
pub mod password_operation;
#[allow(dead_code)]
pub mod pat_service;
pub mod project_service;
#[cfg(feature = "scim")]
pub mod provisioning_service;
pub mod realm_service;
pub mod security_service;
pub mod system_integration_service;
pub mod trace_context;
#[allow(dead_code)]
pub mod upstream_service;

#[cfg(feature = "dev-perf-test")]
pub mod test_service;
