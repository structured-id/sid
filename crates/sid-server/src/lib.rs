// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Server library.
//!
//! Pure gRPC server. REST is provided by sid-auth (separate crate).

// tonic::Status is 176 bytes — standard for gRPC Result<T, Status> pattern.
#![allow(clippy::result_large_err)]

pub mod auth_mail;
pub mod config;
#[cfg(feature = "http")]
pub mod cookie_scope;
pub mod embedded_nats;
pub mod feature_flags;
pub mod grpc;
pub mod init;
#[cfg(feature = "telemetry")]
pub mod metrics;
pub mod organization_publications;
pub mod serve;
#[cfg(feature = "http")]
pub mod session_establish;
pub mod state;
pub mod telemetry;
#[cfg(feature = "ui")]
pub mod ui;
