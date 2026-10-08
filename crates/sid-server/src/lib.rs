// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Server library.
//!
//! Pure gRPC server. REST is provided by sid-auth (separate crate).

// tonic::Status is 176 bytes — standard for gRPC Result<T, Status> pattern.
#![allow(clippy::result_large_err)]

pub mod background_tasks;
pub mod embedded_nats;
pub mod feature_flags;
pub mod field_keys;
pub mod grpc;
pub mod init;
#[cfg(feature = "telemetry")]
pub mod metrics;
pub mod rate_limit;
pub mod serve;
pub mod state;
pub mod telemetry;

#[cfg(feature = "webtransport")]
pub mod webtransport_dispatch;
