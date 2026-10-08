// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Admin Ops Library
//!
//! Operational admin logic for the CE instance, consumed by the `sid-admin` CLI
//! and by gRPC service handlers in `sid-server`. NOT a network surface:
//! the Admin API is exposed exclusively as gRPC `AdminService` (with REST
//! transcoding via sid-auth). This crate carries only the ops logic that has
//! no gRPC home of its own.
//!
//! - [`backup`] — encrypted backup/restore manifests and crypto.
//! - [`integrity`] — multi-layer data integrity verification (audit chains,
//!   graph consistency). Invoked by `sid-server` security service.
//! - [`migration`] — bulk user import from competitor exports.

pub mod backup;
pub mod integrity;
pub mod migration;
