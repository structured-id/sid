// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM 2.0 provisioning for StructuredID.
//!
//! Implements RFC 7643 (Core Schema) + RFC 7644 (Protocol).
//! SCIM operates exclusively in the corporate profile domain.

pub mod filter;
pub mod grpc;
pub mod mapping;
pub mod outbound;
pub mod patch;
pub mod protocol;
mod refusal;
