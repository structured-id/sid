// SPDX-License-Identifier: AGPL-3.0-only
//! SCIM 2.0 outbound provisioning.
//!
//! Pushes corporate profile changes to downstream apps via their SCIM API.
//! Event-driven: subscribes to NATS/InProcess events and dispatches SCIM requests.

pub mod client;
pub mod mapper;
pub mod worker;
