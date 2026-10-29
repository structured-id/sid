// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Infrastructure Backends
//!
//! Production implementations of plugin traits for external services.
//! Extracted from sid-plugin to maintain crate boundary discipline:
//! sid-plugin = trait definitions only, sid-infra = production implementations.
//!
//! - `NatsEventBus` — NATS JetStream event bus for multi-binary deployments
//! - `RedisCacheBackend` — Redis/Dragonfly distributed cache
//! - `issuer_registry` — the issuer registry over gRPC

#[cfg(feature = "issuer-client")]
pub mod client_credential;
#[cfg(feature = "issuer-client")]
pub mod deadline;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "issuer-client")]
pub mod issuer_client;
#[cfg(feature = "issuer-client")]
pub mod issuer_registry;
#[cfg(feature = "nats")]
pub mod nats_event_bus;
#[cfg(feature = "nats")]
pub mod nats_topology;
#[cfg(feature = "redis")]
pub mod redis_cache;
pub mod route;
#[cfg(feature = "redis")]
pub mod shared_cache;

#[cfg(feature = "nats")]
pub use nats_event_bus::NatsEventBus;
#[cfg(feature = "nats")]
pub use nats_topology::{Topology, TopologyError, TopologyRole};
#[cfg(feature = "redis")]
pub use redis_cache::RedisCacheBackend;
#[cfg(feature = "redis")]
pub use shared_cache::{cache_url_from_env, shared_cache};
