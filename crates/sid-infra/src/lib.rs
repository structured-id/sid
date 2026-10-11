// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Infrastructure Backends
//!
//! Production implementations of plugin traits for external services.
//! Extracted from sid-plugin to maintain crate boundary discipline:
//! sid-plugin = trait definitions only, sid-infra = production implementations.
//!
//! - `NatsEventBus` — NATS JetStream event bus for multi-binary deployments
//! - `RedisCacheBackend` — Redis/Dragonfly distributed cache

#[cfg(feature = "http")]
pub mod http;
pub mod nats_event_bus;
pub mod nats_topology;
pub mod redis_cache;
pub mod shared_cache;

pub use nats_event_bus::NatsEventBus;
pub use nats_topology::{Topology, TopologyError, TopologyRole};
pub use redis_cache::RedisCacheBackend;
pub use shared_cache::{cache_url_from_env, shared_cache};
