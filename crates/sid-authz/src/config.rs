// SPDX-License-Identifier: AGPL-3.0-only
//! Configuration for sid-authz standalone binary.

use std::net::SocketAddr;

/// Authorization service configuration.
///
/// All values can be overridden via environment variables.
pub struct AuthzConfig {
    /// gRPC bind address (default: 127.0.0.1:50052).
    pub bind_addr: SocketAddr,
    /// Database URL for storage backend.
    pub database_url: String,
    /// Whether maintenance mode is initially enabled.
    pub maintenance_mode: bool,
}

impl AuthzConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let bind_addr = std::env::var("SID_AUTHZ_BIND")
            .unwrap_or_else(|_| "127.0.0.1:50052".to_string())
            .parse()
            .expect("SID_AUTHZ_BIND must be a valid socket address");

        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:5432/sid".to_string());

        let maintenance_mode = std::env::var("SID_MAINTENANCE_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            bind_addr,
            database_url,
            maintenance_mode,
        }
    }
}
