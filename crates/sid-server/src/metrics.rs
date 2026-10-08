// SPDX-License-Identifier: AGPL-3.0-only
//! Prometheus metrics catalog for StructuredID CE.
//!
//! Compiled only with the `telemetry` feature (default ON).

use opentelemetry::{global, metrics::*};

/// CE metric handles — initialized once at startup.
pub struct SidMetrics {
    pub auth_attempts: Counter<u64>,
    pub auth_duration: Histogram<f64>,
    pub token_issued: Counter<u64>,
    pub token_introspection_duration: Histogram<f64>,
    pub session_active: UpDownCounter<i64>,
    pub profile_operations: Counter<u64>,
    pub grpc_requests: Counter<u64>,
    pub grpc_request_duration: Histogram<f64>,
    pub db_pool_connections: UpDownCounter<i64>,
    pub zk_proof_verification: Histogram<f64>,
    pub audit_write: Histogram<f64>,
}

impl SidMetrics {
    /// Create and register all CE metrics with the global meter.
    pub fn init() -> Self {
        let meter = global::meter("sid");

        Self {
            auth_attempts: meter
                .u64_counter("sid_auth_attempts_total")
                .with_description("Authentication attempts")
                .build(),
            auth_duration: meter
                .f64_histogram("sid_auth_duration_seconds")
                .with_description("Auth flow latency")
                .build(),
            token_issued: meter
                .u64_counter("sid_token_issued_total")
                .with_description("Tokens issued")
                .build(),
            token_introspection_duration: meter
                .f64_histogram("sid_token_introspection_seconds")
                .with_description("Token introspection latency")
                .build(),
            session_active: meter
                .i64_up_down_counter("sid_session_active_gauge")
                .with_description("Active sessions")
                .build(),
            profile_operations: meter
                .u64_counter("sid_profile_operations_total")
                .with_description("Profile CRUD operations")
                .build(),
            grpc_requests: meter
                .u64_counter("sid_grpc_requests_total")
                .with_description("gRPC request count")
                .build(),
            grpc_request_duration: meter
                .f64_histogram("sid_grpc_request_duration_seconds")
                .with_description("gRPC request latency")
                .build(),
            db_pool_connections: meter
                .i64_up_down_counter("sid_db_pool_connections")
                .with_description("DB connection pool gauge")
                .build(),
            zk_proof_verification: meter
                .f64_histogram("sid_zk_proof_verification_seconds")
                .with_description("ZK proof verification latency")
                .build(),
            audit_write: meter
                .f64_histogram("sid_audit_write_seconds")
                .with_description("Audit log write latency")
                .build(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::KeyValue;

    #[test]
    fn test_metrics_init() {
        let metrics = SidMetrics::init();
        // Verify counters can be incremented without panic
        metrics.auth_attempts.add(
            1,
            &[
                KeyValue::new("method", "opaque"),
                KeyValue::new("outcome", "success"),
            ],
        );
        metrics
            .token_issued
            .add(1, &[KeyValue::new("grant_type", "authorization_code")]);
        metrics
            .profile_operations
            .add(1, &[KeyValue::new("operation", "create")]);
        metrics.grpc_requests.add(
            1,
            &[
                KeyValue::new("service", "AuthService"),
                KeyValue::new("method", "Login"),
            ],
        );
    }

    #[test]
    fn test_metrics_histograms() {
        let metrics = SidMetrics::init();
        metrics
            .auth_duration
            .record(0.042, &[KeyValue::new("method", "opaque")]);
        metrics
            .grpc_request_duration
            .record(0.005, &[KeyValue::new("service", "AuthService")]);
        metrics
            .token_introspection_duration
            .record(0.001, &[KeyValue::new("active", "true")]);
    }

    #[test]
    fn test_metrics_gauges() {
        let metrics = SidMetrics::init();
        metrics.session_active.add(1, &[]);
        metrics.session_active.add(-1, &[]);
        metrics
            .db_pool_connections
            .add(5, &[KeyValue::new("state", "active")]);
        metrics
            .db_pool_connections
            .add(-2, &[KeyValue::new("state", "active")]);
    }

    #[test]
    fn test_metrics_zk_proof_and_audit() {
        let metrics = SidMetrics::init();
        metrics.zk_proof_verification.record(
            0.025,
            &[
                KeyValue::new("circuit", "password_policy"),
                KeyValue::new("outcome", "valid"),
            ],
        );
        metrics.zk_proof_verification.record(
            0.001,
            &[
                KeyValue::new("circuit", "password_policy"),
                KeyValue::new("outcome", "invalid"),
            ],
        );
        metrics
            .audit_write
            .record(0.003, &[KeyValue::new("chain_scope", "profile")]);
        metrics
            .audit_write
            .record(0.001, &[KeyValue::new("chain_scope", "site")]);
    }
}
