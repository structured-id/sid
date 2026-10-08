// SPDX-License-Identifier: AGPL-3.0-only
//! Kubernetes health probe and infrastructure endpoints.
//!
//! - `GET /health` — legacy health check
//! - `GET /health/live` — liveness probe (process alive)
//! - `GET /health/ready` — readiness probe (upstream gRPC reachable)
//! - `GET /health/startup` — startup probe (initialization complete)
//! - `GET /metrics` — Prometheus metrics

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::ProxyState;

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
}

/// Build health check and infrastructure routes.
pub fn routes() -> Router<ProxyState> {
    Router::new()
        .route("/health", get(health))
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        .route("/health/startup", get(startup))
        .route("/metrics", get(metrics))
}

async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        service: "sid-proxy",
    })
}

async fn liveness() -> StatusCode {
    StatusCode::OK
}

async fn readiness(State(state): State<ProxyState>) -> impl IntoResponse {
    // Real gRPC health check to upstream sid-server.
    let mut client = tonic_health::pb::health_client::HealthClient::new(state.grpc_channel);
    match client
        .check(tonic_health::pb::HealthCheckRequest {
            service: String::new(),
        })
        .await
    {
        Ok(resp) => {
            let status = resp.into_inner().status;
            if status == tonic_health::pb::health_check_response::ServingStatus::Serving as i32 {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn startup() -> StatusCode {
    StatusCode::OK
}

async fn metrics() -> impl IntoResponse {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::default_registry().gather();
    match encoder.encode_to_string(&metric_families) {
        Ok(text) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            text,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[cfg(test)]
mod tests;
