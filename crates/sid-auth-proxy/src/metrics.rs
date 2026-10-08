// SPDX-License-Identifier: AGPL-3.0-only
//! Prometheus metrics middleware for sid-proxy.
//!
//! Tracks HTTP request count and latency histograms per endpoint class.

use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts};
use std::sync::LazyLock;
use std::time::Instant;

/// HTTP request counter: (method, path_class, status_code).
static HTTP_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let opts = Opts::new("sid_proxy_http_requests_total", "Total HTTP requests")
        .namespace("sid")
        .subsystem("proxy");
    let counter = IntCounterVec::new(opts, &["method", "path_class", "status"]).unwrap();
    prometheus::default_registry()
        .register(Box::new(counter.clone()))
        .unwrap();
    counter
});

/// HTTP request duration in seconds: (method, path_class).
static HTTP_REQUEST_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let opts = HistogramOpts::new(
        "sid_proxy_http_request_duration_seconds",
        "HTTP request duration in seconds",
    )
    .namespace("sid")
    .subsystem("proxy")
    .buckets(vec![
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
    ]);
    let histogram = HistogramVec::new(opts, &["method", "path_class"]).unwrap();
    prometheus::default_registry()
        .register(Box::new(histogram.clone()))
        .unwrap();
    histogram
});

/// Classify path into a low-cardinality label to avoid metric explosion. An
/// issuer's endpoint is classified by what follows its handle, so handles
/// never become label values.
fn path_class(path: &str) -> &'static str {
    if let Some(endpoint) = sid_auth::issuers::issuer_endpoint(path) {
        return if endpoint.starts_with("/.well-known") || endpoint == "/jwks" {
            "discovery"
        } else if endpoint == "/userinfo" {
            "userinfo"
        } else {
            "oauth2"
        };
    }
    if path.starts_with("/health") {
        "health"
    } else if path.starts_with("/.well-known") {
        "discovery"
    } else if path == "/metrics" {
        "metrics"
    } else if path.starts_with("/v1/auth/magic-link") {
        "magic_link"
    } else if path.starts_with("/v1/auth/opaque/register")
        || path.starts_with("/v1/auth/webauthn/register")
    {
        "register"
    } else if path.starts_with("/v1/auth/") {
        "auth"
    } else if path.starts_with("/oauth2/") {
        "oauth2"
    } else if path.starts_with("/v1/admin/") {
        "admin"
    } else if path.starts_with("/v1/identity/") {
        "identity"
    } else if path.starts_with("/v1/projects/") || path.starts_with("/v1/authz/") {
        "project"
    } else {
        "other"
    }
}

/// Axum middleware that records request count and latency.
pub async fn metrics_middleware(request: Request<axum::body::Body>, next: Next) -> Response {
    let method = request.method().clone();
    let class = path_class(request.uri().path());
    let start = Instant::now();

    let response = next.run(request).await;

    let status_code = response.status().as_u16().to_string();
    let duration = start.elapsed().as_secs_f64();
    let method_str = method.as_str();

    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method_str, class, &status_code])
        .inc();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[method_str, class])
        .observe(duration);

    response
}

#[cfg(test)]
mod tests;
