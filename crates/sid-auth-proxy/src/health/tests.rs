// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

fn test_state() -> ProxyState {
    crate::test_state()
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = routes().with_state(test_state());
    let response = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "sid-proxy");
}

#[tokio::test]
async fn test_liveness_endpoint() {
    let app = routes().with_state(test_state());
    let response = app
        .oneshot(Request::get("/health/live").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_startup_endpoint() {
    let app = routes().with_state(test_state());
    let response = app
        .oneshot(Request::get("/health/startup").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_readiness_unreachable_upstream() {
    // gRPC channel to unreachable upstream → 503 (connection refused)
    let app = routes().with_state(test_state());
    let response = app
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_metrics_endpoint() {
    let app = routes().with_state(test_state());
    let response = app
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/plain"));
}
