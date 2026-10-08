// SPDX-License-Identifier: AGPL-3.0-only
//! Anomaly event log storage + query integration tests.
//!
//! Tests SecurityService.GetAnomalyEventLog RPC with real event persistence.
//! Handler-level tests (MockStorage) + PostgreSQL integration (port 54399).

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token};
use sid_core::models::{AnomalyEventRecord, ProfileId};
use sid_plugin::storage::StorageBackend;
use sid_proto::sid::v1::admin::security_service_server::SecurityService;
use sid_proto::sid::v1::admin::*;
use std::sync::Arc;
use tonic::Request;

fn admin_request<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );
    req
}

// ═══════════════════════════════════════════════════════════════════
// Handler-level tests (MockStorage + real JWT)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_get_anomaly_event_log_empty() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());

    let req = admin_request(
        GetAnomalyEventLogRequest {
            page_size: 10,
            page_token: String::new(),
            rule_id: None,
        },
        &token,
    );
    let resp = svc.security.get_anomaly_event_log(req).await.unwrap();
    let log = resp.into_inner();
    assert!(log.events.is_empty());
    assert!(log.next_page_token.is_empty());
}

#[tokio::test]
async fn test_get_anomaly_event_log_with_events() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());

    // Save some events.
    for i in 0..3 {
        let event = AnomalyEventRecord::new(
            "brute_force",
            format!("profile-{i}"),
            "10.0.0.1",
            format!("Test event {i}"),
            95,
            "block",
        );
        svc.storage.save_anomaly_event(&event).await.unwrap();
    }

    let req = admin_request(
        GetAnomalyEventLogRequest {
            page_size: 10,
            page_token: String::new(),
            rule_id: None,
        },
        &token,
    );
    let resp = svc.security.get_anomaly_event_log(req).await.unwrap();
    let log = resp.into_inner();
    assert_eq!(log.events.len(), 3);
    assert_eq!(log.events[0].rule_id, "brute_force");
    assert_eq!(log.events[0].risk_score, 95);
}

#[tokio::test]
async fn test_get_anomaly_event_log_filter_by_rule() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());

    // Mix of rule types.
    svc.storage
        .save_anomaly_event(&AnomalyEventRecord::new(
            "brute_force",
            "p1",
            "10.0.0.1",
            "bf",
            95,
            "block",
        ))
        .await
        .unwrap();
    svc.storage
        .save_anomaly_event(&AnomalyEventRecord::new(
            "credential_stuffing",
            "p2",
            "10.0.0.2",
            "cs",
            90,
            "captcha",
        ))
        .await
        .unwrap();
    svc.storage
        .save_anomaly_event(&AnomalyEventRecord::new(
            "brute_force",
            "p3",
            "10.0.0.3",
            "bf2",
            95,
            "block",
        ))
        .await
        .unwrap();

    let req = admin_request(
        GetAnomalyEventLogRequest {
            page_size: 10,
            page_token: String::new(),
            rule_id: Some("brute_force".to_string()),
        },
        &token,
    );
    let resp = svc.security.get_anomaly_event_log(req).await.unwrap();
    let log = resp.into_inner();
    assert_eq!(log.events.len(), 2);
    assert!(log.events.iter().all(|e| e.rule_id == "brute_force"));
}

#[tokio::test]
async fn test_get_anomaly_event_log_pagination() {
    let svc = TestServices::new(MockStorage::new());
    let token = issue_admin_token(&svc.jwt, ProfileId::generate());

    for i in 0..5 {
        svc.storage
            .save_anomaly_event(&AnomalyEventRecord::new(
                "brute_force",
                format!("p{i}"),
                "10.0.0.1",
                format!("event {i}"),
                95,
                "block",
            ))
            .await
            .unwrap();
    }

    // Page 1: first 2 events.
    let req = admin_request(
        GetAnomalyEventLogRequest {
            page_size: 2,
            page_token: String::new(),
            rule_id: None,
        },
        &token,
    );
    let resp = svc.security.get_anomaly_event_log(req).await.unwrap();
    let page1 = resp.into_inner();
    assert_eq!(page1.events.len(), 2);
    assert_eq!(page1.next_page_token, "2"); // offset for next page

    // Page 2: next 2 events.
    let req = admin_request(
        GetAnomalyEventLogRequest {
            page_size: 2,
            page_token: "2".to_string(),
            rule_id: None,
        },
        &token,
    );
    let resp = svc.security.get_anomaly_event_log(req).await.unwrap();
    let page2 = resp.into_inner();
    assert_eq!(page2.events.len(), 2);
    assert_eq!(page2.next_page_token, "4");

    // Page 3: last event.
    let req = admin_request(
        GetAnomalyEventLogRequest {
            page_size: 2,
            page_token: "4".to_string(),
            rule_id: None,
        },
        &token,
    );
    let resp = svc.security.get_anomaly_event_log(req).await.unwrap();
    let page3 = resp.into_inner();
    assert_eq!(page3.events.len(), 1);
    assert!(page3.next_page_token.is_empty(), "No more pages");
}

#[tokio::test]
async fn test_get_anomaly_event_log_no_auth() {
    let svc = TestServices::new(MockStorage::new());
    let req = Request::new(GetAnomalyEventLogRequest {
        page_size: 10,
        page_token: String::new(),
        rule_id: None,
    });
    let err = svc.security.get_anomaly_event_log(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

// ═══════════════════════════════════════════════════════════════════
// PostgreSQL integration tests (port 54399)
// ═══════════════════════════════════════════════════════════════════

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_anomaly_event_save_and_list() {
    let backend = match sid_storage::PostgresBackend::new(&database_url(), None).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: PostgreSQL not available: {e}");
            return;
        }
    };
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");

    let storage: Arc<dyn StorageBackend> = Arc::new(backend);

    let event = AnomalyEventRecord::new(
        "brute_force",
        "pg-test-profile",
        "192.168.1.1",
        "5 failed attempts in 300s",
        95,
        "block",
    );
    let event_id = event.id;

    storage.save_anomaly_event(&event).await.unwrap();

    let events = storage.list_anomaly_events(None, 10, 0).await.unwrap();
    let found = events.iter().find(|e| e.id == event_id);
    assert!(found.is_some(), "Saved event must be retrievable");
    let found = found.unwrap();
    assert_eq!(found.rule_id, "brute_force");
    assert_eq!(found.profile_id, "pg-test-profile");
    assert_eq!(found.ip_address, "192.168.1.1");
    assert_eq!(found.risk_score, 95);
    assert_eq!(found.reaction, "block");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pg_anomaly_event_filter_by_rule() {
    let backend = match sid_storage::PostgresBackend::new(&database_url(), None).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: PostgreSQL not available: {e}");
            return;
        }
    };
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");

    let storage: Arc<dyn StorageBackend> = Arc::new(backend);

    // Use unique rule_id to avoid collision with other tests.
    let unique_rule = format!("test_rule_{}", uuid::Uuid::now_v7());
    storage
        .save_anomaly_event(&AnomalyEventRecord::new(
            &unique_rule,
            "p1",
            "10.0.0.1",
            "test",
            50,
            "alert",
        ))
        .await
        .unwrap();
    storage
        .save_anomaly_event(&AnomalyEventRecord::new(
            "other_rule",
            "p2",
            "10.0.0.2",
            "test",
            30,
            "allow",
        ))
        .await
        .unwrap();

    let filtered = storage
        .list_anomaly_events(Some(&unique_rule), 10, 0)
        .await
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].rule_id, unique_rule);
}
