// SPDX-License-Identifier: AGPL-3.0-only
//! AcknowledgeExport answers by what happened: no export is NOT_FOUND, an
//! export not ready or past its window is FAILED_PRECONDITION, never an
//! internal error, and only a ready export inside its window is acknowledged.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_token, test_profile};
use sid_core::models::{AuditEntry, ExportFormat, ExportJob, ExportStatus};
use sid_proto::sid::v1::AcknowledgeExportRequest;
use sid_proto::sid::v1::identity_service_server::IdentityService;
use tonic::{Code, Request};
use tonic_types::StatusExt;

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

#[tokio::test]
async fn acknowledge_export_answers_by_outcome() {
    let owner = test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(owner.clone()));
    let token = issue_token(&svc.jwt, &owner, &["openid".to_string()]);

    let missing = svc
        .identity
        .acknowledge_export(authed(AcknowledgeExportRequest {}, &token))
        .await
        .expect_err("no export");
    assert_eq!(missing.code(), Code::NotFound);
    assert_eq!(
        missing.get_error_details().error_info().unwrap().reason,
        "EXPORT_NOT_FOUND"
    );

    let mut lapsed = ExportJob::new(owner.id, ExportFormat::Json);
    lapsed.mark_ready("exports/a.json".into(), 1, "ab".repeat(32));
    lapsed.expires_at = Some(chrono::Utc::now() - chrono::Duration::hours(1));
    svc.storage
        .create_export_job(&lapsed, AuditEntry::system("test", "export").into())
        .await
        .unwrap();
    let expired = svc
        .identity
        .acknowledge_export(authed(AcknowledgeExportRequest {}, &token))
        .await
        .expect_err("expired export");
    assert_eq!(expired.code(), Code::FailedPrecondition);
    let details = expired.get_error_details();
    let violation = &details.precondition_failure().unwrap().violations[0];
    assert_eq!(violation.r#type, "EXPORT_STATE");
    assert_eq!(violation.subject, owner.id.to_string());

    let mut ready = ExportJob::new(owner.id, ExportFormat::Json);
    ready.created_at = lapsed.created_at + chrono::Duration::seconds(1);
    ready.mark_ready("exports/b.json".into(), 1, "cd".repeat(32));
    svc.storage
        .create_export_job(&ready, AuditEntry::system("test", "export").into())
        .await
        .unwrap();
    svc.identity
        .acknowledge_export(authed(AcknowledgeExportRequest {}, &token))
        .await
        .expect("ready export");
    let stored = svc
        .storage
        .get_export_job_by_id(ready.id)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(stored.status, ExportStatus::Downloaded);
}
