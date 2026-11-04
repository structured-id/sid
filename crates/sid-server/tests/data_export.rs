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

/// `msg` as one new command of `token`'s (a method that promises a safe
/// retry takes an operation key).
fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    common::name_new_command(req.metadata_mut());
    req
}

/// A preparation that reused the ready export is that command's outcome: a
/// retry of it after the export was acknowledged answers with the same
/// export and prepares no other.
#[tokio::test]
async fn a_reused_export_is_recorded_for_the_retry() {
    let owner = test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(owner.clone()));
    let token = issue_token(&svc.jwt, &owner, &["openid".to_string()]);
    let keyed = |key: &str| {
        let mut req = Request::new(sid_proto::sid::v1::PrepareExportRequest::default());
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        common::name_command(req.metadata_mut(), key);
        req
    };
    let first = svc
        .identity
        .prepare_export(keyed("k-prepare"))
        .await
        .unwrap()
        .into_inner();
    let reused = svc
        .identity
        .prepare_export(keyed("k-prepare-again"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        reused.export_id, first.export_id,
        "the ready export is reused"
    );
    svc.identity
        .acknowledge_export(authed(AcknowledgeExportRequest {}, &token))
        .await
        .unwrap();

    let retried = svc
        .identity
        .prepare_export(keyed("k-prepare-again"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        retried.export_id, reused.export_id,
        "the retry prepared another export"
    );
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
