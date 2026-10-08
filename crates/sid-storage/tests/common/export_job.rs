// SPDX-License-Identifier: AGPL-3.0-only
//! Data export jobs: created once, read back field for field, moved only from
//! ready (to downloaded while the window is open, to expired once it closed),
//! and committed with the mutation's audit and owed work.

use chrono::{Duration, Utc};
use sid_core::models::{ExportFormat, ExportJob, ExportStatus, NewWork, WorkKind};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, test_audit};

async fn stored_profile(backend: &dyn StorageBackend) -> sid_core::models::ProfileId {
    let profile = create_test_profile("export");
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    profile.id
}

fn ready_job(pid: sid_core::models::ProfileId) -> ExportJob {
    let mut job = ExportJob::new(pid, ExportFormat::Json);
    job.mark_ready("exports/a.zip".into(), 42, "ab".repeat(32));
    job
}

async fn status(backend: &dyn StorageBackend, job: &ExportJob) -> ExportStatus {
    backend
        .get_export_job_by_id(job.id)
        .await
        .unwrap()
        .expect("stored")
        .status
}

/// A job round-trips; a second create never replaces it, and the latest job
/// of the profile is the one returned by profile.
pub async fn test_export_job_roundtrip(backend: &dyn StorageBackend) {
    let pid = stored_profile(backend).await;
    let job = ready_job(pid);
    backend.create_export_job(&job, test_audit()).await.unwrap();

    let loaded = backend.get_export_job(pid).await.unwrap().expect("latest");
    assert_eq!(loaded.id, job.id);
    assert_eq!(loaded.profile_id, pid);
    assert_eq!(loaded.status, ExportStatus::Ready);
    assert_eq!(loaded.format, ExportFormat::Json);
    assert_eq!(loaded.archive_path.as_deref(), Some("exports/a.zip"));
    assert_eq!(loaded.size_bytes, Some(42));
    assert_eq!(loaded.checksum_sha256, job.checksum_sha256);
    assert!(loaded.ready_at.is_some());
    assert!(loaded.expires_at.is_some());

    let mut replaced = job.clone();
    replaced.archive_path = Some("exports/other.zip".into());
    assert!(matches!(
        backend.create_export_job(&replaced, test_audit()).await,
        Err(sid_core::Error::Conflict(_))
    ));

    assert!(
        backend
            .get_export_job_by_id(Uuid::new_v4())
            .await
            .unwrap()
            .is_none()
    );
}

/// Only a ready export inside its window is acknowledged, once; a passed
/// window expires only a ready export, never an acknowledged one.
pub async fn test_export_job_status_transitions(backend: &dyn StorageBackend) {
    let pid = stored_profile(backend).await;
    let now = Utc::now();

    let preparing = ExportJob::new(pid, ExportFormat::Json);
    backend
        .create_export_job(&preparing, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .acknowledge_export_job(preparing.id, now, test_audit())
            .await
            .unwrap(),
        "an export not yet ready was acknowledged"
    );

    let job = ready_job(pid);
    backend.create_export_job(&job, test_audit()).await.unwrap();
    let window_end = job.expires_at.expect("ready export has a window");
    assert!(
        !backend
            .acknowledge_export_job(job.id, window_end + Duration::seconds(1), test_audit())
            .await
            .unwrap(),
        "an expired export was acknowledged"
    );
    assert!(
        backend
            .acknowledge_export_job(job.id, now, test_audit())
            .await
            .unwrap()
    );
    assert_eq!(status(backend, &job).await, ExportStatus::Downloaded);
    assert!(
        !backend
            .acknowledge_export_job(job.id, now, test_audit())
            .await
            .unwrap()
    );
    assert!(
        !backend
            .expire_export_job(job.id, window_end + Duration::seconds(1), test_audit())
            .await
            .unwrap(),
        "an acknowledged export was expired"
    );
    assert_eq!(status(backend, &job).await, ExportStatus::Downloaded);

    let lapsed = ready_job(pid);
    backend
        .create_export_job(&lapsed, test_audit())
        .await
        .unwrap();
    assert!(
        !backend
            .expire_export_job(lapsed.id, now, test_audit())
            .await
            .unwrap(),
        "an open window was closed"
    );
    assert!(
        backend
            .expire_export_job(
                lapsed.id,
                lapsed.expires_at.unwrap() + Duration::seconds(1),
                test_audit()
            )
            .await
            .unwrap()
    );
    assert_eq!(status(backend, &lapsed).await, ExportStatus::Expired);
}

/// Work owed by the export mutation commits with it.
pub async fn test_export_job_commits_owed_work(backend: &dyn StorageBackend) {
    let pid = stored_profile(backend).await;
    let job = ExportJob::new(pid, ExportFormat::Json);
    let work = NewWork::new(WorkKind::new("test.export").unwrap(), b"{}".to_vec());
    let work_id = work.id;
    backend
        .create_export_job(&job, test_audit().with_work(work))
        .await
        .unwrap();
    assert!(backend.get_work(work_id).await.unwrap().is_some());
}
