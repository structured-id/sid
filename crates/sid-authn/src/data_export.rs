// SPDX-License-Identifier: AGPL-3.0-only
//! GDPR Art. 20 data export service (CE).
//!
//! Collects profile data into a JSON archive for data portability.
//! CE supports JSON format only. EE adds JSON-LD and W3C VC.

use std::io::Write;
use std::sync::Arc;

use chrono::Utc;
use sha2::{Digest, Sha256};
use tracing::info;

use sid_core::Error as SidError;
use sid_core::Result as SidResult;
use sid_core::models::{AuditEntry, ExportFormat, ExportJob, ExportStatus, ProfileId};
use sid_plugin::StorageBackend;

/// Data export service — prepares and manages GDPR Art. 20 export packages.
pub struct DataExportService {
    storage: Arc<dyn StorageBackend>,
    /// Directory where export archives are written.
    export_dir: String,
}

impl DataExportService {
    pub fn new(storage: Arc<dyn StorageBackend>, export_dir: String) -> Self {
        Self {
            storage,
            export_dir,
        }
    }

    /// Prepare a data export for the given profile.
    ///
    /// Collects profile data, identifiers, credentials metadata, sessions,
    /// and metadata into a JSON archive. Returns the export job for tracking.
    pub async fn prepare_export(
        &self,
        profile_id: ProfileId,
        format: ExportFormat,
        initiated_by: &str,
    ) -> SidResult<ExportJob> {
        // Check for existing in-progress export.
        if let Some(existing) = self.storage.get_export_job(profile_id).await? {
            match existing.status {
                ExportStatus::Preparing => {
                    return Err(SidError::InvalidState("export already in progress".into()));
                }
                // Re-use existing ready export if not expired.
                ExportStatus::Ready if !existing.is_expired() => {
                    return Ok(existing);
                }
                // Expired Ready or other statuses — fall through to create new.
                _ => {}
            }
        }

        let mut job = ExportJob::new(profile_id, format);

        // Collect data into JSON.
        let export_data = self.collect_profile_data(profile_id).await?;

        // Serialize to JSON bytes.
        let json_bytes = serde_json::to_vec_pretty(&export_data)
            .map_err(|e| SidError::Internal(format!("JSON serialization failed: {}", e)))?;

        // Compute checksum.
        let mut hasher = Sha256::new();
        hasher.update(&json_bytes);
        let checksum = format!("{:x}", hasher.finalize());

        // Write to disk.
        let archive_path = format!("{}/{}.json", self.export_dir, job.id);
        std::fs::create_dir_all(&self.export_dir)
            .map_err(|e| SidError::Internal(format!("Failed to create export dir: {}", e)))?;

        let mut file = std::fs::File::create(&archive_path)
            .map_err(|e| SidError::Internal(format!("Failed to create export file: {}", e)))?;
        file.write_all(&json_bytes)
            .map_err(|e| SidError::Internal(format!("Failed to write export: {}", e)))?;

        let size_bytes = json_bytes.len() as i64;
        job.mark_ready(archive_path.clone(), size_bytes, checksum);

        // Persist the job, created once.
        self.storage
            .create_export_job(
                &job,
                AuditEntry::user(initiated_by, "export.prepared", profile_id.to_string()).into(),
            )
            .await?;

        info!(
            profile_id = %profile_id,
            export_id = %job.id,
            size_bytes = size_bytes,
            "Data export prepared",
        );

        Ok(job)
    }

    /// Get current export status for a profile.
    pub async fn get_export_status(&self, profile_id: ProfileId) -> SidResult<Option<ExportJob>> {
        let job = self.storage.get_export_job(profile_id).await?;

        // Close a passed download window on the fly; only a ready export
        // changes, so a download acknowledged meanwhile stays acknowledged.
        if let Some(mut j) = job {
            if j.status == ExportStatus::Ready
                && j.is_expired()
                && self
                    .storage
                    .expire_export_job(
                        j.id,
                        Utc::now(),
                        AuditEntry::system("export.expired", profile_id.to_string()).into(),
                    )
                    .await?
            {
                j.status = ExportStatus::Expired;
            }
            Ok(Some(j))
        } else {
            Ok(None)
        }
    }

    /// Read export archive bytes for streaming download.
    ///
    /// Returns the archive bytes if the export is ready and not expired.
    pub async fn read_export_archive(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<(Vec<u8>, ExportJob)> {
        let job = self
            .storage
            .get_export_job(profile_id)
            .await?
            .ok_or_else(|| SidError::NotFound("no export available".into()))?;

        if job.status != ExportStatus::Ready {
            return Err(SidError::InvalidState(format!(
                "export is not ready (status: {})",
                job.status.as_str()
            )));
        }

        if job.is_expired() {
            return Err(SidError::InvalidState("export has expired".into()));
        }

        let path = job
            .archive_path
            .as_ref()
            .ok_or_else(|| SidError::Internal("export has no archive path".into()))?;

        let data = std::fs::read(path)
            .map_err(|e| SidError::Internal(format!("Failed to read export archive: {}", e)))?;

        Ok((data, job))
    }

    /// Acknowledge the download of the profile's ready export. An export not
    /// ready, expired or already acknowledged is refused: it was not downloaded.
    pub async fn acknowledge_export(
        &self,
        profile_id: ProfileId,
        initiated_by: &str,
    ) -> SidResult<()> {
        let job = self
            .storage
            .get_export_job(profile_id)
            .await?
            .ok_or_else(|| SidError::NotFound("no export available".into()))?;

        let acknowledged = self
            .storage
            .acknowledge_export_job(
                job.id,
                Utc::now(),
                AuditEntry::user(initiated_by, "export.acknowledged", profile_id.to_string())
                    .into(),
            )
            .await?;
        if !acknowledged {
            return Err(SidError::InvalidState(
                "export is not ready for download or has expired".into(),
            ));
        }

        info!(
            profile_id = %profile_id,
            export_id = %job.id,
            "Export acknowledged by user",
        );

        Ok(())
    }

    /// Collect all exportable profile data into a serializable structure.
    async fn collect_profile_data(&self, profile_id: ProfileId) -> SidResult<serde_json::Value> {
        use serde_json::json;

        // Profile.
        let profile = self
            .storage
            .get_profile(profile_id)
            .await?
            .ok_or_else(|| SidError::NotFound("profile not found".into()))?;

        // Principals.
        let identifiers = self.storage.get_principals_by_profile(profile_id).await?;

        // Credentials metadata (no secrets).
        let credentials = self
            .storage
            .get_credentials_by_profile(profile_id, None)
            .await?;

        // Sessions (sanitized — no tokens).
        let sessions = self.storage.list_sessions_by_profile(profile_id).await?;

        // Metadata.
        let metadata = self.storage.list_profile_metadata(profile_id).await?;

        // PATs (no secret values).
        let pats = self.storage.list_pats_by_profile(profile_id).await?;

        let now = Utc::now();

        Ok(json!({
            "export_version": "1.0",
            "exported_at": now.to_rfc3339(),
            "profile": {
                "id": profile.id.to_string(),
                "username": profile.username,
                "given_name": profile.given_name,
                "family_name": profile.family_name,
                "middle_name": profile.middle_name,
                "honorific_prefix": profile.honorific_prefix,
                "honorific_suffix": profile.honorific_suffix,
                "formatted_name": profile.formatted_name(),
                "profile_type": format!("{:?}", profile.profile_type),
                "status": profile.status.as_str(),
                "created_at": profile.created_at.to_rfc3339(),
            },
            "principals": identifiers.iter().map(|i| json!({
                "type": i.principal_type.as_str(),
                "value": i.value,
                "verified": i.verified,
                "is_primary": i.is_primary,
            })).collect::<Vec<_>>(),
            "credentials": credentials.iter().map(|c| json!({
                "id": c.id.0.to_string(),
                "type": c.credential_type.as_str(),
                "created_at": c.created_at.to_rfc3339(),
            })).collect::<Vec<_>>(),
            "sessions": sessions.iter().map(|s| json!({
                "id": s.id.to_string(),
                "created_at": s.created_at.to_rfc3339(),
                "expires_at": s.expires_at.to_rfc3339(),
                "user_agent": s.user_agent,
            })).collect::<Vec<_>>(),
            "metadata": metadata.iter().map(|m| json!({
                "key": m.key,
                "value": m.value,
            })).collect::<Vec<_>>(),
            "personal_access_tokens": pats.iter().map(|p| json!({
                "id": p.id.0.to_string(),
                "name": p.name,
                "status": p.status.as_str(),
                "created_at": p.created_at.to_rfc3339(),
                "expires_at": p.expires_at.map(|e| e.to_rfc3339()),
            })).collect::<Vec<_>>(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sid_core::models::{EXPORT_DOWNLOAD_WINDOW_HOURS, ExportFormat};

    #[test]
    fn test_export_job_lifecycle() {
        let pid = ProfileId::generate();
        let mut job = ExportJob::new(pid, ExportFormat::Json);

        assert_eq!(job.status, ExportStatus::Preparing);
        assert!(job.archive_path.is_none());
        assert!(!job.is_expired());

        job.mark_ready("/tmp/test.json".to_string(), 1024, "abc123".to_string());
        assert_eq!(job.status, ExportStatus::Ready);
        assert_eq!(job.size_bytes, Some(1024));
        assert_eq!(job.checksum_sha256.as_deref(), Some("abc123"));
        assert!(job.ready_at.is_some());
        assert!(job.expires_at.is_some());
        assert!(!job.is_expired());

        job.mark_downloaded();
        assert_eq!(job.status, ExportStatus::Downloaded);
    }

    #[test]
    fn test_export_job_expiry() {
        let pid = ProfileId::generate();
        let mut job = ExportJob::new(pid, ExportFormat::Json);
        job.mark_ready("/tmp/test.json".to_string(), 100, "hash".to_string());

        // Not expired immediately.
        assert!(!job.is_expired());

        // Force expire.
        job.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(job.is_expired());
    }

    #[test]
    fn test_export_format_as_str() {
        assert_eq!(ExportFormat::Json.as_str(), "json");
    }

    #[test]
    fn test_export_download_window() {
        assert_eq!(EXPORT_DOWNLOAD_WINDOW_HOURS, 72);
    }

    #[test]
    fn test_export_job_new_has_uuid() {
        let pid = ProfileId::generate();
        let job1 = ExportJob::new(pid, ExportFormat::Json);
        let job2 = ExportJob::new(pid, ExportFormat::Json);
        assert_ne!(job1.id, job2.id);
    }
}
