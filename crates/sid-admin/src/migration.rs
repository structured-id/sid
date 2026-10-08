// SPDX-License-Identifier: AGPL-3.0-only
//! Migration import service for bulk user import from legacy IdPs.
//!
//! Uses `MigrationAdapter` to parse provider-specific exports, then creates
//! profiles and legacy credentials in the storage backend idempotently.

use sid_authn::migration::{ImportedUser, MigrationAdapter, MigrationImportError};
use sid_core::models::{
    AuditEntry, Credential, CredentialType, EmailLabel, Principal, PrincipalId, PrincipalType,
    Profile, ProfileAssurance, ProfileEmail, ProfileEmailId, ProfileId, ProfileStatus, ProfileType,
    ProfileVisibility,
};
use sid_plugin::storage::StorageBackend;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

/// Result of a bulk import operation.
#[derive(Debug, Clone)]
pub struct ImportResult {
    /// Total users parsed from the export file.
    pub total_parsed: usize,
    /// Users successfully imported (created or updated).
    pub imported: usize,
    /// Users skipped (already exist, idempotency).
    pub skipped: usize,
    /// Users that failed to import.
    pub failed: usize,
    /// Details of failed imports.
    pub errors: Vec<ImportError>,
}

/// A single import failure.
#[derive(Debug, Clone)]
pub struct ImportError {
    /// Email or username of the user that failed.
    pub identifier: String,
    /// Error description.
    pub reason: String,
}

/// Service for importing users from legacy IdPs.
pub struct MigrationImportService {
    storage: Arc<dyn StorageBackend>,
}

impl MigrationImportService {
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    /// Import users from a parsed export file.
    ///
    /// Idempotent: if a profile with the same email already exists, it is skipped.
    /// Creates: profile + email identifier + legacy credential (if password hash present).
    pub async fn import_users(&self, users: Vec<ImportedUser>) -> ImportResult {
        let total_parsed = users.len();
        let mut imported = 0;
        let mut skipped = 0;
        let mut failed = 0;
        let mut errors = Vec::new();

        for user in users {
            match self.import_single_user(&user).await {
                Ok(ImportOutcome::Created) => {
                    imported += 1;
                }
                Ok(ImportOutcome::Skipped) => {
                    skipped += 1;
                }
                Err(e) => {
                    failed += 1;
                    errors.push(ImportError {
                        identifier: user.email.clone(),
                        reason: e.to_string(),
                    });
                    warn!(email = %user.email, error = %e, "Failed to import user");
                }
            }
        }

        info!(
            total = total_parsed,
            imported, skipped, failed, "Migration import completed"
        );

        ImportResult {
            total_parsed,
            imported,
            skipped,
            failed,
            errors,
        }
    }

    /// Parse an export file using the given adapter, then import all users.
    pub async fn import_from_file(
        &self,
        adapter: &dyn MigrationAdapter,
        data: &[u8],
    ) -> Result<ImportResult, MigrationImportError> {
        let users = adapter.parse(data)?;
        info!(
            provider = adapter.provider_name(),
            count = users.len(),
            "Parsed users from export"
        );
        Ok(self.import_users(users).await)
    }

    async fn import_single_user(
        &self,
        user: &ImportedUser,
    ) -> Result<ImportOutcome, ImportUserError> {
        // The email as the installation's login handle: its key for lookup
        // and uniqueness, its address as the export spelled it for mail.
        let email =
            sid_authn::email::parse(user.email.trim(), &sid_authn::email::EmailPolicy::LOCAL)
                .map_err(|e| ImportUserError::InvalidEmail(e.to_string()))?;

        // Idempotency: check if email already exists.
        let existing = self
            .storage
            .get_profile_by_principal(PrincipalType::Email, &email.key)
            .await
            .map_err(|e| ImportUserError::Storage(e.to_string()))?;

        if existing.is_some() {
            return Ok(ImportOutcome::Skipped);
        }

        let profile_id = ProfileId::generate();
        let now = chrono::Utc::now();
        // Map legacy display_name + first/last into structured fields.
        let given_name = user
            .first_name
            .clone()
            .or_else(|| user.display_name.clone());
        let family_name = user.last_name.clone();
        let profile = Profile {
            id: profile_id,
            profile_type: ProfileType::Personal,
            username: Some(user.username.clone()),
            given_name,
            family_name,
            middle_name: None,
            honorific_prefix: None,
            honorific_suffix: None,
            roles: user.roles.clone(),
            status: if user.enabled {
                ProfileStatus::Active
            } else {
                ProfileStatus::Suspended
            },
            visibility: ProfileVisibility::Private,
            max_assurance: ProfileAssurance::Anonymous,
            manager_id: None,
            migration_pending: user.password_hash.is_some(),
            migration_started_at: Some(now),
            migration_completed_at: None,
            revision: 0,
            created_at: now,
            updated_at: now,
        };

        let audit: sid_core::models::MutationContext =
            sid_core::models::AuditEntry::system("migration.import", profile_id.to_string()).into();

        // Create profile.
        self.storage
            .create_profile(&profile, audit.clone())
            .await
            .map_err(|e| ImportUserError::Storage(e.to_string()))?;

        // The email contact the principal comes from, in the export's spelling.
        let contact = ProfileEmail {
            id: ProfileEmailId::new(),
            profile_id,
            email: email.delivery.clone(),
            label: EmailLabel::Personal,
            custom_label: None,
            is_primary: true,
            verified: user.email_verified,
            verified_at: None,
            created_at: now,
            updated_at: now,
        };
        self.storage
            .create_profile_email(
                &contact,
                AuditEntry::system("migration.import.email", profile_id.to_string()).into(),
            )
            .await
            .map_err(|e| ImportUserError::Storage(e.to_string()))?;

        // Create email principal.
        let principal = Principal {
            id: PrincipalId(Uuid::now_v7()),
            profile_id,
            principal_type: PrincipalType::Email,
            value: email.key,
            email_policy_revision: Some(email.revision),
            verified: user.email_verified,
            verified_at: None,
            verification_expires: None,
            assigned_profile_id: Some(profile_id),
            assignment_revision: 1,
            is_primary: true,
            source_field: Some("email".into()),
            source_email_id: Some(contact.id),
            source_phone_id: None,
            created_at: now,
            updated_at: now,
        };
        self.storage
            .save_principal(
                &principal,
                AuditEntry::system("migration.import.principal", profile_id.to_string()).into(),
            )
            .await
            .map_err(|e| ImportUserError::Storage(e.to_string()))?;

        // Create legacy credential if password hash present.
        if let Some(ref hash) = user.password_hash {
            let mut credential = Credential::new(
                profile_id,
                CredentialType::LegacyHash,
                hash.as_bytes().to_vec(),
                Some("Migrated password".to_string()),
            );
            credential.legacy_algorithm = user.hash_algorithm.clone();
            self.storage
                .create_credential(
                    &credential,
                    AuditEntry::system("migration.import.credential", profile_id.to_string())
                        .into(),
                )
                .await
                .map_err(|e| ImportUserError::Storage(e.to_string()))?;
        }

        Ok(ImportOutcome::Created)
    }
}

enum ImportOutcome {
    Created,
    Skipped,
}

#[derive(Debug, thiserror::Error)]
enum ImportUserError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("not an admissible email address: {0}")]
    InvalidEmail(String),
}

#[cfg(test)]
mod tests;
