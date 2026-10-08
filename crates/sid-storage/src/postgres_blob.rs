// SPDX-License-Identifier: AGPL-3.0-only
//! PostgreSQL blob store implementation.
//!
//! Stores encrypted profile blobs in `profile_blobs` table.
//! BYTEA column with TOAST auto-externalizes large blobs (>2KB).
//! Optimistic concurrency via version column.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sid_core::models::{BlobError, BlobMeta, BlobStorageStatus, EncryptedBlob, ProfileId};
use sid_plugin::blob_store::BlobStore;
use sqlx::PgPool;

/// PostgreSQL-backed blob store for encrypted profile data.
pub struct PostgresBlobStore {
    pool: PgPool,
}

impl PostgresBlobStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct BlobRow {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    version: i64,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct BlobMetaRow {
    version: i64,
    size_bytes: i32,
    storage_status: String,
    updated_at: DateTime<Utc>,
}

fn parse_storage_status(s: &str) -> BlobStorageStatus {
    match s {
        "local" => BlobStorageStatus::Local,
        "saas_vault" => BlobStorageStatus::SaasVault,
        "external" => BlobStorageStatus::External,
        "deleted" => BlobStorageStatus::Deleted,
        _ => BlobStorageStatus::Local,
    }
}

#[async_trait]
impl BlobStore for PostgresBlobStore {
    async fn get_blob(&self, profile_id: &ProfileId) -> Result<Option<EncryptedBlob>, BlobError> {
        let row = sqlx::query_as::<_, BlobRow>(
            "SELECT ciphertext, nonce, version, updated_at FROM profile_blobs
             WHERE profile_id = $1 AND storage_status != 'deleted'",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| BlobError::Storage(format!("query failed: {e}")))?;

        Ok(row.map(|r| {
            let mut nonce = [0u8; 12];
            let len = r.nonce.len().min(12);
            nonce[..len].copy_from_slice(&r.nonce[..len]);

            EncryptedBlob {
                ciphertext: r.ciphertext,
                nonce,
                version: r.version as u64,
                updated_at: r.updated_at,
            }
        }))
    }

    async fn put_blob(
        &self,
        profile_id: &ProfileId,
        blob: EncryptedBlob,
        expected_version: u64,
    ) -> Result<u64, BlobError> {
        let new_version = expected_version as i64 + 1;
        let now = Utc::now();

        if expected_version == 0 {
            // Initial upload — INSERT with conflict handling.
            let result = sqlx::query(
                "INSERT INTO profile_blobs (profile_id, ciphertext, nonce, version, storage_status, updated_at)
                 VALUES ($1, $2, $3, $4, 'local', $5)
                 ON CONFLICT (profile_id) DO UPDATE SET
                     ciphertext = EXCLUDED.ciphertext,
                     nonce = EXCLUDED.nonce,
                     version = EXCLUDED.version,
                     storage_status = 'local',
                     updated_at = EXCLUDED.updated_at
                 WHERE profile_blobs.version = $6",
            ).bind(profile_id)
            .bind(&blob.ciphertext)
            .bind(blob.nonce.as_slice())
            .bind(new_version)
            .bind(now)
            .bind(expected_version as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| BlobError::Storage(format!("insert failed: {e}")))?;

            // If ON CONFLICT matched but WHERE didn't → 0 rows affected = version conflict.
            // If no existing row → INSERT succeeds → 1 row.
            // But INSERT with ON CONFLICT returns 1 even when WHERE fails on UPDATE...
            // Use a different approach: check rows_affected on the INSERT.
            if result.rows_affected() == 0 {
                // Row exists but version doesn't match.
                let current = sqlx::query_scalar::<_, i64>(
                    "SELECT version FROM profile_blobs WHERE profile_id = $1",
                )
                .bind(profile_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| BlobError::Storage(format!("version check failed: {e}")))?
                .unwrap_or(0);

                return Err(BlobError::VersionConflict {
                    expected: expected_version,
                    actual: current as u64,
                });
            }

            Ok(new_version as u64)
        } else {
            // Update existing blob — optimistic lock on version.
            let result = sqlx::query(
                "UPDATE profile_blobs
                 SET ciphertext = $2, nonce = $3, version = $4, storage_status = 'local', updated_at = $5
                 WHERE profile_id = $1 AND version = $6",
            ).bind(profile_id)
            .bind(&blob.ciphertext)
            .bind(blob.nonce.as_slice())
            .bind(new_version)
            .bind(now)
            .bind(expected_version as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| BlobError::Storage(format!("update failed: {e}")))?;

            if result.rows_affected() == 0 {
                let current = sqlx::query_scalar::<_, i64>(
                    "SELECT version FROM profile_blobs WHERE profile_id = $1",
                )
                .bind(profile_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| BlobError::Storage(format!("version check failed: {e}")))?
                .unwrap_or(0);

                return Err(BlobError::VersionConflict {
                    expected: expected_version,
                    actual: current as u64,
                });
            }

            Ok(new_version as u64)
        }
    }

    async fn delete_blob(&self, profile_id: &ProfileId) -> Result<(), BlobError> {
        // Soft delete — set status to 'deleted', clear ciphertext.
        sqlx::query(
            "UPDATE profile_blobs SET storage_status = 'deleted', ciphertext = '\\x00', updated_at = now()
             WHERE profile_id = $1",
        ).bind(profile_id)
        .execute(&self.pool)
        .await
        .map_err(|e| BlobError::Storage(format!("delete failed: {e}")))?;

        Ok(())
    }

    async fn blob_metadata(&self, profile_id: &ProfileId) -> Result<Option<BlobMeta>, BlobError> {
        let row = sqlx::query_as::<_, BlobMetaRow>(
            "SELECT version, octet_length(ciphertext) AS size_bytes, storage_status, updated_at
             FROM profile_blobs WHERE profile_id = $1",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| BlobError::Storage(format!("query failed: {e}")))?;

        Ok(row.map(|r| BlobMeta {
            version: r.version as u64,
            size_bytes: r.size_bytes as u64,
            updated_at: r.updated_at,
            storage_status: parse_storage_status(&r.storage_status),
        }))
    }
}
