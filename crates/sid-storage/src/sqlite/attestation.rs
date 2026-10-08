// SPDX-License-Identifier: AGPL-3.0-only
//! Device attestation operations for SQLite backend.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        AttestationStatus, DeviceAttestation, DeviceAttestationId, DeviceId, MutationContext,
        ProfileId,
    },
};

use super::{SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error, uuid_col};

/// The columns an attestation is read from.
macro_rules! attestation_columns {
    () => {
        "id, device_id, profile_id, format, key_storage, status, device_public_key, \
         attestation_object, attestation_certificate, aaguid, credential_id, \
         created_at, updated_at, revoked_at"
    };
}

fn row_to_attestation(row: &sqlx::sqlite::SqliteRow) -> SidResult<DeviceAttestation> {
    Ok(DeviceAttestation {
        id: DeviceAttestationId(uuid_col(row, "id")?),
        device_id: col(row, "device_id")?,
        profile_id: col(row, "profile_id")?,
        format: col::<String>(row, "format")?
            .parse()
            .map_err(SidError::Storage)?,
        key_storage: col::<String>(row, "key_storage")?
            .parse()
            .map_err(SidError::Storage)?,
        status: col::<String>(row, "status")?
            .parse()
            .map_err(SidError::Storage)?,
        device_public_key: col(row, "device_public_key")?,
        attestation_object: col(row, "attestation_object")?,
        attestation_certificate: col(row, "attestation_certificate")?,
        aaguid: col(row, "aaguid")?,
        credential_id: col(row, "credential_id")?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
        revoked_at: dt_col_opt(row, "revoked_at")?,
    })
}

impl SqliteBackend {
    pub(crate) async fn create_device_attestation_impl(
        &self,
        att: &DeviceAttestation,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        // One attestation per device: a revoked one is replaced by the new
        // enrollment; a live one makes the insert apply nothing.
        let stored = sqlx::query(concat!(
            "INSERT INTO device_attestations (",
            attestation_columns!(),
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(device_id) DO UPDATE SET \
                id = excluded.id, profile_id = excluded.profile_id, \
                format = excluded.format, key_storage = excluded.key_storage, \
                status = excluded.status, device_public_key = excluded.device_public_key, \
                attestation_object = excluded.attestation_object, \
                attestation_certificate = excluded.attestation_certificate, \
                aaguid = excluded.aaguid, credential_id = excluded.credential_id, \
                created_at = excluded.created_at, updated_at = excluded.updated_at, \
                revoked_at = excluded.revoked_at \
             WHERE device_attestations.status = 'revoked'"
        ))
        .bind(att.id.0.to_string())
        .bind(att.device_id)
        .bind(att.profile_id)
        .bind(att.format.as_str())
        .bind(att.key_storage.as_str())
        .bind(att.status.as_str())
        .bind(&att.device_public_key)
        .bind(&att.attestation_object)
        .bind(&att.attestation_certificate)
        .bind(&att.aaguid)
        .bind(&att.credential_id)
        .bind(fmt_dt(&att.created_at))
        .bind(fmt_dt(&att.updated_at))
        .bind(fmt_dt_opt(att.revoked_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("device attestation", e))?
        .rows_affected()
            == 1;
        if !stored {
            return Err(SidError::Conflict(
                "device already has a live attestation".into(),
            ));
        }
        Self::commit_mutation(tx, &format!("device_attestation:{}", att.device_id), audit).await
    }

    pub(crate) async fn rotate_device_attestation_impl(
        &self,
        device_id: DeviceId,
        device_public_key: &[u8],
        attestation_object: Option<&[u8]>,
        attestation_certificate: Option<&[u8]>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let rotated = sqlx::query(
            "UPDATE device_attestations SET device_public_key = ?, attestation_object = ?,
                attestation_certificate = ?, status = ?, updated_at = ?
             WHERE device_id = ? AND status != 'revoked'",
        )
        .bind(device_public_key)
        .bind(attestation_object)
        .bind(attestation_certificate)
        .bind(AttestationStatus::Unverified.as_str())
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(device_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("rotate device attestation: {e}")))?
        .rows_affected()
            == 1;
        if !rotated {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("device_attestation:{device_id}"), audit).await?;
        Ok(true)
    }

    pub(crate) async fn revoke_device_attestation_impl(
        &self,
        device_id: DeviceId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("revoke device attestation: {e}"));
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        let revoked = sqlx::query(
            "UPDATE device_attestations SET status = 'revoked', revoked_at = ?, updated_at = ?
             WHERE device_id = ? AND status != 'revoked'",
        )
        .bind(&now)
        .bind(&now)
        .bind(device_id)
        .execute(&mut *tx)
        .await
        .map_err(storage)?
        .rows_affected()
            == 1;
        if !revoked {
            return Ok(false);
        }
        // A revoked key no longer attests anything about the device.
        sqlx::query("UPDATE devices SET hardware_attested = 0 WHERE id = ?")
            .bind(device_id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        Self::commit_mutation(tx, &format!("device_attestation:{device_id}"), audit).await?;
        Ok(true)
    }

    pub(crate) async fn get_device_attestation_impl(
        &self,
        id: DeviceAttestationId,
    ) -> SidResult<Option<DeviceAttestation>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            attestation_columns!(),
            " FROM device_attestations WHERE id = ?"
        ))
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_attestation).transpose()
    }

    pub(crate) async fn get_device_attestation_by_device_id_impl(
        &self,
        device_id: DeviceId,
    ) -> SidResult<Option<DeviceAttestation>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            attestation_columns!(),
            " FROM device_attestations WHERE device_id = ? AND status != 'revoked'"
        ))
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_attestation).transpose()
    }

    pub(crate) async fn list_device_attestations_by_profile_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<DeviceAttestation>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            attestation_columns!(),
            " FROM device_attestations WHERE profile_id = ? ORDER BY created_at DESC"
        ))
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_attestation).collect()
    }

    pub(crate) async fn delete_device_attestation_impl(
        &self,
        device_id: DeviceId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM device_attestations WHERE device_id = ?")
            .bind(device_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Failed to delete attestation: {e}")))?;
        Self::commit_mutation(tx, &format!("device_attestation:{device_id}"), audit).await
    }
}
