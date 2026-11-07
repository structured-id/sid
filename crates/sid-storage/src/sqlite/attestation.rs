// SPDX-License-Identifier: AGPL-3.0-only
//! Device attestation operations for SQLite backend.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        AttestationStatus, DeviceAttestation, DeviceAttestationId, DeviceEnrollment, DeviceId,
        EnrollmentTarget, MutationContext, ProfileId, ProfileStatus,
    },
};

use super::{SqliteBackend, WriteTx, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error};

/// The columns an attestation is read from.
macro_rules! attestation_columns {
    () => {
        "id, device_id, profile_id, format, key_storage, status, public_jwk, \
         attestation_object, attestation_certificate, aaguid, \
         created_at, updated_at, revoked_at"
    };
}

/// Check that `owner` still holds device `id`: a removed device is
/// `NotFound`, another Profile's `Conflict`.
async fn owned_device(tx: &mut WriteTx, id: DeviceId, owner: ProfileId) -> SidResult<()> {
    let held: Option<ProfileId> = sqlx::query_scalar("SELECT profile_id FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| SidError::Storage(format!("read device: {e}")))?;
    match held {
        None => Err(SidError::NotFound(format!("device {id}"))),
        Some(profile) if profile != owner => Err(SidError::Conflict(format!(
            "device {id} is another profile's"
        ))),
        Some(_) => Ok(()),
    }
}

/// The key binding of device `id`: its id, status and key.
async fn binding(
    tx: &mut WriteTx,
    id: DeviceId,
) -> SidResult<Option<(DeviceAttestationId, String, String)>> {
    let row =
        sqlx::query("SELECT id, status, public_jwk FROM device_attestations WHERE device_id = ?")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| SidError::Storage(format!("read device binding: {e}")))?;
    row.map(|row| {
        Ok((
            col(&row, "id")?,
            col::<String>(&row, "status")?,
            col::<String>(&row, "public_jwk")?,
        ))
    })
    .transpose()
}

fn row_to_attestation(row: &sqlx::sqlite::SqliteRow) -> SidResult<DeviceAttestation> {
    Ok(DeviceAttestation {
        id: col(row, "id")?,
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
        public_jwk: col(row, "public_jwk")?,
        attestation_object: col(row, "attestation_object")?,
        attestation_certificate: col(row, "attestation_certificate")?,
        aaguid: col(row, "aaguid")?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
        revoked_at: dt_col_opt(row, "revoked_at")?,
    })
}

impl SqliteBackend {
    pub(crate) async fn commit_device_enrollment_impl(
        &self,
        enrollment: &DeviceEnrollment,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("commit device enrollment: {e}"));
        let att = &enrollment.attestation;
        let device_id = enrollment.target.device();
        // The write transaction holds SQLite's write lock: nothing changes
        // between these checks and the commit.
        let mut ctx = ctx;
        let mut tx = self.begin_write().await?;

        // A retry of a finish that committed is answered by its outcome
        // before anything it changed is judged again.
        if let Some(operation) = ctx.operation.take() {
            super::operation::record_in_tx(&mut tx, &operation).await?;
        }

        // The owner, as it stands now: it can still sign in, and the session
        // the ceremony was authorized under is still live.
        let status: Option<String> = sqlx::query_scalar("SELECT status FROM profiles WHERE id = ?")
            .bind(enrollment.profile_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?;
        let status = status.ok_or_else(|| SidError::NotFound("profile".into()))?;
        if !status
            .parse::<ProfileStatus>()
            .is_ok_and(|s| s.can_authenticate())
        {
            return Err(SidError::Fenced("the owner can no longer sign in".into()));
        }
        if let Some(session) = enrollment.session {
            let row =
                sqlx::query("SELECT expires_at FROM sessions WHERE id = ? AND profile_id = ?")
                    .bind(session)
                    .bind(enrollment.profile_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(storage)?;
            let live = match &row {
                Some(row) => dt_col(row, "expires_at")? > chrono::Utc::now(),
                None => false,
            };
            if !live {
                return Err(SidError::Fenced("the authorizing session ended".into()));
            }
        }

        // The target as the ceremony found it.
        let changed =
            || SidError::Conflict("the device's key changed since the ceremony started".into());
        match &enrollment.target {
            EnrollmentTarget::NewDevice(device) => {
                if device.profile_id != enrollment.profile_id {
                    return Err(SidError::Validation("device of another profile".into()));
                }
                sqlx::query(
                    "INSERT INTO devices (id, profile_id, display_name, device_type, os_info,
                        assurance, trusted, hardware_attested, fingerprint_hash, last_ip_geo,
                        first_seen_at, last_seen_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(device.id)
                .bind(device.profile_id)
                .bind(&device.display_name)
                .bind(device.device_type.as_str())
                .bind(&device.os_info)
                .bind(device.assurance.as_str())
                .bind(device.trusted)
                .bind(device.hardware_attested)
                .bind(&device.fingerprint_hash)
                .bind(&device.last_ip_geo)
                .bind(fmt_dt(&device.first_seen_at))
                .bind(fmt_dt(&device.last_seen_at))
                .execute(&mut *tx)
                .await
                .map_err(|e| insert_error("device", e))?;
            }
            EnrollmentTarget::ExistingDevice { revoked, .. } => {
                owned_device(&mut tx, device_id, enrollment.profile_id).await?;
                let unchanged = match (binding(&mut tx, device_id).await?, revoked) {
                    (None, None) => true,
                    (Some((id, status, _)), Some(expected)) => {
                        id == *expected && status == "revoked"
                    }
                    _ => false,
                };
                if !unchanged {
                    return Err(changed());
                }
            }
            EnrollmentTarget::Rotation {
                current,
                current_key,
                ..
            } => {
                owned_device(&mut tx, device_id, enrollment.profile_id).await?;
                let unchanged =
                    binding(&mut tx, device_id)
                        .await?
                        .is_some_and(|(id, status, key)| {
                            id == *current && status != "revoked" && &key == current_key
                        });
                if !unchanged {
                    return Err(changed());
                }
            }
        }

        // The new binding over the old one; the device is hardware-attested
        // only by verified hardware evidence.
        sqlx::query(concat!(
            "INSERT INTO device_attestations (",
            attestation_columns!(),
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(device_id) DO UPDATE SET \
                id = excluded.id, profile_id = excluded.profile_id, \
                format = excluded.format, key_storage = excluded.key_storage, \
                status = excluded.status, public_jwk = excluded.public_jwk, \
                attestation_object = excluded.attestation_object, \
                attestation_certificate = excluded.attestation_certificate, \
                aaguid = excluded.aaguid, \
                created_at = excluded.created_at, updated_at = excluded.updated_at, \
                revoked_at = excluded.revoked_at"
        ))
        .bind(att.id)
        .bind(device_id)
        .bind(enrollment.profile_id)
        .bind(att.format.as_str())
        .bind(att.key_storage.as_str())
        .bind(att.status.as_str())
        .bind(&att.public_jwk)
        .bind(&att.attestation_object)
        .bind(&att.attestation_certificate)
        .bind(&att.aaguid)
        .bind(fmt_dt(&att.created_at))
        .bind(fmt_dt(&att.updated_at))
        .bind(fmt_dt_opt(att.revoked_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("device attestation", e))?;
        sqlx::query("UPDATE devices SET hardware_attested = ? WHERE id = ?")
            .bind(att.status == AttestationStatus::Verified && att.is_hardware_backed())
            .bind(device_id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        Self::commit_mutation(tx, &format!("device_attestation:{device_id}"), ctx).await
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
        .bind(id)
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
