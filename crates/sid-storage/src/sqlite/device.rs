// SPDX-License-Identifier: AGPL-3.0-only
//! Device and DeviceAuthorization operations for SQLite backend.

use super::{
    SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error, parsed_col, uuid_col,
};
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        Device, DeviceAuthCodeId, DeviceAuthDecision, DeviceAuthStatus, DeviceAuthorizationCode,
        DeviceCodeRedemption, DeviceId, DevicePoll, DeviceTrustChange, MutationContext, ProfileId,
        ProjectId, RefreshToken, Session, SessionId,
    },
};

fn row_to_device(row: &sqlx::sqlite::SqliteRow) -> SidResult<Device> {
    Ok(Device {
        id: col(row, "id")?,
        profile_id: col(row, "profile_id")?,
        display_name: col(row, "display_name")?,
        device_type: parsed_col(row, "device_type")?,
        os_info: col(row, "os_info")?,
        assurance: parsed_col(row, "assurance")?,
        trusted: col(row, "trusted")?,
        hardware_attested: col(row, "hardware_attested")?,
        fingerprint_hash: col(row, "fingerprint_hash")?,
        last_ip_geo: col(row, "last_ip_geo")?,
        first_seen_at: dt_col(row, "first_seen_at")?,
        last_seen_at: dt_col(row, "last_seen_at")?,
    })
}

/// An unknown status is an error, never a pending request.
fn row_to_device_auth(row: &sqlx::sqlite::SqliteRow) -> SidResult<DeviceAuthorizationCode> {
    Ok(DeviceAuthorizationCode {
        id: DeviceAuthCodeId(uuid_col(row, "id")?),
        client_id: col(row, "client_id")?,
        device_code_hash: col(row, "device_code_hash")?,
        user_code: col(row, "user_code")?,
        scope: col(row, "scope")?,
        resource: col(row, "resource_id")?,
        status: parsed_col(row, "status")?,
        authorized_by: col(row, "authorized_by")?,
        project_id: ProjectId(uuid_col(row, "project_id")?),
        interval: col(row, "interval_secs")?,
        created_at: dt_col(row, "created_at")?,
        expires_at: dt_col(row, "expires_at")?,
        authorized_at: dt_col_opt(row, "authorized_at")?,
        last_polled_at: dt_col_opt(row, "last_polled_at")?,
        redeemed_session_id: col(row, "redeemed_session_id")?,
    })
}

/// RFC 8628 §3.5: each slow_down adds 5 seconds to the polling interval.
const SLOW_DOWN_STEP_SECS: i32 = 5;

impl SqliteBackend {
    // === Device ===

    pub(crate) async fn create_device_impl(
        &self,
        device: &Device,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO devices (id, profile_id, display_name, device_type, os_info, assurance, trusted, hardware_attested, fingerprint_hash, last_ip_geo, first_seen_at, last_seen_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).bind(device.id).bind(device.profile_id)
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
        Self::commit_mutation(tx, &format!("device:{}", device.id), audit).await
    }

    pub(crate) async fn rename_device_impl(
        &self,
        id: DeviceId,
        display_name: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let renamed = sqlx::query("UPDATE devices SET display_name = ? WHERE id = ?")
            .bind(display_name)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("rename device: {e}")))?
            .rows_affected()
            == 1;
        if !renamed {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("device:{id}"), audit).await?;
        Ok(true)
    }

    /// `BEGIN IMMEDIATE` orders the count with every other write, so
    /// concurrent trusts cannot exceed `max_trusted`.
    pub(crate) async fn set_device_trust_impl(
        &self,
        id: DeviceId,
        trusted: bool,
        max_trusted: usize,
        audit: MutationContext,
    ) -> SidResult<DeviceTrustChange> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("set device trust: {e}"));
        let mut tx = self.begin_write().await?;
        let current: Option<(ProfileId, bool)> =
            sqlx::query_as("SELECT profile_id, trusted FROM devices WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
        let Some((profile_id, was_trusted)) = current else {
            return Ok(DeviceTrustChange::NotFound);
        };
        if was_trusted == trusted {
            return Ok(DeviceTrustChange::Unchanged);
        }
        let now = fmt_dt(&chrono::Utc::now());
        if trusted {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE profile_id = ? AND trusted")
                    .bind(profile_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(storage)?;
            if usize::try_from(count).map_err(|e| SidError::Storage(e.to_string()))? >= max_trusted
            {
                return Ok(DeviceTrustChange::LimitReached);
            }
            sqlx::query(
                "UPDATE devices SET trusted = 1, last_seen_at = ?,
                    assurance = CASE WHEN assurance IN ('unknown', 'recognized')
                        THEN 'trusted' ELSE assurance END
                 WHERE id = ?",
            )
        } else {
            sqlx::query(
                "UPDATE devices SET trusted = 0, last_seen_at = ?,
                    assurance = CASE WHEN assurance = 'trusted'
                        THEN 'recognized' ELSE assurance END
                 WHERE id = ?",
            )
        }
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        Self::commit_mutation(tx, &format!("device:{id}"), audit).await?;
        Ok(DeviceTrustChange::Changed)
    }

    pub(crate) async fn get_device_impl(&self, id: DeviceId) -> SidResult<Option<Device>> {
        let row = sqlx::query("SELECT * FROM devices WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_device).transpose()
    }

    pub(crate) async fn list_devices_by_profile_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<Device>> {
        let rows = sqlx::query("SELECT * FROM devices WHERE profile_id = ?")
            .bind(profile_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_device).collect()
    }

    pub(crate) async fn delete_device_impl(
        &self,
        id: DeviceId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM devices WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("device:{id}"), audit).await
    }

    pub(crate) async fn get_device_by_fingerprint_impl(
        &self,
        profile_id: ProfileId,
        fingerprint_hash: &str,
    ) -> SidResult<Option<Device>> {
        let row =
            sqlx::query("SELECT * FROM devices WHERE profile_id = ? AND fingerprint_hash = ?")
                .bind(profile_id)
                .bind(fingerprint_hash)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_device).transpose()
    }

    // === DeviceAuthorization ===

    pub(crate) async fn create_device_auth_code_impl(
        &self,
        code: &DeviceAuthorizationCode,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO device_authorization_codes (id, client_id, device_code_hash, user_code,
                scope, status, authorized_by, project_id, interval_secs, created_at, expires_at,
                authorized_at, last_polled_at, redeemed_session_id, resource_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(code.id.0.to_string())
        .bind(&code.client_id)
        .bind(&code.device_code_hash)
        .bind(&code.user_code)
        .bind(&code.scope)
        .bind(code.status.as_str())
        .bind(code.authorized_by)
        .bind(code.project_id.0.to_string())
        .bind(code.interval)
        .bind(fmt_dt(&code.created_at))
        .bind(fmt_dt(&code.expires_at))
        .bind(fmt_dt_opt(code.authorized_at))
        .bind(fmt_dt_opt(code.last_polled_at))
        .bind(code.redeemed_session_id)
        .bind(code.resource)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("device authorization", e))?;
        Self::commit_mutation(tx, &format!("device_auth:{}", code.id.0), audit).await
    }

    pub(crate) async fn get_device_auth_by_device_code_hash_impl(
        &self,
        device_code_hash: &[u8],
    ) -> SidResult<Option<DeviceAuthorizationCode>> {
        let row =
            sqlx::query("SELECT * FROM device_authorization_codes WHERE device_code_hash = ?")
                .bind(device_code_hash)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_device_auth).transpose()
    }

    pub(crate) async fn get_device_auth_by_user_code_impl(
        &self,
        user_code: &str,
    ) -> SidResult<Option<DeviceAuthorizationCode>> {
        let row = sqlx::query("SELECT * FROM device_authorization_codes WHERE user_code = ?")
            .bind(user_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_device_auth).transpose()
    }

    pub(crate) async fn decide_device_auth_impl(
        &self,
        id: DeviceAuthCodeId,
        decision: DeviceAuthDecision,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let now = fmt_dt(&chrono::Utc::now());
        let (status, authorized_by, authorized_at) = match decision {
            DeviceAuthDecision::Authorize(profile_id) => {
                ("authorized", Some(profile_id), Some(now.clone()))
            }
            DeviceAuthDecision::Deny => ("denied", None, None),
        };
        let mut tx = self.begin_write().await?;
        let decided = sqlx::query(
            "UPDATE device_authorization_codes SET status = ?, authorized_by = ?, authorized_at = ?
             WHERE id = ? AND status = 'pending' AND expires_at > ?",
        )
        .bind(status)
        .bind(authorized_by)
        .bind(authorized_at)
        .bind(id.0.to_string())
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("decide device authorization: {e}")))?
        .rows_affected()
            == 1;
        if !decided {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("device_auth:{}", id.0), audit).await?;
        Ok(true)
    }

    /// The write lock of `BEGIN IMMEDIATE` orders concurrent polls: each sees
    /// the previous one's time.
    pub(crate) async fn record_device_poll_impl(
        &self,
        id: DeviceAuthCodeId,
        audit: MutationContext,
    ) -> SidResult<DevicePoll> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("record device poll: {e}"));
        let mut tx = self.begin_write().await?;
        let row = sqlx::query(
            "SELECT last_polled_at, interval_secs FROM device_authorization_codes WHERE id = ?",
        )
        .bind(id.0.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?
        .ok_or_else(|| SidError::NotFound(format!("device authorization {}", id.0)))?;
        let last = dt_col_opt(&row, "last_polled_at")?;
        let interval: i32 = col(&row, "interval_secs")?;
        let now = chrono::Utc::now();
        let too_soon = last.is_some_and(|t| now - t < chrono::Duration::seconds(interval.into()));
        let (poll, interval) = if too_soon {
            let grown = interval
                .checked_add(SLOW_DOWN_STEP_SECS)
                .ok_or_else(|| SidError::Storage("device poll interval overflow".into()))?;
            (DevicePoll::SlowDown, grown)
        } else {
            (DevicePoll::Allowed, interval)
        };
        sqlx::query(
            "UPDATE device_authorization_codes SET last_polled_at = ?, interval_secs = ? WHERE id = ?",
        )
        .bind(fmt_dt(&now))
        .bind(interval)
        .bind(id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        Self::commit_mutation(tx, &format!("device_auth:{}", id.0), audit).await?;
        Ok(poll)
    }

    pub(crate) async fn redeem_device_code_impl(
        &self,
        device_code_hash: &[u8],
        session: &Session,
        refresh_token: &RefreshToken,
        audit: MutationContext,
    ) -> SidResult<DeviceCodeRedemption> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("redeem device code: {e}"));
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        // The session goes first (the code references it); a redemption that
        // does not apply rolls it back with the transaction.
        super::session::insert_session(&mut *tx, session).await?;
        let redeemed = sqlx::query(
            "UPDATE device_authorization_codes SET status = 'redeemed', redeemed_session_id = ?
             WHERE device_code_hash = ? AND status = 'authorized' AND expires_at > ?",
        )
        .bind(session.id)
        .bind(device_code_hash)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(storage)?
        .rows_affected()
            == 1;
        if !redeemed {
            let row = sqlx::query(
                "SELECT status, redeemed_session_id FROM device_authorization_codes
                 WHERE device_code_hash = ?",
            )
            .bind(device_code_hash)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?;
            return match row {
                Some(row)
                    if parsed_col::<DeviceAuthStatus>(&row, "status")?
                        == DeviceAuthStatus::Redeemed =>
                {
                    Ok(DeviceCodeRedemption::AlreadyRedeemed {
                        session_id: col::<Option<SessionId>>(&row, "redeemed_session_id")?,
                    })
                }
                _ => Ok(DeviceCodeRedemption::NotAuthorized),
            };
        }
        super::auth::insert_refresh_token(&mut tx, refresh_token).await?;
        Self::commit_mutation(tx, &format!("session:{}", session.id), audit).await?;
        Ok(DeviceCodeRedemption::Redeemed)
    }

    pub(crate) async fn cleanup_expired_device_auth_codes_impl(
        &self,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        let result = sqlx::query(
            "DELETE FROM device_authorization_codes WHERE expires_at < ? AND status = 'pending'",
        )
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        if result.rows_affected() == 0 && audit.work.is_empty() {
            // Nothing expired and nothing owed: no action to record.
            return Ok(0);
        }
        Self::commit_mutation(tx, "device_auth:cleanup", audit).await?;
        Ok(result.rows_affected())
    }
}
