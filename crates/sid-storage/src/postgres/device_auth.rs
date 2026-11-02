// SPDX-License-Identifier: AGPL-3.0-only
//! Device authorization requests (RFC 8628).

use chrono::Utc;
use sid_core::models::{
    DeviceAuthCodeId, DeviceAuthDecision, DeviceAuthorizationCode, DeviceCodeRedemption,
    DevicePoll, MutationContext, RefreshToken, Session, SessionId,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::PostgresBackend;

/// RFC 8628 §3.5: each slow_down adds 5 seconds to the polling interval.
const SLOW_DOWN_STEP_SECS: i32 = 5;

fn storage(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

impl PostgresBackend {
    pub(super) async fn create_device_auth_code_impl(
        &self,
        code: &DeviceAuthorizationCode,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        sqlx::query(
            "INSERT INTO device_authorization_codes (id, client_id, device_code_hash, user_code,
                scope, project_id, expires_at, interval_secs, status,
                authorized_by, authorized_at, last_polled_at, created_at, redeemed_session_id,
                resource_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
        )
        .bind(code.id.0)
        .bind(&code.client_id)
        .bind(&code.device_code_hash)
        .bind(&code.user_code)
        .bind(code.scope.as_deref())
        .bind(code.project_id.0)
        .bind(code.expires_at)
        .bind(code.interval)
        .bind(code.status.as_str())
        .bind(code.authorized_by)
        .bind(code.authorized_at)
        .bind(code.last_polled_at)
        .bind(code.created_at)
        .bind(code.redeemed_session_id)
        .bind(code.resource)
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("device authorization", e))?;
        Self::audit_in_tx(&mut tx, &format!("device_auth:{}", code.id.0), ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(())
    }

    pub(super) async fn decide_device_auth_impl(
        &self,
        id: DeviceAuthCodeId,
        decision: DeviceAuthDecision,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let (status, authorized_by) = match decision {
            DeviceAuthDecision::Authorize(profile_id) => ("authorized", Some(profile_id)),
            DeviceAuthDecision::Deny => ("denied", None),
        };
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        let decided = sqlx::query(
            "UPDATE device_authorization_codes SET status = $2, authorized_by = $3,
                authorized_at = CASE WHEN $3::UUID IS NULL THEN NULL ELSE NOW() END
             WHERE id = $1 AND status = 'pending' AND expires_at > NOW()",
        )
        .bind(id.0)
        .bind(status)
        .bind(authorized_by)
        .execute(&mut *tx)
        .await
        .map_err(storage("decide device authorization"))?
        .rows_affected()
            == 1;
        if !decided {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("device_auth:{}", id.0), ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(true)
    }

    pub(super) async fn record_device_poll_impl(
        &self,
        id: DeviceAuthCodeId,
        ctx: MutationContext,
    ) -> SidResult<DevicePoll> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        // The row lock orders concurrent polls: each sees the previous one's time.
        let (last, interval): (Option<chrono::DateTime<Utc>>, i32) = sqlx::query_as(
            "SELECT last_polled_at, interval_secs FROM device_authorization_codes
             WHERE id = $1 FOR UPDATE",
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage("read device poll"))?
        .ok_or_else(|| SidError::NotFound(format!("device authorization {}", id.0)))?;
        let now = Utc::now();
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
            "UPDATE device_authorization_codes SET last_polled_at = $2, interval_secs = $3
             WHERE id = $1",
        )
        .bind(id.0)
        .bind(now)
        .bind(interval)
        .execute(&mut *tx)
        .await
        .map_err(storage("record device poll"))?;
        Self::audit_in_tx(&mut tx, &format!("device_auth:{}", id.0), ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(poll)
    }

    pub(super) async fn redeem_device_code_impl(
        &self,
        device_code_hash: &[u8],
        session: &Session,
        refresh_token: &RefreshToken,
        ctx: MutationContext,
    ) -> SidResult<DeviceCodeRedemption> {
        let mut tx = self.pool.begin().await.map_err(storage("begin"))?;
        // The session goes first (the code references it); a redemption that
        // does not apply rolls it back with the transaction.
        super::session::write(&mut tx, session).await?;
        // The conditional update decides a race: every other redemption waits
        // on the row lock, then finds the code redeemed and updates nothing.
        let redeemed = sqlx::query(
            "UPDATE device_authorization_codes SET status = 'redeemed', redeemed_session_id = $2
             WHERE device_code_hash = $1 AND status = 'authorized' AND expires_at > NOW()",
        )
        .bind(device_code_hash)
        .bind(session.id)
        .execute(&mut *tx)
        .await
        .map_err(storage("redeem device code"))?
        .rows_affected()
            == 1;
        if !redeemed {
            let row: Option<(String, Option<SessionId>)> = sqlx::query_as(
                "SELECT status, redeemed_session_id FROM device_authorization_codes
                 WHERE device_code_hash = $1",
            )
            .bind(device_code_hash)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage("read device code"))?;
            return Ok(match row {
                Some((status, session_id)) if status == "redeemed" => {
                    DeviceCodeRedemption::AlreadyRedeemed { session_id }
                }
                _ => DeviceCodeRedemption::NotAuthorized,
            });
        }
        super::refresh_token::insert(&mut tx, refresh_token).await?;
        Self::audit_in_tx(&mut tx, &format!("profile:{}", session.profile_id), ctx).await?;
        tx.commit().await.map_err(storage("commit"))?;
        Ok(DeviceCodeRedemption::Redeemed)
    }
}
