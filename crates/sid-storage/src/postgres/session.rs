// SPDX-License-Identifier: AGPL-3.0-only
//! Writing a session row: one statement for every path that stores one.

use sid_core::models::{Session, SessionAuthentication, SessionId};
use sid_core::{Error as SidError, Result as SidResult};

/// Insert `session` in `tx`; an existing session with its id is a
/// `Conflict`, never replaced.
pub(super) async fn write(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    session: &Session,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO sessions (
            id, profile_id, client_id, device_id, ip_address, user_agent,
            scopes, assurance_level, elevation_level, elevation_until,
            authenticated_at, amr, is_provisional, passkey_prompt, policy_grace,
            grace_deadline, created_at, expires_at, last_activity_at, browser_secret_hash,
            authenticated_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)",
    )
    .bind(session.id)
    .bind(session.profile_id)
    .bind(&session.client_id)
    .bind(session.device_id)
    .bind(&session.ip_address)
    .bind(&session.user_agent)
    .bind(session.scopes_string())
    .bind(session.assurance_level.as_str())
    .bind(session.elevation.map(|e| e.level.as_str()))
    .bind(session.elevation.map(|e| e.until))
    .bind(session.authenticated_at)
    .bind(session.amr.join(" "))
    .bind(session.is_provisional)
    .bind(session.passkey_prompt)
    .bind(session.policy_grace)
    .bind(session.grace_deadline)
    .bind(session.created_at)
    .bind(session.expires_at)
    .bind(session.last_activity_at)
    .bind(session.browser_secret_hash.map(|h| h.as_bytes().to_vec()))
    .bind(session.authenticated_by)
    .execute(&mut **tx)
    .await
    .map_err(|e| super::insert_error("session", e))?;
    Ok(())
}

/// Delete session `id` and the sessions it authenticated in `tx`; returns
/// every session ended.
pub(super) async fn end_with_dependents(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: SessionId,
) -> SidResult<Vec<Session>> {
    sqlx::query_as::<_, crate::pg_row::SessionRow>(
        "DELETE FROM sessions WHERE id = $1 OR authenticated_by = $1 RETURNING *",
    )
    .bind(id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("end session: {e}")))?
    .into_iter()
    .map(crate::pg_row::SessionRow::into_domain)
    .collect()
}

/// Write `new` over the authentication of session `id` while the stored one
/// equals `expected` and the session has not expired; true when it did.
pub(super) async fn record_authentication(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: SessionId,
    expected: &SessionAuthentication,
    new: &SessionAuthentication,
) -> SidResult<bool> {
    let applied = sqlx::query(
        "UPDATE sessions SET assurance_level = $6, elevation_level = $7, elevation_until = $8,
            authenticated_at = $9, amr = $10
         WHERE id = $1 AND expires_at > NOW()
           AND assurance_level = $2
           AND elevation_level IS NOT DISTINCT FROM $3
           AND elevation_until IS NOT DISTINCT FROM $4
           AND authenticated_at = $5 AND amr = $11",
    )
    .bind(id)
    .bind(expected.assurance_level.as_str())
    .bind(expected.elevation.map(|e| e.level.as_str()))
    .bind(expected.elevation.map(|e| e.until))
    .bind(expected.authenticated_at)
    .bind(new.assurance_level.as_str())
    .bind(new.elevation.map(|e| e.level.as_str()))
    .bind(new.elevation.map(|e| e.until))
    .bind(new.authenticated_at)
    .bind(new.amr.join(" "))
    .bind(expected.amr.join(" "))
    .execute(&mut **tx)
    .await
    .map_err(|e| SidError::Storage(format!("record session authentication: {e}")))?
    .rows_affected()
        == 1;
    Ok(applied)
}
