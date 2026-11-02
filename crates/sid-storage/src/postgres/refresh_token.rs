// SPDX-License-Identifier: AGPL-3.0-only
//! Writing a refresh token row: one statement for every path that stores one.

use sid_core::Result as SidResult;
use sid_core::models::RefreshToken;

/// Insert `token` in `tx`; an existing id or token hash is a `Conflict`.
pub(super) async fn insert(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token: &RefreshToken,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO refresh_tokens (id, token_hash, session_id, profile_id, client_id,
            scopes, expires_at, created_at, revoked, replaced_by, family_id, grace_expires_at,
            dpop_jkt, resource_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(token.id)
    .bind(&token.token_hash)
    .bind(token.session_id)
    .bind(token.profile_id)
    .bind(&token.client_id)
    .bind(token.scopes.join(" "))
    .bind(token.expires_at)
    .bind(token.created_at)
    .bind(token.revoked)
    .bind(token.replaced_by)
    .bind(token.family_id)
    .bind(token.grace_expires_at)
    .bind(&token.dpop_jkt)
    .bind(token.resource)
    .execute(&mut **tx)
    .await
    .map_err(|e| super::insert_error("refresh token", e))?;
    Ok(())
}
