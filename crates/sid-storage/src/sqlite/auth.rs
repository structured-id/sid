// SPDX-License-Identifier: AGPL-3.0-only
//! RefreshToken, AuthorizationCode, and InitialAccessToken operations for SQLite backend.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        AuthCodeRedemption, AuthorizationCode, GrantAuthentication, InitialAccessToken,
        InitialAccessTokenId, MutationContext, ProjectId, RefreshToken, Session, SessionId,
    },
};
use uuid::Uuid;

use super::{SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, insert_error, uuid_col};

/// Space-separated words of a text column.
fn words(row: &sqlx::sqlite::SqliteRow, name: &str) -> SidResult<Vec<String>> {
    let raw: String = col(row, name)?;
    Ok(raw.split_whitespace().map(String::from).collect())
}

/// A stored count that must fit `u32`.
fn count_col(row: &sqlx::sqlite::SqliteRow, name: &str) -> SidResult<u32> {
    u32::try_from(col::<i64>(row, name)?)
        .map_err(|e| SidError::Storage(format!("column {name}: {e}")))
}

/// A malformed id or time is an error: a replacement read as none would hide
/// a refresh token's rotation from reuse detection.
fn row_to_refresh_token(row: &sqlx::sqlite::SqliteRow) -> SidResult<RefreshToken> {
    let replaced_by: Option<String> = col(row, "replaced_by")?;
    Ok(RefreshToken {
        id: uuid_col(row, "id")?,
        token_hash: col(row, "token_hash")?,
        session_id: col(row, "session_id")?,
        profile_id: col(row, "profile_id")?,
        client_id: col(row, "client_id")?,
        scopes: words(row, "scopes")?,
        resource: col(row, "resource_id")?,
        expires_at: dt_col(row, "expires_at")?,
        created_at: dt_col(row, "created_at")?,
        revoked: col(row, "revoked")?,
        replaced_by: replaced_by
            .map(|s| {
                Uuid::parse_str(&s)
                    .map_err(|e| SidError::Storage(format!("column replaced_by: {e}")))
            })
            .transpose()?,
        family_id: uuid_col(row, "family_id")?,
        grace_expires_at: dt_col_opt(row, "grace_expires_at")?,
        dpop_jkt: col(row, "dpop_jkt")?,
    })
}

fn row_to_auth_code(row: &sqlx::sqlite::SqliteRow) -> SidResult<AuthorizationCode> {
    Ok(AuthorizationCode {
        code_hash: col(row, "code_hash")?,
        profile_id: col(row, "profile_id")?,
        client_id: col(row, "client_id")?,
        redirect_uri: col(row, "redirect_uri")?,
        scopes: words(row, "scopes")?,
        resource: col(row, "resource_id")?,
        code_challenge: col(row, "code_challenge")?,
        nonce: col(row, "nonce")?,
        authentication: GrantAuthentication {
            session: col(row, "authorizing_session_id")?,
            authenticated_at: dt_col(row, "authenticated_at")?,
            amr: words(row, "amr")?,
            assurance_level: super::session::auth_level(
                "assurance_level",
                &col::<String>(row, "assurance_level")?,
            )?,
            elevation: super::session::elevation_col(row)?,
        },
        expires_at: dt_col(row, "expires_at")?,
        created_at: dt_col(row, "created_at")?,
        used: col(row, "used")?,
        session_id: col(row, "session_id")?,
    })
}

fn row_to_initial_access_token(row: &sqlx::sqlite::SqliteRow) -> SidResult<InitialAccessToken> {
    Ok(InitialAccessToken {
        id: InitialAccessTokenId(uuid_col(row, "id")?),
        project_id: ProjectId(uuid_col(row, "project_id")?),
        token_hash: col(row, "token_hash")?,
        max_clients: count_col(row, "max_clients")?,
        clients_registered: count_col(row, "clients_registered")?,
        allowed_scopes: words(row, "allowed_scopes")?,
        allowed_grant_types: words(row, "allowed_grant_types")?,
        allowed_redirect_patterns: words(row, "allowed_redirect_patterns")?,
        created_by: col(row, "created_by")?,
        revoked: col(row, "revoked")?,
        expires_at: dt_col(row, "expires_at")?,
        created_at: dt_col(row, "created_at")?,
    })
}

/// Insert `token` in `tx`; an existing id or token hash is a `Conflict`,
/// never an update (a revoked token stays revoked).
pub(super) async fn insert_refresh_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token: &RefreshToken,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO refresh_tokens (id, token_hash, session_id, profile_id, client_id, scopes,
            expires_at, created_at, revoked, replaced_by, family_id, grace_expires_at, dpop_jkt,
            resource_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(token.id.to_string())
    .bind(&token.token_hash)
    .bind(token.session_id)
    .bind(token.profile_id)
    .bind(&token.client_id)
    .bind(token.scopes.join(" "))
    .bind(fmt_dt(&token.expires_at))
    .bind(fmt_dt(&token.created_at))
    .bind(token.revoked)
    .bind(token.replaced_by.map(|u| u.to_string()))
    .bind(token.family_id.to_string())
    .bind(token.grace_expires_at.as_ref().map(fmt_dt))
    .bind(&token.dpop_jkt)
    .bind(token.resource)
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("refresh token", e))?;
    Ok(())
}

impl SqliteBackend {
    // === RefreshToken ===

    pub(crate) async fn create_refresh_token_impl(
        &self,
        token: &RefreshToken,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        insert_refresh_token(&mut tx, token).await?;
        Self::commit_mutation(tx, &format!("refresh_token:{}", token.id), audit).await
    }

    pub(crate) async fn get_refresh_token_by_hash_impl(
        &self,
        token_hash: &[u8],
    ) -> SidResult<Option<RefreshToken>> {
        let row = sqlx::query("SELECT * FROM refresh_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_refresh_token).transpose()
    }

    pub(crate) async fn revoke_refresh_tokens_by_session_impl(
        &self,
        session_id: SessionId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        // Tokens in a grace window are revoked too: the window ends with them.
        let mut tx = self.begin_write().await?;
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked = 1, grace_expires_at = NULL
             WHERE session_id = ? AND (revoked = 0 OR grace_expires_at IS NOT NULL)",
        )
        .bind(session_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("session:{session_id}"), audit).await?;
        Ok(result.rows_affected())
    }

    pub(crate) async fn revoke_refresh_tokens_by_family_impl(
        &self,
        family_id: Uuid,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked = 1, grace_expires_at = NULL
             WHERE family_id = ? AND (revoked = 0 OR grace_expires_at IS NOT NULL)",
        )
        .bind(family_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("token_family:{family_id}"), audit).await?;
        Ok(result.rows_affected())
    }

    pub(crate) async fn rotate_refresh_token_impl(
        &self,
        old_id: Uuid,
        new: &RefreshToken,
        grace_expires_at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let now = fmt_dt(&chrono::Utc::now());
        let mut tx = self.begin_write().await?;
        let rotated = sqlx::query(
            "UPDATE refresh_tokens SET revoked = 1, replaced_by = ?,
                grace_expires_at = COALESCE(grace_expires_at, ?)
             WHERE id = ? AND expires_at > ? AND (revoked = 0 OR grace_expires_at > ?)",
        )
        .bind(new.id.to_string())
        .bind(fmt_dt(&grace_expires_at))
        .bind(old_id.to_string())
        .bind(&now)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected()
            == 1;
        if !rotated {
            return Ok(false);
        }
        insert_refresh_token(&mut tx, new).await?;
        Self::commit_mutation(tx, &format!("token_family:{}", new.family_id), audit).await?;
        Ok(true)
    }

    // === AuthorizationCode ===

    pub(crate) async fn create_auth_code_impl(
        &self,
        code: &AuthorizationCode,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO authorization_codes (code_hash, profile_id, client_id, redirect_uri, scopes, code_challenge, nonce, expires_at, created_at, used, resource_id,
                authenticated_at, amr, assurance_level, elevation_level, elevation_until, authorizing_session_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&code.code_hash).bind(code.profile_id)
        .bind(&code.client_id)
        .bind(&code.redirect_uri)
        .bind(code.scopes.join(" "))
        .bind(&code.code_challenge)
        .bind(&code.nonce)
        .bind(fmt_dt(&code.expires_at))
        .bind(fmt_dt(&code.created_at))
        .bind(code.used)
        .bind(code.resource)
        .bind(fmt_dt(&code.authentication.authenticated_at))
        .bind(code.authentication.amr.join(" "))
        .bind(code.authentication.assurance_level.as_str())
        .bind(code.authentication.elevation.map(|e| e.level.as_str()))
        .bind(code.authentication.elevation.map(|e| fmt_dt(&e.until)))
        .bind(code.authentication.session)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("authorization code", e))?;
        Self::commit_mutation(tx, &format!("auth_code:{}", code.client_id), audit).await
    }

    pub(crate) async fn get_auth_code_by_hash_impl(
        &self,
        code_hash: &[u8],
    ) -> SidResult<Option<AuthorizationCode>> {
        let row = sqlx::query("SELECT * FROM authorization_codes WHERE code_hash = ?")
            .bind(code_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_auth_code).transpose()
    }

    pub(crate) async fn redeem_auth_code_impl(
        &self,
        code_hash: &[u8],
        session: &Session,
        refresh_token: &RefreshToken,
        audit: MutationContext,
    ) -> SidResult<AuthCodeRedemption> {
        // The write lock is taken up front, so two redemptions are
        // serialized and the second sees `used = 1`.
        let mut tx = self.begin_write().await?;

        let redeemed = sqlx::query(
            "UPDATE authorization_codes SET used = 1, session_id = ?
             WHERE code_hash = ? AND used = 0",
        )
        .bind(session.id)
        .bind(code_hash)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected()
            == 1;
        if !redeemed {
            let row = sqlx::query("SELECT session_id FROM authorization_codes WHERE code_hash = ?")
                .bind(code_hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
            let session_id = match row {
                Some(row) => col(&row, "session_id")?,
                None => None,
            };
            return Ok(AuthCodeRedemption::AlreadyRedeemed { session_id });
        }

        super::session::insert_session(&mut *tx, session).await?;
        insert_refresh_token(&mut tx, refresh_token).await?;
        Self::commit_mutation(tx, &format!("session:{}", session.id), audit).await?;
        Ok(AuthCodeRedemption::Redeemed)
    }

    // === InitialAccessToken ===

    pub(crate) async fn create_initial_access_token_impl(
        &self,
        token: &InitialAccessToken,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO initial_access_tokens (id, project_id, token_hash, max_clients, clients_registered, allowed_scopes, allowed_grant_types, allowed_redirect_patterns, created_by, revoked, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(token.id.0.to_string())
        .bind(token.project_id.0.to_string())
        .bind(&token.token_hash)
        .bind(i64::from(token.max_clients))
        .bind(i64::from(token.clients_registered))
        .bind(token.allowed_scopes.join(" "))
        .bind(token.allowed_grant_types.join(" "))
        .bind(token.allowed_redirect_patterns.join(" "))
        .bind(&token.created_by)
        .bind(token.revoked)
        .bind(fmt_dt(&token.expires_at))
        .bind(fmt_dt(&token.created_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("initial access token", e))?;
        Self::commit_mutation(tx, &format!("iat:{}", token.id.0), audit).await
    }

    pub(crate) async fn get_initial_access_token_impl(
        &self,
        id: InitialAccessTokenId,
    ) -> SidResult<Option<InitialAccessToken>> {
        let row = sqlx::query("SELECT * FROM initial_access_tokens WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_initial_access_token).transpose()
    }

    pub(crate) async fn get_initial_access_token_by_hash_impl(
        &self,
        token_hash: &[u8],
    ) -> SidResult<Option<InitialAccessToken>> {
        let row = sqlx::query("SELECT * FROM initial_access_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_initial_access_token).transpose()
    }

    pub(crate) async fn list_initial_access_tokens_by_project_impl(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Vec<InitialAccessToken>> {
        let rows = sqlx::query("SELECT * FROM initial_access_tokens WHERE project_id = ?")
            .bind(project_id.0.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_initial_access_token).collect()
    }

    pub(crate) async fn revoke_initial_access_token_impl(
        &self,
        id: InitialAccessTokenId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        let revoked = sqlx::query("UPDATE initial_access_tokens SET revoked = 1 WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?
            .rows_affected();
        if revoked == 0 {
            return Err(SidError::NotFound(format!("initial access token {}", id.0)));
        }
        Self::commit_mutation(tx, &format!("iat:{}", id.0), audit).await
    }
}
