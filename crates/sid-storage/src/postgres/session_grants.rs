// SPDX-License-Identifier: AGPL-3.0-only
//! A session's grants as stored, for a move between stores: its refresh
//! tokens, the authorization codes it authorized and its native generations.
//! An import holds the session's row, so the session cannot end under it.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        AuthorizationCode, MutationContext, NativeGeneration, NativeGenerationState, SessionGrants,
        SessionId, StoredNativeGeneration,
    },
};
use sqlx::Row;

use super::PostgresBackend;
use super::native_session::{insert_generation, presented_row};

type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

fn storage(e: sqlx::Error) -> SidError {
    SidError::Storage(e.to_string())
}

/// Insert `code` in `tx` as given; an existing code hash is a `Conflict`.
pub(super) async fn insert_auth_code(tx: &mut Tx<'_>, code: &AuthorizationCode) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO authorization_codes (code_hash, profile_id, client_id, redirect_uri,
            scopes, code_challenge, nonce, expires_at, created_at, used, resource_id,
            authenticated_at, amr, assurance_level, elevation_level, elevation_until,
            authorizing_session_id, session_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)",
    )
    .bind(&code.code_hash)
    .bind(code.profile_id)
    .bind(&code.client_id)
    .bind(&code.redirect_uri)
    .bind(code.scopes.join(" "))
    .bind(&code.code_challenge)
    .bind(&code.nonce)
    .bind(code.expires_at)
    .bind(code.created_at)
    .bind(code.used)
    .bind(code.resource)
    .bind(code.authentication.authenticated_at)
    .bind(code.authentication.amr.join(" "))
    .bind(code.authentication.assurance_level.as_str())
    .bind(code.authentication.elevation.map(|e| e.level.as_str()))
    .bind(code.authentication.elevation.map(|e| e.until))
    .bind(code.authentication.session)
    .bind(code.session_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| match &e {
        // The authorizing session ended before the code was stored.
        sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
            SidError::NotFound(format!("session {}", code.authentication.session))
        }
        _ => super::insert_error("authorization code", e),
    })?;
    Ok(())
}

/// The credential hashes of generation `id`, in byte order.
async fn credential_hashes<'e, E>(executor: E, id: uuid::Uuid) -> SidResult<Vec<Vec<u8>>>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_scalar(
        "SELECT credential_hash FROM native_credentials WHERE generation_id = $1
         ORDER BY credential_hash",
    )
    .bind(id)
    .fetch_all(executor)
    .await
    .map_err(storage)
}

fn stored_generation(
    row: &sqlx::postgres::PgRow,
    credential_hashes: Vec<Vec<u8>>,
) -> SidResult<StoredNativeGeneration> {
    let presented = presented_row(row)?;
    Ok(StoredNativeGeneration {
        generation: NativeGeneration {
            id: presented.generation,
            session_id: presented.session_id,
            key_jkt: presented.key_jkt,
            credential_hashes,
            expires_at: presented.expires_at,
            created_at: row
                .try_get("created_at")
                .map_err(|e| SidError::Storage(format!("native generation: {e}")))?,
        },
        state: presented.state,
    })
}

/// `stored` is `given`, or nothing is stored under its key.
fn same<T: PartialEq>(stored: Option<T>, given: &T, what: &str) -> SidResult<bool> {
    match stored {
        None => Ok(false),
        Some(stored) if &stored == given => Ok(true),
        Some(_) => Err(SidError::Conflict(format!(
            "a different {what} is stored under the same key"
        ))),
    }
}

/// Insert generation `stored` in `tx`, with where it stands.
async fn insert_stored_generation(
    tx: &mut Tx<'_>,
    stored: &StoredNativeGeneration,
) -> SidResult<()> {
    insert_generation(tx, &stored.generation).await?;
    if let NativeGenerationState::Rotated {
        exchange,
        successor,
        redeliver_until,
        sealed,
    } = &stored.state
    {
        sqlx::query(
            "UPDATE native_generations
             SET exchange = $2, successor_id = $3, redeliver_until = $4, sealed = $5
             WHERE id = $1",
        )
        .bind(stored.generation.id)
        .bind(exchange.as_bytes().as_slice())
        .bind(successor)
        .bind(redeliver_until)
        .bind(sealed)
        .execute(&mut **tx)
        .await
        .map_err(storage)?;
    }
    Ok(())
}

impl PostgresBackend {
    pub(crate) async fn export_session_grants_impl(
        &self,
        id: SessionId,
    ) -> SidResult<SessionGrants> {
        let tokens = sqlx::query_as::<_, crate::pg_row::RefreshTokenRow>(
            "SELECT * FROM refresh_tokens WHERE session_id = $1 ORDER BY id",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        let codes = sqlx::query_as::<_, crate::pg_row::AuthCodeRow>(
            "SELECT * FROM authorization_codes WHERE authorizing_session_id = $1
             ORDER BY code_hash",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        let generations =
            sqlx::query("SELECT * FROM native_generations WHERE session_id = $1 ORDER BY id")
                .bind(id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage)?;
        let mut native_generations = Vec::with_capacity(generations.len());
        for row in &generations {
            let generation: uuid::Uuid = row.try_get("id").map_err(storage)?;
            let hashes = credential_hashes(&self.pool, generation).await?;
            native_generations.push(stored_generation(row, hashes)?);
        }
        Ok(SessionGrants {
            session: id,
            refresh_tokens: tokens.into_iter().map(|r| r.into_domain()).collect(),
            authorization_codes: codes
                .into_iter()
                .map(|r| r.into_domain())
                .collect::<SidResult<_>>()?,
            native_generations,
        })
    }

    pub(crate) async fn import_session_grants_impl(
        &self,
        grants: &SessionGrants,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        if grants
            .refresh_tokens
            .iter()
            .any(|t| t.session_id != grants.session)
            || grants
                .authorization_codes
                .iter()
                .any(|c| c.authentication.session != grants.session)
            || grants
                .native_generations
                .iter()
                .any(|g| g.generation.session_id != grants.session)
        {
            return Err(SidError::Validation(
                "a grant names another session than the one it moves with".into(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(storage)?;
        // The session is held first, the order its end takes its grants.
        let held: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM sessions WHERE id = $1 FOR SHARE")
                .bind(grants.session)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
        if held.is_none() {
            return Err(SidError::NotFound(format!("session {}", grants.session)));
        }
        let mut written = false;
        for token in &grants.refresh_tokens {
            let stored = sqlx::query_as::<_, crate::pg_row::RefreshTokenRow>(
                "SELECT * FROM refresh_tokens WHERE id = $1",
            )
            .bind(token.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?
            .map(|r| r.into_domain());
            if !same(stored, token, "refresh token")? {
                super::refresh_token::insert(&mut tx, token).await?;
                written = true;
            }
        }
        for code in &grants.authorization_codes {
            let stored = sqlx::query_as::<_, crate::pg_row::AuthCodeRow>(
                "SELECT * FROM authorization_codes WHERE code_hash = $1",
            )
            .bind(&code.code_hash)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?
            .map(|r| r.into_domain())
            .transpose()?;
            if !same(stored, code, "authorization code")? {
                insert_auth_code(&mut tx, code).await?;
                written = true;
            }
        }
        for generation in &grants.native_generations {
            let row = sqlx::query("SELECT * FROM native_generations WHERE id = $1")
                .bind(generation.generation.id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
            let stored = match &row {
                None => None,
                Some(row) => {
                    let hashes = credential_hashes(&mut *tx, generation.generation.id).await?;
                    Some(stored_generation(row, hashes)?)
                }
            };
            let mut given = generation.clone();
            given.generation.credential_hashes.sort();
            if !same(stored, &given, "native generation")? {
                insert_stored_generation(&mut tx, &given).await?;
                written = true;
            }
        }
        if !written {
            Self::unchanged_in_tx(tx, &ctx).await?;
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("session:{}", grants.session), ctx).await?;
        tx.commit().await.map_err(storage)?;
        Ok(true)
    }
}
