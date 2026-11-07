// SPDX-License-Identifier: AGPL-3.0-only
//! A session's grants as stored, for a move between stores: its refresh
//! tokens, the authorization codes it authorized and its native generations.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        MutationContext, NativeGeneration, NativeGenerationState, SessionGrants, SessionId,
        StoredNativeGeneration,
    },
};

use super::auth::{insert_auth_code, insert_refresh_token, row_to_auth_code, row_to_refresh_token};
use super::native_session::{insert_generation, presented_row};
use super::{SqliteBackend, WriteTx, dt_col, fmt_dt};

fn storage(e: sqlx::Error) -> SidError {
    SidError::Storage(e.to_string())
}

/// The credential hashes of generation `id`, in byte order.
async fn credential_hashes<'e, E>(executor: E, id: uuid::Uuid) -> SidResult<Vec<Vec<u8>>>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query_scalar(
        "SELECT credential_hash FROM native_credentials WHERE generation_id = ?
         ORDER BY credential_hash",
    )
    .bind(id)
    .fetch_all(executor)
    .await
    .map_err(storage)
}

fn stored_generation(
    row: &sqlx::sqlite::SqliteRow,
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
            created_at: dt_col(row, "created_at")?,
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
    tx: &mut WriteTx,
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
             SET exchange = ?, successor_id = ?, redeliver_until = ?, sealed = ?
             WHERE id = ?",
        )
        .bind(exchange.as_bytes().as_slice())
        .bind(successor)
        .bind(fmt_dt(redeliver_until))
        .bind(sealed)
        .bind(stored.generation.id)
        .execute(&mut **tx)
        .await
        .map_err(storage)?;
    }
    Ok(())
}

impl SqliteBackend {
    pub(crate) async fn export_session_grants_impl(
        &self,
        id: SessionId,
    ) -> SidResult<SessionGrants> {
        let tokens = sqlx::query("SELECT * FROM refresh_tokens WHERE session_id = ? ORDER BY id")
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage)?;
        let codes = sqlx::query(
            "SELECT * FROM authorization_codes WHERE authorizing_session_id = ?
             ORDER BY code_hash",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        let generations =
            sqlx::query("SELECT * FROM native_generations WHERE session_id = ? ORDER BY id")
                .bind(id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage)?;
        let mut native_generations = Vec::with_capacity(generations.len());
        for row in &generations {
            let hashes = credential_hashes(&self.pool, super::uuid_col(row, "id")?).await?;
            native_generations.push(stored_generation(row, hashes)?);
        }
        Ok(SessionGrants {
            session: id,
            refresh_tokens: tokens
                .iter()
                .map(row_to_refresh_token)
                .collect::<SidResult<_>>()?,
            authorization_codes: codes
                .iter()
                .map(row_to_auth_code)
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
        let mut tx = self.begin_write().await?;
        let held: Option<i64> = sqlx::query_scalar("SELECT 1 FROM sessions WHERE id = ?")
            .bind(grants.session)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?;
        if held.is_none() {
            return Err(SidError::NotFound(format!("session {}", grants.session)));
        }
        let mut written = false;
        for token in &grants.refresh_tokens {
            let stored = sqlx::query("SELECT * FROM refresh_tokens WHERE id = ?")
                .bind(token.id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
            let stored = stored.as_ref().map(row_to_refresh_token).transpose()?;
            if !same(stored, token, "refresh token")? {
                insert_refresh_token(&mut tx, token).await?;
                written = true;
            }
        }
        for code in &grants.authorization_codes {
            let stored = sqlx::query("SELECT * FROM authorization_codes WHERE code_hash = ?")
                .bind(&code.code_hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
            let stored = stored.as_ref().map(row_to_auth_code).transpose()?;
            if !same(stored, code, "authorization code")? {
                insert_auth_code(&mut tx, code).await?;
                written = true;
            }
        }
        for generation in &grants.native_generations {
            let row = sqlx::query("SELECT * FROM native_generations WHERE id = ?")
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
            Self::commit_unchanged(tx, &ctx).await?;
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("session:{}", grants.session), ctx).await?;
        Ok(true)
    }
}
