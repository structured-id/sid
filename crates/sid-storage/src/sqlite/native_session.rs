// SPDX-License-Identifier: AGPL-3.0-only
//! Native session generations for the SQLite backend: each write runs under
//! the database write lock (`BEGIN IMMEDIATE`), which serializes rotations of
//! one generation against each other and against its session's end.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        MutationContext, NativeExchange, NativeGeneration, NativeGenerationState, NativePresented,
        NativeRotation, NativeRotationOutcome,
    },
};

use super::{SqliteBackend, WriteTx, col, dt_col, dt_col_opt, fmt_dt, insert_error, uuid_col};

fn storage(e: sqlx::Error) -> SidError {
    SidError::Storage(e.to_string())
}

/// Insert `generation` and its credentials in `tx`.
pub(super) async fn insert_generation(
    tx: &mut WriteTx,
    generation: &NativeGeneration,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO native_generations (id, session_id, key_jkt, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(generation.id)
    .bind(generation.session_id)
    .bind(&generation.key_jkt)
    .bind(fmt_dt(&generation.expires_at))
    .bind(fmt_dt(&generation.created_at))
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("native generation", e))?;
    for hash in &generation.credential_hashes {
        sqlx::query(
            "INSERT INTO native_credentials (credential_hash, generation_id) VALUES (?, ?)",
        )
        .bind(hash)
        .bind(generation.id)
        .execute(&mut **tx)
        .await
        .map_err(|e| insert_error("native credential", e))?;
    }
    Ok(())
}

/// Whether session `id` exists and has not expired, read in `tx`.
async fn session_live(
    tx: &mut WriteTx,
    id: sid_core::models::SessionId,
    now: &str,
) -> SidResult<bool> {
    let live: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM sessions WHERE id = ? AND expires_at > ?")
            .bind(id)
            .bind(now)
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage)?;
    Ok(live.is_some())
}

pub(super) fn presented_row(row: &sqlx::sqlite::SqliteRow) -> SidResult<NativePresented> {
    let exchange: Option<Vec<u8>> = col(row, "exchange")?;
    let state = match exchange {
        None => NativeGenerationState::Current,
        Some(exchange) => NativeGenerationState::Rotated {
            exchange: NativeExchange::from_bytes(&exchange)
                .ok_or_else(|| SidError::Storage("column exchange: not 16 bytes".into()))?,
            successor: uuid_col(row, "successor_id")?,
            redeliver_until: dt_col_opt(row, "redeliver_until")?
                .ok_or_else(|| SidError::Storage("column redeliver_until: missing".into()))?,
            sealed: col(row, "sealed")?,
        },
    };
    Ok(NativePresented {
        generation: uuid_col(row, "id")?,
        session_id: col(row, "session_id")?,
        key_jkt: col(row, "key_jkt")?,
        expires_at: dt_col(row, "expires_at")?,
        state,
    })
}

impl SqliteBackend {
    pub(crate) async fn issue_native_generation_impl(
        &self,
        generation: &NativeGeneration,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        let now = fmt_dt(&chrono::Utc::now());
        if !session_live(&mut tx, generation.session_id, &now).await? {
            return Err(SidError::Fenced(
                "the session ended before its native generation".into(),
            ));
        }
        insert_generation(&mut tx, generation).await?;
        Self::commit_mutation(tx, &format!("session:{}", generation.session_id), ctx).await
    }

    pub(crate) async fn native_generation_by_credential_impl(
        &self,
        hash: &[u8],
    ) -> SidResult<Option<NativePresented>> {
        let row = sqlx::query(
            "SELECT g.* FROM native_credentials c
             JOIN native_generations g ON g.id = c.generation_id
             WHERE c.credential_hash = ?",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.as_ref().map(presented_row).transpose()
    }

    pub(crate) async fn rotate_native_generation_impl(
        &self,
        rotation: NativeRotation<'_>,
        ctx: MutationContext,
    ) -> SidResult<NativeRotationOutcome> {
        let mut tx = self.begin_write().await?;
        let now = chrono::Utc::now();
        let now_text = fmt_dt(&now);
        let Some(row) = sqlx::query("SELECT * FROM native_generations WHERE id = ?")
            .bind(rotation.presented)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?
        else {
            // The generation went with its session.
            return Ok(NativeRotationOutcome::Ended);
        };
        let presented = presented_row(&row)?;
        if !session_live(&mut tx, presented.session_id, &now_text).await? {
            return Ok(NativeRotationOutcome::Ended);
        }
        match presented.state {
            NativeGenerationState::Current => {
                // Its predecessor's redelivery ends now that this one is used.
                sqlx::query("UPDATE native_generations SET sealed = NULL WHERE successor_id = ?")
                    .bind(rotation.presented)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage)?;
                sqlx::query(
                    "UPDATE native_generations
                     SET exchange = ?, successor_id = ?, redeliver_until = ?, sealed = ?
                     WHERE id = ?",
                )
                .bind(rotation.exchange.as_bytes().as_slice())
                .bind(rotation.successor.id)
                .bind(fmt_dt(&rotation.redeliver_until))
                .bind(rotation.sealed)
                .bind(rotation.presented)
                .execute(&mut *tx)
                .await
                .map_err(storage)?;
                insert_generation(&mut tx, rotation.successor).await?;
                Self::commit_mutation(tx, &format!("session:{}", presented.session_id), ctx)
                    .await?;
                Ok(NativeRotationOutcome::Rotated)
            }
            NativeGenerationState::Rotated {
                exchange,
                redeliver_until,
                sealed: Some(sealed),
                ..
            } if exchange == rotation.exchange && now < redeliver_until => {
                Ok(NativeRotationOutcome::Redeliver(sealed))
            }
            NativeGenerationState::Rotated { .. } => Ok(NativeRotationOutcome::Retired),
        }
    }
}

#[cfg(test)]
mod tests;
