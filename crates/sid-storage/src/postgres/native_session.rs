// SPDX-License-Identifier: AGPL-3.0-only
//! Native session generations for the PostgreSQL backend. A rotation shares
//! its session's row, so the session cannot end under it: its end waits for
//! the rotation and then takes the successor too. It then locks its
//! generation's row, so concurrent rotations of one generation commit one
//! after another.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        MutationContext, NativeExchange, NativeGeneration, NativeGenerationState, NativePresented,
        NativeRotation, NativeRotationOutcome, SessionId,
    },
};
use sqlx::Row;

use super::PostgresBackend;

type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

fn storage(e: sqlx::Error) -> SidError {
    SidError::Storage(e.to_string())
}

/// Insert `generation` and its credentials in `tx`.
pub(super) async fn insert_generation(
    tx: &mut Tx<'_>,
    generation: &NativeGeneration,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO native_generations (id, session_id, key_jkt, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(generation.id)
    .bind(generation.session_id)
    .bind(&generation.key_jkt)
    .bind(generation.expires_at)
    .bind(generation.created_at)
    .execute(&mut **tx)
    .await
    .map_err(|e| super::insert_error("native generation", e))?;
    sqlx::query(
        "INSERT INTO native_credentials (credential_hash, generation_id)
         SELECT hash, $2 FROM unnest($1::bytea[]) AS hash",
    )
    .bind(&generation.credential_hashes)
    .bind(generation.id)
    .execute(&mut **tx)
    .await
    .map_err(|e| super::insert_error("native credential", e))?;
    Ok(())
}

/// Whether session `id` exists and has not expired, holding its row against
/// deletion until `tx` ends.
async fn hold_live_session(tx: &mut Tx<'_>, id: SessionId) -> SidResult<bool> {
    let live: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM sessions WHERE id = $1 AND expires_at > NOW() FOR SHARE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage)?;
    Ok(live.is_some())
}

pub(super) fn presented_row(row: &sqlx::postgres::PgRow) -> SidResult<NativePresented> {
    let get = |e: sqlx::Error| SidError::Storage(format!("native generation: {e}"));
    let exchange: Option<Vec<u8>> = row.try_get("exchange").map_err(get)?;
    let state = match exchange {
        None => NativeGenerationState::Current,
        Some(exchange) => NativeGenerationState::Rotated {
            exchange: NativeExchange::from_bytes(&exchange)
                .ok_or_else(|| SidError::Storage("column exchange: not 16 bytes".into()))?,
            successor: row
                .try_get::<Option<uuid::Uuid>, _>("successor_id")
                .map_err(get)?
                .ok_or_else(|| SidError::Storage("column successor_id: missing".into()))?,
            redeliver_until: row
                .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("redeliver_until")
                .map_err(get)?
                .ok_or_else(|| SidError::Storage("column redeliver_until: missing".into()))?,
            sealed: row.try_get("sealed").map_err(get)?,
        },
    };
    Ok(NativePresented {
        generation: row.try_get("id").map_err(get)?,
        session_id: row.try_get("session_id").map_err(get)?,
        key_jkt: row.try_get("key_jkt").map_err(get)?,
        expires_at: row.try_get("expires_at").map_err(get)?,
        state,
    })
}

impl PostgresBackend {
    pub(crate) async fn issue_native_generation_impl(
        &self,
        generation: &NativeGeneration,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.pool.begin().await.map_err(storage)?;
        if !hold_live_session(&mut tx, generation.session_id).await? {
            return Err(SidError::Fenced(
                "the session ended before its native generation".into(),
            ));
        }
        insert_generation(&mut tx, generation).await?;
        Self::audit_in_tx(&mut tx, &format!("session:{}", generation.session_id), ctx).await?;
        tx.commit().await.map_err(storage)
    }

    pub(crate) async fn native_generation_by_credential_impl(
        &self,
        hash: &[u8],
    ) -> SidResult<Option<NativePresented>> {
        let row = sqlx::query(
            "SELECT g.* FROM native_credentials c
             JOIN native_generations g ON g.id = c.generation_id
             WHERE c.credential_hash = $1",
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
        let mut tx = self.pool.begin().await.map_err(storage)?;
        // The session's row is held before the generation's, the order its
        // end takes them (the session, then the generations by cascade), so
        // a rotation and an end wait for each other instead of deadlocking.
        // A generation never changes its session.
        let session: Option<SessionId> =
            sqlx::query_scalar("SELECT session_id FROM native_generations WHERE id = $1")
                .bind(rotation.presented)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
        let Some(session) = session else {
            // The generation went with its session.
            return Ok(NativeRotationOutcome::Ended);
        };
        if !hold_live_session(&mut tx, session).await? {
            return Ok(NativeRotationOutcome::Ended);
        }
        let Some(row) = sqlx::query("SELECT * FROM native_generations WHERE id = $1 FOR UPDATE")
            .bind(rotation.presented)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?
        else {
            return Ok(NativeRotationOutcome::Ended);
        };
        let presented = presented_row(&row)?;
        match presented.state {
            NativeGenerationState::Current => {
                // Its predecessor's redelivery ends now that this one is used.
                sqlx::query("UPDATE native_generations SET sealed = NULL WHERE successor_id = $1")
                    .bind(rotation.presented)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage)?;
                sqlx::query(
                    "UPDATE native_generations
                     SET exchange = $2, successor_id = $3, redeliver_until = $4, sealed = $5
                     WHERE id = $1",
                )
                .bind(rotation.presented)
                .bind(rotation.exchange.as_bytes().as_slice())
                .bind(rotation.successor.id)
                .bind(rotation.redeliver_until)
                .bind(rotation.sealed)
                .execute(&mut *tx)
                .await
                .map_err(storage)?;
                insert_generation(&mut tx, rotation.successor).await?;
                Self::audit_in_tx(&mut tx, &format!("session:{}", presented.session_id), ctx)
                    .await?;
                tx.commit().await.map_err(storage)?;
                Ok(NativeRotationOutcome::Rotated)
            }
            NativeGenerationState::Rotated {
                exchange,
                redeliver_until,
                sealed: Some(sealed),
                ..
            } if exchange == rotation.exchange && chrono::Utc::now() < redeliver_until => {
                Ok(NativeRotationOutcome::Redeliver(sealed))
            }
            NativeGenerationState::Rotated { .. } => Ok(NativeRotationOutcome::Retired),
        }
    }
}
