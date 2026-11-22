// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's browser-facing settings for the PostgreSQL backend:
//! one JSON document, replaced only while it is still what the caller read.

use sid_core::models::{MutationContext, SessionEnd, WebSettings};
use sid_core::{Error as SidError, Result as SidResult};

use super::PostgresBackend;

/// The stored settings read on `executor`; none before they were set.
async fn stored<'e, E>(executor: E) -> SidResult<Option<WebSettings>>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT settings FROM web_settings WHERE scope = 'installation'")
            .fetch_optional(executor)
            .await
            .map_err(|e| SidError::Storage(format!("read web settings: {e}")))?;
    row.map(|(settings,)| {
        serde_json::from_value(settings)
            .map_err(|e| SidError::Storage(format!("stored web settings: {e}")))
    })
    .transpose()
}

impl PostgresBackend {
    pub(super) async fn web_settings_impl(&self) -> SidResult<Option<WebSettings>> {
        stored(&self.pool).await
    }

    pub(super) async fn set_web_settings_impl(
        &self,
        settings: &WebSettings,
        expected: Option<&WebSettings>,
        end_browser: Option<&SessionEnd>,
        mut ctx: MutationContext,
    ) -> SidResult<bool> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("write web settings: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        // One writer at a time, also while no row exists yet; readers are
        // not held. What is read below is what this write replaces.
        sqlx::query("LOCK TABLE web_settings IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        if stored(&mut *tx).await?.as_ref() != expected {
            return Ok(false);
        }
        let body = serde_json::to_value(settings)
            .map_err(|e| SidError::Internal(format!("encode web settings: {e}")))?;
        let revision = i64::try_from(settings.revision)
            .map_err(|_| SidError::Validation("web settings revision out of range".into()))?;
        sqlx::query(
            "INSERT INTO web_settings (scope, settings, revision, updated_at)
             VALUES ('installation', $1, $2, NOW())
             ON CONFLICT (scope) DO UPDATE SET
                 settings = EXCLUDED.settings,
                 revision = EXCLUDED.revision,
                 updated_at = NOW()",
        )
        .bind(body)
        .bind(revision)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        if let Some(end) = end_browser {
            // The browser sessions and the application sessions they signed
            // in: access derived from the formerly shared secret ends too.
            let ended = sqlx::query_as::<_, crate::pg_row::SessionRow>(
                "DELETE FROM sessions
                 WHERE browser_secret_hash IS NOT NULL
                    OR authenticated_by IN
                       (SELECT id FROM sessions WHERE browser_secret_hash IS NOT NULL)
                 RETURNING *",
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("end browser sessions: {e}")))?;
            for row in ended {
                ctx.work.extend(end.owed_by(&row.into_domain()?));
            }
        }
        Self::audit_in_tx(&mut tx, "installation:web_settings", ctx).await?;
        tx.commit().await.map_err(storage)?;
        Ok(true)
    }
}
