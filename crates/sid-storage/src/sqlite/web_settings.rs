// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's browser-facing settings for the SQLite backend: one
//! JSON document, replaced under the single writer's transaction only while
//! it is still what the caller read.

use sid_core::models::{MutationContext, SessionEnd, WebSettings};
use sid_core::{Error as SidError, Result as SidResult};

use super::SqliteBackend;
use super::session::row_to_session;

/// The stored settings read on `executor`; none before they were set.
async fn stored<'e, E>(executor: E) -> SidResult<Option<WebSettings>>
where
    E: sqlx::SqliteExecutor<'e>,
{
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT settings FROM web_settings WHERE scope = 'installation'")
            .fetch_optional(executor)
            .await
            .map_err(|e| SidError::Storage(format!("read web settings: {e}")))?;
    row.map(|(settings,)| {
        serde_json::from_slice(&settings)
            .map_err(|e| SidError::Storage(format!("stored web settings: {e}")))
    })
    .transpose()
}

impl SqliteBackend {
    pub(crate) async fn web_settings_impl(&self) -> SidResult<Option<WebSettings>> {
        stored(&self.pool).await
    }

    pub(crate) async fn set_web_settings_impl(
        &self,
        settings: &WebSettings,
        expected: Option<&WebSettings>,
        end_browser: Option<&SessionEnd>,
        mut ctx: MutationContext,
    ) -> SidResult<bool> {
        // The write lock is held from here: what is read below is what this
        // write replaces.
        let mut tx = self.begin_write().await?;
        if stored(&mut *tx).await?.as_ref() != expected {
            return Ok(false);
        }
        let body = serde_json::to_vec(settings)
            .map_err(|e| SidError::Internal(format!("encode web settings: {e}")))?;
        let revision = i64::try_from(settings.revision)
            .map_err(|_| SidError::Validation("web settings revision out of range".into()))?;
        sqlx::query(
            "INSERT INTO web_settings (scope, settings, revision, updated_at)
             VALUES ('installation', ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             ON CONFLICT (scope) DO UPDATE SET
                 settings = excluded.settings,
                 revision = excluded.revision,
                 updated_at = excluded.updated_at",
        )
        .bind(body)
        .bind(revision)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("write web settings: {e}")))?;
        if let Some(end) = end_browser {
            // The browser sessions and the application sessions they signed
            // in: access derived from the formerly shared secret ends too.
            let ended = sqlx::query(
                "DELETE FROM sessions
                 WHERE browser_secret_hash IS NOT NULL
                    OR authenticated_by IN
                       (SELECT id FROM sessions WHERE browser_secret_hash IS NOT NULL)
                 RETURNING *",
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("end browser sessions: {e}")))?;
            for row in &ended {
                ctx.work.extend(end.owed_by(&row_to_session(row)?));
            }
        }
        Self::commit_mutation(tx, "installation:web_settings", ctx).await?;
        Ok(true)
    }
}
