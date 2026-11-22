// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's browser-facing settings in CoordiNode: one node holding
//! the JSON document, replaced only while it is still what the caller read.

use sid_core::models::{MutationContext, SessionEnd, WebSettings};
use sid_core::{Error as SidError, Result as SidResult};

use super::{CoordinodeBackend, Params, hold_first};

/// The one scope web settings are stored for.
fn scope() -> coordinode_core::graph::types::Value {
    coordinode_core::graph::types::Value::String("installation".into())
}

/// The stored settings of `row`, read as `s.settings AS settings`.
fn stored(row: &super::Row) -> SidResult<WebSettings> {
    serde_json::from_slice(&super::get_bytes(row, "settings")?)
        .map_err(|e| SidError::Storage(format!("stored web settings: {e}")))
}

/// The values of `settings` as a write binds them.
fn values(settings: &WebSettings) -> SidResult<Params> {
    use coordinode_core::graph::types::Value;
    let body = serde_json::to_vec(settings)
        .map_err(|e| SidError::Internal(format!("encode web settings: {e}")))?;
    let revision = i64::try_from(settings.revision)
        .map_err(|_| SidError::Validation("web settings revision out of range".into()))?;
    Ok(Params::default()
        .with("scope", scope())
        .with("settings", Value::Binary(body))
        .with("revision", Value::Int(revision))
        .with("now", super::time(jiff::Timestamp::now())))
}

impl CoordinodeBackend {
    pub(super) async fn web_settings(&self) -> SidResult<Option<WebSettings>> {
        self.read(|tx| {
            let rows = tx.run(
                "MATCH (s:SidWebSettings) WHERE s.scope = $scope RETURN s.settings AS settings",
                Params::default().with("scope", scope()),
            )?;
            rows.first().map(stored).transpose()
        })
        .await
    }

    pub(super) async fn set_web_settings(
        &self,
        settings: &WebSettings,
        expected: Option<&WebSettings>,
        end_browser: Option<&SessionEnd>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let settings = settings.clone();
        let expected = expected.cloned();
        let end_browser = end_browser.cloned();
        self.transaction(move |tx| {
            // The stored settings, held for the commit: a write committed
            // meanwhile conflicts with this one.
            let rows = tx.run(
                "MATCH (s:SidWebSettings) WHERE s.scope = $scope
                 RETURN id(s) AS node, s.settings AS settings",
                Params::default().with("scope", scope()),
            )?;
            let held = rows.first().map(stored).transpose()?;
            if held != expected || (held.is_some() && !hold_first(tx, &rows)?) {
                return Ok(super::Decision::Abandon(false));
            }
            let updated = tx.run(
                "MATCH (s:SidWebSettings) WHERE s.scope = $scope
                 SET s.settings = $settings, s.revision = $revision, s.updated_at = $now
                 RETURN s.scope AS scope",
                values(&settings)?,
            )?;
            if updated.is_empty() {
                // Another first write may have created the node since this
                // transaction looked: it then runs again, finds settings it
                // did not expect and writes nothing.
                tx.create_absent(
                    "CREATE (s:SidWebSettings {scope: $scope, settings: $settings,
                         revision: $revision, updated_at: $now})",
                    values(&settings)?,
                )?;
            }
            let mut ctx = ctx.clone();
            if let Some(end) = &end_browser {
                super::session::end_browser_sessions(tx, end, &mut ctx)?;
            }
            super::finalize(tx, "installation:web_settings", ctx)?;
            Ok(super::Decision::Commit(true))
        })
        .await
    }
}
