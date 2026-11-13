// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's login-policy epoch in CoordiNode: one node, advanced
//! by every policy write of the host and held by every session or code
//! decided under a policy, so a policy write committed meanwhile refuses it.

use coordinode_embed::TransactionId;
use sid_core::{Error as SidError, Result as SidResult};

use super::{CoordinodeBackend, Params, Statements, get_int, hold_first, storage};

/// Fail with `Fenced` unless the login-policy epoch is still `epoch`; the
/// epoch is held for the commit.
pub(super) fn check_fence(tx: &Statements<'_>, epoch: i64) -> SidResult<()> {
    let rows = tx.run(
        "MATCH (e:SidLoginPolicyEpoch) WHERE e.id = 1 RETURN id(e) AS node, e.epoch AS epoch",
        Params::default(),
    )?;
    let current = rows.first().map(|row| get_int(row, "epoch")).transpose()?;
    if current != Some(epoch) || !hold_first(tx, &rows)? {
        return Err(SidError::Fenced(
            "the login policy changed since it was read".into(),
        ));
    }
    Ok(())
}

/// The one scope login settings are stored for.
fn settings_scope() -> coordinode_core::graph::types::Value {
    coordinode_core::graph::types::Value::String("installation".into())
}

impl CoordinodeBackend {
    /// Advance the login-policy epoch in `tx`, a transaction of the host's
    /// policy write on this database, and return the new epoch: decisions
    /// taken under the earlier one no longer commit. The first write starts
    /// it at 1. Blocks the calling thread, as the host's own statements do.
    pub fn advance_login_policy_epoch_in(&self, tx: TransactionId) -> SidResult<i64> {
        let run = |query: &str| {
            self.db
                .execute_in_transaction(tx, query, Some(Params::default().0))
                .map_err(storage)
        };
        let advanced = run(
            "MATCH (e:SidLoginPolicyEpoch) WHERE e.id = 1 SET e.epoch = e.epoch + 1
             RETURN e.epoch AS epoch",
        )?;
        let rows = if advanced.is_empty() {
            // Concurrent first writes create one unique node: all but one
            // commit conflict.
            run("CREATE (e:SidLoginPolicyEpoch {id: 1, epoch: 1}) RETURN e.epoch AS epoch")?
        } else {
            advanced
        };
        rows.first()
            .map(|row| get_int(row, "epoch"))
            .transpose()?
            .ok_or_else(|| SidError::Storage("login policy epoch not written".into()))
    }

    /// The current login-policy epoch; none before any policy write.
    pub async fn login_policy_epoch(&self) -> SidResult<Option<i64>> {
        self.read(|tx| {
            let rows = tx.run(
                "MATCH (e:SidLoginPolicyEpoch) WHERE e.id = 1 RETURN e.epoch AS epoch",
                Params::default(),
            )?;
            rows.first().map(|row| get_int(row, "epoch")).transpose()
        })
        .await
    }

    pub(super) async fn login_settings(
        &self,
    ) -> SidResult<Option<sid_core::models::LoginSettings>> {
        self.read(|tx| {
            let rows = tx.run(
                "MATCH (s:SidLoginSettings) WHERE s.scope = $scope
                 RETURN s.allow_personal_profiles AS personal,
                        s.allow_foreign_corporate_profiles AS corporate",
                Params::default().with("scope", settings_scope()),
            )?;
            rows.first()
                .map(|row| {
                    Ok(sid_core::models::LoginSettings {
                        allow_personal_profiles: super::get_bool(row, "personal")?,
                        allow_foreign_corporate_profiles: super::get_bool(row, "corporate")?,
                    })
                })
                .transpose()
        })
        .await
    }

    pub(super) async fn set_login_settings(
        &self,
        settings: &sid_core::models::LoginSettings,
        expected: Option<&sid_core::models::LoginSettings>,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        use coordinode_core::graph::types::Value;
        let settings = *settings;
        let expected = expected.copied();
        self.transaction(move |tx| {
            // The stored settings, held for the commit: a write committed
            // meanwhile conflicts with this one.
            let rows = tx.run(
                "MATCH (s:SidLoginSettings) WHERE s.scope = $scope
                 RETURN id(s) AS node, s.allow_personal_profiles AS personal,
                        s.allow_foreign_corporate_profiles AS corporate",
                Params::default().with("scope", settings_scope()),
            )?;
            let stored = rows
                .first()
                .map(|row| {
                    Ok::<_, SidError>(sid_core::models::LoginSettings {
                        allow_personal_profiles: super::get_bool(row, "personal")?,
                        allow_foreign_corporate_profiles: super::get_bool(row, "corporate")?,
                    })
                })
                .transpose()?;
            if stored != expected || (stored.is_some() && !hold_first(tx, &rows)?) {
                return Ok(super::Decision::Abandon(false));
            }
            let values = || {
                Params::default()
                    .with("scope", settings_scope())
                    .with("personal", Value::Bool(settings.allow_personal_profiles))
                    .with(
                        "corporate",
                        Value::Bool(settings.allow_foreign_corporate_profiles),
                    )
                    .with("now", super::time(chrono::Utc::now()))
            };
            let updated = tx.run(
                "MATCH (s:SidLoginSettings) WHERE s.scope = $scope
                 SET s.allow_personal_profiles = $personal,
                     s.allow_foreign_corporate_profiles = $corporate, s.updated_at = $now
                 RETURN s.scope AS scope",
                values(),
            )?;
            if updated.is_empty() {
                // Concurrent first writes create one unique node: all but one
                // commit conflict.
                tx.run(
                    "CREATE (s:SidLoginSettings {scope: $scope,
                         allow_personal_profiles: $personal,
                         allow_foreign_corporate_profiles: $corporate, updated_at: $now})",
                    values(),
                )?;
            }
            // A sign-in decided under the earlier settings no longer commits.
            let advanced = tx.run(
                "MATCH (e:SidLoginPolicyEpoch) WHERE e.id = 1 SET e.epoch = e.epoch + 1
                 RETURN e.epoch AS epoch",
                Params::default(),
            )?;
            if advanced.is_empty() {
                tx.run(
                    "CREATE (e:SidLoginPolicyEpoch {id: 1, epoch: 1})",
                    Params::default(),
                )?;
            }
            super::finalize(tx, "installation:login_settings", ctx.clone())?;
            Ok(super::Decision::Commit(true))
        })
        .await
    }

    pub(super) async fn import_login_policy_epoch(
        &self,
        epoch: i64,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        self.transaction(move |tx| {
            let rows = tx.run(
                "MATCH (e:SidLoginPolicyEpoch) WHERE e.id = 1 RETURN e.epoch AS epoch",
                Params::default(),
            )?;
            if let Some(row) = rows.first() {
                return crate::transfer_repeat(
                    &get_int(row, "epoch")?,
                    &epoch,
                    "login policy epoch",
                )
                .map(super::Decision::Abandon);
            }
            // Concurrent importers meet on the unique node.
            tx.run(
                "CREATE (e:SidLoginPolicyEpoch {id: 1, epoch: $epoch})",
                Params::default().with("epoch", coordinode_core::graph::types::Value::Int(epoch)),
            )?;
            super::finalize(tx, "installation:login_policy", ctx.clone())?;
            Ok(super::Decision::Commit(true))
        })
        .await
    }
}
