// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's login-policy epoch: a host that stores its login
//! policy advances it in every policy write, and a session or code decided
//! under a policy commits only while the epoch is still the one it read.

use sid_core::{Error as SidError, Result as SidResult};

use super::PostgresBackend;

type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// The stored login settings row: both admission switches, the admitted
/// sources, the status policy and the revision.
type SettingsRow = (bool, bool, Vec<uuid::Uuid>, Vec<u8>, i64);

/// The stored login settings read on `executor`; none before they were set.
async fn stored_settings<'e, E>(executor: E) -> SidResult<Option<sid_core::models::LoginSettings>>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<SettingsRow> = sqlx::query_as(
        "SELECT allow_personal_profiles, allow_foreign_corporate_profiles,
                admitted_sources, status_policy, revision
         FROM login_settings WHERE scope = 'installation'",
    )
    .fetch_optional(executor)
    .await
    .map_err(|e| SidError::Storage(format!("read login settings: {e}")))?;
    row.map(|(personal, corporate, sources, policy, revision)| {
        let corrupt = |what: &str| SidError::Storage(format!("stored login settings: {what}"));
        let sources = sources
            .into_iter()
            .map(sid_core::models::OrgId::from_uuid)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| corrupt(&e.to_string()))?;
        Ok(sid_core::models::LoginSettings {
            allow_personal_profiles: personal,
            allow_foreign_corporate_profiles: corporate,
            admitted_sources: sources
                .try_into()
                .map_err(|_| corrupt("too many sources"))?,
            status_policy: sid_core::models::StatusPolicy::from_tag(&policy)
                .ok_or_else(|| corrupt("a status policy no policy encodes"))?,
            revision: u64::try_from(revision).map_err(|_| corrupt("negative revision"))?,
        })
    })
    .transpose()
}

/// The admitted source organizations as the `uuid[]` column holds them.
fn sources(settings: &sid_core::models::LoginSettings) -> Vec<uuid::Uuid> {
    settings
        .admitted_sources
        .as_slice()
        .iter()
        .map(|id| id.into_uuid())
        .collect()
}

/// The settings' revision as the `bigint` column holds it.
fn revision(settings: &sid_core::models::LoginSettings) -> SidResult<i64> {
    i64::try_from(settings.revision)
        .map_err(|_| SidError::Validation("login settings revision out of range".into()))
}

impl PostgresBackend {
    /// Fail with `Fenced` unless the login-policy epoch is still `epoch` in
    /// this transaction. The epoch row is share-locked until the transaction
    /// ends, so a policy write either waits for this commit or is seen by it.
    pub(super) async fn check_login_policy_fence(tx: &mut Tx<'_>, epoch: i64) -> SidResult<()> {
        let current: Option<i64> =
            sqlx::query_scalar("SELECT epoch FROM login_policy_epoch WHERE id = 1 FOR SHARE")
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| SidError::Storage(format!("check login policy fence: {e}")))?;
        if current == Some(epoch) {
            Ok(())
        } else {
            Err(SidError::Fenced(
                "the login policy changed since it was read".into(),
            ))
        }
    }

    /// Advance the login-policy epoch in `tx`, the transaction of a host's
    /// policy write, and return the new epoch: decisions taken under the
    /// earlier one no longer commit. The first write starts it at 1.
    pub async fn advance_login_policy_epoch(tx: &mut Tx<'_>) -> SidResult<i64> {
        sqlx::query_scalar(
            "INSERT INTO login_policy_epoch (id, epoch) VALUES (1, 1)
             ON CONFLICT (id) DO UPDATE SET epoch = login_policy_epoch.epoch + 1
             RETURNING epoch",
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| SidError::Storage(format!("advance login policy epoch: {e}")))
    }

    /// The current login-policy epoch read on `executor`; none before any
    /// policy write.
    pub async fn login_policy_epoch<'e, E>(executor: E) -> SidResult<Option<i64>>
    where
        E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_scalar("SELECT epoch FROM login_policy_epoch WHERE id = 1")
            .fetch_optional(executor)
            .await
            .map_err(|e| SidError::Storage(format!("read login policy epoch: {e}")))
    }

    pub(super) async fn login_settings_impl(
        &self,
    ) -> SidResult<Option<sid_core::models::LoginSettings>> {
        stored_settings(&self.pool).await
    }

    pub(super) async fn set_login_settings_impl(
        &self,
        settings: &sid_core::models::LoginSettings,
        expected: Option<&sid_core::models::LoginSettings>,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("write login settings: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        // One writer at a time, also while no row exists yet; readers are
        // not held. What is read below is what this write replaces.
        sqlx::query("LOCK TABLE login_settings IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        if stored_settings(&mut *tx).await?.as_ref() != expected {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO login_settings (scope, allow_personal_profiles,
                 allow_foreign_corporate_profiles, admitted_sources, status_policy, revision,
                 updated_at)
             VALUES ('installation', $1, $2, $3, $4, $5, NOW())
             ON CONFLICT (scope) DO UPDATE SET
                 allow_personal_profiles = EXCLUDED.allow_personal_profiles,
                 allow_foreign_corporate_profiles = EXCLUDED.allow_foreign_corporate_profiles,
                 admitted_sources = EXCLUDED.admitted_sources,
                 status_policy = EXCLUDED.status_policy,
                 revision = EXCLUDED.revision,
                 updated_at = NOW()",
        )
        .bind(settings.allow_personal_profiles)
        .bind(settings.allow_foreign_corporate_profiles)
        .bind(sources(settings))
        .bind(settings.status_policy.tag().as_slice())
        .bind(revision(settings)?)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        // A sign-in decided under the earlier settings no longer commits:
        // its fence share-locks the epoch row this write updates.
        Self::advance_login_policy_epoch(&mut tx).await?;
        Self::audit_in_tx(&mut tx, "installation:login_settings", ctx).await?;
        tx.commit().await.map_err(storage)?;
        Ok(true)
    }

    pub(super) async fn import_login_settings_impl(
        &self,
        settings: &sid_core::models::LoginSettings,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("import login settings: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        // The row's insert serializes concurrent importers on its key.
        let inserted = sqlx::query(
            "INSERT INTO login_settings (scope, allow_personal_profiles,
                 allow_foreign_corporate_profiles, admitted_sources, status_policy, revision)
             VALUES ('installation', $1, $2, $3, $4, $5) ON CONFLICT (scope) DO NOTHING",
        )
        .bind(settings.allow_personal_profiles)
        .bind(settings.allow_foreign_corporate_profiles)
        .bind(sources(settings))
        .bind(settings.status_policy.tag().as_slice())
        .bind(revision(settings)?)
        .execute(&mut *tx)
        .await
        .map_err(storage)?
        .rows_affected()
            == 1;
        if !inserted {
            let held = stored_settings(&mut *tx)
                .await?
                .ok_or_else(|| SidError::Storage("login settings vanished while read".into()))?;
            return crate::transfer_repeat(&held, settings, "login settings");
        }
        Self::audit_in_tx(&mut tx, "installation:login_settings", ctx).await?;
        tx.commit().await.map_err(storage)?;
        Ok(true)
    }

    pub(super) async fn import_login_policy_epoch_impl(
        &self,
        epoch: i64,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("import login policy epoch: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        // The row's insert serializes concurrent importers on its key.
        let inserted = sqlx::query(
            "INSERT INTO login_policy_epoch (id, epoch) VALUES (1, $1) ON CONFLICT (id) DO NOTHING",
        )
        .bind(epoch)
        .execute(&mut *tx)
        .await
        .map_err(storage)?
        .rows_affected()
            == 1;
        if !inserted {
            let held = Self::login_policy_epoch(&mut *tx).await?;
            return crate::transfer_repeat(&held, &Some(epoch), "login policy epoch");
        }
        Self::audit_in_tx(&mut tx, "installation:login_policy", ctx).await?;
        tx.commit().await.map_err(storage)?;
        Ok(true)
    }
}
