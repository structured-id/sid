// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's login-policy epoch for the SQLite backend: advanced by
//! every policy write of the host, checked by every session or code decided
//! under a policy, both inside the single writer's transaction.

use sid_core::{Error as SidError, Result as SidResult};

use super::SqliteBackend;

type Tx<'a> = sqlx::Transaction<'a, sqlx::Sqlite>;

/// Fail with `Fenced` unless the login-policy epoch is still `epoch`, read in
/// the write transaction (which holds the database write lock, so no policy
/// write lands before this commit).
pub(super) async fn check_fence(tx: &mut Tx<'_>, epoch: i64) -> SidResult<()> {
    let current: Option<i64> =
        sqlx::query_scalar("SELECT epoch FROM login_policy_epoch WHERE id = 1")
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

impl SqliteBackend {
    /// Advance the login-policy epoch in `tx`, a host's policy write started
    /// with [`SqliteBackend::begin_write_on`], and return the new epoch:
    /// decisions taken under the earlier one no longer commit. The first
    /// write starts it at 1.
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
        E: sqlx::SqliteExecutor<'e>,
    {
        sqlx::query_scalar("SELECT epoch FROM login_policy_epoch WHERE id = 1")
            .fetch_optional(executor)
            .await
            .map_err(|e| SidError::Storage(format!("read login policy epoch: {e}")))
    }

    pub(crate) async fn login_settings_impl(
        &self,
    ) -> SidResult<Option<sid_core::models::LoginSettings>> {
        let row: Option<(bool, bool)> = sqlx::query_as(
            "SELECT allow_personal_profiles, allow_foreign_corporate_profiles
             FROM login_settings WHERE scope = 'installation'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("read login settings: {e}")))?;
        Ok(
            row.map(|(personal, corporate)| sid_core::models::LoginSettings {
                allow_personal_profiles: personal,
                allow_foreign_corporate_profiles: corporate,
            }),
        )
    }

    pub(crate) async fn set_login_settings_impl(
        &self,
        settings: &sid_core::models::LoginSettings,
        expected: Option<&sid_core::models::LoginSettings>,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        // The write lock is held from here: what is read below is what this
        // write replaces.
        let mut tx = self.begin_write().await?;
        let stored: Option<(bool, bool)> = sqlx::query_as(
            "SELECT allow_personal_profiles, allow_foreign_corporate_profiles
             FROM login_settings WHERE scope = 'installation'",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("read login settings: {e}")))?;
        let expected = expected.map(|e| {
            (
                e.allow_personal_profiles,
                e.allow_foreign_corporate_profiles,
            )
        });
        if stored != expected {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO login_settings (scope, allow_personal_profiles,
                 allow_foreign_corporate_profiles, updated_at)
             VALUES ('installation', ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             ON CONFLICT (scope) DO UPDATE SET
                 allow_personal_profiles = excluded.allow_personal_profiles,
                 allow_foreign_corporate_profiles = excluded.allow_foreign_corporate_profiles,
                 updated_at = excluded.updated_at",
        )
        .bind(settings.allow_personal_profiles)
        .bind(settings.allow_foreign_corporate_profiles)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("write login settings: {e}")))?;
        // A sign-in decided under the earlier settings no longer commits.
        Self::advance_login_policy_epoch(&mut tx).await?;
        Self::commit_mutation(tx, "installation:login_settings", ctx).await?;
        Ok(true)
    }

    pub(crate) async fn import_login_settings_impl(
        &self,
        settings: &sid_core::models::LoginSettings,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let stored: Option<(bool, bool)> = sqlx::query_as(
            "SELECT allow_personal_profiles, allow_foreign_corporate_profiles
             FROM login_settings WHERE scope = 'installation'",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("read login settings: {e}")))?;
        if let Some((personal, corporate)) = stored {
            let held = sid_core::models::LoginSettings {
                allow_personal_profiles: personal,
                allow_foreign_corporate_profiles: corporate,
            };
            return crate::transfer_repeat(&held, settings, "login settings");
        }
        sqlx::query(
            "INSERT INTO login_settings (scope, allow_personal_profiles,
                 allow_foreign_corporate_profiles)
             VALUES ('installation', ?, ?)",
        )
        .bind(settings.allow_personal_profiles)
        .bind(settings.allow_foreign_corporate_profiles)
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("login settings", e))?;
        Self::commit_mutation(tx, "installation:login_settings", ctx).await?;
        Ok(true)
    }

    pub(crate) async fn import_login_policy_epoch_impl(
        &self,
        epoch: i64,
        ctx: sid_core::models::MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        if let Some(held) = Self::login_policy_epoch(&mut *tx).await? {
            return crate::transfer_repeat(&held, &epoch, "login policy epoch");
        }
        sqlx::query("INSERT INTO login_policy_epoch (id, epoch) VALUES (1, ?)")
            .bind(epoch)
            .execute(&mut *tx)
            .await
            .map_err(|e| super::insert_error("login policy epoch", e))?;
        Self::commit_mutation(tx, "installation:login_policy", ctx).await?;
        Ok(true)
    }
}
