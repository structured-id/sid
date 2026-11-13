// SPDX-License-Identifier: AGPL-3.0-only
//! The installation's login-policy epoch: a host that stores its login
//! policy advances it in every policy write, and a session or code decided
//! under a policy commits only while the epoch is still the one it read.

use sid_core::{Error as SidError, Result as SidResult};

use super::PostgresBackend;

type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

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
        let stored: Option<(bool, bool)> = sqlx::query_as(
            "SELECT allow_personal_profiles, allow_foreign_corporate_profiles
             FROM login_settings WHERE scope = 'installation'",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
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
             VALUES ('installation', $1, $2, NOW())
             ON CONFLICT (scope) DO UPDATE SET
                 allow_personal_profiles = EXCLUDED.allow_personal_profiles,
                 allow_foreign_corporate_profiles = EXCLUDED.allow_foreign_corporate_profiles,
                 updated_at = NOW()",
        )
        .bind(settings.allow_personal_profiles)
        .bind(settings.allow_foreign_corporate_profiles)
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
