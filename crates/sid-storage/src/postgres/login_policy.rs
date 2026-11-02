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
}
