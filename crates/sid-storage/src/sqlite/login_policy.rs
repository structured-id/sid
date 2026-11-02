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
}
