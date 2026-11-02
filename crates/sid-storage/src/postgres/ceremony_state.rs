// SPDX-License-Identifier: AGPL-3.0-only
//! Ceremony state and single-use admissions. Every statement is one atomic
//! step on its row, and every deadline is the server's `NOW()`.

use std::time::Duration;

use async_trait::async_trait;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::CeremonyStateStore;

use super::PostgresBackend;

fn failure(what: &str) -> impl FnOnce(sqlx::Error) -> SidError + '_ {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

/// `ttl` in seconds, as `make_interval` takes it.
fn seconds(ttl: Duration) -> f64 {
    ttl.as_secs_f64()
}

#[async_trait]
impl CeremonyStateStore for PostgresBackend {
    async fn put_ceremony_state(
        &self,
        namespace: &str,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> SidResult<()> {
        sqlx::query(
            "INSERT INTO ceremony_states (namespace, state_key, value, expires_at)
             VALUES ($1, $2, $3, NOW() + make_interval(secs => $4))
             ON CONFLICT (namespace, state_key) DO UPDATE SET
                 value = EXCLUDED.value, expires_at = EXCLUDED.expires_at",
        )
        .bind(namespace)
        .bind(key)
        .bind(value)
        .bind(seconds(ttl))
        .execute(&self.pool)
        .await
        .map_err(failure("store ceremony state"))?;
        Ok(())
    }

    async fn take_ceremony_state(&self, namespace: &str, key: &str) -> SidResult<Option<Vec<u8>>> {
        // A concurrent delete of the same row waits for this one and then
        // finds nothing, so one taker gets the value.
        sqlx::query_scalar(
            "DELETE FROM ceremony_states
             WHERE namespace = $1 AND state_key = $2 AND expires_at > NOW()
             RETURNING value",
        )
        .bind(namespace)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(failure("take ceremony state"))
    }

    async fn read_ceremony_state(&self, namespace: &str, key: &str) -> SidResult<Option<Vec<u8>>> {
        sqlx::query_scalar(
            "SELECT value FROM ceremony_states
             WHERE namespace = $1 AND state_key = $2 AND expires_at > NOW()",
        )
        .bind(namespace)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(failure("read ceremony state"))
    }

    async fn replace_ceremony_state(
        &self,
        namespace: &str,
        key: &str,
        expected: &[u8],
        value: &[u8],
        ttl: Duration,
    ) -> SidResult<bool> {
        // A concurrent update of the row waits, then re-evaluates the
        // condition on the version it left: only the first one applies.
        let replaced = sqlx::query(
            "UPDATE ceremony_states
             SET value = $4, expires_at = NOW() + make_interval(secs => $5)
             WHERE namespace = $1 AND state_key = $2 AND value = $3 AND expires_at > NOW()",
        )
        .bind(namespace)
        .bind(key)
        .bind(expected)
        .bind(value)
        .bind(seconds(ttl))
        .execute(&self.pool)
        .await
        .map_err(failure("replace ceremony state"))?
        .rows_affected();
        Ok(replaced == 1)
    }

    async fn admit_once(&self, namespace: &str, key: &str, ttl: Duration) -> SidResult<bool> {
        // A concurrent insert of the key waits for this one; the conflict
        // then takes the key over only from an expired admission.
        let admitted = sqlx::query(
            "INSERT INTO ceremony_states (namespace, state_key, value, expires_at)
             VALUES ($1, $2, ''::bytea, NOW() + make_interval(secs => $3))
             ON CONFLICT (namespace, state_key) DO UPDATE SET
                 value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
             WHERE ceremony_states.expires_at <= NOW()",
        )
        .bind(namespace)
        .bind(key)
        .bind(seconds(ttl))
        .execute(&self.pool)
        .await
        .map_err(failure("admit once"))?
        .rows_affected();
        Ok(admitted == 1)
    }

    async fn purge_expired_ceremony_state(&self) -> SidResult<u64> {
        sqlx::query("DELETE FROM ceremony_states WHERE expires_at <= NOW()")
            .execute(&self.pool)
            .await
            .map(|done| done.rows_affected())
            .map_err(failure("purge ceremony state"))
    }
}
