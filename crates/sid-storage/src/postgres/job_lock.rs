// SPDX-License-Identifier: AGPL-3.0-only
//! Background job locks on PostgreSQL session advisory locks.
//!
//! A session lock belongs to the connection that took it, so the lock keeps
//! that connection out of the pool for as long as it is held and unlocks on
//! it. A lock dropped without release closes its connection, which ends the
//! session and with it the lock; returning it to the pool would leave the
//! job locked for every instance for the life of that connection.

use async_trait::async_trait;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::storage::{JobLock, JobLockHolder};
use sqlx::PgPool;
use sqlx::pool::PoolConnection;

pub(super) async fn try_job_lock(pool: &PgPool, job: i64) -> SidResult<Option<JobLock>> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| SidError::Storage(format!("job lock connection: {e}")))?;
    let taken: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(job)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| SidError::Storage(format!("job lock: {e}")))?;
    Ok(taken.then(|| {
        JobLock::new(PgJobLock {
            conn: Some(conn),
            job,
        })
    }))
}

struct PgJobLock {
    conn: Option<PoolConnection<sqlx::Postgres>>,
    job: i64,
}

#[async_trait]
impl JobLockHolder for PgJobLock {
    async fn release(mut self: Box<Self>) -> SidResult<()> {
        let Some(mut conn) = self.conn.take() else {
            return Ok(());
        };
        let unlocked = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
            .bind(self.job)
            .fetch_one(&mut *conn)
            .await;
        match unlocked {
            Ok(true) => Ok(()),
            Ok(false) => {
                drop(conn.detach());
                Err(SidError::Storage(format!(
                    "job lock {} was not held by its connection",
                    self.job
                )))
            }
            Err(e) => {
                // The session still holds the lock: closing it frees it.
                drop(conn.detach());
                Err(SidError::Storage(format!("job unlock: {e}")))
            }
        }
    }
}

impl Drop for PgJobLock {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            drop(conn.detach());
        }
    }
}
