// SPDX-License-Identifier: AGPL-3.0-only
//! Background job locks for processes sharing one SQLite file: a leased row
//! per held job, taken under the database write lock.

use async_trait::async_trait;
use chrono::Utc;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::storage::{JobLock, JobLockHolder};
use sqlx::SqlitePool;

use super::{SqliteBackend, fmt_dt};

/// How long a held lock survives a holder that vanished without releasing
/// it. A job runs within this time; one that takes longer may be started a
/// second time by another process.
const JOB_LOCK_LEASE: chrono::Duration = chrono::Duration::hours(1);

impl SqliteBackend {
    pub(super) async fn try_job_lock_impl(&self, job: i64) -> SidResult<Option<JobLock>> {
        let now = Utc::now();
        let holder = uuid::Uuid::new_v4().to_string();
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM job_locks WHERE job = ? AND expires_at <= ?")
            .bind(job)
            .bind(fmt_dt(&now))
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("job lock: {e}")))?;
        let taken = sqlx::query(
            "INSERT INTO job_locks (job, holder, expires_at) VALUES (?, ?, ?) \
             ON CONFLICT(job) DO NOTHING",
        )
        .bind(job)
        .bind(&holder)
        .bind(fmt_dt(&(now + JOB_LOCK_LEASE)))
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("job lock: {e}")))?
        .rows_affected()
            == 1;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(format!("job lock commit: {e}")))?;
        Ok(taken.then(|| {
            JobLock::new(SqliteJobLock {
                pool: self.pool.clone(),
                job,
                holder: Some(holder),
            })
        }))
    }
}

struct SqliteJobLock {
    pool: SqlitePool,
    job: i64,
    /// `None` once released.
    holder: Option<String>,
}

async fn delete_lock(pool: &SqlitePool, job: i64, holder: &str) -> SidResult<u64> {
    sqlx::query("DELETE FROM job_locks WHERE job = ? AND holder = ?")
        .bind(job)
        .bind(holder)
        .execute(pool)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| SidError::Storage(format!("job unlock: {e}")))
}

#[async_trait]
impl JobLockHolder for SqliteJobLock {
    async fn release(mut self: Box<Self>) -> SidResult<()> {
        let Some(holder) = self.holder.take() else {
            return Ok(());
        };
        if delete_lock(&self.pool, self.job, &holder).await? == 0 {
            return Err(SidError::Storage(format!(
                "job lock {} expired before release and may have run twice",
                self.job
            )));
        }
        Ok(())
    }
}

impl Drop for SqliteJobLock {
    fn drop(&mut self) {
        let Some(holder) = self.holder.take() else {
            return;
        };
        // Free it now when a runtime is at hand; otherwise the lease ends it.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let pool = self.pool.clone();
            let job = self.job;
            runtime.spawn(async move {
                if let Err(e) = delete_lock(&pool, job, &holder).await {
                    tracing::warn!(job, error = %e, "dropped job lock not freed; its lease will end it");
                }
            });
        }
    }
}
