// SPDX-License-Identifier: AGPL-3.0-only
//! Background job locks in CoordiNode: one leased `SidJobLock` node per held
//! job, unique by job, for every instance sharing the database.

use async_trait::async_trait;
use chrono::Utc;
use coordinode_core::graph::types::Value;
use sid_core::{Error as SidError, Result as SidResult};
use sid_plugin::storage::{JobLock, JobLockHolder};
use uuid::Uuid;

use super::{CoordinodeBackend, Decision, Params, time, uuid};

/// How long a held lock survives a holder that vanished without releasing
/// it. A job runs within this time; one that takes longer may be started a
/// second time by another instance.
const JOB_LOCK_LEASE: chrono::Duration = chrono::Duration::hours(1);

impl CoordinodeBackend {
    pub(super) async fn try_job_lock(&self, job: i64) -> SidResult<Option<JobLock>> {
        let holder = Uuid::new_v4();
        let taken = self
            .transaction(move |tx| {
                let now = Utc::now();
                let params = Params::default()
                    .with("job", Value::Int(job))
                    .with("holder", uuid(&holder))
                    .with("now", time(now))
                    .with("expires_at", time(now + JOB_LOCK_LEASE));
                tx.run(
                    "MATCH (l:SidJobLock) WHERE l.job = $job AND l.expires_at <= $now
                     DETACH DELETE l",
                    params.clone(),
                )?;
                let held = tx.run(
                    "MATCH (l:SidJobLock) WHERE l.job = $job RETURN l.job AS job",
                    params.clone(),
                )?;
                if !held.is_empty() {
                    return Ok(Decision::Abandon(false));
                }
                tx.run(
                    "CREATE (l:SidJobLock {job: $job, holder: $holder, expires_at: $expires_at})",
                    params,
                )?;
                Ok(Decision::Commit(true))
            })
            .await;
        match taken {
            Ok(true) => Ok(Some(JobLock::new(CoordinodeJobLock {
                backend: self.clone(),
                job,
                holder: Some(holder),
            }))),
            Ok(false) => Ok(None),
            // The job's unique key was taken by another instance meanwhile:
            // it holds the lock.
            Err(SidError::Conflict(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Free `job`'s lock while `holder` holds it; `false` when it does not.
    async fn release_job_lock(&self, job: i64, holder: Uuid) -> SidResult<bool> {
        self.transaction(move |tx| {
            let params = Params::default()
                .with("job", Value::Int(job))
                .with("holder", uuid(&holder));
            let held = tx.run(
                "MATCH (l:SidJobLock) WHERE l.job = $job AND l.holder = $holder
                 RETURN l.job AS job",
                params.clone(),
            )?;
            if held.is_empty() {
                return Ok(Decision::Abandon(false));
            }
            tx.run(
                "MATCH (l:SidJobLock) WHERE l.job = $job AND l.holder = $holder DETACH DELETE l",
                params,
            )?;
            Ok(Decision::Commit(true))
        })
        .await
    }
}

struct CoordinodeJobLock {
    backend: CoordinodeBackend,
    job: i64,
    /// `None` once released.
    holder: Option<Uuid>,
}

#[async_trait]
impl JobLockHolder for CoordinodeJobLock {
    async fn release(mut self: Box<Self>) -> SidResult<()> {
        let Some(holder) = self.holder.take() else {
            return Ok(());
        };
        if !self.backend.release_job_lock(self.job, holder).await? {
            return Err(SidError::Storage(format!(
                "job lock {} expired before release and may have run twice",
                self.job
            )));
        }
        Ok(())
    }
}

impl Drop for CoordinodeJobLock {
    fn drop(&mut self) {
        let Some(holder) = self.holder.take() else {
            return;
        };
        // Free it now when a runtime is at hand; otherwise the lease ends it.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let backend = self.backend.clone();
            let job = self.job;
            runtime.spawn(async move {
                if let Err(e) = backend.release_job_lock(job, holder).await {
                    tracing::warn!(job, error = %e, "dropped job lock not freed; its lease will end it");
                }
            });
        }
    }
}
