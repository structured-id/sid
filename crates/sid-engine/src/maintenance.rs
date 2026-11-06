// SPDX-License-Identifier: AGPL-3.0-only
//! The maintenance an installation owes: closures past their grace period,
//! purges, expiries and storage upkeep. Each job runs on its own schedule;
//! one that must not run twice at once runs under its job lock, so one
//! instance of a replicated installation runs it each round. A drain stops
//! the schedules; a run in progress finishes and releases its lock first.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sid_authn::account_closure::AccountClosureService;
use sid_authn::password_operation::HistoryEvaluation;
use sid_core::models::{AuditEntry, NewWork, OwnerPurge, Profile, ProfileId, ProfileStatus};
use sid_plugin::storage::StorageBackend;
use tokio::sync::watch;
use tracing::{info, warn};

/// Default migration deadline in days.
pub const DEFAULT_MIGRATION_DEADLINE_DAYS: i64 = 180;

/// What happens to audit records past retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionAction {
    /// Kept until they are archived to cold storage (the default).
    Archive,
    /// Removed, with a chain checkpoint left behind.
    Delete,
}

/// Audit retention: how long records are kept and what happens after.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditRetention {
    pub days: u32,
    pub action: RetentionAction,
}

impl Default for AuditRetention {
    /// A year, archived.
    fn default() -> Self {
        Self {
            days: 365,
            action: RetentionAction::Archive,
        }
    }
}

// Job locks of the CE maintenance: one number per job across the installation.
const LOCK_PAT_AUTO_REVOKE: i64 = 43;
const LOCK_CREDENTIAL_EXPIRY: i64 = 44;
const LOCK_ROLE_EXPIRY: i64 = 45;
const LOCK_QUARANTINE_CLEANUP: i64 = 46;
const LOCK_PROFILE_PURGE: i64 = 47;
const LOCK_MIGRATION_DEADLINE: i64 = 48;
const LOCK_AUDIT_PARTITION: i64 = 49;
const LOCK_PRINCIPAL_EXPIRY: i64 = 50;
const LOCK_ENROLLMENT_COMPACTION: i64 = 51;

/// The future of one run of a job.
pub type RunFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// One run of a job.
pub type JobRun = Arc<dyn Fn() -> RunFuture + Send + Sync>;

/// A run over the store alone.
type StoreRun = fn(Arc<dyn StorageBackend>) -> RunFuture;

/// When a job first runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstRun {
    /// As soon as the schedule starts.
    AtStart,
    /// One interval after the schedule starts.
    AfterInterval,
}

/// A recurring job.
pub struct Job {
    name: &'static str,
    every: Duration,
    first: FirstRun,
    /// Held while the job runs, so one instance runs it at a time.
    lock: Option<i64>,
    run: JobRun,
}

impl Job {
    /// A job any number of instances may run at once (its effect is
    /// idempotent).
    pub fn shared(name: &'static str, every: Duration, first: FirstRun, run: JobRun) -> Self {
        Self {
            name,
            every,
            first,
            lock: None,
            run,
        }
    }

    /// A job one instance runs at a time, under job lock `lock`.
    pub fn exclusive(
        name: &'static str,
        every: Duration,
        first: FirstRun,
        lock: i64,
        run: JobRun,
    ) -> Self {
        Self {
            name,
            every,
            first,
            lock: Some(lock),
            run,
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
}

/// The jobs an engine runs.
#[derive(Default)]
pub struct Maintenance {
    jobs: Vec<Job>,
}

/// What the CE maintenance acts on.
pub struct CeMaintenance {
    pub storage: Arc<dyn StorageBackend>,
    pub closures: Arc<AccountClosureService>,
    /// The history evaluator, when it runs in this process.
    pub history_evaluation: Option<Arc<HistoryEvaluation>>,
    pub audit_retention: AuditRetention,
    pub migration_deadline_days: i64,
    /// The source the alerts this maintenance raises name.
    pub source: String,
}

impl Maintenance {
    /// The maintenance every CE installation owes.
    pub fn ce(parts: CeMaintenance) -> Self {
        let CeMaintenance {
            storage,
            closures,
            history_evaluation,
            audit_retention,
            migration_deadline_days,
            source,
        } = parts;
        let hour = Duration::from_secs(3600);
        let day = Duration::from_secs(86400);
        let minute = Duration::from_secs(60);
        let source: Arc<str> = source.into();
        let with = |f: StoreRun| {
            let storage = storage.clone();
            let run: JobRun = Arc::new(move || f(storage.clone()));
            run
        };
        let mut jobs = Vec::new();
        {
            // Ended first enrollments' records: their work, aborts and fences
            // are dropped once no step of them can still arrive.
            let storage = storage.clone();
            let evaluation = history_evaluation.clone();
            jobs.push(Job::exclusive(
                "enrollment_compaction",
                hour,
                FirstRun::AtStart,
                LOCK_ENROLLMENT_COMPACTION,
                Arc::new(move || {
                    let (storage, evaluation) = (storage.clone(), evaluation.clone());
                    Box::pin(async move {
                        match sid_authn::password_operation::compact_enrollments(
                            storage.as_ref(),
                            evaluation.as_deref(),
                            Utc::now(),
                        )
                        .await
                        {
                            Ok(0) => {}
                            Ok(n) => info!("Compacted {} ended enrollment records", n),
                            Err(e) => warn!("enrollment compaction failed: {}", e),
                        }
                    })
                }),
            ));
        }
        // Operation results and periods past their retention: a period that
        // stopped accepting commands is retired with its completions once its
        // retention passed. Idempotent, so no job lock.
        jobs.push(Job::shared(
            "operation_upkeep",
            minute,
            FirstRun::AfterInterval,
            with(|s| {
                Box::pin(async move {
                    sid_authn::operation::upkeep(s.as_ref(), Utc::now()).await;
                })
            }),
        ));
        // Ceremony state past its deadline: one-time proofs, codes and counts
        // leave rows no database expires by itself.
        jobs.push(Job::shared(
            "ceremony_state_expiry",
            minute,
            FirstRun::AfterInterval,
            with(|s| {
                Box::pin(async move {
                    purge_ceremony_state(s.as_ref()).await;
                })
            }),
        ));
        jobs.push(Job::exclusive(
            "pat_auto_revoke",
            hour,
            FirstRun::AtStart,
            LOCK_PAT_AUTO_REVOKE,
            with(|s| {
                Box::pin(async move {
                    revoke_unused_pats(s.as_ref()).await;
                })
            }),
        ));
        {
            let storage = storage.clone();
            let source = source.clone();
            jobs.push(Job::exclusive(
                "credential_expiry",
                hour,
                FirstRun::AtStart,
                LOCK_CREDENTIAL_EXPIRY,
                Arc::new(move || {
                    let (storage, source) = (storage.clone(), source.clone());
                    Box::pin(async move {
                        alert_credential_expiry(storage.as_ref(), &source, Utc::now()).await;
                    })
                }),
            ));
        }
        jobs.push(Job::exclusive(
            "role_expiry",
            Duration::from_secs(300),
            FirstRun::AtStart,
            LOCK_ROLE_EXPIRY,
            with(|s| {
                Box::pin(async move {
                    expire_role_assignments(s.as_ref(), Utc::now()).await;
                })
            }),
        ));
        jobs.push(Job::exclusive(
            "quarantine_cleanup",
            day,
            FirstRun::AtStart,
            LOCK_QUARANTINE_CLEANUP,
            with(|s| {
                Box::pin(async move {
                    cleanup_quarantine(s.as_ref()).await;
                })
            }),
        ));
        {
            // Closures whose grace period ended are executed; closed profiles
            // are purged at the end of their quarantine.
            let storage = storage.clone();
            jobs.push(Job::exclusive(
                "profile_purge",
                hour,
                FirstRun::AtStart,
                LOCK_PROFILE_PURGE,
                Arc::new(move || {
                    let (storage, closures) = (storage.clone(), closures.clone());
                    Box::pin(async move {
                        execute_due_closures(storage.as_ref(), &closures).await;
                        purge_closed_profiles(storage.as_ref()).await;
                    })
                }),
            ));
        }
        {
            let storage = storage.clone();
            jobs.push(Job::exclusive(
                "migration_deadline",
                day,
                FirstRun::AtStart,
                LOCK_MIGRATION_DEADLINE,
                Arc::new(move || {
                    let storage = storage.clone();
                    Box::pin(async move {
                        enforce_migration_deadline(storage.as_ref(), migration_deadline_days).await;
                    })
                }),
            ));
        }
        {
            // This and next month's audit storage prepared; months past
            // retention removed when the site chose `delete`.
            let storage = storage.clone();
            jobs.push(Job::exclusive(
                "audit_partition",
                day,
                FirstRun::AtStart,
                LOCK_AUDIT_PARTITION,
                Arc::new(move || {
                    let storage = storage.clone();
                    Box::pin(async move {
                        if let Err(e) =
                            manage_audit_partitions(storage.as_ref(), audit_retention, Utc::now())
                                .await
                        {
                            tracing::error!(error = %e, "audit storage maintenance failed");
                        }
                    })
                }),
            ));
        }
        jobs.push(Job::exclusive(
            "principal_expiry",
            day,
            FirstRun::AtStart,
            LOCK_PRINCIPAL_EXPIRY,
            with(|s| {
                Box::pin(async move {
                    expire_principal_verifications(s.as_ref()).await;
                })
            }),
        ));
        Self { jobs }
    }

    /// These jobs and `job`.
    pub fn with(mut self, job: Job) -> Self {
        self.jobs.push(job);
        self
    }

    /// The names of the jobs, in order.
    pub fn job_names(&self) -> Vec<&'static str> {
        self.jobs.iter().map(Job::name).collect()
    }

    /// Start every job's schedule; each stops when `stop` turns true.
    pub(crate) fn spawn(
        self,
        storage: Arc<dyn StorageBackend>,
        stop: &watch::Receiver<bool>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        self.jobs
            .into_iter()
            .map(|job| tokio::spawn(schedule(job, storage.clone(), stop.clone())))
            .collect()
    }
}

/// Run `job` on its schedule until `stop` turns true; a run in progress
/// finishes and releases its lock first.
async fn schedule(job: Job, storage: Arc<dyn StorageBackend>, mut stop: watch::Receiver<bool>) {
    let start = match job.first {
        FirstRun::AtStart => tokio::time::Instant::now(),
        FirstRun::AfterInterval => tokio::time::Instant::now() + job.every,
    };
    let mut interval = tokio::time::interval_at(start, job.every);
    loop {
        if *stop.borrow() {
            return;
        }
        tokio::select! {
            _ = interval.tick() => {}
            changed = stop.changed() => {
                // A dropped sender stops the schedule as a drain does.
                if changed.is_err() || *stop.borrow() {
                    return;
                }
                continue;
            }
        }
        // A tick and a drain ready together may resolve to the tick.
        if *stop.borrow() {
            return;
        }
        match job.lock {
            None => (job.run)().await,
            Some(lock) => {
                if let Some(held) = take_job_lock(storage.as_ref(), lock, job.name).await {
                    run_held(&job, held, &stop).await;
                }
            }
        }
    }
}

/// Run `job` under its lock `held`, then free it. The lock can arrive after a
/// drain began (it waits for a pooled connection), so a drain seen by then
/// frees the lock without starting the run.
async fn run_held(job: &Job, held: sid_plugin::storage::JobLock, stop: &watch::Receiver<bool>) {
    if !*stop.borrow() {
        (job.run)().await;
    }
    release_job_lock(held, job.name).await;
}

/// This round's lock of `job`: `None` when another instance holds it, or
/// when the store cannot be asked (logged; the next round retries).
async fn take_job_lock(
    storage: &dyn StorageBackend,
    job: i64,
    name: &str,
) -> Option<sid_plugin::storage::JobLock> {
    match storage.try_job_lock(job).await {
        Ok(lock) => lock,
        Err(e) => {
            warn!(job = name, error = %e, "background job lock unavailable, skipping this round");
            None
        }
    }
}

/// Free a job lock after the run. A failed release is logged: the lock frees
/// itself (closed session, lease end), so the job resumes later.
async fn release_job_lock(lock: sid_plugin::storage::JobLock, name: &str) {
    if let Err(e) = lock.release().await {
        warn!(job = name, error = %e, "background job lock release failed");
    }
}

// ─── Migration deadline enforcement ─────────────────────────────

/// Whether a profile's migration deadline has expired: it was started at
/// least `deadline_days` ago.
pub fn is_migration_expired(profile: &Profile, deadline_days: i64, now: DateTime<Utc>) -> bool {
    let started = profile.migration_started_at.unwrap_or(profile.created_at);
    let deadline = started + chrono::Duration::days(deadline_days);
    now >= deadline
}

/// One run of migration deadline enforcement: each profile with
/// `migration_pending` past `deadline_days` has its flag cleared and its
/// legacy password hashes deleted in one write, over the revision listed (a
/// profile changed since is seen again on the next run). Returns the number
/// of profiles expired.
pub async fn enforce_migration_deadline(storage: &dyn StorageBackend, deadline_days: i64) -> u64 {
    let profiles = match storage.list_profiles_with_pending_migration().await {
        Ok(p) => p,
        Err(e) => {
            warn!("Migration deadline scan failed: {}", e);
            return 0;
        }
    };

    let now = Utc::now();
    let mut expired_count = 0u64;

    for profile in &profiles {
        if !is_migration_expired(profile, deadline_days, now) {
            continue;
        }

        let mut p = profile.clone();
        p.migration_pending = false;
        match storage
            .end_legacy_migration(
                &p,
                AuditEntry::system("profile.migration_deadline_expired", profile.id.to_string())
                    .into(),
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                warn!(profile_id = %profile.id, error = %e, "Failed to end legacy migration");
                continue;
            }
        }

        info!(
            profile_id = %profile.id,
            deadline_days = deadline_days,
            "Migration deadline expired, legacy credential removed"
        );
        expired_count += 1;
    }

    expired_count
}

// ─── Closure execution (closing → Closed) ───────────────────────

/// Profile states in which a closure request is pending.
const CLOSING_STATES: [ProfileStatus; 3] = [
    ProfileStatus::ClosureRequested,
    ProfileStatus::ExportAvailable,
    ProfileStatus::GracePeriod,
];

/// One run of closure execution: every pending closure whose grace period
/// has ended and that no legal hold freezes is executed (cascade, principal
/// quarantine, deletion of principals, credentials and metadata, status
/// Closed). Returns the number of profiles closed.
pub async fn execute_due_closures(
    storage: &dyn StorageBackend,
    closures: &AccountClosureService,
) -> u64 {
    let mut closed = 0u64;
    for status in CLOSING_STATES {
        let profiles = match storage.list_profiles_with_status(status).await {
            Ok(p) => p,
            Err(e) => {
                warn!("Closure scan ({}) failed: {}", status, e);
                continue;
            }
        };
        for profile in &profiles {
            let request = match storage.get_closure_request(profile.id).await {
                Ok(Some(request)) => request,
                Ok(None) => {
                    warn!(profile_id = %profile.id, "Closing profile without a closure request");
                    continue;
                }
                Err(e) => {
                    warn!(profile_id = %profile.id, error = %e, "Closure request lookup failed");
                    continue;
                }
            };
            if request.legal_hold.is_some() || !request.grace_period_elapsed() {
                continue;
            }
            match closures.execute_closure(profile.id).await {
                Ok(()) => closed += 1,
                Err(e) => {
                    warn!(profile_id = %profile.id, error = %e, "Closure execution failed")
                }
            }
        }
    }
    // A closure stored as Closed whose erasure was interrupted is finished.
    match storage
        .list_profiles_with_status(ProfileStatus::Closed)
        .await
    {
        Ok(profiles) => {
            for profile in &profiles {
                match closures.erasure_pending(profile.id).await {
                    Ok(false) => {}
                    Ok(true) => {
                        if let Err(e) = closures.execute_closure(profile.id).await {
                            warn!(profile_id = %profile.id, error = %e, "Closure erasure failed");
                        }
                    }
                    Err(e) => {
                        warn!(profile_id = %profile.id, error = %e, "Closure erasure check failed")
                    }
                }
            }
        }
        Err(e) => warn!("Closure scan (closed) failed: {}", e),
    }
    if closed > 0 {
        info!("Executed {} account closure(s)", closed);
    }
    closed
}

// ─── Profile purge (Closed → Purged) ────────────────────────────

/// Whether a closed profile may be purged: its principals' quarantine
/// (counted from the end of the grace period, when the closure executes) is over.
pub fn quarantine_ended(request: &sid_core::models::ClosureRequest, now: DateTime<Utc>) -> bool {
    let closed_from = request.grace_period_end.unwrap_or(request.requested_at);
    now >= closed_from
        + chrono::Duration::days(i64::from(sid_core::models::IDENTIFIER_QUARANTINE_DAYS))
}

/// The purge the deletion of `profile` owes the history evaluator, to be
/// committed with the deletion; `None` when the installation has no
/// authority yet, and so no history domain any key could be under.
pub async fn owner_purge(
    storage: &dyn StorageBackend,
    profile: ProfileId,
) -> sid_core::Result<Option<NewWork>> {
    Ok(storage.instance_organization().await?.map(|org| {
        OwnerPurge {
            owner_domain: sid_authn::password_history::owner_domain(org.id.as_bytes(), profile),
        }
        .work()
    }))
}

/// One run of the profile purge: each `Closed` profile whose principal
/// quarantine has ended transitions to `Purged`. Returns the number purged.
pub async fn purge_closed_profiles(storage: &dyn StorageBackend) -> u64 {
    let profiles = match storage
        .list_profiles_with_status(ProfileStatus::Closed)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            warn!("Purge scan failed: {}", e);
            return 0;
        }
    };

    let mut purged_count = 0u64;
    let now = Utc::now();

    for profile in &profiles {
        match storage.get_closure_request(profile.id).await {
            Ok(Some(req)) if quarantine_ended(&req, now) => {
                let mut p = profile.clone();
                if p.transition_status(ProfileStatus::Purged).is_ok() {
                    let mut ctx: sid_core::models::MutationContext =
                        AuditEntry::system("profile.purged", profile.id.to_string()).into();
                    // The owner's history keys go with it, owed in the same
                    // transaction.
                    match owner_purge(storage, profile.id).await {
                        Ok(Some(purge)) => ctx = ctx.with_work(purge),
                        Ok(None) => {}
                        Err(e) => {
                            warn!(profile_id = %profile.id, error = %e, "Purge deferred");
                            continue;
                        }
                    }
                    match storage.update_profile(&p, ctx).await {
                        Ok(false) => {}
                        Ok(true) => {
                            info!(
                                profile_id = %profile.id,
                                "Profile purged (closure grace period elapsed)"
                            );
                            purged_count += 1;
                        }
                        Err(e) => {
                            warn!(
                                profile_id = %profile.id,
                                error = %e,
                                "Failed to purge profile"
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }

    purged_count
}

// ─── Quarantine cleanup ─────────────────────────────────────────

/// One run of quarantine cleanup; returns how many expired entries it removed.
pub async fn cleanup_quarantine(storage: &dyn StorageBackend) -> u64 {
    match storage
        .cleanup_expired_quarantine(
            AuditEntry::system("quarantine.cleanup", "background_task").into(),
        )
        .await
    {
        Ok(n) => {
            if n > 0 {
                info!("Quarantine cleanup: removed {} expired entries", n);
            }
            n
        }
        Err(e) => {
            warn!("Quarantine cleanup failed: {}", e);
            0
        }
    }
}

// ─── Ceremony state expiry ──────────────────────────────────────

/// Drop the ceremony state, admissions and counts past their deadline.
/// Use already refuses them; this reclaims their storage. Returns how many.
pub async fn purge_ceremony_state(store: &dyn sid_plugin::CeremonyStateStore) -> u64 {
    match store.purge_expired_ceremony_state().await {
        Ok(n) => n,
        Err(e) => {
            warn!("ceremony state expiry failed: {}", e);
            0
        }
    }
}

// ─── Personal access tokens ─────────────────────────────────────

/// Revoke the tokens unused past their allowed idle time; returns how many.
pub async fn revoke_unused_pats(storage: &dyn StorageBackend) -> u64 {
    match storage
        .revoke_unused_pats(
            sid_core::models::pat::PAT_AUTO_REVOKE_UNUSED_DAYS,
            AuditEntry::system("pat.auto_revoke_unused", "background_task").into(),
        )
        .await
    {
        Ok(0) => 0,
        Ok(n) => {
            info!("Auto-revoked {} unused PATs", n);
            n
        }
        Err(e) => {
            warn!("PAT auto-revoke failed: {}", e);
            0
        }
    }
}

// ─── Machine credential expiry ──────────────────────────────────

const CREDENTIAL_ALERT_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x9b47_2c1e_65fa_4d38_a0c2_e81f_3d96_7b54);

/// The id of a machine-credential alert: the same alert gets the same id, so
/// a repeated scan relays it once.
fn credential_alert_id(alert: &str) -> String {
    uuid::Uuid::new_v5(&CREDENTIAL_ALERT_NAMESPACE, alert.as_bytes()).to_string()
}

/// One scan of machine credentials expiring within the alert window at
/// `now`. Each alert is relayed as durable work whose id follows from the
/// credential (and the day count), so an expiry is announced once and each
/// day's warning once. Returns how many credentials it alerted about.
pub async fn alert_credential_expiry(
    storage: &dyn StorageBackend,
    source: &str,
    now: DateTime<Utc>,
) -> usize {
    use sid_core::models::event::{Event, event_types};
    let alert_days = sid_core::models::machine_user::CREDENTIAL_ALERT_BEFORE_EXPIRY_DAYS;
    let creds = match storage.list_expiring_machine_credentials(alert_days).await {
        Ok(creds) => creds,
        Err(e) => {
            warn!("Credential expiry scan failed: {}", e);
            return 0;
        }
    };
    for cred in &creds {
        let Some(exp) = cred.expires_at else {
            continue;
        };
        let event = if exp <= now {
            warn!(
                kid = %cred.kid,
                machine_user_id = %cred.machine_user_id,
                "Machine credential expired, should be revoked"
            );
            let mut event = Event::new(source, event_types::MACHINE_USER_CREDENTIAL_EXPIRED)
                .with_subject(format!("machine_credential/{}", cred.kid))
                .with_data(serde_json::json!({
                    "kid": cred.kid,
                    "machine_user_id": cred.machine_user_id,
                    "expired_at": exp.to_rfc3339(),
                }));
            event.id = credential_alert_id(&format!("expired:{}", cred.kid));
            event
        } else {
            let days_left = (exp - now).num_days();
            info!(
                kid = %cred.kid,
                machine_user_id = %cred.machine_user_id,
                days_left = days_left,
                "Machine credential expiring soon"
            );
            let mut event = Event::new(source, event_types::MACHINE_USER_CREDENTIAL_EXPIRING)
                .with_subject(format!("machine_credential/{}", cred.kid))
                .with_data(serde_json::json!({
                    "kid": cred.kid,
                    "machine_user_id": cred.machine_user_id,
                    "expires_at": exp.to_rfc3339(),
                    "days_left": days_left,
                }));
            event.id = credential_alert_id(&format!("expiring:{}:{days_left}", cred.kid));
            event
        };
        if let Err(e) = sid_authn::event_relay::relay_observed(storage, &event).await {
            warn!("Failed to relay credential expiry event: {}", e);
        }
    }
    if !creds.is_empty() {
        info!(
            "Credential expiry scan: {} credentials expiring/expired",
            creds.len()
        );
    }
    creds.len()
}

// ─── Role assignment expiry ─────────────────────────────────────

/// One run of role assignment expiry at `now`: each warning threshold is
/// announced once per assignment, and each removal owes its expired event in
/// the removal's own transaction.
pub async fn expire_role_assignments(storage: &dyn StorageBackend, now: DateTime<Utc>) {
    let thresholds = sid_core::models::authz::ROLE_EXPIRY_ALERT_HOURS;
    let max_window = *thresholds.first().unwrap_or(&72);
    match storage.list_expiring_role_assignments(max_window).await {
        Ok(assignments) => {
            for a in &assignments {
                let Some(exp) = a.expires_at.filter(|exp| *exp > now) else {
                    continue;
                };
                let hours_left = (exp - now).num_hours();
                // The thresholds descend: the last one reached is the
                // tightest warning due now.
                if let Some(&threshold) = thresholds.iter().rev().find(|&&t| hours_left <= t) {
                    let event = a.expiring_event(threshold, hours_left);
                    if let Err(e) = sid_authn::event_relay::relay_observed(storage, &event).await {
                        warn!("Failed to relay role_expiring event: {}", e);
                    }
                }
            }
        }
        Err(e) => warn!("Role expiry scan failed: {}", e),
    }

    match storage
        .cleanup_expired_role_assignments(
            AuditEntry::system("role_assignment.auto_revoke", "background_task").into(),
        )
        .await
    {
        Ok(removed) if removed.is_empty() => {}
        Ok(removed) => info!("Auto-revoked {} expired role assignments", removed.len()),
        Err(e) => warn!("Role assignment auto-revoke failed: {}", e),
    }
}

// ─── Audit partition auto-management ─────────────────────────────

/// One run of audit storage maintenance at `now`: the current and next
/// month get their storage ahead of time, and with the `delete` action the
/// months past retention are removed (whole months only, chains
/// checkpointed). With `archive` nothing is removed: records stay until an
/// archive holds them.
pub async fn manage_audit_partitions(
    storage: &dyn StorageBackend,
    retention: AuditRetention,
    now: DateTime<Utc>,
) -> sid_core::Result<u64> {
    use chrono::{Datelike, NaiveDate};
    let this_month = NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
        .ok_or_else(|| sid_core::Error::Internal(format!("no month start for {now}")))?;
    let next_month = this_month
        .checked_add_months(chrono::Months::new(1))
        .ok_or_else(|| sid_core::Error::Internal(format!("no month after {this_month}")))?;
    for month in [this_month, next_month] {
        if storage.ensure_audit_partition(month).await? {
            info!("Audit storage prepared for {month}");
        }
    }

    match retention.action {
        RetentionAction::Archive => Ok(0),
        RetentionAction::Delete => {
            let cut_before = now - chrono::Duration::days(i64::from(retention.days));
            let removed = storage
                .drop_expired_audit_records(
                    cut_before,
                    AuditEntry::system("audit.retention_cut", cut_before.to_rfc3339()).into(),
                )
                .await?;
            if removed > 0 {
                info!(removed, %cut_before, "Removed audit records past retention");
            }
            Ok(removed)
        }
    }
}

// ─── Principal verification expiry ─────────────────────────────

/// Expire principal verifications past their TTL: `verified = false` and no
/// owner for each. Returns how many it expired.
pub async fn expire_principal_verifications(storage: &dyn StorageBackend) -> i64 {
    match storage.expire_principal_verifications().await {
        Ok(n) => {
            if n > 0 {
                info!(
                    "Principal verification expiry: cleared {} expired verifications",
                    n
                );
            }
            n
        }
        Err(e) => {
            warn!("Principal verification expiry failed: {}", e);
            0
        }
    }
}

#[cfg(test)]
mod tests;
