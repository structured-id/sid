// SPDX-License-Identifier: AGPL-3.0-only
//! Extracted background task logic for testability.
//!
//! Each function performs a single scan iteration (no loop).
//! The `tokio::spawn` loop in `main.rs` calls these once per interval.

use chrono::{DateTime, Duration, Utc};
use sid_core::models::{AuditEntry, Profile, ProfileStatus};
use sid_plugin::storage::StorageBackend;
use tracing::{info, warn};

/// Default migration deadline in days (overridden by SID_MIGRATION_DEADLINE_DAYS).
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

impl AuditRetention {
    /// `SID_AUDIT_RETENTION_DAYS` (default 365, 1 to 36500) and
    /// `SID_AUDIT_RETENTION_ACTION` (`archive`, the default, or `delete`);
    /// anything else is an error, never a silent default.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let days = match get("SID_AUDIT_RETENTION_DAYS") {
            None => 365,
            Some(v) => v
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|d| (1..=36500).contains(d))
                .ok_or_else(|| {
                    format!("SID_AUDIT_RETENTION_DAYS must be 1 to 36500 days, got {v:?}")
                })?,
        };
        let action = match get("SID_AUDIT_RETENTION_ACTION").as_deref().map(str::trim) {
            None | Some("archive") => RetentionAction::Archive,
            Some("delete") => RetentionAction::Delete,
            Some(other) => {
                return Err(format!(
                    "SID_AUDIT_RETENTION_ACTION must be archive or delete, got {other:?}"
                ));
            }
        };
        Ok(Self { days, action })
    }
}

// ─── Migration deadline enforcement ─────────────────────────────

/// Check if a profile's migration deadline has expired.
///
/// Returns `true` if the profile was started at least `deadline_days` ago.
pub fn is_migration_expired(profile: &Profile, deadline_days: i64, now: DateTime<Utc>) -> bool {
    let started = profile.migration_started_at.unwrap_or(profile.created_at);
    let deadline = started + Duration::days(deadline_days);
    now >= deadline
}

/// Run one iteration of migration deadline enforcement.
///
/// Each profile with `migration_pending = true` past `deadline_days` has its
/// flag cleared and its legacy password hashes deleted in one write, over the
/// revision listed (a profile changed since is seen again on the next run).
///
/// Returns the number of profiles expired.
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

/// Run one iteration of closure execution: every pending closure whose grace
/// period has ended and that no legal hold freezes is executed (cascade,
/// principal quarantine, deletion of principals, credentials and metadata,
/// status Closed). Returns the number of profiles closed.
pub async fn execute_due_closures(
    storage: &dyn StorageBackend,
    closures: &sid_authn::account_closure::AccountClosureService,
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
    now >= closed_from + Duration::days(i64::from(sid_core::models::IDENTIFIER_QUARANTINE_DAYS))
}

/// Run one iteration of profile purge scan: each `Closed` profile whose
/// principal quarantine has ended transitions to `Purged`.
///
/// Returns the number of profiles purged.
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
                    match crate::grpc::password_operation::owner_purge(storage, profile.id).await {
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

/// Run one iteration of quarantine cleanup.
///
/// Returns the number of expired quarantine entries removed.
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

// ─── Audit partition auto-management ─────────────────────────────

/// One run of audit storage maintenance at `now`: the current and next
/// month get their storage ahead of time, and with the `delete` action the
/// months past retention are removed (whole months only, chains
/// checkpointed). With `archive` nothing is removed: records stay until an
/// archive holds them. Called daily under the `LOCK_AUDIT_PARTITION` job lock.
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
            let cut_before = now - Duration::days(i64::from(retention.days));
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

/// Expire principal verifications past their TTL.
///
/// Called daily under the `LOCK_PRINCIPAL_EXPIRY` job lock.
/// Sets `verified = false`, `owner_profile_id = NULL` for expired principals.
/// Returns the number of expired principals.
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
