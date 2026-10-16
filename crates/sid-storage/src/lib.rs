// SPDX-License-Identifier: AGPL-3.0-only
//! StructuredID Storage Backends
//!
//! Provides async, non-blocking storage implementations:
//! - PostgreSQL (sqlx for all CRUD + audit log + migrator) — `storage-pg` feature
//! - SQLite (for embedded-dev mode) — `storage-sqlite` feature
//!
//! All implementations are fully async and work with tokio event loop.

// PostgreSQL backend (default)
#[cfg(feature = "storage-pg")]
pub mod audit_log;
#[cfg(feature = "storage-pg")]
pub mod migrator;
#[cfg(feature = "storage-pg")]
pub mod pg_row;
#[cfg(feature = "storage-pg")]
pub mod postgres;

#[cfg(feature = "storage-pg")]
pub mod postgres_blob;

#[cfg(feature = "storage-pg")]
pub use postgres::{PgHistoryKeyStore, PgWorkStore, PostgresBackend};
#[cfg(feature = "storage-pg")]
pub use postgres_blob::PostgresBlobStore;

#[cfg(any(feature = "storage-pg", feature = "storage-sqlite"))]
mod directory_query;
#[cfg(any(feature = "storage-pg", feature = "storage-sqlite"))]
mod key_versions;
#[cfg(any(feature = "storage-pg", feature = "storage-sqlite"))]
mod policy_evidence;

/// Open work per kind a mutation may still add; beyond it the mutation is
/// refused rather than accepted without its obligation.
pub const OWED_WORK_CAPACITY: u64 = 100_000;

/// Whether a profile holds the `admin` role (`roles` is space-joined).
#[cfg(any(feature = "storage-pg", feature = "storage-sqlite"))]
const ADMIN_EXISTS_SQL: &str =
    "SELECT EXISTS (SELECT 1 FROM profiles WHERE ' ' || roles || ' ' LIKE '% admin %')";

/// Whether the installation is centrally managed (`bootstrap_policy` holds
/// its row).
#[cfg(any(feature = "storage-pg", feature = "storage-sqlite"))]
const CENTRALLY_MANAGED_SQL: &str = "SELECT EXISTS (SELECT 1 FROM bootstrap_policy)";

/// The installation's enrollment policy row.
#[cfg(any(feature = "storage-pg", feature = "storage-sqlite"))]
const ENROLLMENT_POLICY_SQL: &str = "SELECT mode, allowed_domains, track_source, \
     invite_default_max_uses, invite_default_expiry_hours \
     FROM enrollment_policy WHERE scope = 'installation'";

/// The PostgreSQL transaction-level advisory lock between a policy change
/// (exclusive) and the registrations it governs (shared): a registration
/// committed after a change was decided under it, and one in progress
/// holds the change back until it commits. A lock rather than a row lock,
/// because the row may not exist yet.
#[cfg(feature = "storage-pg")]
const ENROLLMENT_POLICY_LOCK: i64 = 0x5349_445f_454e_524f;

/// An enrollment policy write's failure: the schema's refusal of a
/// domain-restricted mode without a domain is the caller's to fix.
#[cfg(any(feature = "storage-pg", feature = "storage-sqlite"))]
fn enrollment_policy_write_error(e: sqlx::Error) -> sid_core::Error {
    let refused = e.as_database_error().is_some_and(|db| {
        db.constraint() == Some("enrollment_policy_domains_for_restricted_mode")
            || db
                .message()
                .contains("enrollment_policy_domains_for_restricted_mode")
    });
    if refused {
        sid_core::Error::Validation(
            "a domain-restricted enrollment mode needs an allowed domain".into(),
        )
    } else {
        sid_core::Error::Storage(format!("set enrollment policy: {e}"))
    }
}

/// The enrollment policy a stored row holds; a value the schema's checks
/// should have refused is an error, never read as a default.
#[cfg(any(feature = "storage-pg", feature = "storage-sqlite"))]
fn enrollment_policy_from_row(
    mode: &str,
    allowed_domains: Vec<String>,
    track_source: bool,
    max_uses: i64,
    expiry_hours: i64,
) -> sid_core::Result<sid_core::models::EnrollmentPolicy> {
    let stored = |what: &str, e: String| {
        sid_core::Error::Storage(format!("stored enrollment policy {what}: {e}"))
    };
    Ok(sid_core::models::EnrollmentPolicy {
        mode: mode.parse().map_err(|e| stored("mode", e))?,
        invite: sid_core::models::InviteConfig {
            default_max_uses: u32::try_from(max_uses)
                .map_err(|e| stored("invite max uses", e.to_string()))?,
            default_expiry_hours: u32::try_from(expiry_hours)
                .map_err(|e| stored("invite expiry", e.to_string()))?,
        },
        allowed_domains,
        track_source,
    })
}

/// How many email keys stay quarantined after the email policy cutover.
#[cfg(any(feature = "storage-pg", feature = "storage-sqlite"))]
const QUARANTINED_EMAIL_KEYS_SQL: &str =
    "SELECT COUNT(*) FROM email_policy_dispositions WHERE disposition = 'quarantined'";

/// Tell the operator, on every start while any remain, that email keys are
/// quarantined: reserved, routing no login and receiving no mail until their
/// owners establish the address again.
#[cfg(any(feature = "storage-pg", feature = "storage-sqlite"))]
fn warn_quarantined_email_keys(count: i64) {
    if count > 0 {
        tracing::warn!(
            quarantined = count,
            "email sign-in handles written before email policy revisions are quarantined \
             (table email_policy_dispositions); their owners sign in another way and \
             confirm the address again"
        );
    }
}

/// Refuse a closure of administrator `closing` when no other administrator
/// (`admins`: id and stored status of each) is active or suspended: the
/// instance would be left without one.
fn check_other_administrator(
    closing: sid_core::models::ProfileId,
    admins: &[(sid_core::models::ProfileId, String)],
) -> sid_core::Result<()> {
    let others = admins
        .iter()
        .filter(|(id, status)| *id != closing && matches!(status.as_str(), "active" | "suspended"))
        .count();
    if others == 0 {
        return Err(sid_core::Error::InvalidState(
            "the last administrator cannot request closure: assign another administrator first"
                .into(),
        ));
    }
    Ok(())
}

/// The time before which an IP reputation entry counts as stale for a decay
/// window of `older_than`; a window that no date can express is refused.
#[cfg(any(feature = "storage-pg", feature = "storage-sqlite"))]
fn decay_cutoff(
    older_than: std::time::Duration,
) -> sid_core::Result<chrono::DateTime<chrono::Utc>> {
    let refused =
        || sid_core::Error::Validation(format!("decay window {older_than:?} is out of range"));
    let window = chrono::Duration::from_std(older_than).map_err(|_| refused())?;
    chrono::Utc::now()
        .checked_sub_signed(window)
        .ok_or_else(refused)
}

// SQLite backend (embedded-dev mode)
#[cfg(feature = "storage-sqlite")]
pub mod sqlite;
