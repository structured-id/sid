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
pub use postgres::{PgWorkStore, PostgresBackend};
#[cfg(feature = "storage-pg")]
pub use postgres_blob::PostgresBlobStore;

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
