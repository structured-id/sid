// SPDX-License-Identifier: AGPL-3.0-only
//! Audit log abstraction for tamper-evident logging.
//!
//! Services use `AuditLog::log()` to record auditable actions.
//! The trait handles chain assignment, hash computation, and storage.
//!
//! Implementation: PostgreSQL append-only table with hash chains.

use async_trait::async_trait;
use sid_core::models::audit::{AuditEntry, AuditError, AuditRecord};

/// Audit log trait for writing and querying audit records.
///
/// Audit writes are mandatory — if audit fails, the operation must roll back.
/// This is NOT best-effort like event publishing.
#[async_trait]
pub trait AuditLog: Send + Sync {
    /// Log an auditable action. Assigns chain, computes hash, persists record.
    ///
    /// `chain_id` is the hash chain scope (e.g., "profile:prof_01J8K...", "site:site_01J8K...").
    /// The implementation fetches the chain head, computes the next hash, and atomically
    /// appends the record.
    async fn log(&self, chain_id: &str, entry: AuditEntry) -> Result<AuditRecord, AuditError>;

    /// Query audit records for a chain within a time range.
    ///
    /// Records are returned in chronological order (oldest first).
    async fn query(
        &self,
        chain_id: &str,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<AuditRecord>, AuditError>;

    /// Verify the integrity of a chain (all hashes valid, all links intact).
    async fn verify_chain(&self, chain_id: &str) -> Result<VerifyResult, AuditError>;

    /// List all distinct chain IDs in the audit log.
    ///
    /// Used by integrity verification to enumerate chains for batch verification.
    async fn list_chain_ids(&self) -> Result<Vec<String>, AuditError>;
}

/// Result of chain verification.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// Whether the chain is valid.
    pub valid: bool,

    /// Number of records verified.
    pub records_verified: u64,

    /// ID of the first broken record (empty if valid).
    pub first_broken_record: Option<String>,
}

/// Verify a chain's records in sequence order: the first must link to
/// `start` (`"genesis"`, or the hash of the last record retention removed),
/// each to the one before it, and each must hash to its stored hash. A chain
/// missing its first records therefore fails instead of verifying.
pub fn verify_records(records: &[AuditRecord], start: String) -> VerifyResult {
    let mut expected = start;
    for (verified, record) in records.iter().enumerate() {
        if record.prev_hash != expected || !sid_core::models::audit::verify_record_hash(record) {
            return VerifyResult {
                valid: false,
                records_verified: verified as u64,
                first_broken_record: Some(record.id.clone()),
            };
        }
        expected.clone_from(&record.hash);
    }
    VerifyResult {
        valid: true,
        records_verified: records.len() as u64,
        first_broken_record: None,
    }
}

#[cfg(test)]
mod tests;
