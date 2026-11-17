// SPDX-License-Identifier: AGPL-3.0-only
//! Audit retention for SQLite: the records of months past retention are
//! deleted, with each chain's checkpoint recorded first (the delete trigger
//! allows removing records only below the recorded cut).

use jiff::Timestamp;
use jiff::tz::TimeZone;
use sid_core::models::MutationContext;
use sid_core::{Error as SidError, Result as SidResult};

use super::SqliteBackend;

impl SqliteBackend {
    pub(crate) async fn drop_expired_audit_records_impl(
        &self,
        cut_before: Timestamp,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        let boundary = cut_before
            .to_zoned_datetime(TimeZone::UTC)
            .date()
            .first_of_month()
            .to_zoned_datetime(TimeZone::UTC)
            .map(|z| z.timestamp())
            .map_err(|e| SidError::Validation(format!("no month start for {cut_before}: {e}")))?;
        // Audit timestamps are stored as RFC 3339 with milliseconds; the cut
        // uses the same form so the text comparison orders as time.
        let boundary = boundary.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO audit_chain_checkpoints (chain_id, sequence, hash, cut_before)
             SELECT r.chain_id, r.sequence, r.hash, ?1 FROM audit_records r
             WHERE r.timestamp < ?1
               AND r.sequence = (SELECT MAX(sequence) FROM audit_records
                                 WHERE chain_id = r.chain_id AND timestamp < ?1)
             ON CONFLICT(chain_id) DO UPDATE SET
                sequence = excluded.sequence, hash = excluded.hash,
                cut_before = excluded.cut_before
             WHERE excluded.sequence > audit_chain_checkpoints.sequence",
        )
        .bind(&boundary)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("audit checkpoint: {e}")))?;
        let removed = sqlx::query("DELETE FROM audit_records WHERE timestamp < ?")
            .bind(&boundary)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("audit retention: {e}")))?
            .rows_affected();
        if removed == 0 {
            return Ok(0);
        }
        Self::commit_mutation(tx, "site:audit_retention", ctx).await?;
        Ok(removed)
    }
}
