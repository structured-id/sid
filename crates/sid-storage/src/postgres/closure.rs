// SPDX-License-Identifier: AGPL-3.0-only
//! A profile's closure request, written inside the transaction that moves the
//! profile's status.

use sid_core::models::ClosureRequest;
use sid_core::{Error as SidError, Result as SidResult};

use super::insert_error;

type Tx<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// What an insert does when the profile already has a closure request.
#[derive(Clone, Copy)]
pub(super) enum OnExisting {
    Refuse,
    /// The new request takes the stored one's place; its cancel count and
    /// legal hold stay, since the cancel limit and a hold outlive a request.
    Replace,
}

pub(super) async fn insert(
    tx: &mut Tx<'_>,
    req: &ClosureRequest,
    on_existing: OnExisting,
) -> SidResult<()> {
    let legal_hold = req
        .legal_hold
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|e| SidError::Storage(format!("legal_hold encode failed: {e}")))?;
    let cancel_count = i32::try_from(req.cancel_count).map_err(|_| {
        SidError::Validation(format!("cancel count {} out of range", req.cancel_count))
    })?;
    let sql = match on_existing {
        OnExisting::Refuse => {
            "INSERT INTO closure_requests (profile_id, mode, closure_reason, requested_by,
                requested_at, grace_period_end, export_status, cancel_count, legal_hold)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        }
        OnExisting::Replace => {
            "INSERT INTO closure_requests (profile_id, mode, closure_reason, requested_by,
                requested_at, grace_period_end, export_status, cancel_count, legal_hold)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (profile_id) DO UPDATE SET
                mode = EXCLUDED.mode,
                closure_reason = EXCLUDED.closure_reason,
                requested_by = EXCLUDED.requested_by,
                requested_at = EXCLUDED.requested_at,
                grace_period_end = EXCLUDED.grace_period_end,
                export_status = EXCLUDED.export_status"
        }
    };
    sqlx::query(sql)
        .bind(req.profile_id)
        .bind(req.mode.as_str())
        .bind(&req.closure_reason)
        .bind(req.requested_by)
        .bind(req.requested_at)
        .bind(req.grace_period_end)
        .bind(req.export_status.as_str())
        .bind(cancel_count)
        .bind(legal_hold)
        .execute(&mut **tx)
        .await
        .map_err(|e| insert_error("closure request", e))?;
    Ok(())
}
