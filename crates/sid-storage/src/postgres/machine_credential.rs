// SPDX-License-Identifier: AGPL-3.0-only
//! Machine user credential rows.

use sid_core::Result as SidResult;
use sid_core::models::MachineUserCredential;

use super::insert_error;

/// Insert a new credential; an existing kid is a `Conflict`, never an update.
pub(super) async fn insert(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    cred: &MachineUserCredential,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO machine_user_credentials (kid, machine_user_id, credential_type,
            status, credential_data, algorithm, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&cred.kid)
    .bind(cred.machine_user_id)
    .bind(cred.credential_type.as_str())
    .bind(cred.status.as_str())
    .bind(&cred.credential_data)
    .bind(cred.algorithm.as_deref())
    .bind(cred.expires_at)
    .bind(cred.created_at)
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("machine credential", e))?;
    Ok(())
}
