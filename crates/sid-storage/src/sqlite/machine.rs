// SPDX-License-Identifier: AGPL-3.0-only
//! MachineUser, MachineUserCredential, and ImpersonationGrant operations for SQLite backend.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        MutationContext, ProjectId,
        machine_user::{
            ImpersonationGrant, MachineRestrictions, MachineUser, MachineUserCredential,
            MachineUserId, MachineUserStatus,
        },
    },
};

use super::{SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error, parsed_col};

/// A space-separated list column.
fn words(row: &sqlx::sqlite::SqliteRow, name: &str) -> SidResult<Vec<String>> {
    let raw: String = col(row, name)?;
    Ok(raw.split_whitespace().map(String::from).collect())
}

/// A non-negative count column.
fn count_col(row: &sqlx::sqlite::SqliteRow, name: &str) -> SidResult<u32> {
    let raw: i64 = col(row, name)?;
    u32::try_from(raw).map_err(|e| SidError::Storage(format!("column {name}: {e}")))
}

// Unknown stored values are errors, never an active service owned by a Profile.
fn row_to_machine_user(row: &sqlx::sqlite::SqliteRow) -> SidResult<MachineUser> {
    let project_id: String = col(row, "project_id")?;
    let max_token_lifetime: Option<i64> = col(row, "max_token_lifetime")?;
    Ok(MachineUser {
        id: col(row, "id")?,
        project_id: ProjectId(
            uuid::Uuid::parse_str(&project_id)
                .map_err(|e| SidError::Storage(format!("column project_id: {e}")))?,
        ),
        machine_type: parsed_col(row, "machine_type")?,
        owner_type: parsed_col(row, "owner_type")?,
        owner_id: col(row, "owner_id")?,
        client_id: col(row, "client_id")?,
        display_name: col(row, "display_name")?,
        description: col(row, "description")?,
        status: parsed_col(row, "status")?,
        scopes: words(row, "scopes")?,
        restrictions: MachineRestrictions {
            ip_allowlist: words(row, "ip_allowlist")?,
            rate_limit_rpm: count_col(row, "rate_limit_rpm")?,
        },
        max_token_lifetime: max_token_lifetime
            .map(|v| {
                u32::try_from(v)
                    .map_err(|e| SidError::Storage(format!("column max_token_lifetime: {e}")))
            })
            .transpose()?,
        expires_at: dt_col_opt(row, "expires_at")?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

// Unknown stored values are errors, never a usable client secret.
fn row_to_machine_credential(row: &sqlx::sqlite::SqliteRow) -> SidResult<MachineUserCredential> {
    Ok(MachineUserCredential {
        kid: col(row, "kid")?,
        machine_user_id: col(row, "machine_user_id")?,
        credential_type: parsed_col(row, "credential_type")?,
        status: parsed_col(row, "status")?,
        credential_data: col(row, "credential_data")?,
        algorithm: col(row, "algorithm")?,
        expires_at: dt_col_opt(row, "expires_at")?,
        created_at: dt_col(row, "created_at")?,
    })
}

// An unknown target type is an error, never a role-wide grant.
fn row_to_impersonation_grant(row: &sqlx::sqlite::SqliteRow) -> SidResult<ImpersonationGrant> {
    Ok(ImpersonationGrant {
        machine_user_id: col(row, "machine_user_id")?,
        target_type: parsed_col(row, "target_type")?,
        target: col(row, "target")?,
        allowed_scopes: words(row, "allowed_scopes")?,
        created_at: dt_col(row, "created_at")?,
    })
}

/// Insert a new credential; an existing kid is a `Conflict`, never an update.
async fn insert_machine_credential(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    cred: &MachineUserCredential,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO machine_user_credentials (kid, machine_user_id, credential_type, credential_data, algorithm, status, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&cred.kid)
    .bind(cred.machine_user_id)
    .bind(cred.credential_type.as_str())
    .bind(&cred.credential_data)
    .bind(&cred.algorithm)
    .bind(cred.status.as_str())
    .bind(fmt_dt_opt(cred.expires_at))
    .bind(fmt_dt(&cred.created_at))
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("machine credential", e))?;
    Ok(())
}

impl SqliteBackend {
    // === MachineUser ===

    pub(crate) async fn get_machine_user_impl(
        &self,
        id: MachineUserId,
    ) -> SidResult<Option<MachineUser>> {
        let row = sqlx::query("SELECT * FROM machine_users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_machine_user).transpose()
    }

    pub(crate) async fn get_machine_user_by_client_id_impl(
        &self,
        client_id: &str,
    ) -> SidResult<Option<MachineUser>> {
        let row = sqlx::query("SELECT * FROM machine_users WHERE client_id = ?")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_machine_user).transpose()
    }

    pub(crate) async fn update_machine_user_impl(
        &self,
        mu: &MachineUser,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let updated = sqlx::query(
            "UPDATE machine_users SET display_name = ?, description = ?, scopes = ?,
                ip_allowlist = ?, rate_limit_rpm = ?, max_token_lifetime = ?, expires_at = ?,
                updated_at = ?
             WHERE id = ? AND status <> 'deleted'",
        )
        .bind(&mu.display_name)
        .bind(&mu.description)
        .bind(mu.scopes.join(" "))
        .bind(mu.restrictions.ip_allowlist.join(" "))
        .bind(mu.restrictions.rate_limit_rpm as i32)
        .bind(mu.max_token_lifetime.map(|v| v as i32))
        .bind(fmt_dt_opt(mu.expires_at))
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(mu.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("machine_user:{}", mu.id), audit).await?;
        Ok(true)
    }

    pub(crate) async fn transition_machine_user_impl(
        &self,
        id: MachineUserId,
        from: MachineUserStatus,
        to: MachineUserStatus,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let moved = sqlx::query(
            "UPDATE machine_users SET status = ?, updated_at = ? WHERE id = ? AND status = ?",
        )
        .bind(to.as_str())
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(id)
        .bind(from.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected()
            == 1;
        if !moved {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("machine_user:{id}"), audit).await?;
        Ok(true)
    }

    pub(crate) async fn create_machine_user_impl(
        &self,
        mu: &MachineUser,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO machine_users (id, project_id, machine_type, owner_type, owner_id, client_id, display_name, description, status, scopes, ip_allowlist, rate_limit_rpm, max_token_lifetime, expires_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ).bind(mu.id)
        .bind(mu.project_id.0.to_string())
        .bind(mu.machine_type.as_str())
        .bind(mu.owner_type.as_str())
        .bind(&mu.owner_id)
        .bind(&mu.client_id)
        .bind(&mu.display_name)
        .bind(&mu.description)
        .bind(mu.status.as_str())
        .bind(mu.scopes.join(" "))
        .bind(mu.restrictions.ip_allowlist.join(" "))
        .bind(mu.restrictions.rate_limit_rpm as i32)
        .bind(mu.max_token_lifetime.map(|v| v as i32))
        .bind(fmt_dt_opt(mu.expires_at))
        .bind(fmt_dt(&mu.created_at))
        .bind(fmt_dt(&mu.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("machine user", e))?;
        Self::commit_mutation(tx, &format!("machine_user:{}", mu.id), audit).await
    }

    pub(crate) async fn delete_machine_user_impl(
        &self,
        id: MachineUserId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("UPDATE machine_users SET status = 'deleted' WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // A deleted machine user keeps its row but no access to any resource.
        sqlx::query(
            "DELETE FROM resource_access WHERE machine_client_id =
                 (SELECT client_id FROM machine_users WHERE id = ?)",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("machine_user:{id}"), audit).await
    }

    pub(crate) async fn list_machine_users_by_project_impl(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Vec<MachineUser>> {
        let rows = sqlx::query("SELECT * FROM machine_users WHERE project_id = ?")
            .bind(project_id.0.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_machine_user).collect()
    }

    // === MachineUserCredential ===

    pub(crate) async fn get_machine_credential_by_kid_impl(
        &self,
        kid: &str,
    ) -> SidResult<Option<MachineUserCredential>> {
        let row = sqlx::query("SELECT * FROM machine_user_credentials WHERE kid = ?")
            .bind(kid)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_machine_credential).transpose()
    }

    pub(crate) async fn add_machine_credential_impl(
        &self,
        cred: &MachineUserCredential,
        active_limit: Option<u64>,
        audit: MutationContext,
    ) -> SidResult<()> {
        // BEGIN IMMEDIATE: the count and the insert are one step.
        let mut tx = self.begin_write().await?;
        if let Some(limit) = active_limit {
            let usable: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM machine_user_credentials
                 WHERE machine_user_id = ? AND status IN ('active', 'grace_period')",
            )
            .bind(cred.machine_user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
            // COUNT(*) is never negative.
            if usable as u64 >= limit {
                return Err(SidError::ResourceExhausted(format!(
                    "machine user already holds {limit} usable credentials"
                )));
            }
        }
        insert_machine_credential(&mut tx, cred).await?;
        Self::commit_mutation(tx, &format!("machine_cred:{}", cred.kid), audit).await
    }

    pub(crate) async fn rotate_machine_credential_impl(
        &self,
        machine_user_id: MachineUserId,
        old_kid: &str,
        new: &MachineUserCredential,
        grace_until: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        // Read under the write lock: the grace ends at the credential's own
        // expiry when that comes first.
        let current: Option<Option<String>> = sqlx::query_scalar(
            "SELECT expires_at FROM machine_user_credentials
             WHERE kid = ? AND machine_user_id = ? AND status = 'active'",
        )
        .bind(old_kid)
        .bind(machine_user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        let Some(current) = current else {
            return Ok(false);
        };
        let ends = match super::parse_dt_opt(current) {
            Some(own) if own < grace_until => own,
            _ => grace_until,
        };
        let moved = sqlx::query(
            "UPDATE machine_user_credentials SET status = 'grace_period', expires_at = ?
             WHERE kid = ? AND machine_user_id = ? AND status = 'active'",
        )
        .bind(super::fmt_dt(&ends))
        .bind(old_kid)
        .bind(machine_user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected()
            == 1;
        if !moved {
            return Ok(false);
        }
        insert_machine_credential(&mut tx, new).await?;
        Self::commit_mutation(tx, &format!("machine_cred:{old_kid}"), audit).await?;
        Ok(true)
    }

    pub(crate) async fn revoke_machine_credential_impl(
        &self,
        machine_user_id: MachineUserId,
        kid: &str,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let revoked = sqlx::query(
            "UPDATE machine_user_credentials SET status = 'revoked'
             WHERE kid = ? AND machine_user_id = ? AND status IN ('active', 'grace_period')",
        )
        .bind(kid)
        .bind(machine_user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected()
            == 1;
        if !revoked {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("machine_cred:{kid}"), audit).await?;
        Ok(true)
    }

    pub(crate) async fn revoke_active_machine_credentials_by_user_impl(
        &self,
        id: MachineUserId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        let result = sqlx::query(
            "UPDATE machine_user_credentials SET status = 'revoked' WHERE machine_user_id = ? AND status IN ('active', 'grace_period')",
        ).bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("machine_cred:cascade_revoke:user:{id}"), audit).await?;
        Ok(result.rows_affected())
    }

    pub(crate) async fn list_machine_credentials_by_user_impl(
        &self,
        id: MachineUserId,
    ) -> SidResult<Vec<MachineUserCredential>> {
        let rows = sqlx::query("SELECT * FROM machine_user_credentials WHERE machine_user_id = ?")
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_machine_credential).collect()
    }

    pub(crate) async fn list_expiring_machine_credentials_impl(
        &self,
        within_days: u32,
    ) -> SidResult<Vec<MachineUserCredential>> {
        let cutoff = chrono::Utc::now() + chrono::Duration::days(within_days as i64);
        let cutoff_str = fmt_dt(&cutoff);
        let rows = sqlx::query(
            "SELECT * FROM machine_user_credentials WHERE status = 'active' AND (expires_at IS NOT NULL AND expires_at <= ?)",
        )
        .bind(&cutoff_str)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_machine_credential).collect()
    }

    // === ImpersonationGrant ===

    pub(crate) async fn save_impersonation_grant_impl(
        &self,
        grant: &ImpersonationGrant,
        audit: MutationContext,
    ) -> SidResult<()> {
        let id = uuid::Uuid::now_v7();
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO impersonation_grants (id, machine_user_id, target_type, target, allowed_scopes, created_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(machine_user_id, target_type, target) DO UPDATE SET
                allowed_scopes=excluded.allowed_scopes"
        )
        .bind(id.to_string()).bind(grant.machine_user_id)
        .bind(grant.target_type.as_str())
        .bind(&grant.target)
        .bind(grant.allowed_scopes.join(" "))
        .bind(fmt_dt(&grant.created_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(
            tx,
            &format!("impersonation_grant:{}", grant.machine_user_id),
            audit,
        )
        .await
    }

    pub(crate) async fn delete_impersonation_grant_impl(
        &self,
        machine_user_id: MachineUserId,
        target_type: &str,
        target: &str,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "DELETE FROM impersonation_grants WHERE machine_user_id = ? AND target_type = ? AND target = ?",
        ).bind(machine_user_id)
        .bind(target_type)
        .bind(target)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("impersonation_grant:{machine_user_id}"), audit).await
    }

    pub(crate) async fn list_impersonation_grants_impl(
        &self,
        machine_user_id: MachineUserId,
    ) -> SidResult<Vec<ImpersonationGrant>> {
        let rows = sqlx::query("SELECT * FROM impersonation_grants WHERE machine_user_id = ?")
            .bind(machine_user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_impersonation_grant).collect()
    }
}
