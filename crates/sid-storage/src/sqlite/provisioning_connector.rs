// SPDX-License-Identifier: AGPL-3.0-only
//! Provisioning connectors and their credentials for the SQLite backend.
//! Writes run under the backend's single-writer transaction, so a state
//! check, a count and the write it allows are one step.

use chrono::{DateTime, Utc};
use sid_core::models::provisioning_connector::MAX_USABLE_CONNECTOR_CREDENTIALS;
use sid_core::models::{
    ActorFence, ConnectorState, MutationContext, OrgId, ProvisioningConnector,
    ProvisioningConnectorId, ProvisioningCredential, ProvisioningCredentialId,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, insert_error, parsed_col};

type Tx<'a> = sqlx::Transaction<'a, sqlx::Sqlite>;

fn failed(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

// Unknown stored values are errors, never an active connector.
fn row_to_connector(row: &sqlx::sqlite::SqliteRow) -> SidResult<ProvisioningConnector> {
    Ok(ProvisioningConnector {
        id: col(row, "id")?,
        org_id: col(row, "org_id")?,
        direction: parsed_col(row, "direction")?,
        client_id: col(row, "client_id")?,
        display_name: col(row, "display_name")?,
        state: parsed_col(row, "state")?,
        revision: col(row, "revision")?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

// Unknown stored values are errors, never a usable credential.
fn row_to_credential(row: &sqlx::sqlite::SqliteRow) -> SidResult<ProvisioningCredential> {
    Ok(ProvisioningCredential {
        id: col(row, "id")?,
        connector_id: col(row, "connector_id")?,
        kind: parsed_col(row, "kind")?,
        status: parsed_col(row, "status")?,
        verifier: col(row, "verifier")?,
        expires_at: dt_col_opt(row, "expires_at")?,
        created_at: dt_col(row, "created_at")?,
    })
}

async fn insert_credential(tx: &mut Tx<'_>, cred: &ProvisioningCredential) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO provisioning_credentials
             (id, connector_id, kind, status, verifier, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(cred.id)
    .bind(cred.connector_id)
    .bind(cred.kind.as_str())
    .bind(cred.status.as_str())
    .bind(&cred.verifier)
    .bind(fmt_dt_opt(cred.expires_at))
    .bind(fmt_dt(&cred.created_at))
    .execute(&mut **tx)
    .await
    .map_err(|e| insert_error("provisioning credential", e))?;
    Ok(())
}

/// Whether the connector exists and is active, read in the write transaction.
async fn is_active(tx: &mut Tx<'_>, id: ProvisioningConnectorId) -> SidResult<bool> {
    Ok(
        sqlx::query("SELECT 1 FROM provisioning_connectors WHERE id = ? AND state = 'active'")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(failed("read connector state"))?
            .is_some(),
    )
}

/// Fail with `Fenced` unless `fence` still holds, read in the write
/// transaction (which holds the database write lock, so nothing changes the
/// connector before this write commits).
pub(super) async fn check_fence(tx: &mut Tx<'_>, fence: &ActorFence) -> SidResult<()> {
    let ActorFence::Connector {
        connector,
        revision,
        credential,
    } = *fence;
    let fenced = || {
        SidError::Fenced(format!(
            "connector {connector} changed since it was authorized"
        ))
    };
    let Some(row) = sqlx::query(
        "SELECT k.* FROM provisioning_connectors c
         JOIN provisioning_credentials k ON k.connector_id = c.id
         WHERE c.id = ? AND k.id = ? AND c.revision = ? AND c.state = 'active'",
    )
    .bind(connector)
    .bind(credential.to_string())
    .bind(revision)
    .fetch_optional(&mut **tx)
    .await
    .map_err(failed("check connector fence"))?
    else {
        return Err(fenced());
    };
    if row_to_credential(&row)?.is_usable_at(Utc::now()) {
        Ok(())
    } else {
        Err(fenced())
    }
}

/// Advance `connector`'s revision in this transaction: its grants changed,
/// so writes authorized before no longer hold.
pub(super) async fn bump_connector_revision(
    tx: &mut Tx<'_>,
    connector: ProvisioningConnectorId,
) -> SidResult<()> {
    sqlx::query(
        "UPDATE provisioning_connectors SET revision = revision + 1, updated_at = ?
         WHERE id = ?",
    )
    .bind(fmt_dt(&Utc::now()))
    .bind(connector)
    .execute(&mut **tx)
    .await
    .map_err(failed("advance connector revision"))?;
    Ok(())
}

impl SqliteBackend {
    pub(crate) async fn connector_get(
        &self,
        id: ProvisioningConnectorId,
    ) -> SidResult<Option<ProvisioningConnector>> {
        sqlx::query("SELECT * FROM provisioning_connectors WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(failed("read connector"))?
            .as_ref()
            .map(row_to_connector)
            .transpose()
    }

    pub(crate) async fn connector_by_client_id(
        &self,
        client_id: &str,
    ) -> SidResult<Option<ProvisioningConnector>> {
        sqlx::query("SELECT * FROM provisioning_connectors WHERE client_id = ?")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(failed("read connector by client id"))?
            .as_ref()
            .map(row_to_connector)
            .transpose()
    }

    pub(crate) async fn connector_list(
        &self,
        org_id: OrgId,
    ) -> SidResult<Vec<ProvisioningConnector>> {
        sqlx::query(
            "SELECT * FROM provisioning_connectors WHERE org_id = ?
             ORDER BY created_at DESC, id DESC",
        )
        .bind(org_id)
        .fetch_all(&self.pool)
        .await
        .map_err(failed("list connectors"))?
        .iter()
        .map(row_to_connector)
        .collect()
    }

    pub(crate) async fn connector_create(
        &self,
        c: &ProvisioningConnector,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO provisioning_connectors
                 (id, org_id, direction, client_id, display_name, state, revision,
                  created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(c.id)
        .bind(c.org_id)
        .bind(c.direction.as_str())
        .bind(&c.client_id)
        .bind(&c.display_name)
        .bind(c.state.as_str())
        .bind(c.revision)
        .bind(fmt_dt(&c.created_at))
        .bind(fmt_dt(&c.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("provisioning connector", e))?;
        Self::commit_mutation(tx, &format!("provisioning_connector:{}", c.id), ctx).await
    }

    pub(crate) async fn connector_rename(
        &self,
        id: ProvisioningConnectorId,
        revision: i64,
        display_name: &str,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let renamed = sqlx::query(
            "UPDATE provisioning_connectors
             SET display_name = ?, revision = revision + 1, updated_at = ?
             WHERE id = ? AND revision = ? AND state <> 'retired'",
        )
        .bind(display_name)
        .bind(fmt_dt(&Utc::now()))
        .bind(id)
        .bind(revision)
        .execute(&mut *tx)
        .await
        .map_err(failed("rename connector"))?
        .rows_affected()
            == 1;
        if !renamed {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("provisioning_connector:{id}"), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn connector_transition(
        &self,
        id: ProvisioningConnectorId,
        from: ConnectorState,
        to: ConnectorState,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        if !from.may_become(to) {
            return Ok(false);
        }
        let mut tx = self.begin_write().await?;
        let moved = sqlx::query(
            "UPDATE provisioning_connectors
             SET state = ?, revision = revision + 1, updated_at = ?
             WHERE id = ? AND state = ?",
        )
        .bind(to.as_str())
        .bind(fmt_dt(&Utc::now()))
        .bind(id)
        .bind(from.as_str())
        .execute(&mut *tx)
        .await
        .map_err(failed("change connector state"))?
        .rows_affected()
            == 1;
        if !moved {
            return Ok(false);
        }
        if to == ConnectorState::Retired {
            sqlx::query(
                "UPDATE provisioning_credentials SET status = 'revoked'
                 WHERE connector_id = ? AND status IN ('active', 'grace_period')",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(failed("revoke retired connector's credentials"))?;
        }
        Self::commit_mutation(tx, &format!("provisioning_connector:{id}"), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn connector_add_credential(
        &self,
        cred: &ProvisioningCredential,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        if !is_active(&mut tx, cred.connector_id).await? {
            return Ok(false);
        }
        let usable: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM provisioning_credentials
             WHERE connector_id = ? AND status IN ('active', 'grace_period')",
        )
        .bind(cred.connector_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(failed("count connector credentials"))?;
        // COUNT(*) is never negative.
        if usable as usize >= MAX_USABLE_CONNECTOR_CREDENTIALS {
            return Err(SidError::ResourceExhausted(format!(
                "connector already holds {MAX_USABLE_CONNECTOR_CREDENTIALS} usable credentials"
            )));
        }
        insert_credential(&mut tx, cred).await?;
        Self::commit_mutation(tx, &format!("provisioning_credential:{}", cred.id), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn connector_rotate_credential(
        &self,
        connector_id: ProvisioningConnectorId,
        old: ProvisioningCredentialId,
        new: &ProvisioningCredential,
        grace_until: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        if !is_active(&mut tx, connector_id).await? {
            return Ok(false);
        }
        let moved = sqlx::query(
            "UPDATE provisioning_credentials SET status = 'grace_period', expires_at = ?
             WHERE id = ? AND connector_id = ? AND status = 'active'",
        )
        .bind(fmt_dt(&grace_until))
        .bind(old.to_string())
        .bind(connector_id)
        .execute(&mut *tx)
        .await
        .map_err(failed("rotate connector credential"))?
        .rows_affected()
            == 1;
        if !moved {
            return Ok(false);
        }
        insert_credential(&mut tx, new).await?;
        Self::commit_mutation(tx, &format!("provisioning_credential:{old}"), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn connector_revoke_credential(
        &self,
        connector_id: ProvisioningConnectorId,
        id: ProvisioningCredentialId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let revoked = sqlx::query(
            "UPDATE provisioning_credentials SET status = 'revoked'
             WHERE id = ? AND connector_id = ? AND status IN ('active', 'grace_period')",
        )
        .bind(id.to_string())
        .bind(connector_id)
        .execute(&mut *tx)
        .await
        .map_err(failed("revoke connector credential"))?
        .rows_affected()
            == 1;
        if !revoked {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("provisioning_credential:{id}"), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn connector_list_credentials(
        &self,
        connector_id: ProvisioningConnectorId,
    ) -> SidResult<Vec<ProvisioningCredential>> {
        sqlx::query(
            "SELECT * FROM provisioning_credentials WHERE connector_id = ?
             ORDER BY created_at DESC, id DESC",
        )
        .bind(connector_id)
        .fetch_all(&self.pool)
        .await
        .map_err(failed("list connector credentials"))?
        .iter()
        .map(row_to_credential)
        .collect()
    }

    pub(crate) async fn connector_find_credential(
        &self,
        verifier: &str,
    ) -> SidResult<Option<(ProvisioningCredential, ProvisioningConnector)>> {
        let Some(row) = sqlx::query("SELECT * FROM provisioning_credentials WHERE verifier = ?")
            .bind(verifier)
            .fetch_optional(&self.pool)
            .await
            .map_err(failed("find connector credential"))?
        else {
            return Ok(None);
        };
        let cred = row_to_credential(&row)?;
        let connector = self
            .connector_get(cred.connector_id)
            .await?
            .ok_or_else(|| {
                SidError::Storage(format!("credential {} names no connector", cred.id))
            })?;
        Ok(Some((cred, connector)))
    }
}
