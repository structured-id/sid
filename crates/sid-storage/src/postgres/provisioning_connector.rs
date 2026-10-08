// SPDX-License-Identifier: AGPL-3.0-only
//! Provisioning connectors and their credentials.

use chrono::{DateTime, Utc};
use sid_core::models::machine_user::CredentialStatus;
use sid_core::models::provisioning_connector::MAX_USABLE_CONNECTOR_CREDENTIALS;
use sid_core::models::{
    ActorFence, ConnectorCredentialKind, ConnectorState, MutationContext, OrgId,
    ProvisioningConnector, ProvisioningConnectorId, ProvisioningCredential,
    ProvisioningCredentialId, ProvisioningDirection,
};
use sid_core::{Error as SidError, Result as SidResult};
use uuid::Uuid;

use super::{PostgresBackend, insert_error};

type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

fn failed(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

fn stored<T: std::str::FromStr<Err = String>>(value: &str) -> SidResult<T> {
    value.parse().map_err(SidError::Storage)
}

#[derive(sqlx::FromRow)]
struct ConnectorRow {
    id: ProvisioningConnectorId,
    org_id: Uuid,
    direction: String,
    client_id: String,
    display_name: String,
    state: String,
    revision: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl ConnectorRow {
    fn into_domain(self) -> SidResult<ProvisioningConnector> {
        Ok(ProvisioningConnector {
            id: self.id,
            org_id: OrgId::from_uuid(self.org_id)
                .map_err(|e| SidError::Storage(format!("connector org: {e}")))?,
            direction: stored::<ProvisioningDirection>(&self.direction)?,
            client_id: self.client_id,
            display_name: self.display_name,
            state: stored::<ConnectorState>(&self.state)?,
            revision: self.revision,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct CredentialRow {
    id: ProvisioningCredentialId,
    connector_id: ProvisioningConnectorId,
    kind: String,
    status: String,
    verifier: String,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl CredentialRow {
    fn into_domain(self) -> SidResult<ProvisioningCredential> {
        Ok(ProvisioningCredential {
            id: self.id,
            connector_id: self.connector_id,
            kind: stored::<ConnectorCredentialKind>(&self.kind)?,
            status: stored::<CredentialStatus>(&self.status)?,
            verifier: self.verifier,
            expires_at: self.expires_at,
            created_at: self.created_at,
        })
    }
}

impl PostgresBackend {
    /// Fail with `Fenced` unless `fence` still holds in this transaction. The
    /// connector and credential rows are share-locked until the transaction
    /// ends, so a concurrent disable, grant change or revocation either waits
    /// for this write or is seen by it.
    pub(super) async fn check_fence(tx: &mut Tx<'_>, fence: &ActorFence) -> SidResult<()> {
        let ActorFence::Connector {
            connector,
            revision,
            credential,
        } = *fence;
        let held = sqlx::query(
            "SELECT 1 FROM provisioning_connectors c
             JOIN provisioning_credentials k ON k.connector_id = c.id
             WHERE c.id = $1 AND k.id = $2 AND c.revision = $3 AND c.state = 'active'
               AND k.status IN ('active', 'grace_period')
               AND (k.expires_at IS NULL OR k.expires_at > NOW())
             FOR SHARE",
        )
        .bind(connector)
        .bind(credential)
        .bind(revision)
        .fetch_optional(&mut **tx)
        .await
        .map_err(failed("check connector fence"))?
        .is_some();
        if held {
            Ok(())
        } else {
            Err(SidError::Fenced(format!(
                "connector {connector} changed since it was authorized"
            )))
        }
    }

    /// Advance `connector`'s revision in this transaction: its grants
    /// changed, so writes authorized before no longer hold.
    pub(super) async fn bump_connector_revision(
        tx: &mut Tx<'_>,
        connector: ProvisioningConnectorId,
    ) -> SidResult<()> {
        sqlx::query(
            "UPDATE provisioning_connectors SET revision = revision + 1, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(connector)
        .execute(&mut **tx)
        .await
        .map_err(failed("advance connector revision"))?;
        Ok(())
    }

    async fn connector_tx(&self) -> SidResult<Tx<'_>> {
        self.pool.begin().await.map_err(failed("begin"))
    }

    async fn connector_commit(tx: Tx<'_>) -> SidResult<()> {
        tx.commit().await.map_err(failed("commit"))
    }

    pub(super) async fn connector_get(
        &self,
        id: ProvisioningConnectorId,
    ) -> SidResult<Option<ProvisioningConnector>> {
        sqlx::query_as::<_, ConnectorRow>("SELECT * FROM provisioning_connectors WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(failed("read connector"))?
            .map(ConnectorRow::into_domain)
            .transpose()
    }

    pub(super) async fn connector_by_client_id(
        &self,
        client_id: &str,
    ) -> SidResult<Option<ProvisioningConnector>> {
        sqlx::query_as::<_, ConnectorRow>(
            "SELECT * FROM provisioning_connectors WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(failed("read connector by client id"))?
        .map(ConnectorRow::into_domain)
        .transpose()
    }

    pub(super) async fn connector_list(
        &self,
        org_id: OrgId,
    ) -> SidResult<Vec<ProvisioningConnector>> {
        sqlx::query_as::<_, ConnectorRow>(
            "SELECT * FROM provisioning_connectors WHERE org_id = $1
             ORDER BY created_at DESC, id DESC",
        )
        .bind(org_id)
        .fetch_all(&self.pool)
        .await
        .map_err(failed("list connectors"))?
        .into_iter()
        .map(ConnectorRow::into_domain)
        .collect()
    }

    pub(super) async fn connector_create(
        &self,
        c: &ProvisioningConnector,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.connector_tx().await?;
        sqlx::query(
            "INSERT INTO provisioning_connectors
                 (id, org_id, direction, client_id, display_name, state, revision,
                  created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(c.id)
        .bind(c.org_id)
        .bind(c.direction.as_str())
        .bind(&c.client_id)
        .bind(&c.display_name)
        .bind(c.state.as_str())
        .bind(c.revision)
        .bind(c.created_at)
        .bind(c.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("provisioning connector", e))?;
        Self::audit_in_tx(&mut tx, &format!("provisioning_connector:{}", c.id), ctx).await?;
        Self::connector_commit(tx).await
    }

    pub(super) async fn connector_rename(
        &self,
        id: ProvisioningConnectorId,
        revision: i64,
        display_name: &str,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.connector_tx().await?;
        let renamed = sqlx::query(
            "UPDATE provisioning_connectors
             SET display_name = $3, revision = revision + 1, updated_at = NOW()
             WHERE id = $1 AND revision = $2 AND state <> 'retired'",
        )
        .bind(id)
        .bind(revision)
        .bind(display_name)
        .execute(&mut *tx)
        .await
        .map_err(failed("rename connector"))?
        .rows_affected()
            == 1;
        if !renamed {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("provisioning_connector:{id}"), ctx).await?;
        Self::connector_commit(tx).await?;
        Ok(true)
    }

    pub(super) async fn connector_transition(
        &self,
        id: ProvisioningConnectorId,
        from: ConnectorState,
        to: ConnectorState,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        if !from.may_become(to) {
            return Ok(false);
        }
        let mut tx = self.connector_tx().await?;
        let moved = sqlx::query(
            "UPDATE provisioning_connectors
             SET state = $3, revision = revision + 1, updated_at = NOW()
             WHERE id = $1 AND state = $2",
        )
        .bind(id)
        .bind(from.as_str())
        .bind(to.as_str())
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
                 WHERE connector_id = $1 AND status IN ('active', 'grace_period')",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(failed("revoke retired connector's credentials"))?;
        }
        Self::audit_in_tx(&mut tx, &format!("provisioning_connector:{id}"), ctx).await?;
        Self::connector_commit(tx).await?;
        Ok(true)
    }

    async fn insert_credential(tx: &mut Tx<'_>, cred: &ProvisioningCredential) -> SidResult<()> {
        sqlx::query(
            "INSERT INTO provisioning_credentials
                 (id, connector_id, kind, status, verifier, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(cred.id)
        .bind(cred.connector_id)
        .bind(cred.kind.as_str())
        .bind(cred.status.as_str())
        .bind(&cred.verifier)
        .bind(cred.expires_at)
        .bind(cred.created_at)
        .execute(&mut **tx)
        .await
        .map_err(|e| insert_error("provisioning credential", e))?;
        Ok(())
    }

    /// Lock an active connector for this transaction: concurrent credential
    /// changes of one connector apply one after another. False when it is
    /// missing or not active.
    async fn lock_active_connector(
        tx: &mut Tx<'_>,
        id: ProvisioningConnectorId,
    ) -> SidResult<bool> {
        Ok(sqlx::query(
            "SELECT 1 FROM provisioning_connectors
             WHERE id = $1 AND state = 'active' FOR NO KEY UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(failed("lock connector"))?
        .is_some())
    }

    pub(super) async fn connector_add_credential(
        &self,
        cred: &ProvisioningCredential,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.connector_tx().await?;
        if !Self::lock_active_connector(&mut tx, cred.connector_id).await? {
            return Ok(false);
        }
        let (usable,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM provisioning_credentials
             WHERE connector_id = $1 AND status IN ('active', 'grace_period')",
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
        Self::insert_credential(&mut tx, cred).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("provisioning_credential:{}", cred.id),
            ctx,
        )
        .await?;
        Self::connector_commit(tx).await?;
        Ok(true)
    }

    pub(super) async fn connector_rotate_credential(
        &self,
        connector_id: ProvisioningConnectorId,
        old: ProvisioningCredentialId,
        new: &ProvisioningCredential,
        grace_until: DateTime<Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.connector_tx().await?;
        if !Self::lock_active_connector(&mut tx, connector_id).await? {
            return Ok(false);
        }
        let moved = sqlx::query(
            "UPDATE provisioning_credentials SET status = 'grace_period', expires_at = $3
             WHERE id = $1 AND connector_id = $2 AND status = 'active'",
        )
        .bind(old)
        .bind(connector_id)
        .bind(grace_until)
        .execute(&mut *tx)
        .await
        .map_err(failed("rotate connector credential"))?
        .rows_affected()
            == 1;
        if !moved {
            return Ok(false);
        }
        Self::insert_credential(&mut tx, new).await?;
        Self::audit_in_tx(&mut tx, &format!("provisioning_credential:{old}"), ctx).await?;
        Self::connector_commit(tx).await?;
        Ok(true)
    }

    pub(super) async fn connector_revoke_credential(
        &self,
        connector_id: ProvisioningConnectorId,
        id: ProvisioningCredentialId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.connector_tx().await?;
        let revoked = sqlx::query(
            "UPDATE provisioning_credentials SET status = 'revoked'
             WHERE id = $1 AND connector_id = $2 AND status IN ('active', 'grace_period')",
        )
        .bind(id)
        .bind(connector_id)
        .execute(&mut *tx)
        .await
        .map_err(failed("revoke connector credential"))?
        .rows_affected()
            == 1;
        if !revoked {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("provisioning_credential:{id}"), ctx).await?;
        Self::connector_commit(tx).await?;
        Ok(true)
    }

    pub(super) async fn connector_list_credentials(
        &self,
        connector_id: ProvisioningConnectorId,
    ) -> SidResult<Vec<ProvisioningCredential>> {
        sqlx::query_as::<_, CredentialRow>(
            "SELECT * FROM provisioning_credentials WHERE connector_id = $1
             ORDER BY created_at DESC, id DESC",
        )
        .bind(connector_id)
        .fetch_all(&self.pool)
        .await
        .map_err(failed("list connector credentials"))?
        .into_iter()
        .map(CredentialRow::into_domain)
        .collect()
    }

    pub(super) async fn connector_find_credential(
        &self,
        verifier: &str,
    ) -> SidResult<Option<(ProvisioningCredential, ProvisioningConnector)>> {
        let Some(cred) = sqlx::query_as::<_, CredentialRow>(
            "SELECT * FROM provisioning_credentials WHERE verifier = $1",
        )
        .bind(verifier)
        .fetch_optional(&self.pool)
        .await
        .map_err(failed("find connector credential"))?
        else {
            return Ok(None);
        };
        let cred = cred.into_domain()?;
        let connector = self
            .connector_get(cred.connector_id)
            .await?
            .ok_or_else(|| {
                SidError::Storage(format!("credential {} names no connector", cred.id))
            })?;
        Ok(Some((cred, connector)))
    }
}
