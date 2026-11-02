// SPDX-License-Identifier: AGPL-3.0-only
//! Applications, their protected-resource role and client-to-resource access.

use sid_core::models::{
    Application, ApplicationId, IssuerId, MutationContext, OAuth2Client, ProjectId,
    ProtectedResource, ResourceAccess, ResourceId, ResourceIndicator, ResourceState,
    SystemIntegration,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::{PostgresBackend, insert_error};
use crate::pg_row::{ApplicationRow, OAuth2ClientRow, ProtectedResourceRow, ResourceAccessRow};

type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

fn failed(what: &'static str) -> impl Fn(sqlx::Error) -> SidError {
    move |e| SidError::Storage(format!("{what}: {e}"))
}

fn revision(value: u64, what: &str) -> SidResult<i64> {
    i64::try_from(value).map_err(|e| SidError::Validation(format!("{what} revision: {e}")))
}

/// A new resource role must be live and name an application.
fn check_new_resource(resource: &ProtectedResource) -> SidResult<()> {
    if resource.application_id.is_none() || resource.state == ResourceState::Retired {
        return Err(SidError::Validation(format!(
            "protected resource {} is registered live, under an application",
            resource.id
        )));
    }
    Ok(())
}

impl PostgresBackend {
    async fn begin(&self) -> SidResult<Tx<'_>> {
        self.pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))
    }

    async fn commit(tx: Tx<'_>) -> SidResult<()> {
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))
    }

    pub(super) async fn insert_application_in_tx(
        tx: &mut Tx<'_>,
        app: &Application,
    ) -> SidResult<()> {
        sqlx::query(
            "INSERT INTO applications
                 (id, project_id, name, revision, created_at, updated_at, system_integration)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(app.id)
        .bind(app.project_id.0)
        .bind(&app.name)
        .bind(revision(app.revision, "application")?)
        .bind(app.created_at)
        .bind(app.updated_at)
        .bind(app.system.map(SystemIntegration::as_str))
        .execute(&mut **tx)
        .await
        .map_err(|e| insert_error("application", e))?;
        Ok(())
    }

    /// Insert a resource role; a taken indicator of the issuer or an
    /// application that already has a resource role is a `Conflict`.
    async fn insert_resource_in_tx(tx: &mut Tx<'_>, resource: &ProtectedResource) -> SidResult<()> {
        check_new_resource(resource)?;
        sqlx::query(
            "INSERT INTO protected_resources
                 (id, application_id, issuer_id, indicator, scopes, state, revision,
                  created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(resource.id)
        .bind(resource.application_id)
        .bind(resource.issuer_id)
        .bind(resource.indicator.as_str())
        .bind(resource.scopes.join(" "))
        .bind(resource.state.as_str())
        .bind(revision(resource.revision, "protected resource")?)
        .bind(resource.created_at)
        .bind(resource.updated_at)
        .execute(&mut **tx)
        .await
        .map_err(|e| insert_error("protected resource", e))?;
        Ok(())
    }

    pub(super) async fn create_application_impl(
        &self,
        app: &Application,
        client: Option<&OAuth2Client>,
        resource: Option<&ProtectedResource>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        if client.is_some_and(|c| c.application_id != app.id || c.project_id != app.project_id) {
            return Err(SidError::Validation(format!(
                "the client role of application {} names another application or project",
                app.id
            )));
        }
        if resource.is_some_and(|r| r.application_id != Some(app.id)) {
            return Err(SidError::Validation(format!(
                "the resource role of application {} names another application",
                app.id
            )));
        }
        let mut tx = self.begin().await?;
        Self::insert_application_in_tx(&mut tx, app).await?;
        // The resource first: the client may name it as its default.
        if let Some(resource) = resource {
            Self::insert_resource_in_tx(&mut tx, resource).await?;
        }
        if let Some(client) = client {
            Self::insert_oauth2_client_in_tx(&mut tx, client).await?;
        }
        Self::audit_in_tx(&mut tx, &format!("application:{}", app.id), ctx).await?;
        Self::commit(tx).await
    }

    pub(super) async fn get_application_impl(
        &self,
        id: ApplicationId,
    ) -> SidResult<Option<Application>> {
        sqlx::query_as::<_, ApplicationRow>("SELECT * FROM applications WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(failed("get application"))?
            .map(ApplicationRow::into_domain)
            .transpose()
    }

    pub(super) async fn system_application_impl(
        &self,
        kind: SystemIntegration,
    ) -> SidResult<Option<Application>> {
        sqlx::query_as::<_, ApplicationRow>(
            "SELECT * FROM applications WHERE system_integration = $1",
        )
        .bind(kind.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(failed("get system application"))?
        .map(ApplicationRow::into_domain)
        .transpose()
    }

    pub(super) async fn list_applications_by_project_impl(
        &self,
        project_id: ProjectId,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<Application>> {
        sqlx::query_as::<_, ApplicationRow>(
            "SELECT * FROM applications WHERE project_id = $1
             ORDER BY created_at, id OFFSET $2 LIMIT $3",
        )
        .bind(project_id.0)
        .bind(i64::try_from(offset).map_err(|e| SidError::Validation(format!("offset: {e}")))?)
        .bind(i64::try_from(limit).map_err(|e| SidError::Validation(format!("limit: {e}")))?)
        .fetch_all(&self.pool)
        .await
        .map_err(failed("list applications"))?
        .into_iter()
        .map(ApplicationRow::into_domain)
        .collect()
    }

    pub(super) async fn update_application_impl(
        &self,
        app: &Application,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin().await?;
        let written = sqlx::query(
            "UPDATE applications SET name = $2, updated_at = $3, revision = revision + 1
             WHERE id = $1 AND revision = $4 AND project_id = $5 AND created_at = $6",
        )
        .bind(app.id)
        .bind(&app.name)
        .bind(app.updated_at)
        .bind(revision(app.revision, "application")?)
        .bind(app.project_id.0)
        .bind(app.created_at)
        .execute(&mut *tx)
        .await
        .map_err(failed("update application"))?
        .rows_affected();
        if written != 1 {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("application:{}", app.id), ctx).await?;
        Self::commit(tx).await?;
        Ok(true)
    }

    pub(super) async fn delete_application_impl(
        &self,
        id: ApplicationId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin().await?;
        // The client role goes; its access rows go with it.
        sqlx::query("DELETE FROM oauth2_clients WHERE application_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(failed("delete client role"))?;
        // The resource role is retired, never deleted: its indicator stays
        // reserved. The row lock orders it after any access being granted.
        let retired: Option<(ResourceId,)> = sqlx::query_as(
            "UPDATE protected_resources
             SET state = 'retired', application_id = NULL, revision = revision + 1,
                 updated_at = NOW()
             WHERE application_id = $1 RETURNING id",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(failed("retire resource role"))?;
        if let Some((resource,)) = retired {
            sqlx::query("DELETE FROM resource_access WHERE resource_id = $1")
                .bind(resource)
                .execute(&mut *tx)
                .await
                .map_err(failed("delete access to a retired resource"))?;
            sqlx::query(
                "UPDATE oauth2_clients SET default_resource = NULL, revision = revision + 1
                 WHERE default_resource = $1",
            )
            .bind(resource)
            .execute(&mut *tx)
            .await
            .map_err(failed("clear a retired default resource"))?;
        }
        let deleted = sqlx::query("DELETE FROM applications WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(failed("delete application"))?
            .rows_affected();
        if deleted != 1 {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("application:{id}"), ctx).await?;
        Self::commit(tx).await?;
        Ok(true)
    }

    pub(super) async fn delete_oauth2_client_impl(
        &self,
        client_id: &str,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin().await?;
        let application: Option<(ApplicationId,)> = sqlx::query_as(
            "DELETE FROM oauth2_clients WHERE client_id = $1 RETURNING application_id",
        )
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(failed("delete oauth2 client"))?;
        if let Some((application,)) = application {
            // An application left without any role goes too.
            sqlx::query(
                "DELETE FROM applications WHERE id = $1 AND NOT EXISTS
                     (SELECT 1 FROM protected_resources WHERE application_id = $1)",
            )
            .bind(application)
            .execute(&mut *tx)
            .await
            .map_err(failed("delete role-less application"))?;
        }
        Self::audit_in_tx(&mut tx, &format!("oauth2_client:{client_id}"), ctx).await?;
        Self::commit(tx).await
    }

    pub(super) async fn oauth2_client_of_application_impl(
        &self,
        id: ApplicationId,
    ) -> SidResult<Option<OAuth2Client>> {
        sqlx::query_as::<_, OAuth2ClientRow>(
            "SELECT * FROM oauth2_clients WHERE application_id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(failed("get client role"))?
        .map(OAuth2ClientRow::into_domain)
        .transpose()
    }

    pub(super) async fn create_protected_resource_impl(
        &self,
        resource: &ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin().await?;
        Self::insert_resource_in_tx(&mut tx, resource).await?;
        Self::audit_in_tx(&mut tx, &format!("protected_resource:{}", resource.id), ctx).await?;
        Self::commit(tx).await
    }

    pub(super) async fn get_protected_resource_impl(
        &self,
        id: ResourceId,
    ) -> SidResult<Option<ProtectedResource>> {
        sqlx::query_as::<_, ProtectedResourceRow>("SELECT * FROM protected_resources WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(failed("get protected resource"))?
            .map(ProtectedResourceRow::into_domain)
            .transpose()
    }

    pub(super) async fn protected_resource_of_application_impl(
        &self,
        id: ApplicationId,
    ) -> SidResult<Option<ProtectedResource>> {
        sqlx::query_as::<_, ProtectedResourceRow>(
            "SELECT * FROM protected_resources WHERE application_id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(failed("get resource role"))?
        .map(ProtectedResourceRow::into_domain)
        .transpose()
    }

    pub(super) async fn list_protected_resources_impl(
        &self,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<ProtectedResource>> {
        sqlx::query_as::<_, ProtectedResourceRow>(
            "SELECT * FROM protected_resources ORDER BY created_at, id OFFSET $1 LIMIT $2",
        )
        .bind(i64::try_from(offset).map_err(|e| SidError::Validation(format!("offset: {e}")))?)
        .bind(i64::try_from(limit).map_err(|e| SidError::Validation(format!("limit: {e}")))?)
        .fetch_all(&self.pool)
        .await
        .map_err(failed("list protected resources"))?
        .into_iter()
        .map(ProtectedResourceRow::into_domain)
        .collect()
    }

    pub(super) async fn import_protected_resource_impl(
        &self,
        resource: &ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin().await?;
        // Only the id is a repeat of this import; any other key held by
        // another resource is a unique violation, i.e. a conflict.
        let written = sqlx::query(
            "INSERT INTO protected_resources
                 (id, application_id, issuer_id, indicator, scopes, state, revision,
                  created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(resource.id)
        .bind(resource.application_id)
        .bind(resource.issuer_id)
        .bind(resource.indicator.as_str())
        .bind(resource.scopes.join(" "))
        .bind(resource.state.as_str())
        .bind(revision(resource.revision, "protected resource")?)
        .bind(resource.created_at)
        .bind(resource.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("protected resource", e))?
        .rows_affected();
        if written != 1 {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("protected_resource:{}", resource.id), ctx).await?;
        Self::commit(tx).await?;
        Ok(true)
    }

    pub(super) async fn protected_resource_by_indicator_impl(
        &self,
        issuer: IssuerId,
        indicator: &ResourceIndicator,
    ) -> SidResult<Option<ProtectedResource>> {
        sqlx::query_as::<_, ProtectedResourceRow>(
            "SELECT * FROM protected_resources WHERE issuer_id = $1 AND indicator = $2",
        )
        .bind(issuer)
        .bind(indicator.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(failed("find protected resource"))?
        .map(ProtectedResourceRow::into_domain)
        .transpose()
    }

    pub(super) async fn update_protected_resource_impl(
        &self,
        resource: &ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        // A resource is retired only with its application.
        if resource.state == ResourceState::Retired {
            return Ok(false);
        }
        let mut tx = self.begin().await?;
        let written = sqlx::query(
            "UPDATE protected_resources
             SET scopes = $2, state = $3, updated_at = $4, revision = revision + 1
             WHERE id = $1 AND revision = $5 AND state <> 'retired'
               AND application_id IS NOT DISTINCT FROM $6 AND issuer_id = $7
               AND indicator = $8 AND created_at = $9",
        )
        .bind(resource.id)
        .bind(resource.scopes.join(" "))
        .bind(resource.state.as_str())
        .bind(resource.updated_at)
        .bind(revision(resource.revision, "protected resource")?)
        .bind(resource.application_id)
        .bind(resource.issuer_id)
        .bind(resource.indicator.as_str())
        .bind(resource.created_at)
        .execute(&mut *tx)
        .await
        .map_err(failed("update protected resource"))?
        .rows_affected();
        if written != 1 {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("protected_resource:{}", resource.id), ctx).await?;
        Self::commit(tx).await?;
        Ok(true)
    }

    pub(super) async fn set_resource_access_impl(
        &self,
        access: &ResourceAccess,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin().await?;
        // The share lock orders this grant against a concurrent retirement.
        let state: Option<(String,)> =
            sqlx::query_as("SELECT state FROM protected_resources WHERE id = $1 FOR SHARE")
                .bind(access.resource_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(failed("lock protected resource"))?;
        match state {
            None => {
                return Err(SidError::NotFound(format!(
                    "protected resource {}",
                    access.resource_id
                )));
            }
            Some((state,)) if state == ResourceState::Retired.as_str() => {
                return Err(SidError::InvalidState(format!(
                    "protected resource {} is retired",
                    access.resource_id
                )));
            }
            Some(_) => {}
        }
        // The client is an OAuth client or, failing that, a live machine user,
        // the order in which the token endpoint resolves a client id. The
        // share lock orders the grant against the client's deletion.
        let oauth: Option<(String,)> =
            sqlx::query_as("SELECT client_id FROM oauth2_clients WHERE client_id = $1 FOR SHARE")
                .bind(&access.client_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(failed("lock oauth client"))?;
        let target = if oauth.is_some() {
            "oauth2_client"
        } else {
            let machine: Option<(String,)> = sqlx::query_as(
                "SELECT client_id FROM machine_users
                 WHERE client_id = $1 AND status <> 'deleted' FOR SHARE",
            )
            .bind(&access.client_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(failed("lock machine user"))?;
            if machine.is_none() {
                return Err(SidError::NotFound(format!("client {}", access.client_id)));
            }
            "machine_user"
        };
        let (oauth_client, machine_client) = if oauth.is_some() {
            (Some(&access.client_id), None)
        } else {
            (None, Some(&access.client_id))
        };
        sqlx::query(
            "INSERT INTO resource_access
                 (oauth_client_id, machine_client_id, resource_id, scopes, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (client_id, resource_id) DO UPDATE SET scopes = EXCLUDED.scopes",
        )
        .bind(oauth_client)
        .bind(machine_client)
        .bind(access.resource_id)
        .bind(access.scopes.join(" "))
        .bind(access.created_at)
        .execute(&mut *tx)
        .await
        .map_err(failed("set resource access"))?;
        Self::audit_in_tx(&mut tx, &format!("{target}:{}", access.client_id), ctx).await?;
        Self::commit(tx).await
    }

    pub(super) async fn remove_resource_access_impl(
        &self,
        client_id: &str,
        resource: ResourceId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin().await?;
        let deleted =
            sqlx::query("DELETE FROM resource_access WHERE client_id = $1 AND resource_id = $2")
                .bind(client_id)
                .bind(resource)
                .execute(&mut *tx)
                .await
                .map_err(failed("remove resource access"))?
                .rows_affected();
        if deleted != 1 {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("oauth2_client:{client_id}"), ctx).await?;
        Self::commit(tx).await?;
        Ok(true)
    }

    pub(super) async fn resource_access_impl(
        &self,
        client_id: &str,
        resource: ResourceId,
    ) -> SidResult<Option<ResourceAccess>> {
        Ok(sqlx::query_as::<_, ResourceAccessRow>(
            "SELECT * FROM resource_access WHERE client_id = $1 AND resource_id = $2",
        )
        .bind(client_id)
        .bind(resource)
        .fetch_optional(&self.pool)
        .await
        .map_err(failed("get resource access"))?
        .map(ResourceAccessRow::into_domain))
    }

    pub(super) async fn list_resource_access_by_client_impl(
        &self,
        client_id: &str,
    ) -> SidResult<Vec<ResourceAccess>> {
        Ok(sqlx::query_as::<_, ResourceAccessRow>(
            "SELECT * FROM resource_access WHERE client_id = $1 ORDER BY created_at, resource_id",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .map_err(failed("list resource access"))?
        .into_iter()
        .map(ResourceAccessRow::into_domain)
        .collect())
    }

    pub(super) async fn list_resource_access_by_resource_impl(
        &self,
        resource: ResourceId,
    ) -> SidResult<Vec<ResourceAccess>> {
        Ok(sqlx::query_as::<_, ResourceAccessRow>(
            "SELECT * FROM resource_access WHERE resource_id = $1 ORDER BY created_at, client_id",
        )
        .bind(resource)
        .fetch_all(&self.pool)
        .await
        .map_err(failed("list resource access"))?
        .into_iter()
        .map(ResourceAccessRow::into_domain)
        .collect())
    }
}
