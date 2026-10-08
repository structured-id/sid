// SPDX-License-Identifier: AGPL-3.0-only
//! Applications, their protected-resource role and client-to-resource access.

use sid_core::models::{
    Application, ApplicationId, IssuerId, MutationContext, OAuth2Client, ProjectId,
    ProtectedResource, ResourceAccess, ResourceId, ResourceIndicator, ResourceState,
    SystemIntegration,
};
use sid_core::{Error as SidError, Result as SidResult};

use super::project::{
    OAUTH2_CLIENT_CREATE, client_conflict, insert_oauth2_client, row_to_oauth2_client,
};
use super::{SqliteBackend, col, dt_col, fmt_dt, insert_error, uuid_col};

fn storage(e: sqlx::Error) -> SidError {
    SidError::Storage(e.to_string())
}

fn revision(value: u64, what: &str) -> SidResult<i64> {
    i64::try_from(value).map_err(|e| SidError::Validation(format!("{what} revision: {e}")))
}

fn count(value: u64, what: &str) -> SidResult<i64> {
    i64::try_from(value).map_err(|e| SidError::Validation(format!("{what}: {e}")))
}

fn stored_revision(row: &sqlx::sqlite::SqliteRow) -> SidResult<u64> {
    let raw: i64 = col(row, "revision")?;
    u64::try_from(raw).map_err(|e| SidError::Storage(format!("column revision: {e}")))
}

fn words(row: &sqlx::sqlite::SqliteRow, column: &str) -> SidResult<Vec<String>> {
    let raw: String = col(row, column)?;
    Ok(raw.split_whitespace().map(String::from).collect())
}

fn row_to_application(row: &sqlx::sqlite::SqliteRow) -> SidResult<Application> {
    Ok(Application {
        id: col(row, "id")?,
        project_id: ProjectId(uuid_col(row, "project_id")?),
        name: col(row, "name")?,
        system: col::<Option<String>>(row, "system_integration")?
            .map(|kind| {
                kind.parse().map_err(|e: String| {
                    SidError::Storage(format!("column system_integration: {e}"))
                })
            })
            .transpose()?,
        revision: stored_revision(row)?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

/// A stored indicator or state that no longer parses is an error, never a
/// default.
fn row_to_resource(row: &sqlx::sqlite::SqliteRow) -> SidResult<ProtectedResource> {
    let indicator: String = col(row, "indicator")?;
    let state: String = col(row, "state")?;
    Ok(ProtectedResource {
        id: col(row, "id")?,
        application_id: col(row, "application_id")?,
        issuer_id: col(row, "issuer_id")?,
        indicator: ResourceIndicator::parse(&indicator)
            .map_err(|e| SidError::Storage(format!("column indicator: {e}")))?,
        scopes: words(row, "scopes")?,
        state: state
            .parse()
            .map_err(|e: String| SidError::Storage(format!("column state: {e}")))?,
        revision: stored_revision(row)?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

fn row_to_access(row: &sqlx::sqlite::SqliteRow) -> SidResult<ResourceAccess> {
    Ok(ResourceAccess {
        client_id: col(row, "client_id")?,
        resource_id: col(row, "resource_id")?,
        scopes: words(row, "scopes")?,
        created_at: dt_col(row, "created_at")?,
    })
}

pub(super) async fn insert_application<'e, E: sqlx::SqliteExecutor<'e>>(
    exec: E,
    app: &Application,
) -> SidResult<()> {
    sqlx::query(
        "INSERT INTO applications
             (id, project_id, name, revision, created_at, updated_at, system_integration)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(app.id)
    .bind(app.project_id.0.to_string())
    .bind(&app.name)
    .bind(revision(app.revision, "application")?)
    .bind(fmt_dt(&app.created_at))
    .bind(fmt_dt(&app.updated_at))
    .bind(app.system.map(SystemIntegration::as_str))
    .execute(exec)
    .await
    .map_err(|e| insert_error("application", e))?;
    Ok(())
}

/// Insert a resource role; a taken indicator of the issuer or an application
/// that already has a resource role is a `Conflict`.
async fn insert_resource<'e, E: sqlx::SqliteExecutor<'e>>(
    exec: E,
    resource: &ProtectedResource,
) -> SidResult<()> {
    if resource.application_id.is_none() || resource.state == ResourceState::Retired {
        return Err(SidError::Validation(format!(
            "protected resource {} is registered live, under an application",
            resource.id
        )));
    }
    sqlx::query(
        "INSERT INTO protected_resources
             (id, application_id, issuer_id, indicator, scopes, state, revision,
              created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(resource.id)
    .bind(resource.application_id)
    .bind(resource.issuer_id)
    .bind(resource.indicator.as_str())
    .bind(resource.scopes.join(" "))
    .bind(resource.state.as_str())
    .bind(revision(resource.revision, "protected resource")?)
    .bind(fmt_dt(&resource.created_at))
    .bind(fmt_dt(&resource.updated_at))
    .execute(exec)
    .await
    .map_err(|e| insert_error("protected resource", e))?;
    Ok(())
}

impl SqliteBackend {
    pub(crate) async fn create_application_impl(
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
        let mut tx = self.begin_write().await?;
        insert_application(&mut *tx, app).await?;
        // The resource first: the client may name it as its default.
        if let Some(resource) = resource {
            insert_resource(&mut *tx, resource).await?;
        }
        if let Some(client) = client
            && insert_oauth2_client(&mut *tx, client, OAUTH2_CLIENT_CREATE).await? == 0
        {
            return Err(client_conflict(client));
        }
        Self::commit_mutation(tx, &format!("application:{}", app.id), ctx).await
    }

    pub(crate) async fn get_application_impl(
        &self,
        id: ApplicationId,
    ) -> SidResult<Option<Application>> {
        sqlx::query("SELECT * FROM applications WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?
            .as_ref()
            .map(row_to_application)
            .transpose()
    }

    pub(crate) async fn system_application_impl(
        &self,
        kind: SystemIntegration,
    ) -> SidResult<Option<Application>> {
        sqlx::query("SELECT * FROM applications WHERE system_integration = ?")
            .bind(kind.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?
            .as_ref()
            .map(row_to_application)
            .transpose()
    }

    pub(crate) async fn list_applications_by_project_impl(
        &self,
        project_id: ProjectId,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<Application>> {
        sqlx::query(
            "SELECT * FROM applications WHERE project_id = ?
             ORDER BY created_at, id LIMIT ? OFFSET ?",
        )
        .bind(project_id.0.to_string())
        .bind(count(limit, "limit")?)
        .bind(count(offset, "offset")?)
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?
        .iter()
        .map(row_to_application)
        .collect()
    }

    pub(crate) async fn update_application_impl(
        &self,
        app: &Application,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let written = sqlx::query(
            "UPDATE applications SET name = ?, updated_at = ?, revision = revision + 1
             WHERE id = ? AND revision = ? AND project_id = ? AND created_at = ?",
        )
        .bind(&app.name)
        .bind(fmt_dt(&app.updated_at))
        .bind(app.id)
        .bind(revision(app.revision, "application")?)
        .bind(app.project_id.0.to_string())
        .bind(fmt_dt(&app.created_at))
        .execute(&mut *tx)
        .await
        .map_err(storage)?
        .rows_affected();
        if written != 1 {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("application:{}", app.id), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn delete_application_impl(
        &self,
        id: ApplicationId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        // The client role goes; its access rows go with it.
        sqlx::query("DELETE FROM oauth2_clients WHERE application_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        // The resource role is retired, never deleted: its indicator stays
        // reserved.
        let retired: Option<ResourceId> = sqlx::query_scalar(
            "UPDATE protected_resources
             SET state = 'retired', application_id = NULL, revision = revision + 1,
                 updated_at = ?
             WHERE application_id = ? RETURNING id",
        )
        .bind(fmt_dt(&chrono::Utc::now()))
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
        if let Some(resource) = retired {
            sqlx::query("DELETE FROM resource_access WHERE resource_id = ?")
                .bind(resource)
                .execute(&mut *tx)
                .await
                .map_err(storage)?;
            sqlx::query(
                "UPDATE oauth2_clients SET default_resource = NULL, revision = revision + 1
                 WHERE default_resource = ?",
            )
            .bind(resource)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        }
        let deleted = sqlx::query("DELETE FROM applications WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?
            .rows_affected();
        if deleted != 1 {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("application:{id}"), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn oauth2_client_of_application_impl(
        &self,
        id: ApplicationId,
    ) -> SidResult<Option<OAuth2Client>> {
        sqlx::query("SELECT * FROM oauth2_clients WHERE application_id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?
            .as_ref()
            .map(row_to_oauth2_client)
            .transpose()
    }

    pub(crate) async fn create_protected_resource_impl(
        &self,
        resource: &ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        insert_resource(&mut *tx, resource).await?;
        Self::commit_mutation(tx, &format!("protected_resource:{}", resource.id), ctx).await
    }

    pub(crate) async fn get_protected_resource_impl(
        &self,
        id: ResourceId,
    ) -> SidResult<Option<ProtectedResource>> {
        sqlx::query("SELECT * FROM protected_resources WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?
            .as_ref()
            .map(row_to_resource)
            .transpose()
    }

    pub(crate) async fn protected_resource_of_application_impl(
        &self,
        id: ApplicationId,
    ) -> SidResult<Option<ProtectedResource>> {
        sqlx::query("SELECT * FROM protected_resources WHERE application_id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?
            .as_ref()
            .map(row_to_resource)
            .transpose()
    }

    pub(crate) async fn list_protected_resources_impl(
        &self,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<ProtectedResource>> {
        sqlx::query("SELECT * FROM protected_resources ORDER BY created_at, id LIMIT ? OFFSET ?")
            .bind(count(limit, "limit")?)
            .bind(count(offset, "offset")?)
            .fetch_all(&self.pool)
            .await
            .map_err(storage)?
            .iter()
            .map(row_to_resource)
            .collect()
    }

    pub(crate) async fn import_protected_resource_impl(
        &self,
        resource: &ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        // Only the id is a repeat of this import; any other key held by
        // another resource is a unique violation, i.e. a conflict.
        let written = sqlx::query(
            "INSERT INTO protected_resources
                 (id, application_id, issuer_id, indicator, scopes, state, revision,
                  created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(resource.id)
        .bind(resource.application_id)
        .bind(resource.issuer_id)
        .bind(resource.indicator.as_str())
        .bind(resource.scopes.join(" "))
        .bind(resource.state.as_str())
        .bind(revision(resource.revision, "protected resource")?)
        .bind(fmt_dt(&resource.created_at))
        .bind(fmt_dt(&resource.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("protected resource", e))?
        .rows_affected();
        if written != 1 {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("protected_resource:{}", resource.id), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn protected_resource_by_indicator_impl(
        &self,
        issuer: IssuerId,
        indicator: &ResourceIndicator,
    ) -> SidResult<Option<ProtectedResource>> {
        sqlx::query("SELECT * FROM protected_resources WHERE issuer_id = ? AND indicator = ?")
            .bind(issuer)
            .bind(indicator.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?
            .as_ref()
            .map(row_to_resource)
            .transpose()
    }

    pub(crate) async fn update_protected_resource_impl(
        &self,
        resource: &ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        // A resource is retired only with its application.
        if resource.state == ResourceState::Retired {
            return Ok(false);
        }
        let mut tx = self.begin_write().await?;
        let written = sqlx::query(
            "UPDATE protected_resources
             SET scopes = ?, state = ?, updated_at = ?, revision = revision + 1
             WHERE id = ? AND revision = ? AND state <> 'retired'
               AND application_id IS ? AND issuer_id = ? AND indicator = ? AND created_at = ?",
        )
        .bind(resource.scopes.join(" "))
        .bind(resource.state.as_str())
        .bind(fmt_dt(&resource.updated_at))
        .bind(resource.id)
        .bind(revision(resource.revision, "protected resource")?)
        .bind(resource.application_id)
        .bind(resource.issuer_id)
        .bind(resource.indicator.as_str())
        .bind(fmt_dt(&resource.created_at))
        .execute(&mut *tx)
        .await
        .map_err(storage)?
        .rows_affected();
        if written != 1 {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("protected_resource:{}", resource.id), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn set_resource_access_impl(
        &self,
        access: &ResourceAccess,
        ctx: MutationContext,
    ) -> SidResult<()> {
        // The write transaction holds the database lock, so no retirement
        // interleaves between the check and the grant.
        let mut tx = self.begin_write().await?;
        let state: Option<String> =
            sqlx::query_scalar("SELECT state FROM protected_resources WHERE id = ?")
                .bind(access.resource_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
        match state.as_deref() {
            None => {
                return Err(SidError::NotFound(format!(
                    "protected resource {}",
                    access.resource_id
                )));
            }
            Some(state) if state == ResourceState::Retired.as_str() => {
                return Err(SidError::InvalidState(format!(
                    "protected resource {} is retired",
                    access.resource_id
                )));
            }
            Some(_) => {}
        }
        // The client is an OAuth client or, failing that, a live machine user,
        // the order in which the token endpoint resolves a client id.
        let oauth: Option<String> =
            sqlx::query_scalar("SELECT client_id FROM oauth2_clients WHERE client_id = ?")
                .bind(&access.client_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
        let target = if oauth.is_some() {
            "oauth2_client"
        } else {
            let machine: Option<String> = sqlx::query_scalar(
                "SELECT client_id FROM machine_users WHERE client_id = ? AND status <> 'deleted'",
            )
            .bind(&access.client_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?;
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
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT (client_id, resource_id) DO UPDATE SET scopes = excluded.scopes",
        )
        .bind(oauth_client)
        .bind(machine_client)
        .bind(access.resource_id)
        .bind(access.scopes.join(" "))
        .bind(fmt_dt(&access.created_at))
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        Self::commit_mutation(tx, &format!("{target}:{}", access.client_id), ctx).await
    }

    pub(crate) async fn remove_resource_access_impl(
        &self,
        client_id: &str,
        resource: ResourceId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let deleted =
            sqlx::query("DELETE FROM resource_access WHERE client_id = ? AND resource_id = ?")
                .bind(client_id)
                .bind(resource)
                .execute(&mut *tx)
                .await
                .map_err(storage)?
                .rows_affected();
        if deleted != 1 {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("oauth2_client:{client_id}"), ctx).await?;
        Ok(true)
    }

    pub(crate) async fn resource_access_impl(
        &self,
        client_id: &str,
        resource: ResourceId,
    ) -> SidResult<Option<ResourceAccess>> {
        sqlx::query("SELECT * FROM resource_access WHERE client_id = ? AND resource_id = ?")
            .bind(client_id)
            .bind(resource)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?
            .as_ref()
            .map(row_to_access)
            .transpose()
    }

    pub(crate) async fn list_resource_access_by_client_impl(
        &self,
        client_id: &str,
    ) -> SidResult<Vec<ResourceAccess>> {
        sqlx::query(
            "SELECT * FROM resource_access WHERE client_id = ? ORDER BY created_at, resource_id",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?
        .iter()
        .map(row_to_access)
        .collect()
    }

    pub(crate) async fn list_resource_access_by_resource_impl(
        &self,
        resource: ResourceId,
    ) -> SidResult<Vec<ResourceAccess>> {
        sqlx::query(
            "SELECT * FROM resource_access WHERE resource_id = ? ORDER BY created_at, client_id",
        )
        .bind(resource)
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?
        .iter()
        .map(row_to_access)
        .collect()
    }
}
