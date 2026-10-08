// SPDX-License-Identifier: AGPL-3.0-only
//! Project and OAuth2Client operations for SQLite backend.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{MutationContext, OAuth2Client, Project, ProjectChange, ProjectId},
};
use sqlx::Row;

use super::{SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, parsed_col, uuid_col};

/// Insert of a new client; an existing `client_id`, or a client role its
/// application already has, writes nothing.
pub(super) const OAUTH2_CLIENT_CREATE: &str =
    "INSERT INTO oauth2_clients (client_id, client_secret_hash,
        redirect_uris, allowed_scopes, grant_types, client_name, active, project_id,
        application_type, required_acr, required_amr, enforcement_mode, min_device_assurance,
        require_verified_email, require_verified_phone, backchannel_logout_uri,
        backchannel_logout_session_required, claim_mappings, created_at,
        logo_uri, token_endpoint_auth_method, response_types, subject_type,
        sector_identifier_uri, contacts, client_id_issued_at, client_secret_expires_at,
        registration_iat, registration_access_token_hash, login_strategy,
        show_federation_button, federation_timeout_ms, unified_input,
        org_id, revision, application_id, default_resource, jwks, post_logout_redirect_uris)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
        ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35,
        ?36, ?37, ?38, ?39)
     ON CONFLICT DO NOTHING";

/// Update of a stored client at revision `?35`, with the parameters of
/// [`OAUTH2_CLIENT_CREATE`]. The client's origin (`?19` creation time, `?26`
/// issue time, `?28` registration token, `?36` application) never changes:
/// an update carrying another origin writes nothing.
const OAUTH2_CLIENT_UPDATE: &str = "UPDATE oauth2_clients SET
        client_secret_hash = ?2, redirect_uris = ?3, allowed_scopes = ?4, grant_types = ?5,
        client_name = ?6, active = ?7, project_id = ?8, application_type = ?9,
        required_acr = ?10, required_amr = ?11, enforcement_mode = ?12,
        min_device_assurance = ?13, require_verified_email = ?14, require_verified_phone = ?15,
        backchannel_logout_uri = ?16, backchannel_logout_session_required = ?17,
        claim_mappings = ?18, logo_uri = ?20, token_endpoint_auth_method = ?21,
        response_types = ?22, subject_type = ?23, sector_identifier_uri = ?24, contacts = ?25,
        client_secret_expires_at = ?27, registration_access_token_hash = ?29,
        login_strategy = ?30, show_federation_button = ?31, federation_timeout_ms = ?32,
        unified_input = ?33, org_id = ?34, default_resource = ?37, jwks = ?38,
        post_logout_redirect_uris = ?39,
        revision = revision + 1
     WHERE client_id = ?1 AND revision = ?35
       AND created_at = ?19 AND client_id_issued_at = ?26 AND registration_iat IS ?28
       AND application_id = ?36";

/// A UUID stored as text.
fn row_to_project(row: &sqlx::sqlite::SqliteRow) -> SidResult<Project> {
    Ok(Project {
        id: ProjectId(uuid_col(row, "id")?),
        name: col(row, "name")?,
        description: col(row, "description")?,
        owner_id: col(row, "owner_id")?,
        is_system: col(row, "is_system")?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

/// Unknown stored settings are errors, never a default: an unknown subject
/// type is not read as public, an unknown mode not as audit.
pub(super) fn row_to_oauth2_client(row: &sqlx::sqlite::SqliteRow) -> SidResult<OAuth2Client> {
    use sid_core::models::InitialAccessTokenId;
    use sid_core::models::session::AuthLevel;
    let words = |column: &str| -> SidResult<Vec<String>> {
        let raw: String = col(row, column)?;
        Ok(raw.split_whitespace().map(String::from).collect())
    };
    let optional_parsed = |column: &str| -> SidResult<Option<String>> { col(row, column) };
    let json_list = |column: &str| -> SidResult<Vec<String>> {
        let raw: String = col(row, column)?;
        serde_json::from_str(&raw).map_err(|e| SidError::Storage(format!("column {column}: {e}")))
    };

    let required_acr = optional_parsed("required_acr")?
        .map(|s| {
            AuthLevel::from_acr_value(&s)
                .ok_or_else(|| SidError::Storage(format!("column required_acr: unknown {s:?}")))
        })
        .transpose()?;
    let min_device_assurance = optional_parsed("min_device_assurance")?
        .map(|s| {
            s.parse()
                .map_err(|e: String| SidError::Storage(format!("column min_device_assurance: {e}")))
        })
        .transpose()?;
    let registration_iat = optional_parsed("registration_iat")?
        .map(|id| {
            uuid::Uuid::parse_str(&id)
                .map(InitialAccessTokenId)
                .map_err(|e| SidError::Storage(format!("column registration_iat: {e}")))
        })
        .transpose()?;
    let claim_mappings = optional_parsed("claim_mappings")?
        .map(|s| {
            serde_json::from_str(&s)
                .map_err(|e| SidError::Storage(format!("column claim_mappings: {e}")))
        })
        .transpose()?
        .unwrap_or_default();
    let federation_timeout_ms: i64 = col(row, "federation_timeout_ms")?;
    let revision: i64 = col(row, "revision")?;

    Ok(OAuth2Client {
        client_id: col(row, "client_id")?,
        project_id: ProjectId(uuid_col(row, "project_id")?),
        application_id: col(row, "application_id")?,
        default_resource: col(row, "default_resource")?,
        application_type: parsed_col(row, "application_type")?,
        client_secret_hash: col(row, "client_secret_hash")?,
        jwks: optional_parsed("jwks")?
            .map(|s| {
                sid_core::models::ClientKeySet::from_json(&s)
                    .map_err(|e| SidError::Storage(format!("column jwks: {e}")))
            })
            .transpose()?,
        redirect_uris: json_list("redirect_uris")?,
        allowed_scopes: words("allowed_scopes")?,
        grant_types: words("grant_types")?,
        client_name: col(row, "client_name")?,
        logo_uri: col(row, "logo_uri")?,
        active: col(row, "active")?,
        token_endpoint_auth_method: parsed_col(row, "token_endpoint_auth_method")?,
        response_types: words("response_types")?,
        subject_type: parsed_col(row, "subject_type")?,
        sector_identifier_uri: col(row, "sector_identifier_uri")?,
        contacts: json_list("contacts")?,
        client_id_issued_at: dt_col(row, "client_id_issued_at")?,
        client_secret_expires_at: dt_col_opt(row, "client_secret_expires_at")?,
        registration_iat,
        registration_access_token_hash: col(row, "registration_access_token_hash")?,
        required_acr,
        required_amr: words("required_amr")?,
        enforcement_mode: parsed_col(row, "enforcement_mode")?,
        min_device_assurance,
        require_verified_email: col(row, "require_verified_email")?,
        require_verified_phone: col(row, "require_verified_phone")?,
        backchannel_logout_uri: col(row, "backchannel_logout_uri")?,
        backchannel_logout_session_required: col(row, "backchannel_logout_session_required")?,
        post_logout_redirect_uris: json_list("post_logout_redirect_uris")?,
        claim_mappings,
        login_strategy: parsed_col(row, "login_strategy")?,
        show_federation_button: col(row, "show_federation_button")?,
        federation_timeout_ms: u32::try_from(federation_timeout_ms)
            .map_err(|e| SidError::Storage(format!("column federation_timeout_ms: {e}")))?,
        unified_input: col(row, "unified_input")?,
        org_id: col(row, "org_id")?,
        revision: u64::try_from(revision)
            .map_err(|e| SidError::Storage(format!("column revision: {e}")))?,
        created_at: dt_col(row, "created_at")?,
    })
}

impl SqliteBackend {
    // === Project ===

    pub(crate) async fn get_project_impl(&self, id: ProjectId) -> SidResult<Option<Project>> {
        let row = sqlx::query("SELECT * FROM projects WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_project).transpose()
    }

    pub(crate) async fn create_project_impl(
        &self,
        project: &Project,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO projects (id, name, description, owner_id, is_system, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(project.id.0.to_string())
        .bind(&project.name)
        .bind(&project.description)
        .bind(project.owner_id)
        .bind(project.is_system)
        .bind(fmt_dt(&project.created_at))
        .bind(fmt_dt(&project.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("project", e))?;
        Self::commit_mutation(tx, &format!("project:{}", project.id.0), audit).await
    }

    pub(crate) async fn update_project_impl(
        &self,
        id: ProjectId,
        change: &ProjectChange,
        audit: MutationContext,
    ) -> SidResult<Option<Project>> {
        let mut tx = self.begin_write().await?;
        let row = sqlx::query(
            "UPDATE projects SET name = COALESCE(?, name),
                description = COALESCE(?, description), updated_at = ?
             WHERE id = ? AND is_system = 0
             RETURNING *",
        )
        .bind(&change.name)
        .bind(&change.description)
        .bind(fmt_dt(&change.updated_at))
        .bind(id.0.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| super::insert_error("project", e))?;
        let Some(project) = row.as_ref().map(row_to_project).transpose()? else {
            return Ok(None);
        };
        Self::commit_mutation(tx, &format!("project:{}", id.0), audit).await?;
        Ok(Some(project))
    }

    pub(crate) async fn delete_project_impl(
        &self,
        id: ProjectId,
        audit: MutationContext,
    ) -> SidResult<()> {
        if id.is_system() {
            return Err(SidError::Validation(
                "Cannot delete the system project".to_string(),
            ));
        }
        let mut tx = self.begin_write().await?;
        // A system project is never deleted, whatever its id.
        sqlx::query("DELETE FROM projects WHERE id = ? AND is_system = 0")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("project:{}", id.0), audit).await
    }

    pub(crate) async fn list_projects_impl(
        &self,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<Project>> {
        let rows =
            sqlx::query("SELECT * FROM projects ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_project).collect()
    }

    pub(crate) async fn count_projects_impl(&self) -> SidResult<u64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM projects")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(row.get::<i64, _>("cnt") as u64)
    }

    pub(crate) async fn ensure_system_project_impl(&self, audit: MutationContext) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT OR IGNORE INTO projects (id, name, description, is_system)
             VALUES ('00000000-0000-0000-0000-000000000000', 'SID', 'Default system project', 1)",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, "project:system", audit).await
    }

    // === OAuth2 Client ===

    pub(crate) async fn get_oauth2_client_impl(
        &self,
        client_id: &str,
    ) -> SidResult<Option<OAuth2Client>> {
        let row = sqlx::query("SELECT * FROM oauth2_clients WHERE client_id = ?")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_oauth2_client).transpose()
    }

    /// Update a stored client at the revision it was read at; false when it
    /// was deleted or changed since.
    pub(crate) async fn update_oauth2_client_impl(
        &self,
        client: &OAuth2Client,
        audit: MutationContext,
    ) -> SidResult<bool> {
        Ok(self
            .write_oauth2_client(client, audit, OAUTH2_CLIENT_UPDATE)
            .await?
            == 1)
    }

    /// Insert a new client; an existing `client_id` is a `Conflict`, never replaced.
    pub(crate) async fn create_oauth2_client_impl(
        &self,
        client: &OAuth2Client,
        audit: MutationContext,
    ) -> SidResult<()> {
        let written = self
            .write_oauth2_client(client, audit, OAUTH2_CLIENT_CREATE)
            .await?;
        if written == 0 {
            return Err(client_conflict(client));
        }
        Ok(())
    }

    /// Run one of the `oauth2_clients` writes; returns rows written.
    /// Nothing is committed, neither the audit record nor the owed work, when
    /// no row was.
    async fn write_oauth2_client(
        &self,
        client: &OAuth2Client,
        audit: MutationContext,
        sql: &'static str,
    ) -> SidResult<u64> {
        let mut tx = self.begin_write().await?;
        let written = insert_oauth2_client(&mut *tx, client, sql).await?;
        if written > 0 {
            Self::commit_mutation(tx, &format!("oauth2_client:{}", client.client_id), audit)
                .await?;
        }
        Ok(written)
    }
}

/// The refusal of a client insert that wrote nothing.
pub(super) fn client_conflict(client: &OAuth2Client) -> SidError {
    SidError::Conflict(format!(
        "oauth2 client {} exists, or application {} already has a client role",
        client.client_id, client.application_id
    ))
}

/// `list` as the JSON array text a list column holds.
fn json_text(list: &[String]) -> SidResult<String> {
    serde_json::to_string(list).map_err(|e| SidError::Internal(format!("list column: {e}")))
}

/// Run one of the `oauth2_clients` writes on `exec`; returns rows written.
pub(super) async fn insert_oauth2_client<'e, E: sqlx::SqliteExecutor<'e>>(
    exec: E,
    client: &OAuth2Client,
    sql: &'static str,
) -> SidResult<u64> {
    let claim_mappings_str = if client.claim_mappings.is_empty() {
        None
    } else {
        Some(
            serde_json::to_string(&client.claim_mappings)
                .map_err(|e| SidError::Internal(format!("claim mappings: {e}")))?,
        )
    };
    let written = sqlx::query(sql)
        .bind(&client.client_id)
        .bind(&client.client_secret_hash)
        .bind(json_text(&client.redirect_uris)?)
        .bind(client.allowed_scopes.join(" "))
        .bind(client.grant_types.join(" "))
        .bind(&client.client_name)
        .bind(client.active)
        .bind(client.project_id.0.to_string())
        .bind(client.application_type.as_str())
        .bind(client.required_acr.map(|a| a.as_str().to_string()))
        .bind(client.required_amr.join(" "))
        .bind(client.enforcement_mode.as_str())
        .bind(client.min_device_assurance.map(|d| d.as_str().to_string()))
        .bind(client.require_verified_email)
        .bind(client.require_verified_phone)
        .bind(&client.backchannel_logout_uri)
        .bind(client.backchannel_logout_session_required)
        .bind(&claim_mappings_str)
        .bind(fmt_dt(&client.created_at))
        .bind(&client.logo_uri)
        .bind(client.token_endpoint_auth_method.as_str())
        .bind(client.response_types.join(" "))
        .bind(client.subject_type.as_str())
        .bind(&client.sector_identifier_uri)
        .bind(json_text(&client.contacts)?)
        .bind(fmt_dt(&client.client_id_issued_at))
        .bind(fmt_dt_opt(client.client_secret_expires_at))
        .bind(client.registration_iat.map(|iat| iat.0.to_string()))
        .bind(&client.registration_access_token_hash)
        .bind(client.login_strategy.as_str())
        .bind(client.show_federation_button)
        .bind(i64::from(client.federation_timeout_ms))
        .bind(client.unified_input)
        .bind(client.org_id)
        .bind(
            i64::try_from(client.revision)
                .map_err(|e| SidError::Validation(format!("client revision: {e}")))?,
        )
        .bind(client.application_id)
        .bind(client.default_resource)
        .bind(
            client
                .jwks
                .as_ref()
                .map(sid_core::models::ClientKeySet::to_json),
        )
        .bind(json_text(&client.post_logout_redirect_uris)?)
        .execute(exec)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .rows_affected();
    Ok(written)
}

impl SqliteBackend {
    /// See [`sid_plugin::storage::StorageBackend::register_dynamic_client`].
    pub(crate) async fn register_dynamic_client_impl(
        &self,
        app: &sid_core::models::Application,
        client: &OAuth2Client,
        iat: sid_core::models::InitialAccessTokenId,
        audit: MutationContext,
    ) -> SidResult<()> {
        if client.application_id != app.id || client.project_id != app.project_id {
            return Err(SidError::Validation(format!(
                "registered client {} names another application or project",
                client.client_id
            )));
        }
        // The write lock is taken up front, so concurrent registrations
        // against one token see each other's count.
        let mut tx = self.begin_write().await?;
        let row = sqlx::query(
            "SELECT revoked, expires_at, max_clients, clients_registered
             FROM initial_access_tokens WHERE id = ?",
        )
        .bind(iat.0.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?
        .ok_or_else(|| SidError::NotFound(format!("initial access token {}", iat.0)))?;
        let revoked: bool = col(&row, "revoked")?;
        let expires_at = dt_col(&row, "expires_at")?;
        let max_clients: i64 = col(&row, "max_clients")?;
        let registered: i64 = col(&row, "clients_registered")?;
        if revoked {
            return Err(SidError::Revoked(format!("initial access token {}", iat.0)));
        }
        if expires_at <= chrono::Utc::now() {
            return Err(SidError::Expired(format!("initial access token {}", iat.0)));
        }
        if max_clients > 0 && registered >= max_clients {
            return Err(SidError::InvalidState(format!(
                "initial access token {} reached its client limit",
                iat.0
            )));
        }
        sqlx::query(
            "UPDATE initial_access_tokens SET clients_registered = clients_registered + 1
             WHERE id = ?",
        )
        .bind(iat.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        super::application::insert_application(&mut *tx, app).await?;
        if insert_oauth2_client(&mut *tx, client, OAUTH2_CLIENT_CREATE).await? == 0 {
            return Err(client_conflict(client));
        }
        Self::commit_mutation(tx, &format!("oauth2_client:{}", client.client_id), audit).await
    }

    pub(crate) async fn delete_oauth2_client_impl(
        &self,
        client_id: &str,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        let application: Option<sid_core::models::ApplicationId> = sqlx::query_scalar(
            "DELETE FROM oauth2_clients WHERE client_id = ? RETURNING application_id",
        )
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        if let Some(application) = application {
            // An application left without any role goes too.
            sqlx::query(
                "DELETE FROM applications WHERE id = ?1 AND NOT EXISTS
                     (SELECT 1 FROM protected_resources WHERE application_id = ?1)",
            )
            .bind(application)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        }
        Self::commit_mutation(tx, &format!("oauth2_client:{}", client_id), audit).await
    }

    pub(crate) async fn list_oauth2_clients_impl(
        &self,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<OAuth2Client>> {
        let rows = sqlx::query(
            "SELECT * FROM oauth2_clients ORDER BY created_at DESC, client_id LIMIT ? OFFSET ?",
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_oauth2_client).collect()
    }

    pub(crate) async fn list_oauth2_clients_by_project_impl(
        &self,
        project_id: ProjectId,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<OAuth2Client>> {
        let rows = sqlx::query(
            "SELECT * FROM oauth2_clients WHERE project_id = ?
             ORDER BY created_at DESC, client_id LIMIT ? OFFSET ?",
        )
        .bind(project_id.0.to_string())
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_oauth2_client).collect()
    }
}
