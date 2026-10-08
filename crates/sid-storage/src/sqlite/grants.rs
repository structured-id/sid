// SPDX-License-Identifier: AGPL-3.0-only
//! ProfileGrant, UpstreamProvider, and UpstreamIdentity operations for SQLite backend.

use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        MutationContext, ProfileGrant, ProfileGrantId, ProfileId, ProjectId, UpstreamIdentity,
        UpstreamIdentityId, UpstreamLogin, UpstreamProvider, UpstreamProviderId,
    },
};
use sid_keys::EncryptedField;

use super::{SqliteBackend, col, dt_col, dt_col_opt, fmt_dt, fmt_dt_opt, parsed_col, uuid_col};

fn row_to_profile_grant(row: &sqlx::sqlite::SqliteRow) -> SidResult<ProfileGrant> {
    let role_keys: String = col(row, "role_keys")?;
    Ok(ProfileGrant {
        id: ProfileGrantId(uuid_col(row, "id")?),
        project_id: ProjectId(uuid_col(row, "project_id")?),
        profile_id: col(row, "profile_id")?,
        role_keys: role_keys
            .split(',')
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .map(String::from)
            .collect(),
        granted_by: col(row, "granted_by")?,
        expires_at: dt_col_opt(row, "expires_at")?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

/// A malformed secret, scope list, protocol or trust category is an error:
/// never a made-up secret, no scopes, OIDC or social.
fn row_to_upstream_provider(row: &sqlx::sqlite::SqliteRow) -> SidResult<UpstreamProvider> {
    let scopes: String = col(row, "scopes")?;
    let client_secret: Vec<u8> = col(row, "client_secret")?;
    let revision: i64 = col(row, "revision")?;
    Ok(UpstreamProvider {
        id: UpstreamProviderId(uuid_col(row, "id")?),
        name: col(row, "name")?,
        protocol: parsed_col(row, "protocol")?,
        trust_category: parsed_col(row, "trust_category")?,
        enabled: col(row, "enabled")?,
        client_id: col(row, "client_id")?,
        client_secret: EncryptedField::from_bytes(&client_secret)
            .map_err(|e| SidError::Storage(format!("column client_secret: {e}")))?,
        discovery_url: col(row, "discovery_url")?,
        authorization_endpoint: col(row, "authorization_endpoint")?,
        token_endpoint: col(row, "token_endpoint")?,
        userinfo_endpoint: col(row, "userinfo_endpoint")?,
        scopes: serde_json::from_str(&scopes)
            .map_err(|e| SidError::Storage(format!("column scopes: {e}")))?,
        show_on_login: col(row, "show_on_login")?,
        display_order: col(row, "display_order")?,
        logo_url: col(row, "logo_url")?,
        revision: u64::try_from(revision)
            .map_err(|e| SidError::Storage(format!("column revision: {e}")))?,
        created_at: dt_col(row, "created_at")?,
        updated_at: dt_col(row, "updated_at")?,
    })
}

fn row_to_upstream_identity(row: &sqlx::sqlite::SqliteRow) -> SidResult<UpstreamIdentity> {
    let login_count: i64 = col(row, "login_count")?;
    Ok(UpstreamIdentity {
        id: UpstreamIdentityId(uuid_col(row, "id")?),
        profile_id: col(row, "profile_id")?,
        provider_id: UpstreamProviderId(uuid_col(row, "provider_id")?),
        upstream_subject: col(row, "upstream_subject")?,
        upstream_issuer: col(row, "upstream_issuer")?,
        upstream_email: col(row, "upstream_email")?,
        upstream_name: col(row, "upstream_name")?,
        upstream_picture: col(row, "upstream_picture")?,
        linked_at: dt_col(row, "linked_at")?,
        last_login_at: dt_col_opt(row, "last_login_at")?,
        login_count: u64::try_from(login_count)
            .map_err(|e| SidError::Storage(format!("column login_count: {e}")))?,
    })
}

impl SqliteBackend {
    // === ProfileGrant ===

    pub(crate) async fn get_profile_grant_impl(
        &self,
        id: ProfileGrantId,
    ) -> SidResult<Option<ProfileGrant>> {
        let row = sqlx::query("SELECT * FROM profile_grants WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_profile_grant).transpose()
    }

    pub(crate) async fn create_profile_grant_impl(
        &self,
        grant: &ProfileGrant,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO profile_grants (id, project_id, profile_id, role_keys, granted_by, expires_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(grant.id.0.to_string())
        .bind(grant.project_id.0.to_string())
        .bind(grant.profile_id)
        .bind(grant.role_keys.join(","))
        .bind(&grant.granted_by)
        .bind(fmt_dt_opt(grant.expires_at))
        .bind(fmt_dt(&grant.created_at))
        .bind(fmt_dt(&grant.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("profile grant", e))?;
        Self::commit_mutation(tx, &format!("profile_grant:{}", grant.id.0), audit).await
    }

    pub(crate) async fn delete_profile_grant_impl(
        &self,
        id: ProfileGrantId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM profile_grants WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("profile_grant:{}", id.0), audit).await
    }

    pub(crate) async fn list_profile_grants_for_profile_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<ProfileGrant>> {
        let rows = sqlx::query("SELECT * FROM profile_grants WHERE profile_id = ?")
            .bind(profile_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_profile_grant).collect()
    }

    pub(crate) async fn list_profile_grants_for_project_impl(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Vec<ProfileGrant>> {
        let rows = sqlx::query("SELECT * FROM profile_grants WHERE project_id = ?")
            .bind(project_id.0.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_profile_grant).collect()
    }

    // === UpstreamProvider ===

    pub(crate) async fn get_upstream_provider_impl(
        &self,
        id: UpstreamProviderId,
    ) -> SidResult<Option<UpstreamProvider>> {
        let row = sqlx::query("SELECT * FROM upstream_providers WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_upstream_provider).transpose()
    }

    pub(crate) async fn create_upstream_provider_impl(
        &self,
        provider: &UpstreamProvider,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.write_upstream_provider(
            provider,
            audit,
            "INSERT INTO upstream_providers (id, name, protocol, trust_category, enabled,
                client_id, client_secret, discovery_url, authorization_endpoint, token_endpoint,
                userinfo_endpoint, scopes, show_on_login, display_order, logo_url, created_at,
                updated_at, revision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                ?17, ?18)",
        )
        .await
        .map(|_| ())
    }

    /// Write over the revision the provider was read at; false when it was
    /// deleted or changed since. The creation time (`?16`) never changes.
    pub(crate) async fn update_upstream_provider_impl(
        &self,
        provider: &UpstreamProvider,
        audit: MutationContext,
    ) -> SidResult<bool> {
        Ok(self
            .write_upstream_provider(
                provider,
                audit,
                "UPDATE upstream_providers SET name = ?2, protocol = ?3, trust_category = ?4,
                    enabled = ?5, client_id = ?6, client_secret = ?7, discovery_url = ?8,
                    authorization_endpoint = ?9, token_endpoint = ?10, userinfo_endpoint = ?11,
                    scopes = ?12, show_on_login = ?13, display_order = ?14, logo_url = ?15,
                    updated_at = ?17, revision = revision + 1
                 WHERE id = ?1 AND revision = ?18 AND created_at = ?16",
            )
            .await?
            == 1)
    }

    /// Run one of the `upstream_providers` writes; returns rows written.
    /// Nothing is committed, the audit record included, when none was.
    async fn write_upstream_provider(
        &self,
        provider: &UpstreamProvider,
        audit: MutationContext,
        sql: &'static str,
    ) -> SidResult<u64> {
        let scopes_json = serde_json::to_string(&provider.scopes)
            .map_err(|e| SidError::Internal(format!("provider scopes: {e}")))?;
        let revision = i64::try_from(provider.revision)
            .map_err(|e| SidError::Validation(format!("provider revision: {e}")))?;
        let mut tx = self.begin_write().await?;
        let written = sqlx::query(sql)
            .bind(provider.id.0.to_string())
            .bind(&provider.name)
            .bind(provider.protocol.as_str())
            .bind(provider.trust_category.as_str())
            .bind(provider.enabled)
            .bind(&provider.client_id)
            .bind(provider.client_secret.to_bytes())
            .bind(&provider.discovery_url)
            .bind(&provider.authorization_endpoint)
            .bind(&provider.token_endpoint)
            .bind(&provider.userinfo_endpoint)
            .bind(&scopes_json)
            .bind(provider.show_on_login)
            .bind(provider.display_order)
            .bind(&provider.logo_url)
            .bind(fmt_dt(&provider.created_at))
            .bind(fmt_dt(&provider.updated_at))
            .bind(revision)
            .execute(&mut *tx)
            .await
            .map_err(|e| super::insert_error("upstream provider", e))?
            .rows_affected();
        if written > 0 {
            Self::commit_mutation(tx, &format!("upstream_provider:{}", provider.id.0), audit)
                .await?;
        }
        Ok(written)
    }

    pub(crate) async fn delete_upstream_provider_impl(
        &self,
        id: UpstreamProviderId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM upstream_providers WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("upstream_provider:{}", id.0), audit).await
    }

    pub(crate) async fn list_enabled_upstream_providers_impl(
        &self,
    ) -> SidResult<Vec<UpstreamProvider>> {
        let rows = sqlx::query(
            "SELECT * FROM upstream_providers WHERE enabled = 1 ORDER BY display_order, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_upstream_provider).collect()
    }

    // === UpstreamIdentity ===

    pub(crate) async fn get_upstream_identity_by_provider_subject_impl(
        &self,
        provider_id: UpstreamProviderId,
        upstream_subject: &str,
    ) -> SidResult<Option<UpstreamIdentity>> {
        let row = sqlx::query(
            "SELECT * FROM upstream_identities WHERE provider_id = ? AND upstream_subject = ?",
        )
        .bind(provider_id.0.to_string())
        .bind(upstream_subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        row.as_ref().map(row_to_upstream_identity).transpose()
    }

    pub(crate) async fn create_upstream_identity_impl(
        &self,
        identity: &UpstreamIdentity,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "INSERT INTO upstream_identities (id, profile_id, provider_id, upstream_subject,
                upstream_issuer, upstream_email, upstream_name, upstream_picture, linked_at,
                last_login_at, login_count)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(identity.id.0.to_string())
        .bind(identity.profile_id)
        .bind(identity.provider_id.0.to_string())
        .bind(&identity.upstream_subject)
        .bind(&identity.upstream_issuer)
        .bind(&identity.upstream_email)
        .bind(&identity.upstream_name)
        .bind(&identity.upstream_picture)
        .bind(fmt_dt(&identity.linked_at))
        .bind(fmt_dt_opt(identity.last_login_at))
        .bind(
            i64::try_from(identity.login_count)
                .map_err(|e| SidError::Validation(format!("login count: {e}")))?,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| super::insert_error("upstream identity", e))?;
        Self::commit_mutation(tx, &format!("upstream_identity:{}", identity.id.0), audit).await
    }

    pub(crate) async fn record_upstream_login_impl(
        &self,
        id: UpstreamIdentityId,
        login: &UpstreamLogin,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self.begin_write().await?;
        let recorded = sqlx::query(
            "UPDATE upstream_identities SET upstream_email = ?, upstream_name = ?,
                upstream_picture = ?, last_login_at = ?, login_count = login_count + 1
             WHERE id = ?",
        )
        .bind(&login.email)
        .bind(&login.name)
        .bind(&login.picture)
        .bind(fmt_dt(&login.at))
        .bind(id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("record upstream login: {e}")))?
        .rows_affected()
            == 1;
        if !recorded {
            return Ok(false);
        }
        Self::commit_mutation(tx, &format!("upstream_identity:{}", id.0), audit).await?;
        Ok(true)
    }

    pub(crate) async fn list_upstream_identities_by_profile_impl(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<UpstreamIdentity>> {
        let rows = sqlx::query("SELECT * FROM upstream_identities WHERE profile_id = ?")
            .bind(profile_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        rows.iter().map(row_to_upstream_identity).collect()
    }

    pub(crate) async fn delete_upstream_identity_impl(
        &self,
        id: UpstreamIdentityId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self.begin_write().await?;
        sqlx::query("DELETE FROM upstream_identities WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::commit_mutation(tx, &format!("upstream_identity:{}", id.0), audit).await
    }
}
