// SPDX-License-Identifier: AGPL-3.0-only
//! PostgreSQL storage backend (sqlx)
//!
//! Fully async, non-blocking implementation for all StructuredID CRUD operations.

use async_trait::async_trait;
use secrecy::ExposeSecret;
use sid_core::{
    Error as SidError, Result as SidResult,
    models::{
        AccessRequest, AccessRequestId, AccessRequestStatus, AuthCodeRedemption, AuthorizationCode,
        CedarPolicy, CedarPolicyId, ClientKeySet, ClosureRequest, Credential, CredentialId,
        CredentialType, Device as CoreDevice, DeviceAuthCodeId,
        DeviceAuthorizationCode as CoreDeviceAuth, DeviceId as CoreDeviceId, EmailSettings,
        ExportJob, Group, GroupId, GroupMember, HistoryCommit, HistoryEpoch, HistoryEpochId,
        ImpersonationGrant, InitialAccessToken, InitialAccessTokenId, Invite, InviteFilter,
        InviteId, MachineUser, MachineUserCredential, MachineUserId, MagicLinkSession,
        MutationContext, NewHistoryEpoch, NewRegistration, OAuth2Client, OutboundDlqEntry,
        OutboundEntityType, PasswordHistory, PatId, PersonalAccessToken, PhoneSettings, Principal,
        PrincipalBinding, PrincipalEntity, PrincipalId, PrincipalType, Profile, ProfileEmail,
        ProfileEmailId, ProfileGrant, ProfileGrantId, ProfileId, ProfileMetadata, ProfilePhone,
        ProfilePhoneId, Project, ProjectChange, ProjectId, RefreshToken, RegistrationSource,
        RegistrationSourceType, RevocationReason, Role, RoleAssignment, RoleAssignmentId,
        RoleAssignmentPrincipal, RoleId, ScimOutboundRecord, ScimOutboundTarget,
        ScimOutboundTargetId, Session, SessionAuthentication, SessionEnd, SessionId,
        SodConflictRule, UpstreamIdentity, UpstreamIdentityId, UpstreamLogin, UpstreamProvider,
        UpstreamProviderId, WebAuthnUserHandle, WrappedHistoryKey,
    },
};
use sid_plugin::audit::AuditLog;
use sid_plugin::storage::StorageBackend;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

/// Map an insert failure: a unique-key violation means the row (account, identifier,
/// active password) already exists, anything else is a storage fault.
fn insert_error(what: &str, e: sqlx::Error) -> SidError {
    match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            SidError::Conflict(format!("{what} already exists"))
        }
        _ => SidError::Storage(format!("Insert {what} failed: {e}")),
    }
}

/// A write refused by a referential constraint. PostgreSQL 18 reports an
/// `ON DELETE/UPDATE RESTRICT` refusal as SQLSTATE 23001 `restrict_violation`
/// (PostgreSQL 18 docs, Appendix A), not as 23503 `foreign_key_violation`.
pub(crate) fn is_reference_violation(db: &dyn sqlx::error::DatabaseError) -> bool {
    db.is_foreign_key_violation() || db.code().as_deref() == Some("23001")
}

/// SQLSTATE the email policy fence raises (migration 053).
const EMAIL_POLICY_FENCE: &str = "SIDEP";

/// A failed principal write: `Fenced` when its email key was derived under a
/// policy revision that is not the installation's active one.
fn principal_write_error(what: &str, e: sqlx::Error) -> SidError {
    match &e {
        sqlx::Error::Database(db) if db.code().as_deref() == Some(EMAIL_POLICY_FENCE) => {
            SidError::Fenced(format!("{what}: {}", db.message()))
        }
        _ => SidError::Storage(format!("{what} failed: {e}")),
    }
}

/// An `oidc_issuers` row as selected: id, handle, canonical URL, authority,
/// recipient organization, creation time.
type IssuerRow = (
    sid_core::models::IssuerId,
    String,
    String,
    String,
    sid_core::models::OrgId,
    chrono::DateTime<chrono::Utc>,
);

fn issuer_from_row(
    (id, handle, canonical_url, authority, recipient_org, created_at): IssuerRow,
) -> SidResult<sid_core::models::OidcIssuer> {
    let stored = |e: String| SidError::Storage(format!("oidc issuer {id}: {e}"));
    Ok(sid_core::models::OidcIssuer {
        id,
        handle: sid_core::models::IssuerHandle::parse(&handle).map_err(stored)?,
        canonical_url,
        authority: authority.parse().map_err(stored)?,
        recipient_org,
        created_at,
    })
}

/// A signing-key generation as the `INTEGER` column holds it.
fn key_generation(generation: u32) -> SidResult<i32> {
    i32::try_from(generation)
        .map_err(|_| SidError::Validation(format!("key generation {generation} out of range")))
}

use crate::key_versions::{key_derivation_name, key_version_params};
use sid_core::models::machine_user::MachineUserStatus;

use crate::{ADMIN_EXISTS_SQL, OWED_WORK_CAPACITY};

/// An initial access token counter as the `INTEGER` column holds it.
fn iat_count(n: u32) -> SidResult<i32> {
    i32::try_from(n).map_err(|_| SidError::Validation(format!("client count {n} out of range")))
}

fn row_to_initial_access_token(row: &sqlx::postgres::PgRow) -> SidResult<InitialAccessToken> {
    use sqlx::Row;
    let count = |column: &str| -> SidResult<u32> {
        u32::try_from(row.get::<i32, _>(column))
            .map_err(|_| SidError::Storage(format!("negative {column} in initial_access_tokens")))
    };
    let words = |column: &str| -> Vec<String> {
        row.get::<String, _>(column)
            .split_whitespace()
            .map(String::from)
            .collect()
    };
    Ok(InitialAccessToken {
        id: InitialAccessTokenId(row.get("id")),
        token_hash: row.get("token_hash"),
        project_id: ProjectId(row.get("project_id")),
        max_clients: count("max_clients")?,
        clients_registered: count("clients_registered")?,
        allowed_scopes: words("allowed_scopes"),
        allowed_grant_types: words("allowed_grant_types"),
        allowed_redirect_patterns: words("allowed_redirect_patterns"),
        expires_at: row.get("expires_at"),
        created_at: row.get("created_at"),
        created_by: row.get("created_by"),
        revoked: row.get("revoked"),
    })
}

/// PostgreSQL storage backend.
///
/// Provides async, non-blocking CRUD operations for profiles, credentials,
/// sessions, OAuth2 clients, refresh tokens, and authorization codes.
///
/// Uses sqlx for all StorageBackend queries.
/// Audit writes use `audit_in_tx()` (static, sqlx transaction).
/// `audit_log` field is kept for AuditLog trait queries (verify_chain, list_chain_ids).
///
/// Supports schema isolation for shared-database deployments:
/// when `schema` is set, all queries use that PostgreSQL schema via `search_path`.
#[derive(Clone)]
pub struct PostgresBackend {
    /// sqlx connection pool (all queries + audit + migrations)
    pool: PgPool,
    #[allow(dead_code)]
    schema: Option<String>,
    audit_log: Option<Arc<dyn AuditLog>>,
}

/// An invite row's status, computed in the order of `Invite::status`.
macro_rules! invite_status_sql {
    () => {
        "(CASE WHEN NOT active THEN 'revoked' \
               WHEN expires_at IS NOT NULL AND expires_at < NOW() THEN 'expired' \
               WHEN max_uses > 0 AND use_count >= max_uses THEN 'consumed' \
               ELSE 'active' END)"
    };
}

/// Insert of a new client; an existing `client_id` writes nothing.
const OAUTH2_CLIENT_CREATE: &str = "INSERT INTO oauth2_clients (client_id, project_id,
        application_type, client_secret_hash,
        redirect_uris, allowed_scopes, grant_types, client_name, logo_uri, active,
        required_acr, required_amr, enforcement_mode, min_device_assurance,
        require_verified_email, require_verified_phone,
        backchannel_logout_uri, backchannel_logout_session_required,
        claim_mappings,
        login_strategy, show_federation_button, federation_timeout_ms, unified_input,
        subject_type, sector_identifier_uri, token_endpoint_auth_method,
        response_types, contacts, registration_iat,
        registration_access_token_hash, org_id,
        client_id_issued_at, client_secret_expires_at,
        created_at, revision, application_id, default_resource, jwks,
        post_logout_redirect_uris)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
        $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35,
        $36, $37, $38, $39)
    ON CONFLICT DO NOTHING";

/// Update of a stored client at revision `$35`, with the parameters of
/// [`OAUTH2_CLIENT_CREATE`]. The client's origin (`$29` registration token,
/// `$32` issue time, `$34` creation time, `$36` application) never changes:
/// an update carrying another origin writes nothing.
const OAUTH2_CLIENT_UPDATE: &str = "UPDATE oauth2_clients SET
        project_id = $2, application_type = $3, client_secret_hash = $4,
        redirect_uris = $5, allowed_scopes = $6, grant_types = $7, client_name = $8,
        logo_uri = $9, active = $10, required_acr = $11, required_amr = $12,
        enforcement_mode = $13, min_device_assurance = $14,
        require_verified_email = $15, require_verified_phone = $16,
        backchannel_logout_uri = $17, backchannel_logout_session_required = $18,
        claim_mappings = $19,
        login_strategy = $20, show_federation_button = $21, federation_timeout_ms = $22,
        unified_input = $23, subject_type = $24, sector_identifier_uri = $25,
        token_endpoint_auth_method = $26, response_types = $27, contacts = $28,
        registration_access_token_hash = $30, org_id = $31,
        client_secret_expires_at = $33, default_resource = $37, jwks = $38,
        post_logout_redirect_uris = $39,
        revision = revision + 1
    WHERE client_id = $1 AND revision = $35
      AND registration_iat IS NOT DISTINCT FROM $29
      AND client_id_issued_at = $32 AND created_at = $34 AND application_id = $36";

impl PostgresBackend {
    /// Create a new PostgreSQL backend
    ///
    /// # Arguments
    /// * `database_url` - PostgreSQL connection string (postgres://user:pass@host/db)
    /// * `schema` - Optional PostgreSQL schema for table isolation (e.g. "sid")
    ///
    /// # Example
    /// ```no_run
    /// use sid_storage::PostgresBackend;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     // Default: tables in public schema
    ///     let backend = PostgresBackend::new("postgres://sid:sid@localhost/sid", None).await?;
    ///
    ///     // Isolated: tables in "sid" schema
    ///     let isolated = PostgresBackend::new(
    ///         "postgres://sid:sid@localhost/app_db",
    ///         Some("sid".to_string()),
    ///     ).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(database_url: &str, schema: Option<String>) -> SidResult<Self> {
        // sqlx pool (target for all new queries)
        let pool_opts = if let Some(ref schema_name) = schema {
            // Every connection runs this, so the name is checked once here
            // rather than trusted from configuration.
            crate::migrator::validate_schema_name(schema_name)?;
            let opts: sqlx::postgres::PgConnectOptions = database_url
                .parse()
                .map_err(|e| SidError::Storage(format!("Invalid database URL: {}", e)))?;
            sqlx::postgres::PgPoolOptions::new()
                .after_connect({
                    let schema_name = schema_name.clone();
                    move |conn, _meta| {
                        let schema_name = schema_name.clone();
                        Box::pin(async move {
                            sqlx::Executor::execute(
                                conn,
                                // Validated above, and quoted so the name
                                // cannot extend the statement.
                                sqlx::query(sqlx::AssertSqlSafe(format!(
                                    "SET search_path TO \"{}\", public",
                                    schema_name
                                ))),
                            )
                            .await?;
                            Ok(())
                        })
                    }
                })
                .connect_with(opts)
                .await
        } else {
            PgPool::connect(database_url).await
        };
        let pool =
            pool_opts.map_err(|e| SidError::Storage(format!("Failed to connect (sqlx): {}", e)))?;

        Ok(Self {
            pool,
            schema,
            audit_log: None,
        })
    }

    /// Set the audit log backend for tamper-evident logging.
    ///
    /// When set, all write operations (save, delete) will log an audit record
    /// alongside the data mutation. Audit failures cause the operation to fail.
    pub fn with_audit_log(mut self, audit_log: Arc<dyn AuditLog>) -> Self {
        self.audit_log = Some(audit_log);
        self
    }

    /// Write the mutation's audit record and the work it owes inside its
    /// transaction: state, audit and work commit together or not at all.
    /// Owed work beyond its kind's capacity refuses the whole mutation.
    ///
    /// `chain_id` is derived from the operation context (e.g., "profile:{id}").
    async fn audit_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        chain_id: &str,
        ctx: MutationContext,
    ) -> SidResult<()> {
        // The authority first: a write whose actor changed commits nothing.
        if let Some(fence) = &ctx.fence {
            Self::check_fence(tx, fence).await?;
        }
        // Then the completion: a keyed command another commit already
        // completed commits nothing, not even its audit or work.
        if let Some(operation) = &ctx.operation {
            operation::record_in_tx(tx, operation).await?;
        }
        crate::audit_log::PostgresAuditLog::log_in_conn(tx, chain_id, ctx.audit)
            .await
            .map_err(|e| SidError::Storage(format!("Audit log failed: {}", e)))?;
        for work in &ctx.work {
            work::insert_work_in_tx(tx, work, OWED_WORK_CAPACITY).await?;
        }
        Ok(())
    }

    /// Store `r`'s editable fields in `tx` while the stored role is still at
    /// `r.revision`, moving the revision on; false when it is not.
    async fn update_role_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        r: &Role,
    ) -> SidResult<bool> {
        let revision = i64::try_from(r.revision)
            .map_err(|e| SidError::Validation(format!("role revision: {e}")))?;
        Ok(sqlx::query(
            "UPDATE roles SET name = $3, description = $4, group_label = $5, permissions = $6,
                updated_at = $7, revision = revision + 1
             WHERE id = $1 AND revision = $2",
        )
        .bind(r.id.0)
        .bind(revision)
        .bind(&r.name)
        .bind(&r.description)
        .bind(&r.group)
        .bind(r.permissions_string())
        .bind(r.updated_at)
        .execute(&mut **tx)
        .await
        .map_err(|e| insert_error("role", e))?
        .rows_affected()
            == 1)
    }

    /// Insert `assignment`; an existing id is a `Conflict`, a missing role or
    /// principal an error.
    async fn insert_role_assignment_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        assignment: &RoleAssignment,
    ) -> SidResult<()> {
        let (mut profile_id, mut group_id, mut machine_user_id, mut oauth_client_id) =
            (None, None, None, None);
        let mut connector_id = None;
        match &assignment.principal {
            RoleAssignmentPrincipal::Profile(pid) => profile_id = Some(*pid),
            RoleAssignmentPrincipal::Group(gid) => group_id = Some(gid.0),
            RoleAssignmentPrincipal::MachineUser(mid) => machine_user_id = Some(*mid),
            RoleAssignmentPrincipal::OAuthClient(client) => oauth_client_id = Some(client),
            RoleAssignmentPrincipal::ProvisioningConnector(id) => connector_id = Some(*id),
        }
        let provenance = assignment.provenance.as_ref();
        sqlx::query(
            "INSERT INTO role_assignments (id, profile_id, group_id, machine_user_id, oauth_client_id,
                provisioning_connector_id, role_id, scope, expires_at, created_at,
                granted_by, basis_assignment_id, depends_on_assignment_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(assignment.id.0)
        .bind(profile_id)
        .bind(group_id)
        .bind(machine_user_id)
        .bind(oauth_client_id)
        .bind(connector_id)
        .bind(assignment.role_id.0)
        .bind(&assignment.scope)
        .bind(assignment.expires_at)
        .bind(assignment.created_at)
        .bind(provenance.map(|p| p.granted_by.as_str()))
        .bind(provenance.and_then(|p| p.basis).map(|id| id.0))
        .bind(provenance.and_then(|p| p.depends_on).map(|id| id.0))
        .execute(&mut **tx)
        .await
        .map_err(|e| insert_error("role assignment", e))?;
        if let Some(envelope) = &assignment.admin {
            Self::insert_admin_envelope_in_tx(tx, assignment.id, envelope).await?;
        }
        if let Some(ceiling) = provenance.and_then(|p| p.ceiling.as_ref()) {
            // An empty ceiling would read back as no ceiling at all.
            if ceiling.is_empty() {
                return Err(SidError::Validation(
                    "an approved ceiling names no permission".into(),
                ));
            }
            let permissions: Vec<&str> = ceiling.iter().map(String::as_str).collect();
            sqlx::query(
                "INSERT INTO role_assignment_ceilings (assignment_id, permission)
                 SELECT $1, UNNEST($2::text[])",
            )
            .bind(assignment.id.0)
            .bind(&permissions)
            .execute(&mut **tx)
            .await
            .map_err(|e| insert_error("approved ceiling", e))?;
        }
        if let Some(connector) = connector_id {
            Self::bump_connector_revision(tx, connector).await?;
        }
        Ok(())
    }

    /// Store the envelope of the administrative assignment `id` in `tx`; an
    /// incomplete envelope is refused.
    async fn insert_admin_envelope_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: RoleAssignmentId,
        envelope: &sid_core::models::AdminEnvelope,
    ) -> SidResult<()> {
        envelope
            .validate()
            .map_err(|e| SidError::Validation(e.to_string()))?;
        sqlx::query(
            "INSERT INTO role_assignment_admin (assignment_id, recipient_group_id, max_validity_secs)
             VALUES ($1, $2, $3)",
        )
        .bind(id.0)
        .bind(envelope.recipient_group.map(|g| g.0))
        .bind(envelope.max_validity_secs)
        .execute(&mut **tx)
        .await
        .map_err(|e| insert_error("administrative envelope", e))?;
        let (kinds, values): (Vec<&str>, Vec<&str>) = envelope
            .operations
            .iter()
            .map(|op| ("operation", op.as_str()))
            .chain(
                envelope
                    .recipient_kinds
                    .iter()
                    .map(|kind| ("recipient_kind", kind.as_str())),
            )
            .chain(
                envelope
                    .permission_ceiling
                    .iter()
                    .map(|p| ("permission", p.as_str())),
            )
            .unzip();
        sqlx::query(
            "INSERT INTO role_assignment_admin_entries (assignment_id, kind, value)
             SELECT $1, k, v FROM UNNEST($2::text[], $3::text[]) AS t(k, v)",
        )
        .bind(id.0)
        .bind(&kinds)
        .bind(&values)
        .execute(&mut **tx)
        .await
        .map_err(|e| insert_error("administrative envelope entry", e))?;
        let roles: Vec<uuid::Uuid> = envelope.roles.iter().map(|r| r.0).collect();
        sqlx::query(
            "INSERT INTO role_assignment_admin_roles (assignment_id, role_id)
             SELECT $1, r FROM UNNEST($2::uuid[]) AS t(r)",
        )
        .bind(id.0)
        .bind(&roles)
        .execute(&mut **tx)
        .await
        .map_err(|e| insert_error("administrative envelope role", e))?;
        Ok(())
    }

    /// Check in `tx` that `fence` still holds, locking what it names until
    /// the transaction ends so no concurrent revoke, role edit or membership
    /// change can slip in before the commit.
    async fn check_assignment_fence_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        fence: &sid_core::models::AssignmentFence,
    ) -> SidResult<()> {
        let revision =
            |r: u64| i64::try_from(r).map_err(|_| SidError::Fenced("revision out of range".into()));
        let read = |e: sqlx::Error| SidError::Storage(format!("check assignment fence: {e}"));
        if let Some((basis, checked)) = fence.basis {
            let held: Option<(i64,)> = sqlx::query_as(
                "SELECT revision FROM role_assignments
                 WHERE id = $1 AND (expires_at IS NULL OR expires_at > now())
                 FOR SHARE",
            )
            .bind(basis.0)
            .fetch_optional(&mut **tx)
            .await
            .map_err(read)?;
            if held.map(|(r,)| r) != Some(revision(checked)?) {
                return Err(SidError::Fenced(
                    "the authorizing assignment changed since it was checked".into(),
                ));
            }
        }
        let (role, checked) = &fence.role;
        let held: Option<(String,)> =
            sqlx::query_as("SELECT permissions FROM roles WHERE id = $1 FOR SHARE")
                .bind(role.0)
                .fetch_optional(&mut **tx)
                .await
                .map_err(read)?;
        let same = held.is_some_and(|(permissions,)| {
            Role::parse_permissions(&permissions)
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                == *checked
        });
        if !same {
            return Err(SidError::Fenced(
                "the role's permissions changed since it was checked".into(),
            ));
        }
        if let Some((group, member)) = fence.recipient_membership {
            let held: Option<(i32,)> = sqlx::query_as(
                "SELECT 1 FROM group_members WHERE group_id = $1 AND profile_id = $2 FOR SHARE",
            )
            .bind(group.0)
            .bind(member)
            .fetch_optional(&mut **tx)
            .await
            .map_err(read)?;
            if held.is_none() {
                return Err(SidError::Fenced(
                    "the recipient left the eligible group since it was checked".into(),
                ));
            }
        }
        if let Some((group, grantor)) = fence.grantor_outside {
            // Shared lock on the group: a member added concurrently takes it
            // FOR UPDATE, so it either commits first and is seen here, or
            // waits and sees this assignment.
            sqlx::query("SELECT 1 FROM groups WHERE id = $1 FOR SHARE")
                .bind(group.0)
                .execute(&mut **tx)
                .await
                .map_err(read)?;
            let inside: Option<(i32,)> = sqlx::query_as(
                "SELECT 1 FROM group_members WHERE group_id = $1 AND profile_id = $2",
            )
            .bind(group.0)
            .bind(grantor)
            .fetch_optional(&mut **tx)
            .await
            .map_err(read)?;
            if inside.is_some() {
                return Err(SidError::Fenced(
                    "the grantor joined the recipient group since it was checked".into(),
                ));
            }
        }
        Ok(())
    }

    /// `rows` as assignments, each administrative one with its envelope.
    async fn role_assignments(
        &self,
        rows: Vec<crate::pg_row::RoleAssignmentRow>,
    ) -> SidResult<Vec<RoleAssignment>> {
        use sid_core::models::{AdminEnvelope, AdminOperation, RecipientKind};
        let mut assignments = rows
            .into_iter()
            .map(|r| r.into_domain())
            .collect::<SidResult<Vec<_>>>()?;
        if assignments.is_empty() {
            return Ok(assignments);
        }
        let ids: Vec<uuid::Uuid> = assignments.iter().map(|a| a.id.0).collect();
        let ceilings: Vec<(uuid::Uuid, String)> = sqlx::query_as(
            "SELECT assignment_id, permission FROM role_assignment_ceilings
             WHERE assignment_id = ANY($1)",
        )
        .bind(&ids)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("read approved ceilings: {e}")))?;
        let position: std::collections::HashMap<uuid::Uuid, usize> =
            ids.iter().enumerate().map(|(i, id)| (*id, i)).collect();
        for (id, permission) in ceilings {
            let provenance = position
                .get(&id)
                .and_then(|i| assignments[*i].provenance.as_mut())
                .ok_or_else(|| {
                    SidError::Storage(format!("approved ceiling of {id} without provenance"))
                })?;
            provenance
                .ceiling
                .get_or_insert_with(Default::default)
                .insert(permission);
        }
        let heads: Vec<(uuid::Uuid, Option<uuid::Uuid>, i64)> = sqlx::query_as(
            "SELECT assignment_id, recipient_group_id, max_validity_secs
             FROM role_assignment_admin WHERE assignment_id = ANY($1)",
        )
        .bind(&ids)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("read administrative envelopes: {e}")))?;
        if heads.is_empty() {
            return Ok(assignments);
        }
        let mut envelopes: std::collections::HashMap<uuid::Uuid, AdminEnvelope> = heads
            .into_iter()
            .map(|(id, group, max)| {
                (
                    id,
                    AdminEnvelope {
                        operations: Default::default(),
                        roles: Default::default(),
                        permission_ceiling: Default::default(),
                        recipient_kinds: Default::default(),
                        recipient_group: group.map(GroupId),
                        max_validity_secs: max,
                    },
                )
            })
            .collect();
        let held: Vec<uuid::Uuid> = envelopes.keys().copied().collect();
        let entries: Vec<(uuid::Uuid, String, String)> = sqlx::query_as(
            "SELECT assignment_id, kind, value FROM role_assignment_admin_entries
             WHERE assignment_id = ANY($1)",
        )
        .bind(&held)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("read administrative envelopes: {e}")))?;
        let unreadable =
            |id: uuid::Uuid| SidError::Storage(format!("administrative envelope {id} unreadable"));
        for (id, kind, value) in entries {
            let envelope = envelopes.get_mut(&id).ok_or_else(|| unreadable(id))?;
            match kind.as_str() {
                "operation" => {
                    envelope
                        .operations
                        .insert(AdminOperation::parse(&value).ok_or_else(|| unreadable(id))?);
                }
                "recipient_kind" => {
                    envelope
                        .recipient_kinds
                        .insert(RecipientKind::parse(&value).ok_or_else(|| unreadable(id))?);
                }
                "permission" => {
                    envelope.permission_ceiling.insert(value);
                }
                _ => return Err(unreadable(id)),
            }
        }
        let roles: Vec<(uuid::Uuid, uuid::Uuid)> = sqlx::query_as(
            "SELECT assignment_id, role_id FROM role_assignment_admin_roles
             WHERE assignment_id = ANY($1)",
        )
        .bind(&held)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("read administrative envelopes: {e}")))?;
        for (id, role) in roles {
            envelopes
                .get_mut(&id)
                .ok_or_else(|| unreadable(id))?
                .roles
                .insert(RoleId(role));
        }
        for assignment in &mut assignments {
            assignment.admin = envelopes.remove(&assignment.id.0);
        }
        Ok(assignments)
    }

    /// Record the decision in `request` on a request still pending; false,
    /// writing nothing, when it was already decided.
    async fn decide_access_request_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        request: &sid_core::models::AccessRequest,
    ) -> SidResult<bool> {
        Ok(sqlx::query(
            "UPDATE access_requests SET status = $2, reviewed_by = $3, review_comment = $4, reviewed_at = $5
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(request.id.0)
        .bind(request.status.as_str())
        .bind(request.reviewed_by)
        .bind(&request.review_comment)
        .bind(request.reviewed_at)
        .execute(&mut **tx)
        .await
        .map_err(|e| SidError::Storage(format!("Decide access_request failed: {}", e)))?
        .rows_affected()
            == 1)
    }

    /// Run [`OAUTH2_CLIENT_CREATE`] or [`OAUTH2_CLIENT_UPDATE`] and, when a
    /// row was written, its audit in the same transaction; returns whether it was.
    async fn write_oauth2_client(
        &self,
        client: &OAuth2Client,
        audit: MutationContext,
        sql: &'static str,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if !Self::write_oauth2_client_in_tx(&mut tx, client, sql).await? {
            return Ok(false);
        }
        Self::audit_in_tx(
            &mut tx,
            &format!("oauth2_client:{}", client.client_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    /// Run one of the `oauth2_clients` writes inside `tx`; true when a row was written.
    async fn write_oauth2_client_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        client: &OAuth2Client,
        sql: &'static str,
    ) -> SidResult<bool> {
        let claim_mappings_json = if client.claim_mappings.is_empty() {
            None
        } else {
            Some(
                serde_json::to_string(&client.claim_mappings)
                    .map_err(|e| SidError::Internal(format!("claim mappings: {e}")))?,
            )
        };
        let revision = i64::try_from(client.revision)
            .map_err(|e| SidError::Validation(format!("client revision: {e}")))?;
        let written = sqlx::query(sql)
            .bind(&client.client_id)
            .bind(client.project_id.0)
            .bind(client.application_type.as_str())
            .bind(&client.client_secret_hash)
            .bind(&client.redirect_uris)
            .bind(client.allowed_scopes.join(" "))
            .bind(client.grant_types.join(" "))
            .bind(&client.client_name)
            .bind(&client.logo_uri)
            .bind(client.active)
            .bind(client.required_acr.map(|a| a.as_str().to_string()))
            .bind(client.required_amr.join(" "))
            .bind(client.enforcement_mode.as_str())
            .bind(client.min_device_assurance.map(|d| d.as_str().to_string()))
            .bind(client.require_verified_email)
            .bind(client.require_verified_phone)
            .bind(&client.backchannel_logout_uri)
            .bind(client.backchannel_logout_session_required)
            .bind(&claim_mappings_json)
            .bind(client.login_strategy.as_str())
            .bind(client.show_federation_button)
            .bind(client.federation_timeout_ms as i32)
            .bind(client.unified_input)
            .bind(client.subject_type.as_str())
            .bind(&client.sector_identifier_uri)
            .bind(client.token_endpoint_auth_method.as_str())
            .bind(client.response_types.join(" "))
            .bind(&client.contacts)
            .bind(client.registration_iat.map(|iat| iat.0))
            .bind(&client.registration_access_token_hash)
            .bind(client.org_id)
            .bind(client.client_id_issued_at)
            .bind(client.client_secret_expires_at)
            .bind(client.created_at)
            .bind(revision)
            .bind(client.application_id)
            .bind(client.default_resource)
            .bind(client.jwks.as_ref().map(ClientKeySet::to_json))
            .bind(&client.post_logout_redirect_uris)
            .execute(&mut **tx)
            .await
            .map_err(|e| SidError::Storage(format!("write oauth2 client: {e}")))?
            .rows_affected();
        Ok(written == 1)
    }

    /// Insert a new client inside `tx`; an existing `client_id`, or a client
    /// role its application already has, is a `Conflict`.
    async fn insert_oauth2_client_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        client: &OAuth2Client,
    ) -> SidResult<()> {
        if !Self::write_oauth2_client_in_tx(tx, client, OAUTH2_CLIENT_CREATE).await? {
            return Err(SidError::Conflict(format!(
                "oauth2 client {} exists, or application {} already has a client role",
                client.client_id, client.application_id
            )));
        }
        Ok(())
    }

    /// Replace the profile's credentials of the types `credential` replaces
    /// (its one password, its recovery-code set) with it, inside `tx`.
    async fn replace_credential_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        credential: &Credential,
    ) -> SidResult<()> {
        let replaced: Vec<&str> = credential
            .credential_type
            .replaces()
            .iter()
            .map(CredentialType::as_str)
            .collect();
        if replaced.is_empty() {
            return Err(SidError::Validation(format!(
                "a {} credential is added, not replaced",
                credential.credential_type.as_str()
            )));
        }
        sqlx::query(
            "DELETE FROM credentials
             WHERE profile_id = $1 AND credential_type = ANY($2)",
        )
        .bind(credential.profile_id)
        .bind(&replaced)
        .execute(&mut **tx)
        .await
        .map_err(|e| SidError::Storage(format!("Delete replaced credentials failed: {}", e)))?;
        Self::insert_credential_in_tx(tx, credential).await
    }

    /// Insert a new credential inside `tx`; an existing id is a `Conflict`,
    /// never an update.
    async fn insert_credential_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        credential: &Credential,
    ) -> SidResult<()> {
        sqlx::query(
            "INSERT INTO credentials (
                id, profile_id, credential_type, status, data, label,
                created_at, last_used_at,
                policy_version, zkpp_verified, opaque_curve, legacy_algorithm,
                opaque_credential_identifier
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(credential.id.0)
        .bind(credential.profile_id)
        .bind(credential.credential_type.as_str())
        .bind(credential.status.as_str())
        .bind(credential.data.expose())
        .bind(&credential.label)
        .bind(credential.created_at)
        .bind(credential.last_used_at)
        .bind(credential.policy_version.map(|v| v as i32))
        .bind(credential.zkpp_verified)
        .bind(credential.opaque_curve.map(|c| c as i16))
        .bind(&credential.legacy_algorithm)
        .bind(
            credential
                .opaque_credential_identifier
                .map(|id| id.to_vec()),
        )
        .execute(&mut **tx)
        .await
        .map_err(|e| insert_error("credential", e))?;
        Ok(())
    }

    /// Get sqlx connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get the configured schema name (if any)
    #[allow(dead_code)]
    pub(crate) fn schema(&self) -> Option<&str> {
        self.schema.as_deref()
    }

    /// Load claim grants for a consent record.
    async fn load_claim_grants(
        &self,
        consent_id: uuid::Uuid,
    ) -> SidResult<Vec<sid_core::models::consent::ClaimGrant>> {
        let rows = sqlx::query_as::<_, ClaimGrantRow>(
            "SELECT id, consent_id, claim_name, claim_type, granted_at, revoked_at \
             FROM claim_grants WHERE consent_id = $1 ORDER BY granted_at",
        )
        .bind(consent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| sid_core::Error::Storage(e.to_string()))?;

        rows.into_iter()
            .map(ClaimGrantRow::into_claim_grant)
            .collect()
    }

    /// Run one export job status change (`$1` id, `$2` time); `true` when it
    /// applied. Nothing is committed, the audit record included, otherwise.
    async fn transition_export_job(
        &self,
        id: Uuid,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
        sql: &'static str,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let changed = sqlx::query(sql)
            .bind(id)
            .bind(at)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("export job status: {e}")))?
            .rows_affected()
            == 1;
        if !changed {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("export_job:{id}"), ctx).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    /// Run one of the `upstream_providers` writes (`$1`..`$18`); returns rows
    /// written. Nothing is committed, the audit record included, when none was.
    async fn write_upstream_provider(
        &self,
        provider: &UpstreamProvider,
        audit: MutationContext,
        sql: &'static str,
    ) -> SidResult<u64> {
        let scopes_json = serde_json::to_value(&provider.scopes)
            .map_err(|e| SidError::Internal(format!("provider scopes: {e}")))?;
        let revision = i64::try_from(provider.revision)
            .map_err(|e| SidError::Validation(format!("provider revision: {e}")))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let written = sqlx::query(sql)
            .bind(provider.id.0)
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
            .bind(provider.created_at)
            .bind(provider.updated_at)
            .bind(revision)
            .execute(&mut *tx)
            .await
            .map_err(|e| insert_error("upstream provider", e))?
            .rows_affected();
        if written == 0 {
            return Ok(0);
        }
        Self::audit_in_tx(
            &mut tx,
            &format!("upstream_provider:{}", provider.id.0),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(written)
    }
}

/// A branding config: its content from `data`, its status, revision and last
/// change from their columns (the status inside `data` is not read).
#[derive(sqlx::FromRow)]
struct BrandingRow {
    status: String,
    revision: i64,
    updated_at: chrono::DateTime<chrono::Utc>,
    data: serde_json::Value,
}

impl BrandingRow {
    fn into_domain(self) -> SidResult<sid_core::models::BrandingConfig> {
        let mut config: sid_core::models::BrandingConfig = serde_json::from_value(self.data)
            .map_err(|e| SidError::Storage(format!("column data: {e}")))?;
        config.status = self
            .status
            .parse()
            .map_err(|e: String| SidError::Storage(format!("column status: {e}")))?;
        config.revision = u64::try_from(self.revision)
            .map_err(|e| SidError::Storage(format!("column revision: {e}")))?;
        config.updated_at = self.updated_at;
        Ok(config)
    }
}

/// A flow action: its content from `data`, its revision from the column.
#[derive(sqlx::FromRow)]
struct FlowActionRow {
    data: serde_json::Value,
    revision: i64,
}

impl FlowActionRow {
    fn into_domain(self) -> SidResult<sid_core::models::FlowAction> {
        let mut action: sid_core::models::FlowAction = serde_json::from_value(self.data)
            .map_err(|e| SidError::Storage(format!("column data: {e}")))?;
        action.revision = u64::try_from(self.revision)
            .map_err(|e| SidError::Storage(format!("column revision: {e}")))?;
        Ok(action)
    }
}

/// Row type for reading consent records from PostgreSQL.
#[derive(sqlx::FromRow)]
struct ConsentRow {
    id: uuid::Uuid,
    profile_id: ProfileId,
    client_id: String,
    status: String,
    consented_at: chrono::DateTime<chrono::Utc>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl ConsentRow {
    fn into_consent_record(
        self,
        grants: Vec<sid_core::models::consent::ClaimGrant>,
    ) -> SidResult<sid_core::models::consent::ConsentRecord> {
        Ok(sid_core::models::consent::ConsentRecord {
            id: sid_core::models::consent::ConsentId(self.id),
            profile_id: self.profile_id,
            client_id: self.client_id,
            status: self.status.parse().map_err(SidError::Storage)?,
            grants,
            consented_at: self.consented_at,
            revoked_at: self.revoked_at,
            updated_at: self.updated_at,
        })
    }
}

/// Row type for reading claim grants from PostgreSQL.
#[derive(sqlx::FromRow)]
struct ClaimGrantRow {
    id: uuid::Uuid,
    consent_id: uuid::Uuid,
    claim_name: String,
    claim_type: String,
    granted_at: chrono::DateTime<chrono::Utc>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl ClaimGrantRow {
    fn into_claim_grant(self) -> SidResult<sid_core::models::consent::ClaimGrant> {
        Ok(sid_core::models::consent::ClaimGrant {
            id: sid_core::models::consent::ClaimGrantId(self.id),
            consent_id: sid_core::models::consent::ConsentId(self.consent_id),
            claim_name: self.claim_name,
            claim_type: self.claim_type.parse().map_err(SidError::Storage)?,
            granted_at: self.granted_at,
            revoked_at: self.revoked_at,
        })
    }
}

/// Row type for anomaly_events table.
#[derive(sqlx::FromRow)]
struct AnomalyEventRow {
    id: uuid::Uuid,
    rule_id: String,
    profile_id: String,
    ip_address: String,
    description: String,
    risk_score: i32,
    reaction: String,
    timestamp: chrono::DateTime<chrono::Utc>,
}

impl AnomalyEventRow {
    fn into_record(self) -> sid_core::models::AnomalyEventRecord {
        sid_core::models::AnomalyEventRecord {
            id: sid_core::models::AnomalyEventId(self.id),
            rule_id: self.rule_id,
            profile_id: self.profile_id,
            ip_address: self.ip_address,
            description: self.description,
            risk_score: self.risk_score,
            reaction: self.reaction,
            timestamp: self.timestamp,
        }
    }
}

#[async_trait]
impl StorageBackend for PostgresBackend {
    fn name(&self) -> &'static str {
        "postgres"
    }

    // === PROFILE OPERATIONS === (sqlx)

    async fn get_profile(&self, id: ProfileId) -> SidResult<Option<Profile>> {
        let row =
            sqlx::query_as::<_, crate::pg_row::ProfileRow>("SELECT * FROM profiles WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn get_profile_by_username(&self, username: &str) -> SidResult<Option<Profile>> {
        let row = sqlx::query_as::<_, crate::pg_row::ProfileRow>(
            "SELECT * FROM profiles WHERE username = $1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn get_profile_by_email(&self, email: &str) -> SidResult<Option<Profile>> {
        let row = sqlx::query_as::<_, crate::pg_row::ProfileRow>(
            "SELECT p.* FROM profiles p
             INNER JOIN profile_emails pe ON pe.profile_id = p.id
             WHERE pe.email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn create_profile(&self, profile: &Profile, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        directory::insert_profile(&mut tx, profile).await?;
        Self::audit_in_tx(&mut tx, &format!("profile:{}", profile.id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn update_profile(&self, profile: &Profile, audit: MutationContext) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if !directory::update_profile(&mut tx, profile).await? {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("profile:{}", profile.id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn delete_profile(&self, id: ProfileId, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM profiles WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("profile:{id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn register_profile(
        &self,
        registration: &NewRegistration,
        audit: MutationContext,
    ) -> SidResult<()> {
        let NewRegistration {
            profile,
            principal,
            email,
            phone,
            credential,
            source,
            instance_claim,
            history,
        } = registration;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;

        // The first administrator's registration consumes the claim first: the
        // removed row serializes two registrants holding the same claim, and a
        // refusal drops the transaction with nothing written.
        if let Some(claim) = instance_claim {
            let consumed =
                sqlx::query("DELETE FROM instance_secrets WHERE name = $1 AND sealed = $2")
                    .bind(sid_core::models::InstanceSecret::AdminClaim.as_str())
                    .bind(claim)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| SidError::Storage(format!("consume admin claim: {e}")))?
                    .rows_affected()
                    == 1;
            let admin_exists: bool = sqlx::query_scalar(ADMIN_EXISTS_SQL)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("admin exists: {e}")))?;
            if !consumed || admin_exists {
                return Err(SidError::InvalidState(
                    "the installation has no open administrator claim".into(),
                ));
            }
        }

        // The principal goes first: the (principal_type, value) key decides the race
        // between two registrations of the same identifier, and a taken identifier
        // leaves nothing behind (the transaction is dropped, not committed).
        // A new identifier is first used here: it is assigned to the registrant.
        let inserted: Option<(Uuid,)> = sqlx::query_as(
            "INSERT INTO principals (
                id, principal_type, value, verified, verified_at,
                verification_expires, assigned_profile_id, assignment_revision,
                email_policy_revision, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, $9, $10)
            ON CONFLICT (principal_type, value) DO NOTHING
            RETURNING id",
        )
        .bind(principal.id.0)
        .bind(principal.principal_type.as_str())
        .bind(&principal.value)
        .bind(principal.verified)
        .bind(principal.verified_at)
        .bind(principal.verification_expires)
        .bind(profile.id)
        .bind(principal.email_policy_revision)
        .bind(principal.created_at)
        .bind(principal.updated_at)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| principal_write_error("insert principal", e))?;
        if inserted.is_none() {
            return Err(SidError::Conflict("principal already registered".into()));
        }

        directory::insert_profile(&mut tx, profile).await?;

        if let Some(email) = email {
            sqlx::query(
                "INSERT INTO profile_emails (
                    id, profile_id, email, label, custom_label,
                    is_primary, verified, verified_at, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(email.id.0)
            .bind(email.profile_id)
            .bind(&email.email)
            .bind(email.label.as_str())
            .bind(&email.custom_label)
            .bind(email.is_primary)
            .bind(email.verified)
            .bind(email.verified_at)
            .bind(email.created_at)
            .bind(email.updated_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| insert_error("profile email", e))?;
        }

        if let Some(phone) = phone {
            sqlx::query(
                "INSERT INTO profile_phones (
                    id, profile_id, e164, extension, label, custom_label,
                    is_primary, can_receive_sms, can_receive_fax, can_receive_voice,
                    verified, verified_at, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            )
            .bind(phone.id.0)
            .bind(phone.profile_id)
            .bind(phone.e164 as i64)
            .bind(phone.extension.map(|e| e as i32))
            .bind(phone.label.as_str())
            .bind(&phone.custom_label)
            .bind(phone.is_primary)
            .bind(phone.can_receive_sms)
            .bind(phone.can_receive_fax)
            .bind(phone.can_receive_voice)
            .bind(phone.verified)
            .bind(phone.verified_at)
            .bind(phone.created_at)
            .bind(phone.updated_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| insert_error("profile phone", e))?;
        }

        sqlx::query(
            "INSERT INTO principal_bindings (
                id, principal_id, profile_id,
                is_primary, source_field, source_email_id, source_phone_id, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(Uuid::now_v7())
        .bind(principal.id.0)
        .bind(principal.profile_id)
        .bind(principal.is_primary)
        .bind(&principal.source_field)
        .bind(principal.source_email_id.map(|id| id.0))
        .bind(principal.source_phone_id.map(|id| id.0))
        .bind(principal.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("principal binding", e))?;

        if let Some(credential) = credential {
            Self::insert_credential_in_tx(&mut tx, credential).await?;
        }
        // A new owner has no history row: nothing can have moved it, so a
        // refusal here is a caller error, not a lost race.
        if let Some(history) = history
            && !password_history::apply_in_tx(&mut tx, history).await?
        {
            return Err(SidError::Conflict(
                "the new profile already has password history".into(),
            ));
        }

        if let Some(source) = source {
            sqlx::query(
                "INSERT INTO registration_sources (profile_id, source_type, source_id, referrer_id, utm_source, utm_medium, utm_campaign, utm_term, utm_content, client_id, created_at)
                 VALUES ($1, $2::registration_source_type, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            )
            .bind(profile.id)
            .bind(source.source_type.as_str())
            .bind(&source.source_id)
            .bind(source.referrer_id)
            .bind(&source.utm.source)
            .bind(&source.utm.medium)
            .bind(&source.utm.campaign)
            .bind(&source.utm.term)
            .bind(&source.utm.content)
            .bind(&source.client_id)
            .bind(source.created_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| insert_error("registration source", e))?;
        }

        Self::audit_in_tx(&mut tx, &format!("profile:{}", profile.id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    // === PROFILE PHONE OPERATIONS ===

    async fn get_profile_phone(&self, id: ProfilePhoneId) -> SidResult<Option<ProfilePhone>> {
        let row = sqlx::query_as::<_, crate::pg_row::ProfilePhoneRow>(
            "SELECT * FROM profile_phones WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.map(|r| r.into_domain()))
    }

    async fn list_profile_phones(&self, profile_id: ProfileId) -> SidResult<Vec<ProfilePhone>> {
        let rows = sqlx::query_as::<_, crate::pg_row::ProfilePhoneRow>(
            "SELECT * FROM profile_phones WHERE profile_id = $1 ORDER BY is_primary DESC, created_at",
        ).bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(rows.into_iter().map(|r| r.into_domain()).collect())
    }

    async fn get_primary_profile_phone(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<ProfilePhone>> {
        let row = sqlx::query_as::<_, crate::pg_row::ProfilePhoneRow>(
            "SELECT * FROM profile_phones WHERE profile_id = $1 AND is_primary = true",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.map(|r| r.into_domain()))
    }

    async fn create_profile_phone(
        &self,
        phone: &ProfilePhone,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if phone.is_primary {
            contact::clear_primary(
                &mut tx,
                contact::Contacts::Phones,
                phone.profile_id,
                phone.updated_at,
            )
            .await?;
        }
        contact::insert_phone(&mut tx, phone).await?;
        Self::audit_in_tx(&mut tx, &format!("profile_phone:{}", phone.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn update_profile_phone_settings(
        &self,
        profile_id: ProfileId,
        id: ProfilePhoneId,
        settings: &PhoneSettings,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let updated = sqlx::query(
            "UPDATE profile_phones SET label = COALESCE($3, label),
                custom_label = CASE WHEN $4 THEN $5 ELSE custom_label END,
                can_receive_sms = COALESCE($6, can_receive_sms),
                can_receive_fax = COALESCE($7, can_receive_fax),
                can_receive_voice = COALESCE($8, can_receive_voice),
                updated_at = $9
             WHERE id = $1 AND profile_id = $2",
        )
        .bind(id.0)
        .bind(profile_id)
        .bind(settings.label.as_ref().map(|l| l.as_str()))
        .bind(settings.custom_label.is_some())
        .bind(settings.custom_label.clone().flatten())
        .bind(settings.can_receive_sms)
        .bind(settings.can_receive_fax)
        .bind(settings.can_receive_voice)
        .bind(at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("update phone: {e}")))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("profile_phone:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn set_primary_profile_phone(
        &self,
        profile_id: ProfileId,
        id: ProfilePhoneId,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if !contact::make_primary(&mut tx, contact::Contacts::Phones, profile_id, id.0, at).await? {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("profile_phone:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn delete_profile_phone(
        &self,
        id: ProfilePhoneId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        directory::delete_phone(&mut tx, id, None).await?;
        Self::audit_in_tx(&mut tx, &format!("profile_phone:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    // === PROFILE EMAIL OPERATIONS ===

    async fn get_profile_email(&self, id: ProfileEmailId) -> SidResult<Option<ProfileEmail>> {
        let row = sqlx::query_as::<_, crate::pg_row::ProfileEmailRow>(
            "SELECT * FROM profile_emails WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.map(|r| r.into_domain()))
    }

    async fn list_profile_emails(&self, profile_id: ProfileId) -> SidResult<Vec<ProfileEmail>> {
        let rows = sqlx::query_as::<_, crate::pg_row::ProfileEmailRow>(
            "SELECT * FROM profile_emails WHERE profile_id = $1 ORDER BY is_primary DESC, created_at",
        ).bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(rows.into_iter().map(|r| r.into_domain()).collect())
    }

    async fn get_primary_profile_email(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<ProfileEmail>> {
        let row = sqlx::query_as::<_, crate::pg_row::ProfileEmailRow>(
            "SELECT * FROM profile_emails WHERE profile_id = $1 AND is_primary = true",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.map(|r| r.into_domain()))
    }

    async fn create_profile_email(
        &self,
        email: &ProfileEmail,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if email.is_primary {
            contact::clear_primary(
                &mut tx,
                contact::Contacts::Emails,
                email.profile_id,
                email.updated_at,
            )
            .await?;
        }
        contact::insert_email(&mut tx, email).await?;
        Self::audit_in_tx(&mut tx, &format!("profile_email:{}", email.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn update_profile_email_settings(
        &self,
        profile_id: ProfileId,
        id: ProfileEmailId,
        settings: &EmailSettings,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let updated = sqlx::query(
            "UPDATE profile_emails SET label = COALESCE($3, label),
                custom_label = CASE WHEN $4 THEN $5 ELSE custom_label END,
                updated_at = $6
             WHERE id = $1 AND profile_id = $2",
        )
        .bind(id.0)
        .bind(profile_id)
        .bind(settings.label.as_ref().map(|l| l.as_str()))
        .bind(settings.custom_label.is_some())
        .bind(settings.custom_label.clone().flatten())
        .bind(at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("update email: {e}")))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("profile_email:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn set_primary_profile_email(
        &self,
        profile_id: ProfileId,
        id: ProfileEmailId,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if !contact::make_primary(&mut tx, contact::Contacts::Emails, profile_id, id.0, at).await? {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("profile_email:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn delete_profile_email(
        &self,
        id: ProfileEmailId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        directory::delete_email(&mut tx, id, None).await?;
        Self::audit_in_tx(&mut tx, &format!("profile_email:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    // === PRINCIPAL OPERATIONS ===
    //
    // principals is the entity table (one per type+value), principal_bindings
    // the M:N relationship to the Profiles claiming them. Queries JOIN both
    // tables to populate Principal with binding context.

    async fn get_principal(&self, id: PrincipalId) -> SidResult<Option<Principal>> {
        let row = sqlx::query_as::<_, crate::pg_row::PrincipalRow>(
            "SELECT p.id, p.principal_type, p.value, p.verified, p.verified_at,
                    p.verification_expires, p.assigned_profile_id, p.assignment_revision,
                    p.email_policy_revision, p.created_at, p.updated_at,
                    pb.id AS binding_id, pb.profile_id,
                    pb.is_primary, pb.source_field, pb.source_email_id, pb.source_phone_id
             FROM principals p
             JOIN principal_bindings pb ON pb.principal_id = p.id
             WHERE p.id = $1 LIMIT 1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn get_principals_by_profile(&self, profile_id: ProfileId) -> SidResult<Vec<Principal>> {
        let rows = sqlx::query_as::<_, crate::pg_row::PrincipalRow>(
            "SELECT p.id, p.principal_type, p.value, p.verified, p.verified_at,
                    p.verification_expires, p.assigned_profile_id, p.assignment_revision,
                    p.email_policy_revision, p.created_at, p.updated_at,
                    pb.id AS binding_id, pb.profile_id,
                    pb.is_primary, pb.source_field, pb.source_email_id, pb.source_phone_id
             FROM principals p
             JOIN principal_bindings pb ON pb.principal_id = p.id
             WHERE pb.profile_id = $1",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn get_profile_by_principal(
        &self,
        principal_type: PrincipalType,
        value: &str,
    ) -> SidResult<Option<Profile>> {
        // The assigned profile, while it still holds its claim; a claim alone
        // resolves nobody.
        let row = sqlx::query_as::<_, crate::pg_row::ProfileRow>(
            "SELECT prof.* FROM principals p
             JOIN profiles prof ON prof.id = p.assigned_profile_id
             JOIN principal_bindings pb ON pb.principal_id = p.id AND pb.profile_id = prof.id
             WHERE p.principal_type = $1 AND p.value = $2",
        )
        .bind(principal_type.as_str())
        .bind(value)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn save_principal(&self, p: &Principal, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        directory::bind_principal(&mut tx, p).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("principal:profile:{}", p.profile_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn unbind_principal(
        &self,
        principal_id: PrincipalId,
        profile_id: ProfileId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if !directory::unbind_principal(&mut tx, principal_id, profile_id).await? {
            return Ok(false);
        }
        Self::audit_in_tx(
            &mut tx,
            &format!("principal_binding:{}:{}", principal_id.0, profile_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn count_active_principal_bindings(&self, principal_id: PrincipalId) -> SidResult<i64> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM principal_bindings pb
             JOIN profiles prof ON pb.profile_id = prof.id
             WHERE pb.principal_id = $1 AND prof.status = 'active'",
        )
        .bind(principal_id.0)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Count failed: {}", e)))?;
        Ok(count.0)
    }

    async fn get_principal_bindings(
        &self,
        principal_id: PrincipalId,
    ) -> SidResult<Vec<PrincipalBinding>> {
        let rows = sqlx::query_as::<_, crate::pg_row::PrincipalBindingRow>(
            "SELECT * FROM principal_bindings WHERE principal_id = $1",
        )
        .bind(principal_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn get_principal_by_value(
        &self,
        principal_type: PrincipalType,
        value: &str,
    ) -> SidResult<Option<PrincipalEntity>> {
        let row = sqlx::query_as::<_, crate::pg_row::PrincipalEntityRow>(
            "SELECT id, principal_type, value, verified, verified_at,
                    verification_expires, assigned_profile_id, assignment_revision,
                    email_policy_revision, created_at, updated_at
             FROM principals
             WHERE principal_type = $1 AND value = $2",
        )
        .bind(principal_type.as_str())
        .bind(value)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn expire_principal_verifications(&self) -> SidResult<i64> {
        // The proof lapses; the assignment and its revision stay.
        let result = sqlx::query(
            "UPDATE principals SET verified = false, updated_at = NOW()
             WHERE verified = true
               AND verification_expires IS NOT NULL
               AND verification_expires < NOW()",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Expire failed: {}", e)))?;
        Ok(result.rows_affected() as i64)
    }

    async fn reconcile_email_key(
        &self,
        principal_id: PrincipalId,
        profile_id: ProfileId,
        contact: &ProfileEmail,
        reason: &str,
        audit: MutationContext,
    ) -> SidResult<bool> {
        if contact.profile_id != profile_id {
            return Err(SidError::Validation(
                "the evidence is a contact of another profile".into(),
            ));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // The key leaves quarantine only while it still is quarantined and
        // assigned to this profile; the row lock orders concurrent repairs.
        let moved = sqlx::query(
            "UPDATE principals SET email_policy_revision =
                 (SELECT revision FROM email_policy_activations WHERE scope = 'installation'),
                 updated_at = NOW()
             WHERE id = $1 AND principal_type = 'email'
               AND email_policy_revision = 0 AND assigned_profile_id = $2",
        )
        .bind(principal_id.0)
        .bind(profile_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| principal_write_error("reconcile email key", e))?
        .rows_affected();
        if moved == 0 {
            return Ok(false);
        }
        directory::upsert_email(&mut tx, contact).await?;
        sqlx::query(
            "UPDATE principal_bindings SET source_field = 'email', source_email_id = $3
             WHERE principal_id = $1 AND profile_id = $2",
        )
        .bind(principal_id.0)
        .bind(profile_id)
        .bind(contact.id.0)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("link reconciled key: {e}")))?;
        sqlx::query(
            "INSERT INTO email_policy_dispositions
                 (principal_id, from_revision, to_revision, disposition, reason)
             SELECT $1, 0, revision, 'migrated', $2
             FROM email_policy_activations WHERE scope = 'installation'
             ON CONFLICT (principal_id) DO UPDATE SET
                 to_revision = EXCLUDED.to_revision, disposition = 'migrated',
                 reason = EXCLUDED.reason, recorded_at = NOW()",
        )
        .bind(principal_id.0)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("record reconciliation: {e}")))?;
        Self::audit_in_tx(&mut tx, &format!("principal:profile:{profile_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    // === CREDENTIAL OPERATIONS === (sqlx)

    async fn get_credential(&self, id: CredentialId) -> SidResult<Option<Credential>> {
        let row = sqlx::query_as::<_, crate::pg_row::CredentialRow>(
            "SELECT * FROM credentials WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn get_credentials_by_profile(
        &self,
        profile_id: ProfileId,
        credential_type: Option<CredentialType>,
    ) -> SidResult<Vec<Credential>> {
        let rows = if let Some(cred_type) = credential_type {
            sqlx::query_as::<_, crate::pg_row::CredentialRow>(
                "SELECT * FROM credentials WHERE profile_id = $1 AND credential_type = $2",
            )
            .bind(profile_id)
            .bind(cred_type.as_str())
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as::<_, crate::pg_row::CredentialRow>(
                "SELECT * FROM credentials WHERE profile_id = $1",
            )
            .bind(profile_id)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn create_credential(
        &self,
        credential: &Credential,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::insert_credential_in_tx(&mut tx, credential).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("profile:{}", credential.profile_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn set_credential_label(
        &self,
        id: CredentialId,
        label: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let profile_id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE credentials SET label = $2
             WHERE id = $1 AND status = 'active' RETURNING profile_id",
        )
        .bind(id.0)
        .bind(label)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("set credential label: {e}")))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn change_password(
        &self,
        id: CredentialId,
        expected: &[u8],
        new: &Credential,
        history: Option<&HistoryCommit>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let profile_id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE credentials SET data = $3,
                policy_version = $4, zkpp_verified = $5,
                opaque_credential_identifier = $6, last_used_at = NOW()
             WHERE id = $1 AND status = 'active' AND data = $2 RETURNING profile_id",
        )
        .bind(id.0)
        .bind(expected)
        .bind(new.data.expose())
        .bind(new.policy_version.map(|v| v as i32))
        .bind(new.zkpp_verified)
        .bind(new.opaque_credential_identifier.map(|id| id.to_vec()))
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("change password: {e}")))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        if let Some(history) = history {
            if history.owner.into_uuid() != profile_id {
                return Err(SidError::Validation(
                    "password history belongs to the credential's profile".into(),
                ));
            }
            if !password_history::apply_in_tx(&mut tx, history).await? {
                return Ok(false);
            }
        }
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn get_password_history(&self, owner: ProfileId) -> SidResult<PasswordHistory> {
        password_history::get(&self.pool, owner).await
    }

    async fn ensure_history_epoch(
        &self,
        new: &NewHistoryEpoch,
        audit: MutationContext,
    ) -> SidResult<HistoryEpoch> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let epoch = password_history::ensure_epoch(&mut tx, new).await?;
        if epoch.id == new.epoch.id {
            Self::audit_in_tx(&mut tx, &format!("profile:{}", epoch.owner), audit).await?;
        }
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(epoch)
    }

    async fn get_history_epoch_key(
        &self,
        epoch: HistoryEpochId,
    ) -> SidResult<Option<WrappedHistoryKey>> {
        password_history::epoch_key(&self.pool, epoch).await
    }

    async fn reseal_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let profile_id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE credentials SET data = $3
             WHERE id = $1 AND data = $2 RETURNING profile_id",
        )
        .bind(id.0)
        .bind(expected)
        .bind(data)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("reseal credential data: {e}")))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn mark_credential_used(
        &self,
        id: CredentialId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let profile_id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE credentials SET last_used_at = NOW()
             WHERE id = $1 AND status = 'active' RETURNING profile_id",
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("mark credential used: {e}")))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn replace_credential_data(
        &self,
        id: CredentialId,
        expected: &[u8],
        data: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let profile_id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE credentials SET data = $3, last_used_at = NOW()
             WHERE id = $1 AND status = 'active' AND data = $2 RETURNING profile_id",
        )
        .bind(id.0)
        .bind(expected)
        .bind(data)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("replace credential data: {e}")))?;
        let Some(profile_id) = profile_id else {
            return Ok(false);
        };
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn write_directory_user(
        &self,
        write: &sid_core::models::DirectoryUserWrite,
        ctx: MutationContext,
    ) -> SidResult<Vec<Session>> {
        self.write_directory_user_impl(write, ctx).await
    }

    async fn write_directory_group(
        &self,
        write: &sid_core::models::DirectoryGroupWrite,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.write_directory_group_impl(write, ctx).await
    }

    async fn replace_credential(
        &self,
        credential: &Credential,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::replace_credential_in_tx(&mut tx, credential).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("profile:{}", credential.profile_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn enroll_credential(
        &self,
        credential: &Credential,
        recovery: Option<&Credential>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        if let Some(set) = recovery
            && set.credential_type != CredentialType::Recovery
        {
            return Err(SidError::Validation(
                "only recovery codes are issued with an enrolled factor".into(),
            ));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::insert_credential_in_tx(&mut tx, credential).await?;
        if let Some(set) = recovery {
            Self::replace_credential_in_tx(&mut tx, set).await?;
        }
        Self::audit_in_tx(&mut tx, &format!("profile:{}", credential.profile_id), ctx).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn delete_credential(&self, id: CredentialId, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM credentials WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("credential:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn revoke_credential(
        &self,
        id: CredentialId,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::CredentialRevocation> {
        use sid_core::models::CredentialRevocation;
        let storage = |e: sqlx::Error| SidError::Storage(format!("revoke credential: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let primary_types: Vec<&str> = CredentialType::PRIMARY.iter().map(|t| t.as_str()).collect();
        let owner: Option<ProfileId> =
            sqlx::query_scalar("SELECT profile_id FROM credentials WHERE id = $1")
                .bind(id.0)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
        let Some(profile_id) = owner else {
            return Ok(CredentialRevocation::AlreadyGone);
        };
        // The profile row lock serializes revocations of one profile, so the
        // count below cannot be raced by a concurrent revocation.
        sqlx::query("SELECT 1 FROM profiles WHERE id = $1 FOR NO KEY UPDATE")
            .bind(profile_id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        let target: Option<(String, String)> = sqlx::query_as(
            "SELECT credential_type, status FROM credentials WHERE id = $1 FOR UPDATE",
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
        let Some((credential_type, status)) = target else {
            return Ok(CredentialRevocation::AlreadyGone);
        };
        if status != "active" {
            return Ok(CredentialRevocation::AlreadyGone);
        }
        if primary_types.contains(&credential_type.as_str()) {
            let others: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM credentials
                 WHERE profile_id = $1 AND id <> $2 AND status = 'active'
                   AND credential_type = ANY($3)",
            )
            .bind(profile_id)
            .bind(id.0)
            .bind(&primary_types)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
            if others == 0 {
                return Ok(CredentialRevocation::LastPrimary);
            }
        }
        sqlx::query("UPDATE credentials SET status = 'revoked' WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        Self::audit_in_tx(&mut tx, &format!("credential:{}", id.0), audit).await?;
        tx.commit().await.map_err(storage)?;
        Ok(CredentialRevocation::Revoked)
    }

    async fn delete_credentials_by_profile(
        &self,
        profile_id: ProfileId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let result = sqlx::query("DELETE FROM credentials WHERE profile_id = $1")
            .bind(profile_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}:credentials"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(result.rows_affected())
    }

    // === WEBAUTHN USER HANDLES === (sqlx)

    async fn ensure_webauthn_user_handle(
        &self,
        profile_id: ProfileId,
        rp_id: &str,
        candidate: WebAuthnUserHandle,
        audit: MutationContext,
    ) -> SidResult<WebAuthnUserHandle> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("WebAuthn user handle: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        // A concurrent first enrollment waits on the key and inserts nothing.
        let created = sqlx::query(
            "INSERT INTO webauthn_user_handles (profile_id, rp_id, user_handle)
             SELECT id, $2, $3 FROM profiles WHERE id = $1
             ON CONFLICT (profile_id, rp_id) DO NOTHING",
        )
        .bind(profile_id)
        .bind(rp_id)
        .bind(candidate.0.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("WebAuthn user handle", e))?
        .rows_affected();
        let stored: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT user_handle FROM webauthn_user_handles WHERE profile_id = $1 AND rp_id = $2",
        )
        .bind(profile_id)
        .bind(rp_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
        let stored = stored.ok_or_else(|| SidError::NotFound(format!("profile {profile_id}")))?;
        let handle = WebAuthnUserHandle::from_slice(&stored)
            .ok_or_else(|| SidError::Storage("column user_handle: not 16 bytes".into()))?;
        if created > 0 {
            Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), audit).await?;
        }
        tx.commit().await.map_err(storage)?;
        Ok(handle)
    }

    async fn get_profile_by_webauthn_user_handle(
        &self,
        rp_id: &str,
        handle: WebAuthnUserHandle,
    ) -> SidResult<Option<ProfileId>> {
        sqlx::query_scalar(
            "SELECT profile_id FROM webauthn_user_handles WHERE rp_id = $1 AND user_handle = $2",
        )
        .bind(rp_id)
        .bind(handle.0.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("WebAuthn user handle lookup: {e}")))
    }

    // === SESSION OPERATIONS === (sqlx)

    async fn create_session(&self, session: &Session, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        session::write(&mut tx, session).await?;
        Self::audit_in_tx(&mut tx, &format!("profile:{}", session.profile_id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn record_session_authentication(
        &self,
        id: SessionId,
        expected: &SessionAuthentication,
        new: &SessionAuthentication,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if !session::record_authentication(&mut tx, id, expected, new).await? {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("session:{id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn create_session_atomic(
        &self,
        session: &Session,
        max_sessions: u32,
        mut audit: MutationContext,
    ) -> SidResult<Vec<SessionId>> {
        if max_sessions == 0 {
            self.create_session(session, audit).await?;
            return Ok(vec![]);
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(format!("begin tx: {e}")))?;

        // The profile row lock serializes session creation per profile for
        // every replica and version alike, until commit or rollback. It does
        // not block other rows that merely reference the profile.
        sqlx::query("SELECT 1 FROM profiles WHERE id = $1 FOR NO KEY UPDATE")
            .bind(session.profile_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("lock profile: {e}")))?;

        // Count active (non-expired) sessions for this profile.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sessions WHERE profile_id = $1 AND expires_at > NOW()",
        )
        .bind(session.profile_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("count sessions: {e}")))?;

        // Evict oldest sessions if at or over limit.
        let mut evicted = Vec::new();
        if count >= max_sessions as i64 {
            let to_evict = (count - max_sessions as i64 + 1) as i64; // +1 for the new session
            let rows: Vec<(SessionId, Option<String>)> = sqlx::query_as(
                "SELECT id, client_id FROM sessions \
                 WHERE profile_id = $1 AND expires_at > NOW() \
                 ORDER BY created_at ASC \
                 LIMIT $2",
            )
            .bind(session.profile_id)
            .bind(to_evict)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("list evictable: {e}")))?;

            let end = SessionEnd::new(RevocationReason::SessionLimit, "system");
            for (sid, _) in &rows {
                // An evicted session ends like any other and owes the same,
                // and so do the sessions it authenticated.
                for ended in session::end_with_dependents(&mut tx, *sid).await? {
                    audit.work.extend(end.owed_by(&ended));
                    evicted.push(ended.id);
                }
            }
        }

        // Insert the new session within the same transaction.
        session::write(&mut tx, session).await?;

        Self::audit_in_tx(&mut tx, &format!("profile:{}", session.profile_id), audit).await?;

        tx.commit()
            .await
            .map_err(|e| SidError::Storage(format!("commit tx: {e}")))?;

        Ok(evicted)
    }

    async fn get_session(&self, id: SessionId) -> SidResult<Option<Session>> {
        let row =
            sqlx::query_as::<_, crate::pg_row::SessionRow>("SELECT * FROM sessions WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn get_session_by_browser_secret(
        &self,
        hash: &sid_core::models::BrowserSecretHash,
    ) -> SidResult<Option<Session>> {
        let row = sqlx::query_as::<_, crate::pg_row::SessionRow>(
            "SELECT * FROM sessions WHERE browser_secret_hash = $1",
        )
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("session by browser secret: {e}")))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn touch_session(
        &self,
        id: SessionId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> SidResult<()> {
        // GREATEST ignores a NULL argument, so a first touch sets the value.
        sqlx::query(
            "UPDATE sessions SET last_activity_at = GREATEST(last_activity_at, $2) WHERE id = $1",
        )
        .bind(id)
        .bind(at)
        .execute(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("touch session: {e}")))?;
        Ok(())
    }

    async fn delete_session(
        &self,
        id: SessionId,
        end: &SessionEnd,
        mut audit: MutationContext,
    ) -> SidResult<Vec<SessionId>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // What each ended session owes commits in this transaction.
        let ended = session::end_with_dependents(&mut tx, id).await?;
        for session in &ended {
            audit.work.extend(end.owed_by(session));
        }
        Self::audit_in_tx(&mut tx, &format!("session:{id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(ended.into_iter().map(|session| session.id).collect())
    }

    async fn delete_sessions_by_profile(
        &self,
        profile_id: ProfileId,
        end: &SessionEnd,
        mut ctx: MutationContext,
    ) -> SidResult<Vec<Session>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let sessions = directory::end_sessions(&mut tx, profile_id, end, &mut ctx).await?;
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}:sessions"), ctx).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(sessions)
    }

    // === PROJECT OPERATIONS ===

    async fn get_project(&self, id: ProjectId) -> SidResult<Option<Project>> {
        let row =
            sqlx::query_as::<_, crate::pg_row::ProjectRow>("SELECT * FROM projects WHERE id = $1")
                .bind(id.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.map(|r| r.into_domain()))
    }

    async fn create_project(&self, proj: &Project, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO projects (id, name, description, owner_id, is_system, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(proj.id.0)
        .bind(&proj.name)
        .bind(&proj.description)
        .bind(proj.owner_id)
        .bind(proj.is_system)
        .bind(proj.created_at)
        .bind(proj.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("project", e))?;
        Self::audit_in_tx(&mut tx, &format!("project:{}", proj.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn update_project(
        &self,
        id: ProjectId,
        change: &ProjectChange,
        audit: MutationContext,
    ) -> SidResult<Option<Project>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let row = sqlx::query_as::<_, crate::pg_row::ProjectRow>(
            "UPDATE projects SET name = COALESCE($2, name),
                description = COALESCE($3, description), updated_at = $4
             WHERE id = $1 AND NOT is_system
             RETURNING *",
        )
        .bind(id.0)
        .bind(&change.name)
        .bind(&change.description)
        .bind(change.updated_at)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| insert_error("project", e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        Self::audit_in_tx(&mut tx, &format!("project:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(Some(row.into_domain()))
    }

    async fn delete_project(&self, id: ProjectId, audit: MutationContext) -> SidResult<()> {
        if id.is_system() {
            return Err(SidError::Validation(
                "Cannot delete the system project".to_string(),
            ));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // A system project is never deleted, whatever its id.
        sqlx::query("DELETE FROM projects WHERE id = $1 AND NOT is_system")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("project:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_projects(&self, offset: u64, limit: u64) -> SidResult<Vec<Project>> {
        let rows = sqlx::query_as::<_, crate::pg_row::ProjectRow>(
            "SELECT * FROM projects ORDER BY created_at DESC, id OFFSET $1 LIMIT $2",
        )
        .bind(offset as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(rows.into_iter().map(|r| r.into_domain()).collect())
    }

    async fn count_projects(&self) -> SidResult<u64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM projects")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.0 as u64)
    }

    async fn list_oauth2_clients_by_project(
        &self,
        project_id: ProjectId,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<OAuth2Client>> {
        let rows = sqlx::query_as::<_, crate::pg_row::OAuth2ClientRow>(
            "SELECT * FROM oauth2_clients WHERE project_id = $1
             ORDER BY created_at DESC, client_id OFFSET $2 LIMIT $3",
        )
        .bind(project_id.0)
        .bind(offset as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn ensure_system_project(&self, audit: MutationContext) -> SidResult<()> {
        if self.get_project(ProjectId::system()).await?.is_some() {
            return Ok(());
        }
        // Replicas starting together race here; the one that loses finds it created.
        match self.create_project(&Project::system(), audit).await {
            Ok(()) | Err(SidError::Conflict(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    // === OAUTH2 CLIENT OPERATIONS ===

    async fn get_oauth2_client(&self, client_id: &str) -> SidResult<Option<OAuth2Client>> {
        let row = sqlx::query_as::<_, crate::pg_row::OAuth2ClientRow>(
            "SELECT * FROM oauth2_clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn delete_oauth2_client(&self, client_id: &str, audit: MutationContext) -> SidResult<()> {
        self.delete_oauth2_client_impl(client_id, audit).await
    }

    async fn oauth2_client_of_application(
        &self,
        id: sid_core::models::ApplicationId,
    ) -> SidResult<Option<OAuth2Client>> {
        self.oauth2_client_of_application_impl(id).await
    }

    // === APPLICATIONS ===

    async fn create_application(
        &self,
        app: &sid_core::models::Application,
        client: Option<&OAuth2Client>,
        resource: Option<&sid_core::models::ProtectedResource>,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_application_impl(app, client, resource, ctx)
            .await
    }

    async fn get_application(
        &self,
        id: sid_core::models::ApplicationId,
    ) -> SidResult<Option<sid_core::models::Application>> {
        self.get_application_impl(id).await
    }

    async fn system_application(
        &self,
        kind: sid_core::models::SystemIntegration,
    ) -> SidResult<Option<sid_core::models::Application>> {
        self.system_application_impl(kind).await
    }

    async fn list_applications_by_project(
        &self,
        project_id: ProjectId,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<sid_core::models::Application>> {
        self.list_applications_by_project_impl(project_id, offset, limit)
            .await
    }

    async fn update_application(
        &self,
        app: &sid_core::models::Application,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.update_application_impl(app, ctx).await
    }

    async fn delete_application(
        &self,
        id: sid_core::models::ApplicationId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.delete_application_impl(id, ctx).await
    }

    // === PROTECTED RESOURCES ===

    async fn create_protected_resource(
        &self,
        resource: &sid_core::models::ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.create_protected_resource_impl(resource, ctx).await
    }

    async fn get_protected_resource(
        &self,
        id: sid_core::models::ResourceId,
    ) -> SidResult<Option<sid_core::models::ProtectedResource>> {
        self.get_protected_resource_impl(id).await
    }

    async fn protected_resource_of_application(
        &self,
        id: sid_core::models::ApplicationId,
    ) -> SidResult<Option<sid_core::models::ProtectedResource>> {
        self.protected_resource_of_application_impl(id).await
    }

    async fn list_protected_resources(
        &self,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<sid_core::models::ProtectedResource>> {
        self.list_protected_resources_impl(offset, limit).await
    }

    async fn import_protected_resource(
        &self,
        resource: &sid_core::models::ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.import_protected_resource_impl(resource, ctx).await
    }

    async fn protected_resource_by_indicator(
        &self,
        issuer: sid_core::models::IssuerId,
        indicator: &sid_core::models::ResourceIndicator,
    ) -> SidResult<Option<sid_core::models::ProtectedResource>> {
        self.protected_resource_by_indicator_impl(issuer, indicator)
            .await
    }

    async fn update_protected_resource(
        &self,
        resource: &sid_core::models::ProtectedResource,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.update_protected_resource_impl(resource, ctx).await
    }

    // === RESOURCE ACCESS ===

    async fn set_resource_access(
        &self,
        access: &sid_core::models::ResourceAccess,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.set_resource_access_impl(access, ctx).await
    }

    async fn remove_resource_access(
        &self,
        client_id: &str,
        resource: sid_core::models::ResourceId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.remove_resource_access_impl(client_id, resource, ctx)
            .await
    }

    async fn resource_access(
        &self,
        client_id: &str,
        resource: sid_core::models::ResourceId,
    ) -> SidResult<Option<sid_core::models::ResourceAccess>> {
        self.resource_access_impl(client_id, resource).await
    }

    async fn list_resource_access_by_client(
        &self,
        client_id: &str,
    ) -> SidResult<Vec<sid_core::models::ResourceAccess>> {
        self.list_resource_access_by_client_impl(client_id).await
    }

    async fn list_resource_access_by_resource(
        &self,
        resource: sid_core::models::ResourceId,
    ) -> SidResult<Vec<sid_core::models::ResourceAccess>> {
        self.list_resource_access_by_resource_impl(resource).await
    }

    async fn list_oauth2_clients(&self, offset: u64, limit: u64) -> SidResult<Vec<OAuth2Client>> {
        let rows = sqlx::query_as::<_, crate::pg_row::OAuth2ClientRow>(
            "SELECT * FROM oauth2_clients ORDER BY created_at DESC, client_id OFFSET $1 LIMIT $2",
        )
        .bind(offset as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    // === ADMIN QUERY OPERATIONS ===

    async fn list_profiles(&self, offset: u64, limit: u64) -> SidResult<Vec<Profile>> {
        let rows = sqlx::query_as::<_, crate::pg_row::ProfileRow>(
            "SELECT * FROM profiles ORDER BY created_at, id OFFSET $1 LIMIT $2",
        )
        .bind(offset as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn list_profiles_with_status(
        &self,
        status: sid_core::models::ProfileStatus,
    ) -> SidResult<Vec<Profile>> {
        let rows = sqlx::query_as::<_, crate::pg_row::ProfileRow>(
            "SELECT * FROM profiles WHERE status = $1 ORDER BY id",
        )
        .bind(status.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn list_profiles_with_pending_migration(&self) -> SidResult<Vec<Profile>> {
        let rows = sqlx::query_as::<_, crate::pg_row::ProfileRow>(
            "SELECT * FROM profiles WHERE migration_pending = true",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn end_legacy_migration(
        &self,
        profile: &Profile,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if !directory::update_profile(&mut tx, profile).await? {
            return Ok(false);
        }
        sqlx::query("DELETE FROM credentials WHERE profile_id = $1 AND credential_type = $2")
            .bind(profile.id)
            .bind(CredentialType::LegacyHash.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete legacy credentials failed: {e}")))?;
        Self::audit_in_tx(&mut tx, &format!("profile:{}", profile.id), ctx).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn count_profiles(&self) -> SidResult<u64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM profiles")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.0 as u64)
    }

    async fn list_sessions_by_profile(&self, profile_id: ProfileId) -> SidResult<Vec<Session>> {
        let rows = sqlx::query_as::<_, crate::pg_row::SessionRow>(
            "SELECT * FROM sessions WHERE profile_id = $1",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn get_most_recent_session_ip(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<(String, chrono::DateTime<chrono::Utc>)>> {
        let row: Option<(String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT ip_address, created_at FROM sessions WHERE profile_id = $1 ORDER BY created_at DESC LIMIT 1",
        ).bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row)
    }

    async fn has_recent_session_from_ip(
        &self,
        profile_id: ProfileId,
        ip: &str,
        window: std::time::Duration,
    ) -> SidResult<bool> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(window.as_secs() as i64);
        let row: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE profile_id = $1 AND ip_address = $2 AND created_at > $3)",
        ).bind(profile_id)
        .bind(ip)
        .bind(cutoff)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.0)
    }

    async fn has_recent_session_from_device(
        &self,
        profile_id: ProfileId,
        device_id: uuid::Uuid,
        window: std::time::Duration,
    ) -> SidResult<bool> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(window.as_secs() as i64);
        let row: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE profile_id = $1 AND device_id = $2 AND created_at > $3)",
        ).bind(profile_id)
        .bind(device_id)
        .bind(cutoff)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.0)
    }

    async fn record_login_location(
        &self,
        profile_id: ProfileId,
        country: &str,
        latitude: f64,
        longitude: f64,
        designated_threshold: u32,
    ) -> SidResult<()> {
        sqlx::query(
            "INSERT INTO profile_locations (profile_id, country, latitude, longitude, login_count, first_seen, last_seen, designated)
             VALUES ($1, $2, $3, $4, 1, now(), now(), 1 >= $5)
             ON CONFLICT (profile_id, country)
             DO UPDATE SET
                login_count = profile_locations.login_count + 1,
                last_seen = now(),
                latitude = $3,
                longitude = $4,
                designated = (profile_locations.login_count + 1) >= $5",
        ).bind(profile_id)
        .bind(country)
        .bind(latitude)
        .bind(longitude)
        .bind(designated_threshold as i32)
        .execute(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Record login location failed: {}", e)))?;
        Ok(())
    }

    async fn get_designated_countries(&self, profile_id: ProfileId) -> SidResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT country FROM profile_locations WHERE profile_id = $1 AND designated = TRUE",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query designated countries failed: {}", e)))?;
        Ok(rows.into_iter().map(|(c,)| c).collect())
    }

    async fn update_oauth2_client(
        &self,
        client: &OAuth2Client,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.write_oauth2_client(client, audit, OAUTH2_CLIENT_UPDATE)
            .await
    }

    async fn create_oauth2_client(
        &self,
        client: &OAuth2Client,
        audit: MutationContext,
    ) -> SidResult<()> {
        if !self
            .write_oauth2_client(client, audit, OAUTH2_CLIENT_CREATE)
            .await?
        {
            return Err(SidError::Conflict(format!(
                "oauth2 client {} exists, or application {} already has a client role",
                client.client_id, client.application_id
            )));
        }
        Ok(())
    }

    // === REFRESH TOKEN OPERATIONS ===

    async fn create_refresh_token(
        &self,
        token: &RefreshToken,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        refresh_token::insert(&mut tx, token).await?;
        Self::audit_in_tx(&mut tx, &format!("refresh_token:{}", token.id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_refresh_token_by_hash(
        &self,
        token_hash: &[u8],
    ) -> SidResult<Option<RefreshToken>> {
        let row = sqlx::query_as::<_, crate::pg_row::RefreshTokenRow>(
            "SELECT * FROM refresh_tokens WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.map(|r| r.into_domain()))
    }

    async fn revoke_refresh_tokens_by_session(
        &self,
        session_id: SessionId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // Tokens in a grace window are revoked too: the window ends with them.
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked = true, grace_expires_at = NULL
             WHERE session_id = $1 AND (revoked = false OR grace_expires_at IS NOT NULL)",
        )
        .bind(session_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Update failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("session:{session_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(result.rows_affected())
    }

    async fn revoke_refresh_tokens_by_family(
        &self,
        family_id: Uuid,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked = true, grace_expires_at = NULL
             WHERE family_id = $1 AND (revoked = false OR grace_expires_at IS NOT NULL)",
        )
        .bind(family_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Update failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("token_family:{}", family_id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(result.rows_affected())
    }

    async fn rotate_refresh_token(
        &self,
        old_id: Uuid,
        new: &RefreshToken,
        grace_expires_at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let rotated = sqlx::query(
            "UPDATE refresh_tokens SET revoked = true, replaced_by = $2,
                grace_expires_at = COALESCE(grace_expires_at, $3)
             WHERE id = $1 AND expires_at > NOW()
               AND (revoked = false OR grace_expires_at > NOW())",
        )
        .bind(old_id)
        .bind(new.id)
        .bind(grace_expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("rotate refresh token: {e}")))?
        .rows_affected()
            == 1;
        if !rotated {
            return Ok(false);
        }
        refresh_token::insert(&mut tx, new).await?;
        Self::audit_in_tx(&mut tx, &format!("token_family:{}", new.family_id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    // === AUTHORIZATION CODE OPERATIONS ===

    async fn create_auth_code(
        &self,
        code: &AuthorizationCode,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO authorization_codes (code_hash, profile_id, client_id, redirect_uri,
                scopes, code_challenge, nonce, expires_at, created_at, used, resource_id,
                authenticated_at, amr, assurance_level, elevation_level, elevation_until,
                authorizing_session_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
        )
        .bind(&code.code_hash)
        .bind(code.profile_id)
        .bind(&code.client_id)
        .bind(&code.redirect_uri)
        .bind(code.scopes.join(" "))
        .bind(&code.code_challenge)
        .bind(&code.nonce)
        .bind(code.expires_at)
        .bind(code.created_at)
        .bind(code.used)
        .bind(code.resource)
        .bind(code.authentication.authenticated_at)
        .bind(code.authentication.amr.join(" "))
        .bind(code.authentication.assurance_level.as_str())
        .bind(code.authentication.elevation.map(|e| e.level.as_str()))
        .bind(code.authentication.elevation.map(|e| e.until))
        .bind(code.authentication.session)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("authorization code", e))?;
        Self::audit_in_tx(&mut tx, &format!("auth_code:{}", code.client_id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_auth_code_by_hash(
        &self,
        code_hash: &[u8],
    ) -> SidResult<Option<AuthorizationCode>> {
        let row = sqlx::query_as::<_, crate::pg_row::AuthCodeRow>(
            "SELECT * FROM authorization_codes WHERE code_hash = $1",
        )
        .bind(code_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn redeem_auth_code(
        &self,
        code_hash: &[u8],
        session: &Session,
        refresh_token: &RefreshToken,
        audit: MutationContext,
    ) -> SidResult<AuthCodeRedemption> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;

        // The conditional update decides a race: the row lock makes every other
        // redemption wait, then see `used = true` and update nothing.
        let redeemed = sqlx::query(
            "UPDATE authorization_codes SET used = true, session_id = $2
             WHERE code_hash = $1 AND used = false",
        )
        .bind(code_hash)
        .bind(session.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("redeem auth code: {e}")))?
        .rows_affected()
            == 1;
        if !redeemed {
            let session_id: Option<Option<SessionId>> = sqlx::query_scalar(
                "SELECT session_id FROM authorization_codes WHERE code_hash = $1",
            )
            .bind(code_hash)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("read auth code: {e}")))?;
            return Ok(AuthCodeRedemption::AlreadyRedeemed {
                session_id: session_id.flatten(),
            });
        }

        session::write(&mut tx, session).await?;
        refresh_token::insert(&mut tx, refresh_token).await?;

        Self::audit_in_tx(&mut tx, &format!("profile:{}", session.profile_id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(AuthCodeRedemption::Redeemed)
    }

    // === INITIAL ACCESS TOKEN OPERATIONS (DCR) ===

    async fn create_initial_access_token(
        &self,
        token: &InitialAccessToken,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO initial_access_tokens (id, project_id, token_hash, max_clients,
                clients_registered, allowed_scopes, allowed_grant_types,
                allowed_redirect_patterns, created_by, revoked, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(token.id.0)
        .bind(token.project_id.0)
        .bind(&token.token_hash)
        .bind(iat_count(token.max_clients)?)
        .bind(iat_count(token.clients_registered)?)
        .bind(token.allowed_scopes.join(" "))
        .bind(token.allowed_grant_types.join(" "))
        .bind(token.allowed_redirect_patterns.join(" "))
        .bind(&token.created_by)
        .bind(token.revoked)
        .bind(token.expires_at)
        .bind(token.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("initial access token", e))?;
        Self::audit_in_tx(&mut tx, &format!("iat:{}", token.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn register_dynamic_client(
        &self,
        app: &sid_core::models::Application,
        client: &OAuth2Client,
        iat: InitialAccessTokenId,
        audit: MutationContext,
    ) -> SidResult<()> {
        if client.application_id != app.id || client.project_id != app.project_id {
            return Err(SidError::Validation(format!(
                "registered client {} names another application or project",
                client.client_id
            )));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // The row lock orders concurrent registrations and revocations of one
        // token: each sees the count and state the previous one committed.
        let row = sqlx::query(
            "SELECT revoked, expires_at, max_clients, clients_registered
             FROM initial_access_tokens WHERE id = $1 FOR UPDATE",
        )
        .bind(iat.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("lock initial access token: {e}")))?
        .ok_or_else(|| SidError::NotFound(format!("initial access token {}", iat.0)))?;
        use sqlx::Row;
        let revoked: bool = row.get("revoked");
        let expires_at: chrono::DateTime<chrono::Utc> = row.get("expires_at");
        let max_clients: i32 = row.get("max_clients");
        let registered: i32 = row.get("clients_registered");
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
             WHERE id = $1",
        )
        .bind(iat.0)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("count initial access token use: {e}")))?;
        Self::insert_application_in_tx(&mut tx, app).await?;
        Self::insert_oauth2_client_in_tx(&mut tx, client).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("oauth2_client:{}", client.client_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_initial_access_token(
        &self,
        id: InitialAccessTokenId,
    ) -> SidResult<Option<InitialAccessToken>> {
        let row = sqlx::query("SELECT * FROM initial_access_tokens WHERE id = $1")
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("get initial access token: {e}")))?;
        row.as_ref().map(row_to_initial_access_token).transpose()
    }

    async fn get_initial_access_token_by_hash(
        &self,
        token_hash: &[u8],
    ) -> SidResult<Option<InitialAccessToken>> {
        let row = sqlx::query("SELECT * FROM initial_access_tokens WHERE token_hash = $1")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("get initial access token: {e}")))?;
        row.as_ref().map(row_to_initial_access_token).transpose()
    }

    async fn list_initial_access_tokens_by_project(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Vec<InitialAccessToken>> {
        let rows = sqlx::query(
            "SELECT * FROM initial_access_tokens WHERE project_id = $1 ORDER BY created_at",
        )
        .bind(project_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("list initial access tokens: {e}")))?;
        rows.iter().map(row_to_initial_access_token).collect()
    }

    async fn revoke_initial_access_token(
        &self,
        id: InitialAccessTokenId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let revoked = sqlx::query("UPDATE initial_access_tokens SET revoked = TRUE WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("revoke initial access token: {e}")))?
            .rows_affected();
        if revoked == 0 {
            return Err(SidError::NotFound(format!("initial access token {}", id.0)));
        }
        Self::audit_in_tx(&mut tx, &format!("iat:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }
    // === INSTANCE SECRETS ===

    async fn get_instance_secret(
        &self,
        secret: sid_core::models::InstanceSecret,
    ) -> SidResult<Option<Vec<u8>>> {
        sqlx::query_scalar("SELECT sealed FROM instance_secrets WHERE name = $1")
            .bind(secret.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("get instance secret: {e}")))
    }

    async fn insert_instance_secret(
        &self,
        secret: sid_core::models::InstanceSecret,
        sealed: &[u8],
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let inserted = sqlx::query(
            "INSERT INTO instance_secrets (name, sealed) VALUES ($1, $2)
             ON CONFLICT (name) DO NOTHING",
        )
        .bind(secret.as_str())
        .bind(sealed)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("insert instance secret: {e}")))?
        .rows_affected()
            == 1;
        if inserted {
            Self::audit_in_tx(&mut tx, &format!("instance_secret:{secret}"), audit).await?;
        }
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(inserted)
    }

    async fn instance_organization(&self) -> SidResult<Option<sid_core::models::Organization>> {
        let row: Option<(
            sid_core::models::OrgId,
            String,
            String,
            String,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            "SELECT id, org_type, status, canonical_domain, created_at
                 FROM organizations WHERE is_instance",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("instance organization: {e}")))?;
        row.map(|(id, org_type, status, canonical_domain, created_at)| {
            let stored = |e: String| SidError::Storage(format!("organization {id}: {e}"));
            Ok(sid_core::models::Organization {
                id,
                org_type: org_type.parse().map_err(stored)?,
                status: status.parse().map_err(stored)?,
                canonical_domain,
                created_at,
            })
        })
        .transpose()
    }

    async fn insert_instance_organization(
        &self,
        org: &sid_core::models::Organization,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let inserted = sqlx::query(
            "INSERT INTO organizations (id, org_type, status, canonical_domain, is_instance, created_at)
             VALUES ($1, $2, $3, $4, TRUE, $5)
             ON CONFLICT (is_instance) WHERE is_instance DO NOTHING",
        )
        .bind(org.id)
        .bind(org.org_type.as_str())
        .bind(org.status.as_str())
        .bind(&org.canonical_domain)
        .bind(org.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("organization", e))?
        .rows_affected()
            == 1;
        if inserted {
            Self::audit_in_tx(&mut tx, &format!("organization:{}", org.id), audit).await?;
        }
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(inserted)
    }

    async fn assign_unowned_clients(
        &self,
        org_id: sid_core::models::OrgId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let assigned = sqlx::query(
            "UPDATE oauth2_clients SET org_id = $1, revision = revision + 1
             WHERE org_id IS NULL",
        )
        .bind(org_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("assign clients to organization: {e}")))?
        .rows_affected();
        if assigned > 0 {
            Self::audit_in_tx(&mut tx, &format!("organization:{org_id}"), audit).await?;
        }
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(assigned)
    }

    async fn oidc_issuer_for(
        &self,
        authority: sid_core::models::IssuerAuthority,
        recipient_org: sid_core::models::OrgId,
    ) -> SidResult<Option<sid_core::models::OidcIssuer>> {
        let row: Option<IssuerRow> = sqlx::query_as(
            "SELECT id, handle, canonical_url, authority, recipient_org, created_at
                 FROM oidc_issuers WHERE authority = $1 AND recipient_org = $2",
        )
        .bind(authority.as_str())
        .bind(recipient_org)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("oidc issuer: {e}")))?;
        row.map(issuer_from_row).transpose()
    }

    async fn oidc_issuer_by_handle(
        &self,
        handle: &sid_core::models::IssuerHandle,
    ) -> SidResult<Option<sid_core::models::OidcIssuer>> {
        let row: Option<IssuerRow> = sqlx::query_as(
            "SELECT id, handle, canonical_url, authority, recipient_org, created_at
                 FROM oidc_issuers WHERE handle = $1",
        )
        .bind(handle.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("oidc issuer by handle: {e}")))?;
        row.map(issuer_from_row).transpose()
    }

    async fn insert_oidc_issuer(
        &self,
        issuer: &sid_core::models::OidcIssuer,
        first_key: &sid_core::models::IssuerSigningKey,
        audit: MutationContext,
    ) -> SidResult<bool> {
        issuer.check_first_key(first_key)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let inserted = sqlx::query(
            "INSERT INTO oidc_issuers (id, handle, canonical_url, authority, recipient_org, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (authority, recipient_org) DO NOTHING",
        )
        .bind(issuer.id)
        .bind(issuer.handle.as_str())
        .bind(&issuer.canonical_url)
        .bind(issuer.authority.as_str())
        .bind(issuer.recipient_org)
        .bind(issuer.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("oidc issuer", e))?
        .rows_affected()
            == 1;
        if inserted {
            sqlx::query(
                "INSERT INTO oidc_issuer_signing_keys
                     (issuer_id, generation, key_id, public_key, sealed_private_key, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(first_key.issuer_id)
            .bind(key_generation(first_key.generation)?)
            .bind(&first_key.key_id)
            .bind(first_key.public_key.as_slice())
            .bind(&first_key.sealed_private_key)
            .bind(first_key.created_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| insert_error("oidc issuer signing key", e))?;
            Self::audit_in_tx(&mut tx, &format!("oidc_issuer:{}", issuer.id), audit).await?;
        }
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(inserted)
    }

    async fn oidc_issuer_signing_keys(
        &self,
        issuer: sid_core::models::IssuerId,
    ) -> SidResult<Vec<sid_core::models::IssuerSigningKey>> {
        let rows: Vec<(
            sid_core::models::IssuerId,
            i32,
            String,
            Vec<u8>,
            Vec<u8>,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            "SELECT issuer_id, generation, key_id, public_key, sealed_private_key, created_at
                 FROM oidc_issuer_signing_keys WHERE issuer_id = $1 ORDER BY generation",
        )
        .bind(issuer)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("oidc issuer signing keys: {e}")))?;
        rows.into_iter()
            .map(
                |(issuer_id, generation, key_id, public_key, sealed_private_key, created_at)| {
                    let stored = |what: &str| {
                        SidError::Storage(format!("signing key of issuer {issuer_id}: {what}"))
                    };
                    Ok(sid_core::models::IssuerSigningKey {
                        issuer_id,
                        generation: u32::try_from(generation)
                            .map_err(|_| stored("negative generation"))?,
                        key_id,
                        public_key: public_key
                            .try_into()
                            .map_err(|_| stored("public key is not 32 bytes"))?,
                        sealed_private_key,
                        created_at,
                    })
                },
            )
            .collect()
    }

    async fn admin_exists(&self) -> SidResult<bool> {
        sqlx::query_scalar(ADMIN_EXISTS_SQL)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("admin exists: {e}")))
    }

    async fn claim_first_admin(
        &self,
        claim_sealed: &[u8],
        profile: &Profile,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // Removing the claim row first locks it: a concurrent claimer waits
        // here and then finds nothing to remove.
        let consumed = sqlx::query("DELETE FROM instance_secrets WHERE name = $1 AND sealed = $2")
            .bind(sid_core::models::InstanceSecret::AdminClaim.as_str())
            .bind(claim_sealed)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("consume admin claim: {e}")))?
            .rows_affected()
            == 1;
        if !consumed {
            return Ok(false);
        }
        let admin_exists: bool = sqlx::query_scalar(ADMIN_EXISTS_SQL)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("admin exists: {e}")))?;
        if admin_exists {
            // A claim left beside an administrator grants nothing: drop it.
            tx.commit()
                .await
                .map_err(|e| SidError::Storage(e.to_string()))?;
            return Ok(false);
        }
        if !directory::update_profile(&mut tx, profile).await? {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("profile:{}", profile.id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn service_binding(
        &self,
        profile_id: ProfileId,
        scope: &sid_core::models::BindingScope,
        ctx: MutationContext,
    ) -> SidResult<sid_core::models::ServiceBinding> {
        binding::get_or_allocate(&self.pool, profile_id, scope, ctx).await
    }

    async fn find_service_binding(
        &self,
        profile_id: ProfileId,
        scope: &sid_core::models::BindingScope,
    ) -> SidResult<Option<sid_core::models::ServiceBinding>> {
        binding::find(&self.pool, profile_id, scope).await
    }

    async fn list_service_bindings(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<sid_core::models::ServiceBinding>> {
        binding::list(&self.pool, profile_id).await
    }

    async fn import_service_binding(
        &self,
        imported: &sid_core::models::ServiceBinding,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        binding::import(&self.pool, imported, ctx).await
    }

    // === FIELD-ENCRYPTION KEY VERSIONS ===

    async fn list_key_versions(&self) -> SidResult<Vec<sid_keys::KeyVersionParams>> {
        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT version, salt, algorithm, context FROM key_versions ORDER BY version",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("list key versions: {e}")))?;
        rows.iter()
            .map(|row| {
                let version = u32::try_from(row.get::<i32, _>("version"))
                    .map_err(|_| SidError::Storage("negative key version".into()))?;
                key_version_params(
                    version,
                    row.get("salt"),
                    &row.get::<String, _>("algorithm"),
                    row.get("context"),
                )
            })
            .collect()
    }

    async fn insert_key_version(
        &self,
        params: &sid_keys::KeyVersionParams,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let version = i32::try_from(params.version).map_err(|_| {
            SidError::Validation(format!("key version {} out of range", params.version))
        })?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let inserted = sqlx::query(
            "INSERT INTO key_versions (version, salt, algorithm, context)
             VALUES ($1, $2, $3, $4) ON CONFLICT (version) DO NOTHING",
        )
        .bind(version)
        .bind(&params.salt)
        .bind(key_derivation_name(params.algorithm))
        .bind(&params.context)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("insert key version: {e}")))?
        .rows_affected()
            == 1;
        if inserted {
            Self::audit_in_tx(&mut tx, &format!("key_version:{}", params.version), audit).await?;
        }
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(inserted)
    }

    async fn list_credentials_by_type(
        &self,
        credential_type: CredentialType,
        after: Option<CredentialId>,
        limit: u32,
    ) -> SidResult<Vec<Credential>> {
        let rows = sqlx::query_as::<_, crate::pg_row::CredentialRow>(
            "SELECT * FROM credentials
             WHERE credential_type = $1 AND ($2::uuid IS NULL OR id > $2)
             ORDER BY id LIMIT $3",
        )
        .bind(credential_type.as_str())
        .bind(after.map(|id| id.0))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("list credentials by type: {e}")))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    // === ROLE OPERATIONS (RBAC) ===

    async fn get_role(&self, id: RoleId) -> SidResult<Option<Role>> {
        let row = sqlx::query_as::<_, crate::pg_row::RoleRow>("SELECT * FROM roles WHERE id = $1")
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn get_role_by_name(&self, project_id: ProjectId, name: &str) -> SidResult<Option<Role>> {
        let row = sqlx::query_as::<_, crate::pg_row::RoleRow>(
            "SELECT * FROM roles WHERE project_id = $1 AND name = $2",
        )
        .bind(project_id.0)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn create_role(&self, r: &Role, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO roles (id, project_id, key, name, description, group_label, permissions, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(r.id.0)
        .bind(r.project_id.0)
        .bind(&r.key)
        .bind(&r.name)
        .bind(&r.description)
        .bind(&r.group)
        .bind(r.permissions_string())
        .bind(r.created_at)
        .bind(r.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("role", e))?;
        Self::audit_in_tx(&mut tx, &format!("role:{}", r.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn update_role(&self, r: &Role, audit: MutationContext) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if !Self::update_role_in_tx(&mut tx, r).await? {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("role:{}", r.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn update_role_fenced(
        &self,
        r: &Role,
        fence: &sid_core::models::RoleEditFence,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let revision =
            |v: u64| i64::try_from(v).map_err(|e| SidError::Validation(format!("revision: {e}")));
        let read = |e: sqlx::Error| SidError::Storage(format!("check role edit fence: {e}"));
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // Locked first: a fenced assignment of the role takes it FOR SHARE,
        // so none can commit unseen between this check and the update.
        let held: Option<(i64,)> =
            sqlx::query_as("SELECT revision FROM roles WHERE id = $1 FOR UPDATE")
                .bind(r.id.0)
                .fetch_optional(&mut *tx)
                .await
                .map_err(read)?;
        if held.map(|(v,)| v) != Some(revision(r.revision)?) {
            return Ok(false);
        }
        if let Some((authority, checked)) = fence.authority {
            let held: Option<(i64,)> = sqlx::query_as(
                "SELECT revision FROM role_assignments
                 WHERE id = $1 AND (expires_at IS NULL OR expires_at > now())
                 FOR SHARE",
            )
            .bind(authority.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(read)?;
            if held.map(|(v,)| v) != Some(revision(checked)?) {
                return Err(SidError::Fenced(
                    "the editor's authority changed since it was checked".into(),
                ));
            }
        }
        if let Some(bounded) = &fence.bounded {
            let present: Vec<(uuid::Uuid,)> = sqlx::query_as(
                "SELECT DISTINCT a.id FROM role_assignments a
                 JOIN role_assignment_ceilings c ON c.assignment_id = a.id
                 WHERE a.role_id = $1",
            )
            .bind(r.id.0)
            .fetch_all(&mut *tx)
            .await
            .map_err(read)?;
            if present
                .iter()
                .any(|(id,)| !bounded.contains(&RoleAssignmentId(*id)))
            {
                return Err(SidError::Fenced(
                    "an assignment under an approved ceiling appeared since the check".into(),
                ));
            }
        }
        if !Self::update_role_in_tx(&mut tx, r).await? {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("role:{}", r.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn delete_role(&self, id: RoleId, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM roles WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("role:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_roles(&self, project_id: ProjectId) -> SidResult<Vec<Role>> {
        let rows = sqlx::query_as::<_, crate::pg_row::RoleRow>(
            "SELECT * FROM roles WHERE project_id = $1",
        )
        .bind(project_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    // === GROUP OPERATIONS ===

    async fn get_group(&self, id: GroupId) -> SidResult<Option<Group>> {
        let row =
            sqlx::query_as::<_, crate::pg_row::GroupRow>("SELECT * FROM groups WHERE id = $1")
                .bind(id.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.map(|r| r.into_domain()))
    }

    async fn create_group(&self, g: &Group, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        directory::insert_group(&mut tx, g).await?;
        Self::audit_in_tx(&mut tx, &format!("group:{}", g.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn set_group_description(
        &self,
        id: GroupId,
        description: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let updated =
            sqlx::query("UPDATE groups SET description = $2, updated_at = NOW() WHERE id = $1")
                .bind(id.0)
                .bind(description)
                .execute(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("update group: {e}")))?
                .rows_affected()
                == 1;
        if !updated {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("group:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn delete_group(&self, id: GroupId, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| match &e {
                // An administrative envelope restricts recipients to it:
                // deleting it would widen the envelope.
                sqlx::Error::Database(db) if is_reference_violation(db.as_ref()) => {
                    SidError::Conflict(
                        "the group restricts the recipients of an administrative assignment".into(),
                    )
                }
                _ => SidError::Storage(format!("Delete failed: {e}")),
            })?;
        Self::audit_in_tx(&mut tx, &format!("group:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_groups(&self, project_id: ProjectId) -> SidResult<Vec<Group>> {
        let rows = sqlx::query_as::<_, crate::pg_row::GroupRow>(
            "SELECT * FROM groups WHERE project_id = $1",
        )
        .bind(project_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(rows.into_iter().map(|r| r.into_domain()).collect())
    }

    async fn add_to_group(&self, member: &GroupMember, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        directory::add_member(&mut tx, member).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("group:{}:member:{}", member.group_id.0, member.profile_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn remove_from_group(
        &self,
        group_id: GroupId,
        profile_id: ProfileId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        directory::remove_member(&mut tx, group_id, profile_id).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("group:{}:member:{}", group_id.0, profile_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_group_members(&self, group_id: GroupId) -> SidResult<Vec<GroupMember>> {
        let rows = sqlx::query_as::<_, crate::pg_row::GroupMemberRow>(
            "SELECT * FROM group_members WHERE group_id = $1",
        )
        .bind(group_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(rows.into_iter().map(|r| r.into_domain()).collect())
    }

    async fn list_groups_for_profile(&self, profile_id: ProfileId) -> SidResult<Vec<Group>> {
        // Single JOIN query instead of two separate queries
        let rows = sqlx::query_as::<_, crate::pg_row::GroupRow>(
            "SELECT g.* FROM groups g
            JOIN group_members gm ON gm.group_id = g.id
            WHERE gm.profile_id = $1",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(rows.into_iter().map(|r| r.into_domain()).collect())
    }

    // === ROLE ASSIGNMENT OPERATIONS ===

    async fn create_role_assignment(
        &self,
        assignment: &RoleAssignment,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::insert_role_assignment_in_tx(&mut tx, assignment).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("role_assignment:{}", assignment.id.0),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn delete_role_assignment(
        &self,
        id: RoleAssignmentId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let removed: Option<(Option<sid_core::models::ProvisioningConnectorId>,)> = sqlx::query_as(
            "DELETE FROM role_assignments WHERE id = $1 RETURNING provisioning_connector_id",
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        if let Some((Some(connector),)) = removed {
            Self::bump_connector_revision(&mut tx, connector).await?;
        }
        Self::audit_in_tx(&mut tx, &format!("role_assignment:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_role_assignment(&self, id: RoleAssignmentId) -> SidResult<Option<RoleAssignment>> {
        let rows = sqlx::query_as::<_, crate::pg_row::RoleAssignmentRow>(
            "SELECT * FROM role_assignments WHERE id = $1",
        )
        .bind(id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("read role assignment: {e}")))?;
        Ok(self.role_assignments(rows).await?.pop())
    }

    async fn create_role_assignment_fenced(
        &self,
        assignment: &RoleAssignment,
        fence: &sid_core::models::AssignmentFence,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::check_assignment_fence_in_tx(&mut tx, fence).await?;
        Self::insert_role_assignment_in_tx(&mut tx, assignment).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("role_assignment:{}", assignment.id.0),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn delete_role_assignment_fenced(
        &self,
        id: RoleAssignmentId,
        fence: &sid_core::models::AssignmentFence,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Self::check_assignment_fence_in_tx(&mut tx, fence).await?;
        let removed: Option<(Option<sid_core::models::ProvisioningConnectorId>,)> = sqlx::query_as(
            "DELETE FROM role_assignments WHERE id = $1 RETURNING provisioning_connector_id",
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Delete failed: {e}")))?;
        let Some((connector,)) = removed else {
            return Ok(false);
        };
        if let Some(connector) = connector {
            Self::bump_connector_revision(&mut tx, connector).await?;
        }
        Self::audit_in_tx(&mut tx, &format!("role_assignment:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn list_role_assignments_for_profile(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows = sqlx::query_as::<_, crate::pg_row::RoleAssignmentRow>(
            "SELECT * FROM role_assignments WHERE profile_id = $1",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        self.role_assignments(rows).await
    }

    async fn list_role_assignments_for_group(
        &self,
        group_id: GroupId,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows = sqlx::query_as::<_, crate::pg_row::RoleAssignmentRow>(
            "SELECT * FROM role_assignments WHERE group_id = $1",
        )
        .bind(group_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        self.role_assignments(rows).await
    }

    async fn list_role_assignments_for_machine_user(
        &self,
        machine_user_id: MachineUserId,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows = sqlx::query_as::<_, crate::pg_row::RoleAssignmentRow>(
            "SELECT * FROM role_assignments WHERE machine_user_id = $1",
        )
        .bind(machine_user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        self.role_assignments(rows).await
    }

    async fn list_role_assignments_for_oauth_client(
        &self,
        client_id: &str,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows = sqlx::query_as::<_, crate::pg_row::RoleAssignmentRow>(
            "SELECT * FROM role_assignments WHERE oauth_client_id = $1",
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        self.role_assignments(rows).await
    }

    async fn list_role_assignments_for_provisioning_connector(
        &self,
        connector_id: sid_core::models::ProvisioningConnectorId,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows = sqlx::query_as::<_, crate::pg_row::RoleAssignmentRow>(
            "SELECT * FROM role_assignments WHERE provisioning_connector_id = $1",
        )
        .bind(connector_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("list connector role assignments: {e}")))?;
        self.role_assignments(rows).await
    }

    async fn list_role_assignments_for_role(
        &self,
        role_id: RoleId,
    ) -> SidResult<Vec<RoleAssignment>> {
        let rows = sqlx::query_as::<_, crate::pg_row::RoleAssignmentRow>(
            "SELECT * FROM role_assignments WHERE role_id = $1",
        )
        .bind(role_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        self.role_assignments(rows).await
    }

    async fn list_expiring_role_assignments(
        &self,
        within_hours: i64,
    ) -> SidResult<Vec<RoleAssignment>> {
        let deadline = chrono::Utc::now() + chrono::Duration::hours(within_hours);
        let rows = sqlx::query_as::<_, crate::pg_row::RoleAssignmentRow>(
            "SELECT * FROM role_assignments WHERE expires_at IS NOT NULL AND expires_at <= $1",
        )
        .bind(deadline)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        self.role_assignments(rows).await
    }

    async fn cleanup_expired_role_assignments(
        &self,
        mut audit: MutationContext,
    ) -> SidResult<Vec<RoleAssignment>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let now = chrono::Utc::now();
        let expired = sqlx::query_as::<_, crate::pg_row::RoleAssignmentRow>(
            "DELETE FROM role_assignments WHERE expires_at IS NOT NULL AND expires_at <= $1 \
             RETURNING *",
        )
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Cleanup failed: {}", e)))?
        .into_iter()
        .map(|row| row.into_domain())
        .collect::<SidResult<Vec<RoleAssignment>>>()?;
        if expired.is_empty() && audit.work.is_empty() {
            // Nothing expired and nothing owed: nothing to record.
            return Ok(expired);
        }
        audit
            .work
            .extend(expired.iter().map(|a| a.expired_event().relay()));
        Self::audit_in_tx(&mut tx, "role_assignment:cleanup_expired", audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(expired)
    }

    async fn list_sod_rules(&self) -> SidResult<Vec<SodConflictRule>> {
        // CE: SoD rules stored in config (sid.yaml) or admin API.
        // DB table for SoD rules will be added with governance feature.
        Ok(vec![])
    }

    // === CEDAR POLICY OPERATIONS ===

    async fn get_cedar_policy(&self, id: CedarPolicyId) -> SidResult<Option<CedarPolicy>> {
        let row = sqlx::query_as::<_, crate::pg_row::CedarPolicyRow>(
            "SELECT * FROM cedar_policies WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn update_cedar_policy(
        &self,
        policy: &CedarPolicy,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let revision = i64::try_from(policy.revision)
            .map_err(|e| SidError::Validation(format!("policy revision: {e}")))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let updated = sqlx::query(
            "UPDATE cedar_policies SET description = $3, policy_text = $4, effect = $5,
                enabled = $6, updated_at = $7, revision = revision + 1
             WHERE id = $1 AND revision = $2",
        )
        .bind(policy.id.0)
        .bind(revision)
        .bind(&policy.description)
        .bind(&policy.policy_text)
        .bind(policy.effect.as_str())
        .bind(policy.enabled)
        .bind(policy.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("update policy: {e}")))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("cedar_policy:{}", policy.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn create_cedar_policy(
        &self,
        policy: &CedarPolicy,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO cedar_policies (id, project_id, name, description, policy_text, effect, enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(policy.id.0)
        .bind(policy.project_id.0)
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(&policy.policy_text)
        .bind(policy.effect.as_str())
        .bind(policy.enabled)
        .bind(policy.created_at)
        .bind(policy.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("policy", e))?;
        Self::audit_in_tx(&mut tx, &format!("cedar_policy:{}", policy.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn delete_cedar_policy(
        &self,
        id: CedarPolicyId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM cedar_policies WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("cedar_policy:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_cedar_policies(&self, project_id: ProjectId) -> SidResult<Vec<CedarPolicy>> {
        let rows = sqlx::query_as::<_, crate::pg_row::CedarPolicyRow>(
            "SELECT * FROM cedar_policies WHERE project_id = $1",
        )
        .bind(project_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    // === PROFILE METADATA OPERATIONS === (sqlx)

    async fn get_profile_metadata(
        &self,
        profile_id: ProfileId,
        key: &str,
    ) -> SidResult<Option<ProfileMetadata>> {
        let row = sqlx::query_as::<_, crate::pg_row::ProfileMetadataRow>(
            "SELECT * FROM profile_metadata WHERE profile_id = $1 AND key = $2",
        )
        .bind(profile_id)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.map(|r| r.into_domain()))
    }

    async fn set_profile_metadata(
        &self,
        metadata: &ProfileMetadata,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        directory::set_metadata(&mut tx, metadata).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("profile:{}:metadata:{}", metadata.profile_id, metadata.key),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn delete_profile_metadata(
        &self,
        profile_id: ProfileId,
        key: &str,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        directory::delete_metadata(&mut tx, profile_id, key).await?;
        Self::audit_in_tx(
            &mut tx,
            &format!("profile:{profile_id}:metadata:{key}"),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_profile_metadata(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<ProfileMetadata>> {
        let rows = sqlx::query_as::<_, crate::pg_row::ProfileMetadataRow>(
            "SELECT * FROM profile_metadata WHERE profile_id = $1",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(rows.into_iter().map(|r| r.into_domain()).collect())
    }

    // === PROFILE GRANT OPERATIONS ===

    async fn get_profile_grant(&self, id: ProfileGrantId) -> SidResult<Option<ProfileGrant>> {
        let row = sqlx::query_as::<_, crate::pg_row::ProfileGrantRow>(
            "SELECT * FROM profile_grants WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.map(|r| r.into_domain()))
    }

    async fn create_profile_grant(
        &self,
        grant: &ProfileGrant,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO profile_grants (id, profile_id, project_id, role_keys, granted_by, expires_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(grant.id.0)
        .bind(grant.profile_id)
        .bind(grant.project_id.0)
        .bind(grant.role_keys.join(" "))
        .bind(&grant.granted_by)
        .bind(grant.expires_at)
        .bind(grant.created_at)
        .bind(grant.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("profile grant", e))?;
        Self::audit_in_tx(&mut tx, &format!("profile_grant:{}", grant.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn delete_profile_grant(
        &self,
        id: ProfileGrantId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM profile_grants WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("profile_grant:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_profile_grants_for_profile(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<ProfileGrant>> {
        let rows = sqlx::query_as::<_, crate::pg_row::ProfileGrantRow>(
            "SELECT * FROM profile_grants WHERE profile_id = $1",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(rows.into_iter().map(|r| r.into_domain()).collect())
    }

    async fn list_profile_grants_for_project(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Vec<ProfileGrant>> {
        let rows = sqlx::query_as::<_, crate::pg_row::ProfileGrantRow>(
            "SELECT * FROM profile_grants WHERE project_id = $1",
        )
        .bind(project_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(rows.into_iter().map(|r| r.into_domain()).collect())
    }

    // === DEVICE MANAGEMENT OPERATIONS ===

    async fn create_device(&self, device: &CoreDevice, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO devices (id, profile_id, display_name, device_type, os_info,
                assurance, trusted, hardware_attested, fingerprint_hash, last_ip_geo,
                first_seen_at, last_seen_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(device.id)
        .bind(device.profile_id)
        .bind(&device.display_name)
        .bind(device.device_type.as_str())
        .bind(&device.os_info)
        .bind(device.assurance.as_str())
        .bind(device.trusted)
        .bind(device.hardware_attested)
        .bind(&device.fingerprint_hash)
        .bind(&device.last_ip_geo)
        .bind(device.first_seen_at)
        .bind(device.last_seen_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("device", e))?;
        Self::audit_in_tx(&mut tx, &format!("device:{}", device.id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn rename_device(
        &self,
        id: CoreDeviceId,
        display_name: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let renamed = sqlx::query("UPDATE devices SET display_name = $2 WHERE id = $1")
            .bind(id)
            .bind(display_name)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("rename device: {e}")))?
            .rows_affected()
            == 1;
        if !renamed {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("device:{id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn set_device_trust(
        &self,
        id: CoreDeviceId,
        trusted: bool,
        max_trusted: usize,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::DeviceTrustChange> {
        use sid_core::models::DeviceTrustChange;
        let storage = |e: sqlx::Error| SidError::Storage(format!("set device trust: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let owner: Option<ProfileId> =
            sqlx::query_scalar("SELECT profile_id FROM devices WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?;
        let Some(profile_id) = owner else {
            return Ok(DeviceTrustChange::NotFound);
        };
        // The profile row lock orders every trust change of one profile (so the
        // count below holds until commit) and is taken before the device row,
        // in the same order as a profile deletion cascading to its devices.
        sqlx::query("SELECT id FROM profiles WHERE id = $1 FOR UPDATE")
            .bind(profile_id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        let current: Option<bool> = sqlx::query_scalar(
            "SELECT trusted FROM devices WHERE id = $1 AND profile_id = $2 FOR UPDATE",
        )
        .bind(id)
        .bind(profile_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
        let Some(was_trusted) = current else {
            return Ok(DeviceTrustChange::NotFound);
        };
        if was_trusted == trusted {
            return Ok(DeviceTrustChange::Unchanged);
        }
        if trusted {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM devices WHERE profile_id = $1 AND trusted",
            )
            .bind(profile_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
            if usize::try_from(count).map_err(|e| SidError::Storage(e.to_string()))? >= max_trusted
            {
                return Ok(DeviceTrustChange::LimitReached);
            }
            sqlx::query(
                "UPDATE devices SET trusted = TRUE, last_seen_at = NOW(),
                    assurance = CASE WHEN assurance IN ('unknown', 'recognized')
                        THEN 'trusted' ELSE assurance END
                 WHERE id = $1",
            )
        } else {
            sqlx::query(
                "UPDATE devices SET trusted = FALSE, last_seen_at = NOW(),
                    assurance = CASE WHEN assurance = 'trusted'
                        THEN 'recognized' ELSE assurance END
                 WHERE id = $1",
            )
        }
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        Self::audit_in_tx(&mut tx, &format!("device:{id}"), audit).await?;
        tx.commit().await.map_err(storage)?;
        Ok(DeviceTrustChange::Changed)
    }

    async fn get_device(&self, id: CoreDeviceId) -> SidResult<Option<CoreDevice>> {
        let row =
            sqlx::query_as::<_, crate::pg_row::DeviceRow>("SELECT * FROM devices WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| SidError::Storage(format!("Failed to get device: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn list_devices_by_profile(&self, profile_id: ProfileId) -> SidResult<Vec<CoreDevice>> {
        let rows = sqlx::query_as::<_, crate::pg_row::DeviceRow>(
            "SELECT * FROM devices WHERE profile_id = $1 ORDER BY last_seen_at DESC",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Failed to list devices: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn delete_device(&self, id: CoreDeviceId, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM devices WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Failed to delete device: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("device:{id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_device_by_fingerprint(
        &self,
        profile_id: ProfileId,
        fingerprint_hash: &str,
    ) -> SidResult<Option<CoreDevice>> {
        let row = sqlx::query_as::<_, crate::pg_row::DeviceRow>(
            "SELECT * FROM devices WHERE profile_id = $1 AND fingerprint_hash = $2",
        )
        .bind(profile_id)
        .bind(fingerprint_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Failed to get device by fingerprint: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    // === DEVICE ATTESTATION OPERATIONS ===

    async fn create_device_attestation(
        &self,
        att: &sid_core::models::DeviceAttestation,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // A revoked attestation is replaced by the new enrollment; a live one
        // makes the insert apply nothing.
        let stored = sqlx::query(
            "INSERT INTO device_attestations (id, device_id, profile_id, format, key_storage,
                status, device_public_key, attestation_object, attestation_certificate,
                aaguid, credential_id, created_at, updated_at, revoked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT (device_id) DO UPDATE SET
                id = EXCLUDED.id,
                profile_id = EXCLUDED.profile_id,
                format = EXCLUDED.format,
                key_storage = EXCLUDED.key_storage,
                status = EXCLUDED.status,
                device_public_key = EXCLUDED.device_public_key,
                attestation_object = EXCLUDED.attestation_object,
                attestation_certificate = EXCLUDED.attestation_certificate,
                aaguid = EXCLUDED.aaguid,
                credential_id = EXCLUDED.credential_id,
                created_at = EXCLUDED.created_at,
                updated_at = EXCLUDED.updated_at,
                revoked_at = EXCLUDED.revoked_at
            WHERE device_attestations.status = 'revoked'",
        )
        .bind(att.id.0)
        .bind(att.device_id)
        .bind(att.profile_id)
        .bind(att.format.as_str())
        .bind(att.key_storage.as_str())
        .bind(att.status.as_str())
        .bind(&att.device_public_key)
        .bind(&att.attestation_object)
        .bind(&att.attestation_certificate)
        .bind(&att.aaguid)
        .bind(&att.credential_id)
        .bind(att.created_at)
        .bind(att.updated_at)
        .bind(att.revoked_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("device attestation", e))?
        .rows_affected()
            == 1;
        if !stored {
            return Err(SidError::Conflict(
                "device already has a live attestation".into(),
            ));
        }
        Self::audit_in_tx(
            &mut tx,
            &format!("device_attestation:{}", att.device_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn rotate_device_attestation(
        &self,
        device_id: CoreDeviceId,
        device_public_key: &[u8],
        attestation_object: Option<&[u8]>,
        attestation_certificate: Option<&[u8]>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let rotated = sqlx::query(
            "UPDATE device_attestations SET device_public_key = $2, attestation_object = $3,
                attestation_certificate = $4, status = $5, updated_at = NOW()
             WHERE device_id = $1 AND status <> 'revoked'",
        )
        .bind(device_id)
        .bind(device_public_key)
        .bind(attestation_object)
        .bind(attestation_certificate)
        .bind(sid_core::models::AttestationStatus::Unverified.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("rotate device attestation: {e}")))?
        .rows_affected()
            == 1;
        if !rotated {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("device_attestation:{device_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn revoke_device_attestation(
        &self,
        device_id: CoreDeviceId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let storage = |e: sqlx::Error| SidError::Storage(format!("revoke device attestation: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let revoked = sqlx::query(
            "UPDATE device_attestations SET status = 'revoked', revoked_at = NOW(),
                updated_at = NOW()
             WHERE device_id = $1 AND status <> 'revoked'",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await
        .map_err(storage)?
        .rows_affected()
            == 1;
        if !revoked {
            return Ok(false);
        }
        // A revoked key no longer attests anything about the device.
        sqlx::query("UPDATE devices SET hardware_attested = FALSE WHERE id = $1")
            .bind(device_id)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        Self::audit_in_tx(&mut tx, &format!("device_attestation:{device_id}"), audit).await?;
        tx.commit().await.map_err(storage)?;
        Ok(true)
    }

    async fn get_device_attestation(
        &self,
        id: sid_core::models::DeviceAttestationId,
    ) -> SidResult<Option<sid_core::models::DeviceAttestation>> {
        let row = sqlx::query_as::<_, crate::pg_row::DeviceAttestationRow>(
            "SELECT * FROM device_attestations WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Failed to get device attestation: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn get_device_attestation_by_device_id(
        &self,
        device_id: CoreDeviceId,
    ) -> SidResult<Option<sid_core::models::DeviceAttestation>> {
        let row = sqlx::query_as::<_, crate::pg_row::DeviceAttestationRow>(
            "SELECT * FROM device_attestations WHERE device_id = $1 AND status != 'revoked'",
        )
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Failed to get attestation by device: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn list_device_attestations_by_profile(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<sid_core::models::DeviceAttestation>> {
        let rows = sqlx::query_as::<_, crate::pg_row::DeviceAttestationRow>(
            "SELECT * FROM device_attestations WHERE profile_id = $1 ORDER BY created_at DESC",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Failed to list attestations: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn delete_device_attestation(
        &self,
        device_id: CoreDeviceId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM device_attestations WHERE device_id = $1")
            .bind(device_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Failed to delete attestation: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("device_attestation:{device_id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    // === DEVICE AUTHORIZATION OPERATIONS (RFC 8628) ===

    async fn create_device_auth_code(
        &self,
        code: &CoreDeviceAuth,
        audit: MutationContext,
    ) -> SidResult<()> {
        self.create_device_auth_code_impl(code, audit).await
    }

    async fn get_device_auth_by_device_code_hash(
        &self,
        device_code_hash: &[u8],
    ) -> SidResult<Option<CoreDeviceAuth>> {
        let row = sqlx::query_as::<_, crate::pg_row::DeviceAuthRow>(
            "SELECT * FROM device_authorization_codes WHERE device_code_hash = $1",
        )
        .bind(device_code_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn get_device_auth_by_user_code(
        &self,
        user_code: &str,
    ) -> SidResult<Option<CoreDeviceAuth>> {
        let row = sqlx::query_as::<_, crate::pg_row::DeviceAuthRow>(
            "SELECT * FROM device_authorization_codes WHERE user_code = $1",
        )
        .bind(user_code)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn decide_device_auth(
        &self,
        id: DeviceAuthCodeId,
        decision: sid_core::models::DeviceAuthDecision,
        audit: MutationContext,
    ) -> SidResult<bool> {
        self.decide_device_auth_impl(id, decision, audit).await
    }

    async fn record_device_poll(
        &self,
        id: DeviceAuthCodeId,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::DevicePoll> {
        self.record_device_poll_impl(id, audit).await
    }

    async fn redeem_device_code(
        &self,
        device_code_hash: &[u8],
        session: &Session,
        refresh_token: &RefreshToken,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::DeviceCodeRedemption> {
        self.redeem_device_code_impl(device_code_hash, session, refresh_token, audit)
            .await
    }

    async fn cleanup_expired_device_auth_codes(&self, audit: MutationContext) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let result = sqlx::query(
            "DELETE FROM device_authorization_codes WHERE expires_at < NOW() AND status = 'pending'",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Cleanup failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, "device_auth:cleanup_expired", audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(result.rows_affected())
    }

    // === UPSTREAM PROVIDER OPERATIONS ===

    async fn get_upstream_provider(
        &self,
        id: UpstreamProviderId,
    ) -> SidResult<Option<UpstreamProvider>> {
        let row = sqlx::query_as::<_, crate::pg_row::UpstreamProviderRow>(
            "SELECT * FROM upstream_providers WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn create_upstream_provider(
        &self,
        provider: &UpstreamProvider,
        audit: MutationContext,
    ) -> SidResult<()> {
        let written = self
            .write_upstream_provider(
                provider,
                audit,
                "INSERT INTO upstream_providers (id, name, protocol, trust_category,
                    enabled, client_id, client_secret, discovery_url,
                    authorization_endpoint, token_endpoint, userinfo_endpoint,
                    scopes, show_on_login, display_order, logo_url, created_at, updated_at,
                    revision)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                    $17, $18)",
            )
            .await?;
        debug_assert_eq!(written, 1, "an insert writes one row or fails");
        Ok(())
    }

    async fn update_upstream_provider(
        &self,
        provider: &UpstreamProvider,
        audit: MutationContext,
    ) -> SidResult<bool> {
        // `$16` (creation time) is bound but never written: the origin stays.
        Ok(self
            .write_upstream_provider(
                provider,
                audit,
                "UPDATE upstream_providers SET name = $2, protocol = $3, trust_category = $4,
                    enabled = $5, client_id = $6, client_secret = $7, discovery_url = $8,
                    authorization_endpoint = $9, token_endpoint = $10, userinfo_endpoint = $11,
                    scopes = $12, show_on_login = $13, display_order = $14, logo_url = $15,
                    updated_at = $17, revision = revision + 1
                 WHERE id = $1 AND revision = $18 AND created_at = $16",
            )
            .await?
            == 1)
    }

    async fn delete_upstream_provider(
        &self,
        id: UpstreamProviderId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM upstream_providers WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("upstream_provider:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_enabled_upstream_providers(&self) -> SidResult<Vec<UpstreamProvider>> {
        let rows = sqlx::query_as::<_, crate::pg_row::UpstreamProviderRow>(
            "SELECT * FROM upstream_providers WHERE enabled = true ORDER BY display_order ASC, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    // === UPSTREAM IDENTITY OPERATIONS ===

    async fn get_upstream_identity_by_provider_subject(
        &self,
        provider_id: UpstreamProviderId,
        upstream_subject: &str,
    ) -> SidResult<Option<UpstreamIdentity>> {
        let row = sqlx::query_as::<_, crate::pg_row::UpstreamIdentityRow>(
            "SELECT * FROM upstream_identities WHERE provider_id = $1 AND upstream_subject = $2",
        )
        .bind(provider_id.0)
        .bind(upstream_subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn create_upstream_identity(
        &self,
        identity: &UpstreamIdentity,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO upstream_identities (id, provider_id, profile_id, upstream_subject,
                upstream_issuer, upstream_email, upstream_name, upstream_picture,
                last_login_at, login_count, linked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(identity.id.0)
        .bind(identity.provider_id.0)
        .bind(identity.profile_id)
        .bind(&identity.upstream_subject)
        .bind(&identity.upstream_issuer)
        .bind(&identity.upstream_email)
        .bind(&identity.upstream_name)
        .bind(&identity.upstream_picture)
        .bind(identity.last_login_at)
        .bind(
            i64::try_from(identity.login_count)
                .map_err(|e| SidError::Validation(format!("login count: {e}")))?,
        )
        .bind(identity.linked_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("upstream identity", e))?;
        Self::audit_in_tx(
            &mut tx,
            &format!("upstream_identity:{}", identity.id.0),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn record_upstream_login(
        &self,
        id: UpstreamIdentityId,
        login: &UpstreamLogin,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let recorded = sqlx::query(
            "UPDATE upstream_identities SET upstream_email = $2, upstream_name = $3,
                upstream_picture = $4, last_login_at = $5, login_count = login_count + 1
             WHERE id = $1",
        )
        .bind(id.0)
        .bind(&login.email)
        .bind(&login.name)
        .bind(&login.picture)
        .bind(login.at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("record upstream login: {e}")))?
        .rows_affected()
            == 1;
        if !recorded {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("upstream_identity:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn list_upstream_identities_by_profile(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<UpstreamIdentity>> {
        let rows = sqlx::query_as::<_, crate::pg_row::UpstreamIdentityRow>(
            "SELECT * FROM upstream_identities WHERE profile_id = $1",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn delete_upstream_identity(
        &self,
        id: UpstreamIdentityId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM upstream_identities WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("upstream_identity:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    // === PERSONAL ACCESS TOKEN OPERATIONS ===

    async fn get_pat(&self, id: PatId) -> SidResult<Option<PersonalAccessToken>> {
        let row = sqlx::query_as::<_, crate::pg_row::PatRow>(
            "SELECT * FROM personal_access_tokens WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn get_pat_by_token_hash(
        &self,
        token_hash: &str,
    ) -> SidResult<Option<PersonalAccessToken>> {
        let row = sqlx::query_as::<_, crate::pg_row::PatRow>(
            "SELECT * FROM personal_access_tokens WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn create_pat(
        &self,
        pat: &PersonalAccessToken,
        active_limit: Option<u64>,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if let Some(limit) = active_limit {
            // Concurrent creates of one profile count one after another.
            sqlx::query("SELECT 1 FROM profiles WHERE id = $1 FOR NO KEY UPDATE")
                .bind(pat.profile_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("lock profile: {e}")))?;
            let (active,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM personal_access_tokens WHERE profile_id = $1 AND status = 'active'",
            )
            .bind(pat.profile_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("count PATs: {e}")))?;
            // COUNT(*) is never negative.
            if active as u64 >= limit {
                return Err(SidError::ResourceExhausted(format!(
                    "profile already holds {limit} active PATs"
                )));
            }
        }
        sqlx::query(
            "INSERT INTO personal_access_tokens (id, profile_id, name, description, token_hash, token_prefix,
                scopes, ip_allowlist, status, expires_at, last_used_at, last_used_ip,
                use_count, revoked_at, revoked_by, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
        )
        .bind(pat.id.0).bind(pat.profile_id)
        .bind(&pat.name)
        .bind(&pat.description)
        .bind(&pat.token_hash)
        .bind(&pat.token_prefix)
        .bind(pat.scopes.join(" "))
        .bind(pat.ip_allowlist.join(" "))
        .bind(pat.status.as_str())
        .bind(pat.expires_at)
        .bind(pat.last_used_at)
        .bind(&pat.last_used_ip)
        .bind(pat.use_count as i64)
        .bind(pat.revoked_at)
        .bind(&pat.revoked_by)
        .bind(pat.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("PAT", e))?;
        Self::audit_in_tx(&mut tx, &format!("pat:{}", pat.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn record_pat_use(
        &self,
        id: PatId,
        ip: Option<&str>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let used = sqlx::query(
            "UPDATE personal_access_tokens
             SET last_used_at = NOW(), last_used_ip = $2, use_count = use_count + 1
             WHERE id = $1 AND status = 'active' AND (expires_at IS NULL OR expires_at > NOW())",
        )
        .bind(id.0)
        .bind(ip)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("record PAT use: {e}")))?
        .rows_affected()
            == 1;
        if !used {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("pat:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn revoke_pat(
        &self,
        id: PatId,
        revoked_by: &str,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let revoked = sqlx::query(
            "UPDATE personal_access_tokens SET status = 'revoked', revoked_at = NOW(), revoked_by = $1
             WHERE id = $2 AND status <> 'revoked'",
        )
        .bind(revoked_by)
        .bind(id.0)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Update failed: {}", e)))?
        .rows_affected()
            == 1;
        if !revoked {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("pat:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn list_pats_by_profile(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<PersonalAccessToken>> {
        let rows = sqlx::query_as::<_, crate::pg_row::PatRow>(
            "SELECT * FROM personal_access_tokens WHERE profile_id = $1 ORDER BY created_at DESC",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn list_all_pats(&self) -> SidResult<Vec<PersonalAccessToken>> {
        let rows = sqlx::query_as::<_, crate::pg_row::PatRow>(
            "SELECT * FROM personal_access_tokens ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn count_active_pats_by_profile(&self, profile_id: ProfileId) -> SidResult<u64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM personal_access_tokens WHERE profile_id = $1 AND status = 'active'",
        ).bind(profile_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.0 as u64)
    }

    async fn revoke_active_pats_by_profile(
        &self,
        profile_id: ProfileId,
        revoked_by: &str,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let revoked = directory::revoke_pats(&mut tx, profile_id, revoked_by).await?;
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}:pats"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(revoked)
    }

    async fn revoke_unused_pats(&self, days: u32, audit: MutationContext) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let cutoff = chrono::Utc::now() - chrono::Duration::days(i64::from(days));
        // Single UPDATE instead of SELECT + loop: atomically revoke all unused PATs
        let result = sqlx::query(
            "UPDATE personal_access_tokens SET status = 'revoked', revoked_at = NOW(), revoked_by = 'system:auto_revoke_unused'
            WHERE status = 'active'
              AND ((last_used_at IS NULL AND created_at < $1) OR (last_used_at < $1))",
        )
        .bind(cutoff)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Bulk revoke unused failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, "pat:revoke_unused", audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(result.rows_affected())
    }

    // === MACHINE USER OPERATIONS ===

    async fn get_machine_user(&self, id: MachineUserId) -> SidResult<Option<MachineUser>> {
        let row = sqlx::query_as::<_, crate::pg_row::MachineUserRow>(
            "SELECT * FROM machine_users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn get_machine_user_by_client_id(
        &self,
        client_id: &str,
    ) -> SidResult<Option<MachineUser>> {
        let row = sqlx::query_as::<_, crate::pg_row::MachineUserRow>(
            "SELECT * FROM machine_users WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn update_machine_user(
        &self,
        mu: &MachineUser,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let updated = sqlx::query(
            "UPDATE machine_users SET display_name = $2, description = $3, scopes = $4,
                ip_allowlist = $5, rate_limit_rpm = $6, max_token_lifetime = $7,
                expires_at = $8, updated_at = NOW()
             WHERE id = $1 AND status <> 'deleted'",
        )
        .bind(mu.id)
        .bind(&mu.display_name)
        .bind(&mu.description)
        .bind(mu.scopes.join(" "))
        .bind(mu.restrictions.ip_allowlist.join(" "))
        .bind(mu.restrictions.rate_limit_rpm as i32)
        .bind(mu.max_token_lifetime.map(|v| v as i32))
        .bind(mu.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("update machine user: {e}")))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("machine_user:{}", mu.id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn transition_machine_user(
        &self,
        id: MachineUserId,
        from: MachineUserStatus,
        to: MachineUserStatus,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let moved = sqlx::query(
            "UPDATE machine_users SET status = $3, updated_at = NOW()
             WHERE id = $1 AND status = $2",
        )
        .bind(id)
        .bind(from.as_str())
        .bind(to.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("machine user status: {e}")))?
        .rows_affected()
            == 1;
        if !moved {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("machine_user:{id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn create_machine_user(&self, mu: &MachineUser, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO machine_users (id, project_id, machine_type, owner_type, owner_id,
                client_id, display_name, description, status, scopes,
                ip_allowlist, rate_limit_rpm, max_token_lifetime, last_used_at,
                expires_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
        )
        .bind(mu.id)
        .bind(mu.project_id.0)
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
        .bind(None::<chrono::DateTime<chrono::Utc>>)
        .bind(mu.expires_at)
        .bind(mu.created_at)
        .bind(mu.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("machine user", e))?;
        Self::audit_in_tx(&mut tx, &format!("machine_user:{}", mu.id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn delete_machine_user(
        &self,
        id: MachineUserId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "UPDATE machine_users SET status = 'deleted', updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Update failed: {}", e)))?;
        // A deleted machine user keeps its row but no access to any resource.
        sqlx::query(
            "DELETE FROM resource_access WHERE machine_client_id =
                 (SELECT client_id FROM machine_users WHERE id = $1)",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("remove resource access: {e}")))?;
        Self::audit_in_tx(&mut tx, &format!("machine_user:{id}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_machine_users_by_project(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Vec<MachineUser>> {
        let rows = sqlx::query_as::<_, crate::pg_row::MachineUserRow>(
            "SELECT * FROM machine_users WHERE project_id = $1 ORDER BY created_at DESC",
        )
        .bind(project_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    // === MACHINE USER CREDENTIAL OPERATIONS ===

    async fn get_machine_credential_by_kid(
        &self,
        kid: &str,
    ) -> SidResult<Option<MachineUserCredential>> {
        let row = sqlx::query_as::<_, crate::pg_row::MachineCredentialRow>(
            "SELECT * FROM machine_user_credentials WHERE kid = $1",
        )
        .bind(kid)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn add_machine_credential(
        &self,
        cred: &MachineUserCredential,
        active_limit: Option<u64>,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if let Some(limit) = active_limit {
            // Concurrent adds for one machine user count one after another.
            sqlx::query("SELECT 1 FROM machine_users WHERE id = $1 FOR NO KEY UPDATE")
                .bind(cred.machine_user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("lock machine user: {e}")))?;
            let (usable,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM machine_user_credentials
                 WHERE machine_user_id = $1 AND status IN ('active', 'grace_period')",
            )
            .bind(cred.machine_user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("count machine credentials: {e}")))?;
            // COUNT(*) is never negative.
            if usable as u64 >= limit {
                return Err(SidError::ResourceExhausted(format!(
                    "machine user already holds {limit} usable credentials"
                )));
            }
        }
        machine_credential::insert(&mut tx, cred).await?;
        Self::audit_in_tx(&mut tx, &format!("machine_credential:{}", cred.kid), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn rotate_machine_credential(
        &self,
        machine_user_id: MachineUserId,
        old_kid: &str,
        new: &MachineUserCredential,
        grace_until: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let moved = sqlx::query(
            "UPDATE machine_user_credentials
             SET status = 'grace_period', expires_at = LEAST(COALESCE(expires_at, $3), $3)
             WHERE kid = $1 AND machine_user_id = $2 AND status = 'active'",
        )
        .bind(old_kid)
        .bind(machine_user_id)
        .bind(grace_until)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("rotate machine credential: {e}")))?
        .rows_affected()
            == 1;
        if !moved {
            return Ok(false);
        }
        machine_credential::insert(&mut tx, new).await?;
        Self::audit_in_tx(&mut tx, &format!("machine_credential:{old_kid}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn revoke_machine_credential(
        &self,
        machine_user_id: MachineUserId,
        kid: &str,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let revoked = sqlx::query(
            "UPDATE machine_user_credentials SET status = 'revoked'
             WHERE kid = $1 AND machine_user_id = $2 AND status IN ('active', 'grace_period')",
        )
        .bind(kid)
        .bind(machine_user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("revoke machine credential: {e}")))?
        .rows_affected()
            == 1;
        if !revoked {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("machine_credential:{kid}"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn revoke_active_machine_credentials_by_user(
        &self,
        id: MachineUserId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let result = sqlx::query(
            "UPDATE machine_user_credentials SET status = 'revoked'
            WHERE machine_user_id = $1 AND status IN ('active', 'grace_period')",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Bulk revoke failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("machine_user:{id}:credentials"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(result.rows_affected())
    }

    async fn get_provisioning_connector(
        &self,
        id: sid_core::models::ProvisioningConnectorId,
    ) -> SidResult<Option<sid_core::models::ProvisioningConnector>> {
        self.connector_get(id).await
    }

    async fn get_provisioning_connector_by_client_id(
        &self,
        client_id: &str,
    ) -> SidResult<Option<sid_core::models::ProvisioningConnector>> {
        self.connector_by_client_id(client_id).await
    }

    async fn list_provisioning_connectors(
        &self,
        org_id: sid_core::models::OrgId,
    ) -> SidResult<Vec<sid_core::models::ProvisioningConnector>> {
        self.connector_list(org_id).await
    }

    async fn create_provisioning_connector(
        &self,
        connector: &sid_core::models::ProvisioningConnector,
        ctx: MutationContext,
    ) -> SidResult<()> {
        self.connector_create(connector, ctx).await
    }

    async fn rename_provisioning_connector(
        &self,
        id: sid_core::models::ProvisioningConnectorId,
        revision: i64,
        display_name: &str,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.connector_rename(id, revision, display_name, ctx).await
    }

    async fn transition_provisioning_connector(
        &self,
        id: sid_core::models::ProvisioningConnectorId,
        from: sid_core::models::ConnectorState,
        to: sid_core::models::ConnectorState,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.connector_transition(id, from, to, ctx).await
    }

    async fn add_provisioning_credential(
        &self,
        credential: &sid_core::models::ProvisioningCredential,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.connector_add_credential(credential, ctx).await
    }

    async fn rotate_provisioning_credential(
        &self,
        connector_id: sid_core::models::ProvisioningConnectorId,
        old: sid_core::models::ProvisioningCredentialId,
        new: &sid_core::models::ProvisioningCredential,
        grace_until: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.connector_rotate_credential(connector_id, old, new, grace_until, ctx)
            .await
    }

    async fn revoke_provisioning_credential(
        &self,
        connector_id: sid_core::models::ProvisioningConnectorId,
        id: sid_core::models::ProvisioningCredentialId,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.connector_revoke_credential(connector_id, id, ctx)
            .await
    }

    async fn list_provisioning_credentials(
        &self,
        connector_id: sid_core::models::ProvisioningConnectorId,
    ) -> SidResult<Vec<sid_core::models::ProvisioningCredential>> {
        self.connector_list_credentials(connector_id).await
    }

    async fn find_provisioning_credential(
        &self,
        verifier: &str,
    ) -> SidResult<
        Option<(
            sid_core::models::ProvisioningCredential,
            sid_core::models::ProvisioningConnector,
        )>,
    > {
        self.connector_find_credential(verifier).await
    }

    async fn list_machine_credentials_by_user(
        &self,
        id: MachineUserId,
    ) -> SidResult<Vec<MachineUserCredential>> {
        let rows = sqlx::query_as::<_, crate::pg_row::MachineCredentialRow>(
            "SELECT * FROM machine_user_credentials WHERE machine_user_id = $1 ORDER BY created_at DESC",
        ).bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn revoke_consents_by_profile(
        &self,
        profile_id: ProfileId,
        audit: MutationContext,
    ) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let result = sqlx::query(
            "UPDATE consents SET status = 'revoked', revoked_at = NOW(), updated_at = NOW() \
             WHERE profile_id = $1 AND status = 'active'",
        )
        .bind(profile_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sid_core::Error::Storage(e.to_string()))?;
        // A revoked consent shares nothing: its grants end with it.
        sqlx::query(
            "UPDATE claim_grants SET revoked_at = NOW() \
             WHERE revoked_at IS NULL AND consent_id IN \
               (SELECT id FROM consents WHERE profile_id = $1 AND status = 'revoked')",
        )
        .bind(profile_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sid_core::Error::Storage(format!("revoke claim grants: {e}")))?;
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}:consents"), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(result.rows_affected())
    }

    async fn create_consent(
        &self,
        consent: &sid_core::models::consent::ConsentRecord,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| sid_core::Error::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO consents (id, profile_id, client_id, status, consented_at, revoked_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(consent.id.0)
        .bind(consent.profile_id)
        .bind(&consent.client_id)
        .bind(consent.status.as_str())
        .bind(consent.consented_at)
        .bind(consent.revoked_at)
        .bind(consent.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("consent", e))?;
        for grant in &consent.grants {
            sqlx::query(
                "INSERT INTO claim_grants (id, consent_id, claim_name, claim_type, granted_at, revoked_at) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(grant.id.0)
            .bind(consent.id.0)
            .bind(&grant.claim_name)
            .bind(grant.claim_type.as_str())
            .bind(grant.granted_at)
            .bind(grant.revoked_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| insert_error("claim grant", e))?;
        }
        Self::audit_in_tx(&mut tx, &format!("consent:{}", consent.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| sid_core::Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn change_claim_grant(
        &self,
        id: sid_core::models::consent::ConsentId,
        claim_name: &str,
        decision: sid_core::models::consent::ClaimDecision,
        audit: MutationContext,
    ) -> SidResult<sid_core::models::consent::ClaimGrantChange> {
        use sid_core::models::consent::{ClaimDecision, ClaimGrantChange};
        let storage = |e: sqlx::Error| SidError::Storage(format!("change claim grant: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        // The consent row lock orders this decision with every other decision
        // and with the consent's revocation or deletion.
        let active =
            sqlx::query_scalar::<_, String>("SELECT status FROM consents WHERE id = $1 FOR UPDATE")
                .bind(id.0)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage)?
                .is_some_and(|status| status == "active");
        if !active {
            return Ok(ClaimGrantChange::ConsentNotActive);
        }
        let changed = match decision {
            ClaimDecision::Grant(claim_type) => sqlx::query(
                "INSERT INTO claim_grants (id, consent_id, claim_name, claim_type, granted_at) \
                 VALUES ($1, $2, $3, $4, NOW()) \
                 ON CONFLICT (consent_id, claim_name) DO UPDATE SET \
                   claim_type = EXCLUDED.claim_type, granted_at = NOW(), revoked_at = NULL \
                 WHERE claim_grants.revoked_at IS NOT NULL",
            )
            .bind(Uuid::now_v7())
            .bind(id.0)
            .bind(claim_name)
            .bind(claim_type.as_str()),
            ClaimDecision::Revoke => sqlx::query(
                "UPDATE claim_grants SET revoked_at = NOW() \
                 WHERE consent_id = $1 AND claim_name = $2 AND revoked_at IS NULL",
            )
            .bind(id.0)
            .bind(claim_name),
        }
        .execute(&mut *tx)
        .await
        .map_err(storage)?
        .rows_affected()
            == 1;
        if !changed {
            return Ok(ClaimGrantChange::Unchanged);
        }
        sqlx::query("UPDATE consents SET updated_at = NOW() WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        Self::audit_in_tx(&mut tx, &format!("consent:{}", id.0), audit).await?;
        tx.commit().await.map_err(storage)?;
        Ok(ClaimGrantChange::Changed)
    }

    async fn get_consent(
        &self,
        id: sid_core::models::consent::ConsentId,
    ) -> SidResult<Option<sid_core::models::consent::ConsentRecord>> {
        let row = sqlx::query_as::<_, ConsentRow>(
            "SELECT id, profile_id, client_id, status, consented_at, revoked_at, updated_at \
             FROM consents WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| sid_core::Error::Storage(e.to_string()))?;

        match row {
            Some(r) => {
                let grants = self.load_claim_grants(r.id).await?;
                r.into_consent_record(grants).map(Some)
            }
            None => Ok(None),
        }
    }

    async fn get_consent_by_client(
        &self,
        profile_id: ProfileId,
        client_id: &str,
    ) -> SidResult<Option<sid_core::models::consent::ConsentRecord>> {
        let row = sqlx::query_as::<_, ConsentRow>(
            "SELECT id, profile_id, client_id, status, consented_at, revoked_at, updated_at \
             FROM consents WHERE profile_id = $1 AND client_id = $2",
        )
        .bind(profile_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| sid_core::Error::Storage(e.to_string()))?;

        match row {
            Some(r) => {
                let grants = self.load_claim_grants(r.id).await?;
                r.into_consent_record(grants).map(Some)
            }
            None => Ok(None),
        }
    }

    async fn list_consents_by_profile(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Vec<sid_core::models::consent::ConsentRecord>> {
        let rows = sqlx::query_as::<_, ConsentRow>(
            "SELECT id, profile_id, client_id, status, consented_at, revoked_at, updated_at \
             FROM consents WHERE profile_id = $1 ORDER BY consented_at DESC",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| sid_core::Error::Storage(e.to_string()))?;

        let mut results = Vec::with_capacity(rows.len());
        for r in rows {
            let grants = self.load_claim_grants(r.id).await?;
            results.push(r.into_consent_record(grants)?);
        }
        Ok(results)
    }

    async fn delete_consent(
        &self,
        id: sid_core::models::consent::ConsentId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // claim_grants cascade-deleted via FK.
        let deleted = sqlx::query("DELETE FROM consents WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| sid_core::Error::Storage(e.to_string()))?
            .rows_affected()
            == 1;
        if !deleted {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("consent:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    // === ANOMALY EVENT OPERATIONS ===

    async fn save_anomaly_event(
        &self,
        event: &sid_core::models::AnomalyEventRecord,
    ) -> SidResult<()> {
        sqlx::query(
            "INSERT INTO anomaly_events (id, rule_id, profile_id, ip_address, description, risk_score, reaction, timestamp)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(event.id.0)
        .bind(&event.rule_id)
        .bind(&event.profile_id)
        .bind(&event.ip_address)
        .bind(&event.description)
        .bind(event.risk_score)
        .bind(&event.reaction)
        .bind(event.timestamp)
        .execute(&self.pool)
        .await
        .map_err(|e| sid_core::Error::Storage(format!("save_anomaly_event: {e}")))?;
        Ok(())
    }

    async fn list_anomaly_events(
        &self,
        rule_id: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> SidResult<Vec<sid_core::models::AnomalyEventRecord>> {
        let rows = if let Some(rid) = rule_id {
            sqlx::query_as::<_, AnomalyEventRow>(
                "SELECT id, rule_id, profile_id, ip_address, description, risk_score, reaction, timestamp
                 FROM anomaly_events
                 WHERE rule_id = $1
                 ORDER BY timestamp DESC
                 LIMIT $2 OFFSET $3",
            )
            .bind(rid)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as::<_, AnomalyEventRow>(
                "SELECT id, rule_id, profile_id, ip_address, description, risk_score, reaction, timestamp
                 FROM anomaly_events
                 ORDER BY timestamp DESC
                 LIMIT $1 OFFSET $2",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|e| sid_core::Error::Storage(format!("list_anomaly_events: {e}")))?;

        Ok(rows.into_iter().map(|r| r.into_record()).collect())
    }

    // === IP REPUTATION ===

    async fn record_ip_reputation_event(&self, ip: &str, success: bool) -> SidResult<()> {
        if success {
            sqlx::query(
                "INSERT INTO ip_reputation (ip, success_count, last_success_at, score, updated_at)
                 VALUES ($1, 1, NOW(), 0.0, NOW())
                 ON CONFLICT (ip) DO UPDATE SET
                     success_count = ip_reputation.success_count + 1,
                     last_success_at = NOW(),
                     score = ip_reputation.failed_count::real / (ip_reputation.failed_count + ip_reputation.success_count + 2)::real,
                     updated_at = NOW()",
            )
            .bind(ip)
            .execute(&self.pool)
            .await
            .map_err(|e| sid_core::Error::Storage(format!("record_ip_reputation_event: {e}")))?;
        } else {
            sqlx::query(
                "INSERT INTO ip_reputation (ip, failed_count, last_failed_at, score, updated_at)
                 VALUES ($1, 1, NOW(), 0.5, NOW())
                 ON CONFLICT (ip) DO UPDATE SET
                     failed_count = ip_reputation.failed_count + 1,
                     last_failed_at = NOW(),
                     score = (ip_reputation.failed_count + 1)::real / (ip_reputation.failed_count + ip_reputation.success_count + 2)::real,
                     updated_at = NOW()",
            )
            .bind(ip)
            .execute(&self.pool)
            .await
            .map_err(|e| sid_core::Error::Storage(format!("record_ip_reputation_event: {e}")))?;
        }
        Ok(())
    }

    async fn get_ip_reputation_score(&self, ip: &str) -> SidResult<Option<f32>> {
        let row: Option<(f32,)> = sqlx::query_as("SELECT score FROM ip_reputation WHERE ip = $1")
            .bind(ip)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| sid_core::Error::Storage(format!("get_ip_reputation_score: {e}")))?;
        Ok(row.map(|(score,)| score))
    }

    async fn list_suspicious_ips(
        &self,
        min_score: f32,
        limit: i64,
    ) -> SidResult<Vec<(String, f32)>> {
        let rows: Vec<(String, f32)> = sqlx::query_as(
            "SELECT ip, score FROM ip_reputation
             WHERE score >= $1
             ORDER BY score DESC
             LIMIT $2",
        )
        .bind(min_score)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| sid_core::Error::Storage(format!("list_suspicious_ips: {e}")))?;
        Ok(rows)
    }

    async fn decay_ip_reputation(&self, older_than: std::time::Duration) -> SidResult<u64> {
        let cutoff = crate::decay_cutoff(older_than)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;

        // Halve counters for stale entries.
        sqlx::query(
            "UPDATE ip_reputation
             SET failed_count = failed_count / 2,
                 success_count = success_count / 2,
                 score = CASE
                     WHEN (failed_count / 2 + success_count / 2) = 0 THEN 0.0
                     ELSE (failed_count / 2)::real / (failed_count / 2 + success_count / 2 + 1)::real
                 END,
                 updated_at = NOW()
             WHERE updated_at < $1 AND (failed_count > 0 OR success_count > 0)",
        )
        .bind(cutoff)
        .execute(&mut *tx)
        .await
        .map_err(|e| sid_core::Error::Storage(format!("decay_ip_reputation: {e}")))?;

        // Delete entries with both counters at zero, in the same transaction:
        // a decay is never left half applied.
        let result =
            sqlx::query("DELETE FROM ip_reputation WHERE failed_count = 0 AND success_count = 0")
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    sid_core::Error::Storage(format!("decay_ip_reputation cleanup: {e}"))
                })?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;

        Ok(result.rows_affected())
    }

    // === IP ALLOWLIST ===

    async fn add_ip_allowlist_entry(&self, cidr: &str, description: &str) -> SidResult<()> {
        sqlx::query(
            "INSERT INTO ip_allowlist_entries (cidr, description)
             VALUES ($1, $2)
             ON CONFLICT (cidr) DO UPDATE SET description = $2",
        )
        .bind(cidr)
        .bind(description)
        .execute(&self.pool)
        .await
        .map_err(|e| sid_core::Error::Storage(format!("add_ip_allowlist_entry: {e}")))?;
        Ok(())
    }

    async fn remove_ip_allowlist_entry(&self, cidr: &str) -> SidResult<()> {
        sqlx::query("DELETE FROM ip_allowlist_entries WHERE cidr = $1")
            .bind(cidr)
            .execute(&self.pool)
            .await
            .map_err(|e| sid_core::Error::Storage(format!("remove_ip_allowlist_entry: {e}")))?;
        Ok(())
    }

    async fn list_ip_allowlist_entries(
        &self,
    ) -> SidResult<Vec<(String, String, chrono::DateTime<chrono::Utc>)>> {
        let rows: Vec<(String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT cidr, description, created_at FROM ip_allowlist_entries ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| sid_core::Error::Storage(format!("list_ip_allowlist_entries: {e}")))?;
        Ok(rows)
    }

    async fn list_expiring_machine_credentials(
        &self,
        within_days: u32,
    ) -> SidResult<Vec<MachineUserCredential>> {
        let cutoff = chrono::Utc::now() + chrono::Duration::days(i64::from(within_days));
        let rows = sqlx::query_as::<_, crate::pg_row::MachineCredentialRow>(
            "SELECT * FROM machine_user_credentials
            WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < $1
            ORDER BY expires_at ASC",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    // === IMPERSONATION GRANT OPERATIONS ===

    async fn save_impersonation_grant(
        &self,
        grant: &ImpersonationGrant,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO impersonation_grants (id, machine_user_id, target_type, target,
                allowed_scopes, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (machine_user_id, target_type, target) DO UPDATE SET
                allowed_scopes = EXCLUDED.allowed_scopes",
        )
        .bind(Uuid::now_v7())
        .bind(grant.machine_user_id)
        .bind(grant.target_type.as_str())
        .bind(&grant.target)
        .bind(grant.allowed_scopes.join(" "))
        .bind(grant.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Insert/update failed: {}", e)))?;
        Self::audit_in_tx(
            &mut tx,
            &format!(
                "impersonation_grant:{}:{}",
                grant.machine_user_id, grant.target
            ),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn delete_impersonation_grant(
        &self,
        machine_user_id: MachineUserId,
        target_type: &str,
        target: &str,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "DELETE FROM impersonation_grants WHERE machine_user_id = $1 AND target_type = $2 AND target = $3",
        ).bind(machine_user_id)
        .bind(target_type)
        .bind(target)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(
            &mut tx,
            &format!(
                "impersonation_grant:{}:{}:{}",
                machine_user_id, target_type, target
            ),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_impersonation_grants(
        &self,
        machine_user_id: MachineUserId,
    ) -> SidResult<Vec<ImpersonationGrant>> {
        let rows = sqlx::query_as::<_, crate::pg_row::ImpersonationGrantRow>(
            "SELECT * FROM impersonation_grants WHERE machine_user_id = $1 ORDER BY created_at DESC",
        ).bind(machine_user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    // === PRINCIPAL QUARANTINE ===

    async fn quarantine_principal(
        &self,
        principal_hash: &str,
        principal_type: &str,
        quarantine_until: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO principal_quarantine (principal_hash, principal_type, quarantine_until, created_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (principal_hash) DO UPDATE SET
                quarantine_until = EXCLUDED.quarantine_until,
                principal_type = EXCLUDED.principal_type",
        )
        .bind(principal_hash)
        .bind(principal_type)
        .bind(quarantine_until)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Insert/update quarantine failed: {}", e)))?;
        Self::audit_in_tx(
            &mut tx,
            &format!("principal_quarantine:{}", principal_hash),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn is_principal_quarantined(&self, principal_hash: &str) -> SidResult<bool> {
        let row: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM principal_quarantine WHERE principal_hash = $1 AND quarantine_until > NOW())",
        )
        .bind(principal_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.0)
    }

    async fn cleanup_expired_quarantine(&self, audit: MutationContext) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let result =
            sqlx::query("DELETE FROM principal_quarantine WHERE quarantine_until <= NOW()")
                .execute(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("Cleanup failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, "principal_quarantine:cleanup_expired", audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(result.rows_affected())
    }

    // === CLOSURE REQUEST ===

    async fn create_closure_request(
        &self,
        req: &ClosureRequest,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        closure::insert(&mut tx, req, closure::OnExisting::Refuse).await?;
        Self::audit_in_tx(&mut tx, &format!("closure_request:{}", req.profile_id), ctx).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn request_profile_closure(
        &self,
        profile: &Profile,
        req: &ClosureRequest,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if profile.is_admin() {
            // Every administrator row is locked in one order, so concurrent
            // requests are decided one after the other.
            let admins: Vec<(ProfileId, String)> = sqlx::query_as(
                "SELECT id, status FROM profiles WHERE ' ' || roles || ' ' LIKE '% admin %'
                 ORDER BY id FOR UPDATE",
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("lock administrators: {e}")))?;
            crate::check_other_administrator(profile.id, &admins)?;
        }
        if !directory::update_profile(&mut tx, profile).await? {
            return Ok(false);
        }
        closure::insert(&mut tx, req, closure::OnExisting::Replace).await?;
        Self::audit_in_tx(&mut tx, &format!("closure_request:{}", req.profile_id), ctx).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn cancel_profile_closure(
        &self,
        profile: &Profile,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if !directory::update_profile(&mut tx, profile).await? {
            return Ok(false);
        }
        let counted = sqlx::query(
            "UPDATE closure_requests SET cancel_count = cancel_count + 1 WHERE profile_id = $1",
        )
        .bind(profile.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(e.to_string()))?;
        if counted.rows_affected() == 0 {
            return Err(SidError::NotFound("no closure request".into()));
        }
        Self::audit_in_tx(&mut tx, &format!("closure_request:{}", profile.id), ctx).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn get_closure_request(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<ClosureRequest>> {
        let row = sqlx::query_as::<_, crate::pg_row::ClosureRequestRow>(
            "SELECT * FROM closure_requests WHERE profile_id = $1",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    // === DATA EXPORT OPERATIONS ===

    async fn acknowledge_export_job(
        &self,
        id: Uuid,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transition_export_job(
            id,
            at,
            ctx,
            "UPDATE export_jobs SET status = 'downloaded'
             WHERE id = $1 AND status = 'ready' AND expires_at > $2",
        )
        .await
    }

    async fn expire_export_job(
        &self,
        id: Uuid,
        at: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> SidResult<bool> {
        self.transition_export_job(
            id,
            at,
            ctx,
            "UPDATE export_jobs SET status = 'expired'
             WHERE id = $1 AND status = 'ready' AND expires_at <= $2",
        )
        .await
    }

    async fn create_export_job(&self, job: &ExportJob, ctx: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO export_jobs (id, profile_id, format, status, archive_path, size_bytes,
                checksum_sha256, created_at, ready_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(job.id)
        .bind(job.profile_id)
        .bind(job.format.as_str())
        .bind(job.status.as_str())
        .bind(&job.archive_path)
        .bind(job.size_bytes)
        .bind(&job.checksum_sha256)
        .bind(job.created_at)
        .bind(job.ready_at)
        .bind(job.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("export job", e))?;
        Self::audit_in_tx(&mut tx, &format!("export_job:{}", job.id), ctx).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_export_job(&self, profile_id: ProfileId) -> SidResult<Option<ExportJob>> {
        sqlx::query_as::<_, crate::pg_row::ExportJobRow>(
            "SELECT * FROM export_jobs WHERE profile_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?
        .map(|r| r.into_domain())
        .transpose()
    }

    async fn get_export_job_by_id(&self, job_id: uuid::Uuid) -> SidResult<Option<ExportJob>> {
        sqlx::query_as::<_, crate::pg_row::ExportJobRow>("SELECT * FROM export_jobs WHERE id = $1")
            .bind(job_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?
            .map(|r| r.into_domain())
            .transpose()
    }

    // === MAGIC LINK OPERATIONS ===

    async fn create_magic_link_session(
        &self,
        session: &MagicLinkSession,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO magic_link_sessions (id, email, token_hash, consumed, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(session.id)
        .bind(&session.email)
        .bind(&session.token_hash)
        .bind(session.consumed)
        .bind(session.created_at)
        .bind(session.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("magic link", e))?;
        Self::audit_in_tx(&mut tx, &format!("magic_link:{}", session.id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_magic_link_session(&self, id: uuid::Uuid) -> SidResult<Option<MagicLinkSession>> {
        let row = sqlx::query_as::<_, crate::pg_row::MagicLinkRow>(
            "SELECT * FROM magic_link_sessions WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.map(|r| r.into_domain()))
    }

    async fn consume_magic_link_session(
        &self,
        id: uuid::Uuid,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("UPDATE magic_link_sessions SET consumed = true WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Update failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("magic_link:{}", id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn try_consume_magic_link_session(
        &self,
        id: uuid::Uuid,
        audit: MutationContext,
    ) -> SidResult<Option<MagicLinkSession>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let row = sqlx::query_as::<_, crate::pg_row::MagicLinkRow>(
            "UPDATE magic_link_sessions
             SET consumed = true
             WHERE id = $1 AND consumed = false AND expires_at > NOW()
             RETURNING *",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Update failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("magic_link:{}", id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(row.map(|r| r.into_domain()))
    }

    async fn delete_expired_magic_link_sessions(&self, audit: MutationContext) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let result = sqlx::query("DELETE FROM magic_link_sessions WHERE expires_at < NOW()")
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, "magic_link:cleanup_expired", audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(result.rows_affected())
    }

    async fn count_active_magic_links_for_email(&self, email: &str) -> SidResult<u32> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM magic_link_sessions WHERE email = $1 AND consumed = false AND expires_at > NOW()",
        )
        .bind(email)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        Ok(row.0 as u32)
    }

    // === SCIM OUTBOUND PROVISIONING ===

    async fn create_scim_outbound_target(
        &self,
        target: &ScimOutboundTarget,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let auth_config_json = serde_json::to_value(&target.auth)
            .map_err(|e| SidError::Storage(format!("JSON serialize failed: {}", e)))?;
        let attr_mapping_json = serde_json::to_value(&target.attribute_mapping)
            .map_err(|e| SidError::Storage(format!("JSON serialize failed: {}", e)))?;
        let group_push_json = serde_json::to_value(&target.group_push)
            .map_err(|e| SidError::Storage(format!("JSON serialize failed: {}", e)))?;
        let sync_config_json = serde_json::to_value(&target.sync_config)
            .map_err(|e| SidError::Storage(format!("JSON serialize failed: {}", e)))?;
        sqlx::query(
            "INSERT INTO scim_outbound_targets (id, client_id, project_id, display_name, endpoint_url,
                auth_config, attribute_mapping, group_push, sync_config, enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(target.id.0)
        .bind(&target.client_id)
        .bind(target.project_id.0)
        .bind(&target.display_name)
        .bind(&target.endpoint_url)
        .bind(&auth_config_json)
        .bind(&attr_mapping_json)
        .bind(&group_push_json)
        .bind(&sync_config_json)
        .bind(target.enabled)
        .bind(target.created_at)
        .bind(target.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("scim outbound target", e))?;
        Self::audit_in_tx(
            &mut tx,
            &format!("scim_outbound_target:{}", target.id.0),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_scim_outbound_target(
        &self,
        id: ScimOutboundTargetId,
    ) -> SidResult<Option<ScimOutboundTarget>> {
        let row = sqlx::query_as::<_, crate::pg_row::ScimOutboundTargetRow>(
            "SELECT * FROM scim_outbound_targets WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn list_scim_outbound_targets(
        &self,
        project_id: ProjectId,
    ) -> SidResult<Vec<ScimOutboundTarget>> {
        let rows = sqlx::query_as::<_, crate::pg_row::ScimOutboundTargetRow>(
            "SELECT * FROM scim_outbound_targets WHERE project_id = $1 AND enabled = true",
        )
        .bind(project_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn delete_scim_outbound_target(
        &self,
        id: ScimOutboundTargetId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM scim_outbound_targets WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("scim_outbound_target:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn create_scim_outbound_record(
        &self,
        record: &ScimOutboundRecord,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO scim_outbound_records (target_id, sid_entity_id, entity_type,
                downstream_id, last_synced_at, last_error, failure_count, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(record.target_id.0)
        .bind(record.sid_entity_id)
        .bind(record.entity_type.as_str())
        .bind(&record.downstream_id)
        .bind(record.last_synced_at)
        .bind(&record.last_error)
        .bind(
            i32::try_from(record.failure_count)
                .map_err(|e| SidError::Validation(format!("failure count: {e}")))?,
        )
        .bind(record.created_at)
        .bind(record.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("scim outbound record", e))?;
        Self::audit_in_tx(
            &mut tx,
            &format!(
                "scim_outbound_record:{}:{}",
                record.target_id.0, record.sid_entity_id
            ),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn record_scim_outbound_sync(
        &self,
        record: &ScimOutboundRecord,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO scim_outbound_records (target_id, sid_entity_id, entity_type,
                downstream_id, last_synced_at, last_error, failure_count, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, NULL, 0, $5, $5)
            ON CONFLICT (target_id, sid_entity_id, entity_type) DO UPDATE SET
                downstream_id = EXCLUDED.downstream_id,
                last_synced_at = EXCLUDED.last_synced_at,
                last_error = NULL,
                failure_count = 0,
                updated_at = EXCLUDED.updated_at",
        )
        .bind(record.target_id.0)
        .bind(record.sid_entity_id)
        .bind(record.entity_type.as_str())
        .bind(&record.downstream_id)
        .bind(record.last_synced_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("record scim sync: {e}")))?;
        Self::audit_in_tx(
            &mut tx,
            &format!(
                "scim_outbound_record:{}:{}",
                record.target_id.0, record.sid_entity_id
            ),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn record_scim_outbound_failure(
        &self,
        target_id: ScimOutboundTargetId,
        sid_entity_id: Uuid,
        entity_type: OutboundEntityType,
        error: &str,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let recorded = sqlx::query(
            "UPDATE scim_outbound_records SET last_error = $4,
                failure_count = failure_count + 1, updated_at = $5
             WHERE target_id = $1 AND sid_entity_id = $2 AND entity_type = $3",
        )
        .bind(target_id.0)
        .bind(sid_entity_id)
        .bind(entity_type.as_str())
        .bind(error)
        .bind(at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("record scim failure: {e}")))?
        .rows_affected()
            == 1;
        if !recorded {
            return Ok(false);
        }
        Self::audit_in_tx(
            &mut tx,
            &format!("scim_outbound_record:{}:{}", target_id.0, sid_entity_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn get_scim_outbound_record(
        &self,
        target_id: ScimOutboundTargetId,
        sid_entity_id: Uuid,
        entity_type: OutboundEntityType,
    ) -> SidResult<Option<ScimOutboundRecord>> {
        let row = sqlx::query_as::<_, crate::pg_row::ScimOutboundRecordRow>(
            "SELECT * FROM scim_outbound_records WHERE target_id = $1 AND sid_entity_id = $2 AND entity_type = $3",
        )
        .bind(target_id.0)
        .bind(sid_entity_id)
        .bind(entity_type.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn create_outbound_dlq_entry(
        &self,
        entry: &OutboundDlqEntry,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let et = entry.entity_type.as_str();
        sqlx::query(
            "INSERT INTO scim_outbound_dlq (id, target_id, event_type, payload, sid_entity_id,
                entity_type, error, attempts, first_attempt, last_attempt)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(entry.id)
        .bind(entry.target_id.0)
        .bind(&entry.event_type)
        .bind(&entry.payload)
        .bind(entry.sid_entity_id)
        .bind(et)
        .bind(&entry.error)
        .bind(
            i32::try_from(entry.attempts)
                .map_err(|e| SidError::Validation(format!("dlq attempts: {e}")))?,
        )
        .bind(entry.first_attempt)
        .bind(entry.last_attempt)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("outbound dlq entry", e))?;
        Self::audit_in_tx(&mut tx, &format!("outbound_dlq:{}", entry.id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_outbound_dlq_entries(
        &self,
        target_id: ScimOutboundTargetId,
    ) -> SidResult<Vec<OutboundDlqEntry>> {
        let rows = sqlx::query_as::<_, crate::pg_row::ScimOutboundDlqRow>(
            "SELECT * FROM scim_outbound_dlq WHERE target_id = $1",
        )
        .bind(target_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn delete_outbound_dlq_entry(&self, id: Uuid, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM scim_outbound_dlq WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, &format!("outbound_dlq:{}", id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    // === AUTH FLOW CONFIGURATION ===

    async fn get_flow_config(
        &self,
        project_id: sid_core::models::ProjectId,
        flow_type: sid_core::models::FlowType,
    ) -> SidResult<Option<sid_core::models::FlowConfig>> {
        let row: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT data FROM flow_configs WHERE project_id = $1 AND flow_type = $2",
        )
        .bind(project_id.0)
        .bind(flow_type.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {e}")))?;

        match row {
            Some((data,)) => {
                let config: sid_core::models::FlowConfig = serde_json::from_value(data)
                    .map_err(|e| SidError::Storage(format!("Deserialize failed: {e}")))?;
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }

    async fn save_flow_config(
        &self,
        config: &sid_core::models::FlowConfig,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let data = serde_json::to_value(config)
            .map_err(|e| SidError::Storage(format!("Serialize failed: {e}")))?;
        sqlx::query(
            "INSERT INTO flow_configs (project_id, flow_type, data, updated_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (project_id, flow_type) DO UPDATE SET data = $3, updated_at = $4",
        )
        .bind(config.project_id.0)
        .bind(config.flow_type.as_str())
        .bind(&data)
        .bind(config.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Insert failed: {e}")))?;
        Self::audit_in_tx(
            &mut tx,
            &format!(
                "flow_config:{}:{}",
                config.project_id.0,
                config.flow_type.as_str()
            ),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_flow_configs(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Vec<sid_core::models::FlowConfig>> {
        let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
            "SELECT data FROM flow_configs WHERE project_id = $1 ORDER BY flow_type",
        )
        .bind(project_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {e}")))?;

        rows.into_iter()
            .map(|(data,)| {
                serde_json::from_value(data)
                    .map_err(|e| SidError::Storage(format!("Deserialize failed: {e}")))
            })
            .collect()
    }

    // === AUTH FLOW ACTIONS ===

    async fn create_flow_action(
        &self,
        action: &sid_core::models::FlowAction,
        audit: MutationContext,
    ) -> SidResult<()> {
        let data = serde_json::to_value(action)
            .map_err(|e| SidError::Internal(format!("flow action: {e}")))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO flow_actions (id, project_id, flow_type, action_point, action_order,
                data, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(action.id.0)
        .bind(action.project_id.0)
        .bind(action.flow_type.as_str())
        .bind(action.action_point.as_str())
        .bind(action.order)
        .bind(&data)
        .bind(action.created_at)
        .bind(action.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("flow action", e))?;
        Self::audit_in_tx(&mut tx, &format!("flow_action:{}", action.id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn update_flow_action(
        &self,
        action: &sid_core::models::FlowAction,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let data = serde_json::to_value(action)
            .map_err(|e| SidError::Internal(format!("flow action: {e}")))?;
        let revision = i64::try_from(action.revision)
            .map_err(|e| SidError::Validation(format!("flow action revision: {e}")))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // The hook point and order move with the content, so the listing
        // sees the action where it now runs.
        let updated = sqlx::query(
            "UPDATE flow_actions SET action_point = $2, action_order = $3, data = $4,
                updated_at = $5, revision = revision + 1
             WHERE id = $1 AND revision = $6",
        )
        .bind(action.id.0)
        .bind(action.action_point.as_str())
        .bind(action.order)
        .bind(&data)
        .bind(action.updated_at)
        .bind(revision)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("update flow action: {e}")))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("flow_action:{}", action.id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn get_flow_action(
        &self,
        id: sid_core::models::ActionId,
    ) -> SidResult<Option<sid_core::models::FlowAction>> {
        sqlx::query_as::<_, FlowActionRow>("SELECT data, revision FROM flow_actions WHERE id = $1")
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SidError::Storage(format!("Query failed: {e}")))?
            .map(FlowActionRow::into_domain)
            .transpose()
    }

    async fn list_flow_actions(
        &self,
        project_id: sid_core::models::ProjectId,
        flow_type: sid_core::models::FlowType,
        action_point: Option<sid_core::models::ActionPoint>,
    ) -> SidResult<Vec<sid_core::models::FlowAction>> {
        let rows = match action_point {
            Some(point) => {
                sqlx::query_as::<_, FlowActionRow>(
                    "SELECT data, revision FROM flow_actions
                     WHERE project_id = $1 AND flow_type = $2 AND action_point = $3
                     ORDER BY action_order, id",
                )
                .bind(project_id.0)
                .bind(flow_type.as_str())
                .bind(point.as_str())
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query_as::<_, FlowActionRow>(
                    "SELECT data, revision FROM flow_actions
                     WHERE project_id = $1 AND flow_type = $2
                     ORDER BY action_point, action_order, id",
                )
                .bind(project_id.0)
                .bind(flow_type.as_str())
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|e| SidError::Storage(format!("Query failed: {e}")))?;
        rows.into_iter().map(FlowActionRow::into_domain).collect()
    }

    async fn delete_flow_action(
        &self,
        id: sid_core::models::ActionId,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("DELETE FROM flow_actions WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Delete failed: {e}")))?;
        Self::audit_in_tx(&mut tx, &format!("flow_action:{}", id), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    // === BRANDING ===

    async fn create_branding_config(
        &self,
        config: &sid_core::models::BrandingConfig,
        audit: MutationContext,
    ) -> SidResult<()> {
        let data = serde_json::to_value(config)
            .map_err(|e| SidError::Internal(format!("branding data: {e}")))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO branding_configs (id, project_id, status, data, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(config.id.0)
        .bind(config.project_id.0)
        .bind(config.status.as_str())
        .bind(&data)
        .bind(config.created_at)
        .bind(config.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("branding config", e))?;
        Self::audit_in_tx(&mut tx, &format!("branding:{}", config.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn update_branding_draft(
        &self,
        config: &sid_core::models::BrandingConfig,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let data = serde_json::to_value(config)
            .map_err(|e| SidError::Internal(format!("branding data: {e}")))?;
        let revision = i64::try_from(config.revision)
            .map_err(|e| SidError::Validation(format!("branding revision: {e}")))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let updated = sqlx::query(
            "UPDATE branding_configs SET data = $2, updated_at = $3, revision = revision + 1
             WHERE id = $1 AND status = 'draft' AND revision = $4",
        )
        .bind(config.id.0)
        .bind(&data)
        .bind(config.updated_at)
        .bind(revision)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("update branding draft: {e}")))?
        .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("branding:{}", config.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn publish_branding_config(
        &self,
        id: sid_core::models::BrandingConfigId,
        project_id: ProjectId,
        at: chrono::DateTime<chrono::Utc>,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // Every config of the project is locked in one order, so concurrent
        // publishes in a project run one after the other and each archives
        // what the previous one published.
        sqlx::query("SELECT id FROM branding_configs WHERE project_id = $1 ORDER BY id FOR UPDATE")
            .bind(project_id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("lock branding: {e}")))?;
        let draft: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM branding_configs
             WHERE id = $1 AND project_id = $2 AND status = 'draft'",
        )
        .bind(id.0)
        .bind(project_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("publish branding: {e}")))?;
        if draft.is_none() {
            return Ok(false);
        }
        sqlx::query(
            "UPDATE branding_configs SET status = 'archived', updated_at = $2,
                revision = revision + 1
             WHERE project_id = $1 AND status = 'published'",
        )
        .bind(project_id.0)
        .bind(at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("archive branding: {e}")))?;
        sqlx::query(
            "UPDATE branding_configs SET status = 'published', updated_at = $2,
                revision = revision + 1
             WHERE id = $1",
        )
        .bind(id.0)
        .bind(at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("published branding", e))?;
        Self::audit_in_tx(&mut tx, &format!("branding:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn get_published_branding(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Option<sid_core::models::BrandingConfig>> {
        sqlx::query_as::<_, BrandingRow>(
            "SELECT status, revision, updated_at, data FROM branding_configs
             WHERE project_id = $1 AND status = 'published'",
        )
        .bind(project_id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {e}")))?
        .map(BrandingRow::into_domain)
        .transpose()
    }

    async fn get_branding_config(
        &self,
        id: sid_core::models::BrandingConfigId,
    ) -> SidResult<Option<sid_core::models::BrandingConfig>> {
        sqlx::query_as::<_, BrandingRow>(
            "SELECT status, revision, updated_at, data FROM branding_configs WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {e}")))?
        .map(BrandingRow::into_domain)
        .transpose()
    }

    async fn list_branding_configs(
        &self,
        project_id: sid_core::models::ProjectId,
    ) -> SidResult<Vec<sid_core::models::BrandingConfig>> {
        sqlx::query_as::<_, BrandingRow>(
            "SELECT status, revision, updated_at, data FROM branding_configs
             WHERE project_id = $1 ORDER BY updated_at DESC, id",
        )
        .bind(project_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {e}")))?
        .into_iter()
        .map(BrandingRow::into_domain)
        .collect()
    }

    async fn delete_branding_config(
        &self,
        id: sid_core::models::BrandingConfigId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // A published config is never deleted, even one published meanwhile.
        let deleted =
            sqlx::query("DELETE FROM branding_configs WHERE id = $1 AND status <> 'published'")
                .bind(id.0)
                .execute(&mut *tx)
                .await
                .map_err(|e| SidError::Storage(format!("Delete failed: {e}")))?
                .rows_affected()
                == 1;
        if !deleted {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("branding:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    // === INVITE OPERATIONS ===

    async fn create_invite(&self, invite: &Invite, audit: MutationContext) -> SidResult<()> {
        let metadata = serde_json::to_value(&invite.metadata)
            .map_err(|e| SidError::Validation(format!("invite metadata: {e}")))?;
        let count = |what: &str, n: u32| {
            i32::try_from(n).map_err(|e| SidError::Validation(format!("invite {what}: {e}")))
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO invites (id, code, created_by, created_by_name, metadata, max_uses, use_count, expires_at, active, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(invite.id.0)
        .bind(&invite.code)
        .bind(invite.created_by)
        .bind(&invite.created_by_name)
        .bind(metadata)
        .bind(count("max uses", invite.max_uses)?)
        .bind(count("use count", invite.use_count)?)
        .bind(invite.expires_at)
        .bind(invite.active)
        .bind(invite.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("invite", e))?;
        Self::audit_in_tx(&mut tx, &format!("invite:{}", invite.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_invite(&self, id: InviteId) -> SidResult<Option<Invite>> {
        let row = sqlx::query_as::<_, crate::pg_row::InviteRow>(
            "SELECT id, code, created_by, created_by_name, metadata, max_uses, use_count, expires_at, active, created_at FROM invites WHERE id = $1"
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Get invite failed: {e}")))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn get_invite_by_code(&self, code: &str) -> SidResult<Option<Invite>> {
        let normalized = code.trim().to_uppercase();
        let row = sqlx::query_as::<_, crate::pg_row::InviteRow>(
            "SELECT id, code, created_by, created_by_name, metadata, max_uses, use_count, expires_at, active, created_at FROM invites WHERE UPPER(code) = $1"
        )
        .bind(&normalized)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Get invite by code failed: {e}")))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn list_invites(
        &self,
        filter: &InviteFilter,
        offset: u64,
        limit: u64,
    ) -> SidResult<Vec<Invite>> {
        // The filter applies before paging, so a page holds `limit`
        // matching invites rather than the matching part of `limit` rows.
        let rows = sqlx::query_as::<_, crate::pg_row::InviteRow>(concat!(
            "SELECT id, code, created_by, created_by_name, metadata, max_uses, use_count, expires_at, active, created_at \
             FROM invites WHERE ($1::text IS NULL OR ",
            invite_status_sql!(),
            " = $1) AND ($4::text IS NULL OR code ILIKE $4 ESCAPE '\\' \
             OR created_by_name ILIKE $4 ESCAPE '\\') \
             ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"
        ))
        .bind(filter.status.map(|s| s.as_str()))
        .bind(i64::try_from(limit).map_err(|e| SidError::Storage(e.to_string()))?)
        .bind(i64::try_from(offset).map_err(|e| SidError::Storage(e.to_string()))?)
        .bind(filter.search_pattern())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("List invites failed: {e}")))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn count_invites(&self, filter: &InviteFilter) -> SidResult<u64> {
        let row: (i64,) = sqlx::query_as(concat!(
            "SELECT COUNT(*) FROM invites WHERE ($1::text IS NULL OR ",
            invite_status_sql!(),
            " = $1) AND ($2::text IS NULL OR code ILIKE $2 ESCAPE '\\' \
             OR created_by_name ILIKE $2 ESCAPE '\\')"
        ))
        .bind(filter.status.map(|s| s.as_str()))
        .bind(filter.search_pattern())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Count invites failed: {e}")))?;
        u64::try_from(row.0).map_err(|e| SidError::Storage(e.to_string()))
    }

    async fn try_use_invite(
        &self,
        id: InviteId,
        audit: MutationContext,
    ) -> SidResult<Option<Invite>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let row = sqlx::query_as::<_, crate::pg_row::InviteRow>(
            "UPDATE invites SET use_count = use_count + 1
             WHERE id = $1 AND active = true
               AND (max_uses = 0 OR use_count < max_uses)
               AND (expires_at IS NULL OR expires_at > NOW())
             RETURNING id, code, created_by, created_by_name, metadata, max_uses, use_count, expires_at, active, created_at"
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Try use invite failed: {e}")))?;
        // No use, nothing recorded: the transaction is dropped uncommitted.
        let Some(row) = row else {
            return Ok(None);
        };
        Self::audit_in_tx(&mut tx, &format!("invite:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        row.into_domain().map(Some)
    }

    async fn revoke_invite(&self, id: InviteId, audit: MutationContext) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query("UPDATE invites SET active = false WHERE id = $1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(|e| SidError::Storage(format!("Revoke invite failed: {e}")))?;
        Self::audit_in_tx(&mut tx, &format!("invite:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    // === REGISTRATION SOURCE OPERATIONS ===

    async fn get_registration_source(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<RegistrationSource>> {
        let row = sqlx::query_as::<_, crate::pg_row::RegistrationSourceRow>(
            "SELECT profile_id, source_type::text, source_id, referrer_id, utm_source, utm_medium, utm_campaign, utm_term, utm_content, client_id, created_at
             FROM registration_sources WHERE profile_id = $1"
        ).bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Get registration source failed: {e}")))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn count_registrations_by_source(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> SidResult<Vec<(RegistrationSourceType, u64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT source_type::text, COUNT(*) FROM registration_sources WHERE created_at >= $1 GROUP BY source_type"
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Count registrations failed: {e}")))?;
        rows.into_iter()
            .map(|(t, c)| Ok((crate::pg_row::parse_source_type(&t)?, c as u64)))
            .collect()
    }

    async fn top_referrers(
        &self,
        since: chrono::DateTime<chrono::Utc>,
        limit: u64,
    ) -> SidResult<Vec<(ProfileId, u64)>> {
        let rows: Vec<(ProfileId, i64)> = sqlx::query_as(
            "SELECT referrer_id, COUNT(*) as cnt FROM registration_sources
             WHERE referrer_id IS NOT NULL AND created_at >= $1
             GROUP BY referrer_id ORDER BY cnt DESC LIMIT $2",
        )
        .bind(since)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Top referrers failed: {e}")))?;
        Ok(rows.into_iter().map(|(id, c)| (id, c as u64)).collect())
    }

    // === DISTRIBUTED LOCKING ===

    async fn try_job_lock(&self, job: i64) -> SidResult<Option<sid_plugin::storage::JobLock>> {
        job_lock::try_job_lock(&self.pool, job).await
    }

    async fn get_operation_result(
        &self,
        namespace: &str,
        key: &sid_core::models::OperationKey,
    ) -> SidResult<Option<sid_core::models::OperationRecord>> {
        operation::get(&self.pool, namespace, key).await
    }

    async fn export_operation_results(&self) -> SidResult<Vec<sid_core::models::OperationRecord>> {
        operation::export(&self.pool).await
    }

    async fn import_operation_result(
        &self,
        record: &sid_core::models::OperationRecord,
    ) -> SidResult<bool> {
        operation::import(&self.pool, record).await
    }

    async fn ensure_audit_partition(&self, month_start: chrono::NaiveDate) -> SidResult<bool> {
        audit_retention::ensure_partition(&self.pool, month_start).await
    }

    async fn drop_expired_audit_records(
        &self,
        cut_before: chrono::DateTime<chrono::Utc>,
        ctx: MutationContext,
    ) -> SidResult<u64> {
        let boundary = audit_retention::month_start(cut_before)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let (partitions, removed) = audit_retention::drop_expired(&mut tx, boundary).await?;
        if partitions == 0 {
            return Ok(0);
        }
        Self::audit_in_tx(&mut tx, "site:audit_retention", ctx).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(removed)
    }

    // === NOTIFICATION PREFERENCES ===

    async fn get_notification_preferences(
        &self,
        profile_id: ProfileId,
    ) -> SidResult<Option<sid_core::models::notification::NotificationPreferences>> {
        let row: Option<(serde_json::Value, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT preferences, updated_at FROM notification_preferences WHERE profile_id = $1",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Get notification preferences failed: {}", e)))?;

        match row {
            Some((prefs_json, updated_at)) => {
                let categories: Vec<sid_core::models::notification::CategoryPreference> =
                    serde_json::from_value(prefs_json).map_err(|e| {
                        SidError::Storage(format!(
                            "Failed to deserialize notification preferences: {}",
                            e
                        ))
                    })?;
                Ok(Some(
                    sid_core::models::notification::NotificationPreferences {
                        profile_id,
                        categories,
                        updated_at,
                    },
                ))
            }
            None => Ok(None),
        }
    }

    async fn save_notification_preferences(
        &self,
        preferences: &sid_core::models::notification::NotificationPreferences,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let prefs_json = serde_json::to_value(&preferences.categories).map_err(|e| {
            SidError::Storage(format!(
                "Failed to serialize notification preferences: {}",
                e
            ))
        })?;

        sqlx::query(
            "INSERT INTO notification_preferences (profile_id, preferences, updated_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (profile_id) DO UPDATE SET preferences = $2, updated_at = $3",
        )
        .bind(preferences.profile_id)
        .bind(&prefs_json)
        .bind(preferences.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Save notification preferences failed: {}", e)))?;

        Self::audit_in_tx(
            &mut tx,
            &format!("profile:{}", preferences.profile_id),
            audit,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    // === INTEGRITY VERIFICATION ===

    async fn count_orphaned_sessions(&self) -> SidResult<u64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sessions s WHERE NOT EXISTS (SELECT 1 FROM profiles p WHERE p.id = s.profile_id)"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Orphan session query failed: {}", e)))?;
        Ok(row.0 as u64)
    }

    async fn count_orphaned_credentials(&self) -> SidResult<u64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM credentials c WHERE NOT EXISTS (SELECT 1 FROM profiles p WHERE p.id = c.profile_id)"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Orphan credential query failed: {}", e)))?;
        Ok(row.0 as u64)
    }

    async fn count_orphaned_role_assignments(&self) -> SidResult<u64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM role_assignments ra WHERE \
             (ra.profile_id IS NOT NULL \
              AND NOT EXISTS (SELECT 1 FROM profiles p WHERE p.id = ra.profile_id)) OR \
             NOT EXISTS (SELECT 1 FROM roles r WHERE r.id = ra.role_id)",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Orphan role assignment query failed: {}", e)))?;
        Ok(row.0 as u64)
    }

    // === ACCESS REQUEST OPERATIONS ===

    async fn create_access_request(
        &self,
        request: &AccessRequest,
        ctx: MutationContext,
    ) -> SidResult<()> {
        let duration = request
            .requested_duration_hours
            .map(i32::try_from)
            .transpose()
            .map_err(|_| SidError::Validation("requested duration out of range".into()))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO access_requests (id, requester_id, project_id, role_key, justification,
             requested_duration_hours, status, reviewed_by, review_comment, created_at, reviewed_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(request.id.0)
        .bind(request.requester_id)
        .bind(request.project_id.0)
        .bind(&request.role_key)
        .bind(&request.justification)
        .bind(duration)
        .bind(request.status.as_str())
        .bind(request.reviewed_by)
        .bind(&request.review_comment)
        .bind(request.created_at)
        .bind(request.reviewed_at)
        .bind(request.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("access request", e))?;
        Self::audit_in_tx(&mut tx, &format!("access_request:{}", request.id.0), ctx).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_access_request(&self, id: AccessRequestId) -> SidResult<Option<AccessRequest>> {
        let row =
            sqlx::query_as::<_, AccessRequestRow>("SELECT * FROM access_requests WHERE id = $1")
                .bind(id.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn list_pending_access_requests(&self) -> SidResult<Vec<AccessRequest>> {
        let rows = sqlx::query_as::<_, AccessRequestRow>(
            "SELECT * FROM access_requests WHERE status = 'pending'
             AND (expires_at IS NULL OR expires_at > now())
             ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Query failed: {}", e)))?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn decide_access_request(
        &self,
        request: &AccessRequest,
        audit: MutationContext,
    ) -> SidResult<bool> {
        request.check_plain_decision()?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        // Already decided: nothing written, nothing audited.
        if !Self::decide_access_request_in_tx(&mut tx, request).await? {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("access_request:{}", request.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn approve_access_request(
        &self,
        request: &AccessRequest,
        grant: &RoleAssignment,
        audit: MutationContext,
    ) -> SidResult<bool> {
        request.check_approval(grant)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        if !Self::decide_access_request_in_tx(&mut tx, request).await? {
            return Ok(false);
        }
        // A grant that cannot be stored rolls the approval back.
        Self::insert_role_assignment_in_tx(&mut tx, grant).await?;
        Self::audit_in_tx(&mut tx, &format!("access_request:{}", request.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    // === PASSWORD RESET SESSION ===

    async fn create_reset_session(
        &self,
        session: &sid_core::models::PasswordResetSession,
        audit: MutationContext,
    ) -> SidResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO password_reset_sessions
                (id, profile_id, email, token_hash, status,
                 created_at, expires_at, verified_at, completed_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(session.id.0)
        .bind(session.profile_id)
        .bind(&session.email)
        .bind(&session.token_hash)
        .bind(session.status.as_str())
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(session.verified_at)
        .bind(session.completed_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| insert_error("reset session", e))?;
        Self::audit_in_tx(&mut tx, &format!("reset_session:{}", session.id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_reset_session(
        &self,
        id: sid_core::models::ResetSessionId,
    ) -> SidResult<Option<sid_core::models::PasswordResetSession>> {
        let row = sqlx::query_as::<_, crate::pg_row::PasswordResetSessionRow>(
            "SELECT * FROM password_reset_sessions WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Get reset_session failed: {}", e)))?;
        row.map(|r| r.into_domain()).transpose()
    }

    async fn verify_reset_session(
        &self,
        id: sid_core::models::ResetSessionId,
        audit: MutationContext,
    ) -> SidResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let verified = sqlx::query(
            "UPDATE password_reset_sessions SET status = 'verified', verified_at = NOW()
             WHERE id = $1 AND status = 'pending' AND expires_at > NOW()",
        )
        .bind(id.0)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Verify reset_session failed: {}", e)))?
        .rows_affected()
            == 1;
        // Not pending or expired: nothing written, nothing audited.
        if !verified {
            return Ok(false);
        }
        Self::audit_in_tx(&mut tx, &format!("reset_session:{}", id.0), audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn complete_password_reset(
        &self,
        id: sid_core::models::ResetSessionId,
        credential: &Credential,
        history: Option<&HistoryCommit>,
        end: &SessionEnd,
        mut ctx: MutationContext,
    ) -> SidResult<Option<Vec<Session>>> {
        if history.is_some_and(|h| h.owner != credential.profile_id) {
            return Err(SidError::Validation(
                "password history belongs to the credential's profile".into(),
            ));
        }
        if credential.credential_type != CredentialType::Opaque {
            return Err(SidError::Validation(
                "a password replacement installs an OPAQUE credential".into(),
            ));
        }
        let storage = |e: sqlx::Error| SidError::Storage(format!("complete password reset: {e}"));
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let completed: Option<ProfileId> = sqlx::query_scalar(
            "UPDATE password_reset_sessions SET status = 'completed', completed_at = NOW()
             WHERE id = $1 AND status = 'verified' AND expires_at > NOW()
             RETURNING profile_id",
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage)?;
        // Not verified or expired: nothing written.
        let Some(profile_id) = completed else {
            return Ok(None);
        };
        if profile_id != credential.profile_id {
            return Err(SidError::Validation(
                "the new password belongs to another profile than the reset".into(),
            ));
        }
        sqlx::query(
            "DELETE FROM credentials WHERE profile_id = $1 AND credential_type IN ($2, $3)",
        )
        .bind(profile_id)
        .bind(CredentialType::Opaque.as_str())
        .bind(CredentialType::LegacyHash.as_str())
        .execute(&mut *tx)
        .await
        .map_err(storage)?;
        Self::insert_credential_in_tx(&mut tx, credential).await?;
        if let Some(history) = history
            && !password_history::apply_in_tx(&mut tx, history).await?
        {
            return Ok(None);
        }
        let sessions = directory::end_sessions(&mut tx, profile_id, end, &mut ctx).await?;
        Self::audit_in_tx(&mut tx, &format!("profile:{profile_id}"), ctx).await?;
        tx.commit().await.map_err(storage)?;
        Ok(Some(sessions))
    }

    async fn count_active_reset_sessions(&self, profile_id: ProfileId) -> SidResult<u32> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM password_reset_sessions
             WHERE profile_id = $1 AND status IN ('pending', 'verified') AND expires_at > NOW()",
        )
        .bind(profile_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Count reset_sessions failed: {}", e)))?;
        Ok(row.0 as u32)
    }

    async fn delete_expired_reset_sessions(&self, audit: MutationContext) -> SidResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        let result = sqlx::query(
            "DELETE FROM password_reset_sessions WHERE expires_at < NOW() AND status = 'pending'",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Delete expired reset_sessions failed: {}", e)))?;
        let count = result.rows_affected();
        if count > 0 {
            Self::audit_in_tx(&mut tx, "reset_sessions:cleanup", audit).await?;
        }
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(count)
    }

    // ── Email provider config ────────────────────────────────────────────────

    async fn get_email_provider_config(
        &self,
    ) -> SidResult<Option<sid_core::models::EmailProviderConfig>> {
        let row = sqlx::query_as::<_, crate::pg_row::EmailProviderConfigRow>(
            "SELECT smtp_host, smtp_port, from_address, from_display_name, reply_to,
                    encryption, auth_type, username, password_enc,
                    oauth2_provider, oauth2_tenant_id, oauth2_client_id,
                    oauth2_client_secret, oauth2_service_account_key, oauth2_token_endpoint
             FROM email_provider_config LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SidError::Storage(format!("Get email_provider_config failed: {}", e)))?;
        Ok(row.map(|r| r.into_domain()))
    }

    async fn upsert_email_provider_config(
        &self,
        config: &sid_core::models::EmailProviderConfig,
        audit: MutationContext,
    ) -> SidResult<()> {
        // Fixed singleton UUID — only one row exists per CE instance.
        let singleton_id =
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("valid UUID");
        let (
            oauth2_provider,
            oauth2_tenant_id,
            oauth2_client_id,
            oauth2_client_secret,
            oauth2_service_account_key,
            oauth2_token_endpoint,
        ) = if let Some(ref x) = config.xoauth2 {
            (
                Some(x.provider.as_str().to_owned()),
                x.tenant_id.clone(),
                Some(x.client_id.clone()),
                Some(x.client_secret.expose_secret().to_owned()),
                x.service_account_key
                    .as_ref()
                    .map(|k| k.expose_secret().to_owned()),
                x.token_endpoint.clone(),
            )
        } else {
            (None, None, None, None, None, None)
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO email_provider_config
                (id, smtp_host, smtp_port, from_address, from_display_name, reply_to,
                 encryption, auth_type, username, password_enc,
                 oauth2_provider, oauth2_tenant_id, oauth2_client_id,
                 oauth2_client_secret, oauth2_service_account_key, oauth2_token_endpoint,
                 updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                     $11, $12, $13, $14, $15, $16, NOW())
             ON CONFLICT (id) DO UPDATE SET
                smtp_host                  = EXCLUDED.smtp_host,
                smtp_port                  = EXCLUDED.smtp_port,
                from_address               = EXCLUDED.from_address,
                from_display_name          = EXCLUDED.from_display_name,
                reply_to                   = EXCLUDED.reply_to,
                encryption                 = EXCLUDED.encryption,
                auth_type                  = EXCLUDED.auth_type,
                username                   = EXCLUDED.username,
                password_enc               = EXCLUDED.password_enc,
                oauth2_provider            = EXCLUDED.oauth2_provider,
                oauth2_tenant_id           = EXCLUDED.oauth2_tenant_id,
                oauth2_client_id           = EXCLUDED.oauth2_client_id,
                oauth2_client_secret       = EXCLUDED.oauth2_client_secret,
                oauth2_service_account_key = EXCLUDED.oauth2_service_account_key,
                oauth2_token_endpoint      = EXCLUDED.oauth2_token_endpoint,
                updated_at                 = NOW()",
        )
        .bind(singleton_id)
        .bind(&config.smtp_host)
        .bind(config.smtp_port as i32)
        .bind(&config.from_address)
        .bind(&config.from_display_name)
        .bind(&config.reply_to)
        .bind(config.encryption.as_str())
        .bind(config.auth_type.as_str())
        .bind(&config.username)
        .bind(config.password.expose_secret())
        .bind(oauth2_provider)
        .bind(oauth2_tenant_id)
        .bind(oauth2_client_id)
        .bind(oauth2_client_secret)
        .bind(oauth2_service_account_key)
        .bind(oauth2_token_endpoint)
        .execute(&mut *tx)
        .await
        .map_err(|e| SidError::Storage(format!("Upsert email_provider_config failed: {}", e)))?;
        Self::audit_in_tx(&mut tx, "email_provider_config", audit).await?;
        tx.commit()
            .await
            .map_err(|e| SidError::Storage(e.to_string()))?;
        Ok(())
    }
}

/// Row type for access_requests table.
#[derive(sqlx::FromRow)]
struct AccessRequestRow {
    id: Uuid,
    requester_id: ProfileId,
    project_id: Uuid,
    role_key: String,
    justification: Option<String>,
    requested_duration_hours: Option<i32>,
    status: String,
    reviewed_by: Option<ProfileId>,
    review_comment: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    reviewed_at: Option<chrono::DateTime<chrono::Utc>>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl AccessRequestRow {
    fn into_domain(self) -> SidResult<AccessRequest> {
        Ok(AccessRequest {
            id: AccessRequestId(self.id),
            requester_id: self.requester_id,
            project_id: ProjectId(self.project_id),
            role_key: self.role_key,
            justification: self.justification,
            requested_duration_hours: self
                .requested_duration_hours
                .map(u32::try_from)
                .transpose()
                .map_err(|e| SidError::Storage(format!("requested_duration_hours: {e}")))?,
            status: AccessRequestStatus::from_str_loose(&self.status).ok_or_else(|| {
                SidError::Storage(format!("unknown access request status: {}", self.status))
            })?,
            reviewed_by: self.reviewed_by,
            review_comment: self.review_comment,
            created_at: self.created_at,
            reviewed_at: self.reviewed_at,
            expires_at: self.expires_at,
        })
    }
}

mod application;
mod audit_retention;
mod binding;
mod closure;
mod contact;
mod device_auth;
mod directory;
mod job_lock;
mod machine_credential;
mod operation;
mod password_history;
mod provisioning_connector;
mod refresh_token;
mod session;
mod work;
pub use work::PgWorkStore;
