// SPDX-License-Identifier: AGPL-3.0-only
//! Embedded SQL migration runner.
//!
//! Executes SQL migrations in order, tracking applied state in a `_migrations` table.
//! Migrations are embedded at compile time via `include_str!`.
//!
//! Supports schema isolation: when `schema` is provided, all tables are created
//! within that PostgreSQL schema (for shared-database embedded deployments).

use sid_core::{Error as SidError, Result as SidResult};
use sqlx::{AssertSqlSafe, PgPool};
use tracing::info;

/// A single migration with name and SQL content.
struct Migration {
    name: &'static str,
    sql: &'static str,
}

/// All embedded migrations in execution order.
const MIGRATIONS: &[Migration] = &[
    Migration {
        name: "20260314_001_initial_schema",
        sql: include_str!("../../../migrations/20260314_001_initial_schema.sql"),
    },
    Migration {
        name: "20260314_002_consent_tables",
        sql: include_str!("../../../migrations/20260314_002_consent_tables.sql"),
    },
    Migration {
        name: "20260315_003_credential_zk_deadline",
        sql: include_str!("../../../migrations/20260315_003_credential_zk_deadline.sql"),
    },
    Migration {
        name: "20260315_004_oauth2_client_subject_type_changed",
        sql: include_str!(
            "../../../migrations/20260315_004_oauth2_client_subject_type_changed.sql"
        ),
    },
    Migration {
        name: "20260315_005_notification_preferences",
        sql: include_str!("../../../migrations/20260315_005_notification_preferences.sql"),
    },
    Migration {
        name: "20260315_006_access_requests",
        sql: include_str!("../../../migrations/20260315_006_access_requests.sql"),
    },
    Migration {
        name: "20260315_007_audit_monthly_partitions",
        sql: include_str!("../../../migrations/20260315_007_audit_monthly_partitions.sql"),
    },
    Migration {
        name: "20260315_008_profile_blobs",
        sql: include_str!("../../../migrations/20260315_008_profile_blobs.sql"),
    },
    Migration {
        name: "20260316_001_logout_dlq",
        sql: include_str!("../../../migrations/20260316_001_logout_dlq.sql"),
    },
    Migration {
        name: "20260316_002_anomaly_events",
        sql: include_str!("../../../migrations/20260316_002_anomaly_events.sql"),
    },
    Migration {
        name: "20260316_003_oauth2_client_logo_uri",
        sql: include_str!("../../../migrations/20260316_003_oauth2_client_logo_uri.sql"),
    },
    Migration {
        name: "20260316_004_device_attestations",
        sql: include_str!("../../../migrations/20260316_004_device_attestations.sql"),
    },
    Migration {
        name: "20260316_005_profile_structured_name",
        sql: include_str!("../../../migrations/20260316_005_profile_structured_name.sql"),
    },
    Migration {
        name: "20260317_001_ip_reputation",
        sql: include_str!("../../../migrations/20260317_001_ip_reputation.sql"),
    },
    Migration {
        name: "20260317_002_ip_allowlist",
        sql: include_str!("../../../migrations/20260317_002_ip_allowlist.sql"),
    },
    Migration {
        name: "20260322_001_profile_locations_and_device_id",
        sql: include_str!("../../../migrations/20260322_001_profile_locations_and_device_id.sql"),
    },
    Migration {
        name: "20260324_001_rename_identifiers_to_principals",
        sql: include_str!("../../../migrations/20260324_001_rename_identifiers_to_principals.sql"),
    },
    Migration {
        name: "20260324_002_principal_subject",
        sql: include_str!("../../../migrations/20260324_002_principal_subject.sql"),
    },
    Migration {
        name: "20260324_003_principal_verification_timestamps",
        sql: include_str!("../../../migrations/20260324_003_principal_verification_timestamps.sql"),
    },
    Migration {
        name: "20260325_001_profile_phone",
        sql: include_str!("../../../migrations/20260325_001_profile_phone.sql"),
    },
    Migration {
        name: "20260329_001_multi_valued_contacts",
        sql: include_str!("../../../migrations/20260329_001_multi_valued_contacts.sql"),
    },
    Migration {
        name: "20260329_002_principal_bindings",
        sql: include_str!("../../../migrations/20260329_002_principal_bindings.sql"),
    },
    Migration {
        name: "20260330_001_login_strategy",
        sql: include_str!("../../../migrations/20260330_001_login_strategy.sql"),
    },
    Migration {
        name: "20260403_001_recovery_shards",
        sql: include_str!("../../../migrations/20260403_001_recovery_shards.sql"),
    },
    Migration {
        name: "20260404_001_password_reset",
        sql: include_str!("../../../migrations/20260404_001_password_reset.sql"),
    },
    Migration {
        name: "20260405_001_refresh_token_families",
        sql: include_str!("../../../migrations/20260405_001_refresh_token_families.sql"),
    },
    Migration {
        name: "20260408_001_email_provider_config",
        sql: include_str!("../../../migrations/20260408_001_email_provider_config.sql"),
    },
    Migration {
        name: "20260408_002_email_provider_xoauth2",
        sql: include_str!("../../../migrations/20260408_002_email_provider_xoauth2.sql"),
    },
    Migration {
        name: "20260412_001_oauth2_client_missing_columns",
        sql: include_str!("../../../migrations/20260412_001_oauth2_client_missing_columns.sql"),
    },
    Migration {
        name: "20260412_002_profile_username_nullable",
        sql: include_str!("../../../migrations/20260412_002_profile_username_nullable.sql"),
    },
    Migration {
        name: "20260923_001_single_active_opaque_credential",
        sql: include_str!("../../../migrations/20260923_001_single_active_opaque_credential.sql"),
    },
    Migration {
        name: "20260923_002_auth_code_session",
        sql: include_str!("../../../migrations/20260923_002_auth_code_session.sql"),
    },
    Migration {
        name: "20260923_003_initial_access_tokens",
        sql: include_str!("../../../migrations/20260923_003_initial_access_tokens.sql"),
    },
    Migration {
        name: "20260923_004_key_versions",
        sql: include_str!("../../../migrations/20260923_004_key_versions.sql"),
    },
    Migration {
        name: "20260923_005_closure_legal_hold",
        sql: include_str!("../../../migrations/20260923_005_closure_legal_hold.sql"),
    },
    Migration {
        name: "20260923_006_instance_secrets",
        sql: include_str!("../../../migrations/20260923_006_instance_secrets.sql"),
    },
    Migration {
        name: "20260923_007_auth_code_nonce",
        sql: include_str!("../../../migrations/20260923_007_auth_code_nonce.sql"),
    },
    Migration {
        name: "20260923_008_refresh_token_dpop_binding",
        sql: include_str!("../../../migrations/20260923_008_refresh_token_dpop_binding.sql"),
    },
    Migration {
        name: "20260923_009_durable_work",
        sql: include_str!("../../../migrations/20260923_009_durable_work.sql"),
    },
    Migration {
        name: "20260923_010_logout_dlq_into_durable_work",
        sql: include_str!("../../../migrations/20260923_010_logout_dlq_into_durable_work.sql"),
    },
    Migration {
        name: "20260923_011_role_key_and_group",
        sql: include_str!("../../../migrations/20260923_011_role_key_and_group.sql"),
    },
    Migration {
        name: "20260923_012_operation_results",
        sql: include_str!("../../../migrations/20260923_012_operation_results.sql"),
    },
    Migration {
        name: "20260923_013_principal_assignment",
        sql: include_str!("../../../migrations/20260923_013_principal_assignment.sql"),
    },
    Migration {
        name: "20260923_014_service_bindings",
        sql: include_str!("../../../migrations/20260923_014_service_bindings.sql"),
    },
    Migration {
        name: "20260923_015_profiles_view",
        sql: include_str!("../../../migrations/20260923_015_profiles_view.sql"),
    },
    Migration {
        name: "20260923_016_export_jobs",
        sql: include_str!("../../../migrations/20260923_016_export_jobs.sql"),
    },
    Migration {
        name: "20260923_017_session_elevation",
        sql: include_str!("../../../migrations/20260923_017_session_elevation.sql"),
    },
    Migration {
        name: "20260924_018_credential_policy_unverified",
        sql: include_str!("../../../migrations/20260924_018_credential_policy_unverified.sql"),
    },
    Migration {
        name: "20260925_019_oauth2_client_revision",
        sql: include_str!("../../../migrations/20260925_019_oauth2_client_revision.sql"),
    },
    Migration {
        name: "20260925_020_revoked_consent_grants",
        sql: include_str!("../../../migrations/20260925_020_revoked_consent_grants.sql"),
    },
    Migration {
        name: "20260925_021_device_code_redemption",
        sql: include_str!("../../../migrations/20260925_021_device_code_redemption.sql"),
    },
    Migration {
        name: "20260925_022_role_key_and_revision",
        sql: include_str!("../../../migrations/20260925_022_role_key_and_revision.sql"),
    },
    Migration {
        name: "20260925_023_profile_revision",
        sql: include_str!("../../../migrations/20260925_023_profile_revision.sql"),
    },
    Migration {
        name: "20260925_024_cedar_policy_revision",
        sql: include_str!("../../../migrations/20260925_024_cedar_policy_revision.sql"),
    },
    Migration {
        name: "20260925_025_upstream_provider_revision",
        sql: include_str!("../../../migrations/20260925_025_upstream_provider_revision.sql"),
    },
    Migration {
        name: "20260925_026_branding_revision",
        sql: include_str!("../../../migrations/20260925_026_branding_revision.sql"),
    },
    Migration {
        name: "20260925_027_flow_action_order_and_revision",
        sql: include_str!("../../../migrations/20260925_027_flow_action_order_and_revision.sql"),
    },
    Migration {
        name: "20260925_028_audit_chain_checkpoints",
        sql: include_str!("../../../migrations/20260925_028_audit_chain_checkpoints.sql"),
    },
    Migration {
        name: "20260925_029_organizations",
        sql: include_str!("../../../migrations/20260925_029_organizations.sql"),
    },
    Migration {
        name: "20260926_030_oidc_issuers",
        sql: include_str!("../../../migrations/20260926_030_oidc_issuers.sql"),
    },
    Migration {
        name: "20260927_031_drop_subject_type_changed_at",
        sql: include_str!("../../../migrations/20260927_031_drop_subject_type_changed_at.sql"),
    },
    Migration {
        name: "20260927_032_audit_partition_in_own_schema",
        sql: include_str!("../../../migrations/20260927_032_audit_partition_in_own_schema.sql"),
    },
    Migration {
        name: "20260927_033_applications_and_resources",
        sql: include_str!("../../../migrations/20260927_033_applications_and_resources.sql"),
    },
    Migration {
        name: "20260927_034_grant_resource",
        sql: include_str!("../../../migrations/20260927_034_grant_resource.sql"),
    },
    Migration {
        name: "20260927_035_oauth_client_role_assignments",
        sql: include_str!("../../../migrations/20260927_035_oauth_client_role_assignments.sql"),
    },
    Migration {
        name: "20260928_036_audit_partition_concurrent_callers",
        sql: include_str!(
            "../../../migrations/20260928_036_audit_partition_concurrent_callers.sql"
        ),
    },
    Migration {
        name: "20260929_037_browser_session",
        sql: include_str!("../../../migrations/20260929_037_browser_session.sql"),
    },
    Migration {
        name: "20260929_038_client_jwks",
        sql: include_str!("../../../migrations/20260929_038_client_jwks.sql"),
    },
    Migration {
        name: "20260929_039_system_integrations",
        sql: include_str!("../../../migrations/20260929_039_system_integrations.sql"),
    },
    Migration {
        name: "20260930_040_password_history",
        sql: include_str!("../../../migrations/20260930_040_password_history.sql"),
    },
    Migration {
        name: "20260930_041_credential_oprf_identifier",
        sql: include_str!("../../../migrations/20260930_041_credential_oprf_identifier.sql"),
    },
    Migration {
        name: "20261002_042_client_post_logout_redirect_uris",
        sql: include_str!("../../../migrations/20261002_042_client_post_logout_redirect_uris.sql"),
    },
    Migration {
        name: "20261002_043_client_uri_lists_as_arrays",
        sql: include_str!("../../../migrations/20261002_043_client_uri_lists_as_arrays.sql"),
    },
    Migration {
        name: "20261003_044_profiles_page_order",
        sql: include_str!("../../../migrations/20261003_044_profiles_page_order.sql"),
    },
    Migration {
        name: "20261003_045_invites_page_order",
        sql: include_str!("../../../migrations/20261003_045_invites_page_order.sql"),
    },
    Migration {
        name: "20261003_046_provisioning_connectors",
        sql: include_str!("../../../migrations/20261003_046_provisioning_connectors.sql"),
    },
    Migration {
        name: "20261003_047_connector_role_assignments",
        sql: include_str!("../../../migrations/20261003_047_connector_role_assignments.sql"),
    },
    Migration {
        name: "20261003_048_connector_oauth_client",
        sql: include_str!("../../../migrations/20261003_048_connector_oauth_client.sql"),
    },
    Migration {
        name: "20261003_049_machine_user_roles_not_inline",
        sql: include_str!("../../../migrations/20261003_049_machine_user_roles_not_inline.sql"),
    },
    Migration {
        name: "20261004_050_principal_binding_profile",
        sql: include_str!("../../../migrations/20261004_050_principal_binding_profile.sql"),
    },
    Migration {
        name: "20261004_051_role_assignment_admin",
        sql: include_str!("../../../migrations/20261004_051_role_assignment_admin.sql"),
    },
    Migration {
        name: "20261005_052_role_assignment_ceiling",
        sql: include_str!("../../../migrations/20261005_052_role_assignment_ceiling.sql"),
    },
    Migration {
        name: "20261005_053_email_policy_revision",
        sql: include_str!("../../../migrations/20261005_053_email_policy_revision.sql"),
    },
    Migration {
        name: "20261008_054_webauthn_user_handles",
        sql: include_str!("../../../migrations/20261008_054_webauthn_user_handles.sql"),
    },
    Migration {
        name: "20261009_056_credential_policy_artifact",
        sql: include_str!("../../../migrations/20261009_056_credential_policy_artifact.sql"),
    },
    Migration {
        name: "20261010_057_password_history_lifecycle",
        sql: include_str!("../../../migrations/20261010_057_password_history_lifecycle.sql"),
    },
];

/// Run all pending migrations against the database.
///
/// Creates the `_migrations` tracking table if it doesn't exist,
/// then executes each migration that hasn't been applied yet.
///
/// If `schema` is provided, creates the schema and sets `search_path`
/// so all tables land in that schema (shared-database isolation).
pub async fn run_migrations(pool: &PgPool, schema: Option<&str>) -> SidResult<()> {
    migrate(pool, schema, None).await
}

/// [`run_migrations`] stopping after the migration named `last`: a staged
/// upgrade, leaving the later ones pending. An unknown name is refused.
pub async fn run_migrations_through(
    pool: &PgPool,
    schema: Option<&str>,
    last: &str,
) -> SidResult<()> {
    if !MIGRATIONS.iter().any(|m| m.name == last) {
        return Err(SidError::Validation(format!("no migration named {last}")));
    }
    migrate(pool, schema, Some(last)).await
}

async fn migrate(pool: &PgPool, schema: Option<&str>, last: Option<&str>) -> SidResult<()> {
    // Schema isolation: create schema and set search_path
    if let Some(schema_name) = schema {
        validate_schema_name(schema_name)?;

        // A schema name cannot be a bind parameter. `validate_schema_name`
        // above admits only ASCII alphanumerics, `_` and `-`, none of which
        // can end the quoted identifier this interpolates into.
        sqlx::query(AssertSqlSafe(format!(
            "CREATE SCHEMA IF NOT EXISTS \"{}\"",
            schema_name
        )))
        .execute(pool)
        .await
        .map_err(|e| {
            SidError::Storage(format!("Failed to create schema '{}': {}", schema_name, e))
        })?;

        // Same validated identifier, same reason.
        sqlx::query(AssertSqlSafe(format!(
            "SET search_path TO \"{}\", public",
            schema_name
        )))
        .execute(pool)
        .await
        .map_err(|e| {
            SidError::Storage(format!(
                "Failed to set search_path to '{}': {}",
                schema_name, e
            ))
        })?;

        info!("Using schema '{}' for SID tables", schema_name);
    }

    // An advisory lock belongs to the session that took it, so the lock, every
    // migration and the unlock run on one connection taken out of the pool.
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| SidError::Storage(format!("Failed to acquire a connection: {}", e)))?;
    sqlx::query("SELECT pg_advisory_lock(42)")
        .execute(&mut *conn)
        .await
        .map_err(|e| SidError::Storage(format!("Failed to acquire migration lock: {}", e)))?;
    let applied = apply_pending(&mut conn, last).await;
    let unlocked = sqlx::query("SELECT pg_advisory_unlock(42)")
        .execute(&mut *conn)
        .await;
    let applied_count = applied?;
    unlocked.map_err(|e| SidError::Storage(format!("Failed to release migration lock: {}", e)))?;

    if applied_count > 0 {
        info!("Applied {} migration(s)", applied_count);
    } else {
        info!("Database is up to date (all migrations applied)");
    }
    if last.is_none() {
        let quarantined: i64 = sqlx::query_scalar(crate::QUARANTINED_EMAIL_KEYS_SQL)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| SidError::Storage(format!("count quarantined email keys: {e}")))?;
        crate::warn_quarantined_email_keys(quarantined);
    }

    // Schema isolation: create read-only reader role for application JOINs.
    if let Some(schema_name) = schema {
        let role_name = format!("{}_reader", schema_name.replace('-', "_"));
        // role_name is the validated schema name with `-` turned into `_`,
        // so it carries no quote that could close this string literal.
        let role_exists: bool = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = '{}')",
            role_name
        )))
        .fetch_one(pool)
        .await
        .map_err(|e| SidError::Storage(format!("Failed to look up reader role: {}", e)))?;

        if !role_exists {
            sqlx::query(AssertSqlSafe(format!(
                "CREATE ROLE \"{}\" NOLOGIN",
                role_name
            )))
            .execute(pool)
            .await
            .map_err(|e| {
                SidError::Storage(format!(
                    "Failed to create reader role '{}': {}",
                    role_name, e
                ))
            })?;
            info!("Created reader role '{}'", role_name);
        }

        sqlx::query(AssertSqlSafe(format!(
            "GRANT USAGE ON SCHEMA \"{}\" TO \"{}\"",
            schema_name, role_name
        )))
        .execute(pool)
        .await
        .map_err(|e| SidError::Storage(format!("Failed to grant schema usage: {}", e)))?;

        sqlx::query(AssertSqlSafe(format!(
            "GRANT SELECT ON \"{}\".profiles_view TO \"{}\"",
            schema_name, role_name
        )))
        .execute(pool)
        .await
        .map_err(|e| {
            SidError::Storage(format!("Failed to grant select on profiles_view: {}", e))
        })?;

        info!(
            "Schema isolation ready: reader role '{}' can SELECT from {}.profiles_view",
            role_name, schema_name
        );
    }

    Ok(())
}

/// Apply every migration not yet recorded (through `last` when named), each
/// in its own transaction with its `_migrations` row, so a crash leaves a
/// migration either applied and recorded or not applied at all. Returns how
/// many were applied.
async fn apply_pending(conn: &mut sqlx::PgConnection, last: Option<&str>) -> SidResult<u32> {
    use sqlx::Connection;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS _migrations (
            name TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| SidError::Storage(format!("Failed to create _migrations table: {}", e)))?;

    let applied: Vec<String> =
        sqlx::query_scalar::<_, String>("SELECT name FROM _migrations ORDER BY name")
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| SidError::Storage(format!("Failed to query _migrations: {}", e)))?;

    let mut applied_count = 0u32;
    for migration in MIGRATIONS {
        if !applied.iter().any(|name| name == migration.name) {
            info!("Running migration: {}", migration.name);

            let fail = |e: sqlx::Error| {
                SidError::Storage(format!("Migration '{}' failed: {}", migration.name, e))
            };
            let mut tx = conn.begin().await.map_err(fail)?;
            sqlx::raw_sql(migration.sql)
                .execute(&mut *tx)
                .await
                .map_err(fail)?;
            sqlx::query("INSERT INTO _migrations (name) VALUES ($1)")
                .bind(migration.name)
                .execute(&mut *tx)
                .await
                .map_err(fail)?;
            tx.commit().await.map_err(fail)?;
            applied_count += 1;
        }
        if last == Some(migration.name) {
            break;
        }
    }
    Ok(applied_count)
}

/// Validate schema name to prevent SQL injection.
/// Only allows alphanumeric characters, underscores, and hyphens.
pub(crate) fn validate_schema_name(name: &str) -> SidResult<()> {
    if name.is_empty() || name.len() > 63 {
        return Err(SidError::Validation(
            "Schema name must be 1-63 characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(SidError::Validation(
            "Schema name must contain only alphanumeric characters, underscores, or hyphens".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
