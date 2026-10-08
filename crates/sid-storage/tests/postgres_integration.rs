// SPDX-License-Identifier: AGPL-3.0-only
//! Integration tests for PostgreSQL backend.
//!
//! These tests require a running PostgreSQL instance.
//! Set DATABASE_URL environment variable to override connection string.
//!
//! Run with: cargo nextest run -p sid-storage --test postgres_integration

mod common;

use sid_plugin::AuditLog;
use sid_plugin::storage::StorageBackend;
use sid_storage::PostgresBackend;

fn database_url() -> String {
    std::env::var("SID_STORAGE_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid_storage_test".to_string())
}

async fn setup() -> PostgresBackend {
    let backend = PostgresBackend::new(&database_url(), None)
        .await
        .expect("Failed to connect to PostgreSQL. Is the database running?");

    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("Failed to run migrations");

    // Tests run concurrently against one database, so none of them clears
    // tables: every scenario works on rows it created under unique keys.
    backend
}

// ─── Backend identity ───

#[tokio::test]
async fn test_backend_name() {
    use sid_plugin::storage::StorageBackend;
    assert_eq!(setup().await.name(), "postgres");
}

// ─── Self-registration (shared) ───

#[tokio::test]
async fn test_register_profile_commits_all() {
    common::test_register_profile_commits_all(&setup().await).await;
}

#[tokio::test]
async fn test_register_profile_without_credential() {
    common::test_register_profile_without_credential(&setup().await).await;
}

#[tokio::test]
async fn test_register_profile_without_username() {
    common::test_register_profile_without_username(&setup().await).await;
}

#[tokio::test]
async fn test_register_profile_conflict_writes_nothing() {
    common::test_register_profile_conflict_writes_nothing(&setup().await).await;
}

#[tokio::test]
async fn test_register_profile_concurrent_single_winner() {
    common::test_register_profile_concurrent_single_winner(&setup().await).await;
}

#[tokio::test]
async fn test_single_active_password() {
    common::test_single_active_password(&setup().await).await;
}

#[tokio::test]
async fn test_replace_credential_data_is_compare_and_swap() {
    common::test_replace_credential_data_is_compare_and_swap(&setup().await).await;
}

#[tokio::test]
async fn test_mark_credential_used_only_when_active() {
    common::test_mark_credential_used_only_when_active(&setup().await).await;
}

#[tokio::test]
async fn test_create_machine_user_never_replaces() {
    common::machine::test_create_machine_user_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_create_connector_never_replaces() {
    common::provisioning_connector::test_create_connector_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_rename_connector_is_revision_checked() {
    common::provisioning_connector::test_rename_connector_is_revision_checked(&setup().await).await;
}

#[tokio::test]
async fn test_transition_connector() {
    common::provisioning_connector::test_transition_connector(&setup().await).await;
}

#[tokio::test]
async fn test_add_connector_credential() {
    common::provisioning_connector::test_add_credential(&setup().await).await;
}

#[tokio::test]
async fn test_rotate_connector_credential() {
    common::provisioning_connector::test_rotate_credential(&setup().await).await;
}

#[tokio::test]
async fn test_revoke_connector_credential_is_scoped() {
    common::provisioning_connector::test_revoke_credential_is_scoped(&setup().await).await;
}

#[tokio::test]
async fn test_find_and_list_connectors() {
    common::provisioning_connector::test_find_and_list(&setup().await).await;
}

#[tokio::test]
async fn test_connector_fence_holds_writes_to_current_authority() {
    common::provisioning_connector::test_connector_fence_holds_writes_to_current_authority(
        &setup().await,
    )
    .await;
}

#[tokio::test]
async fn test_connector_client_id_and_credential_kind() {
    common::provisioning_connector::test_client_id_and_credential_kind(&setup().await).await;
}

#[tokio::test]
async fn test_connector_fence_races_a_disable() {
    common::provisioning_connector::test_connector_fence_races_a_disable(&setup().await).await;
}

#[tokio::test]
async fn test_add_machine_credential_never_replaces() {
    common::machine::test_add_machine_credential_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_update_machine_user_keeps_status() {
    common::machine::test_update_machine_user_keeps_status(&setup().await).await;
}

#[tokio::test]
async fn test_transition_machine_user_is_compare_and_swap() {
    common::machine::test_transition_machine_user_is_compare_and_swap(&setup().await).await;
}

#[tokio::test]
async fn test_add_machine_credential_limit_under_concurrency() {
    common::machine::test_add_machine_credential_limit_under_concurrency(&setup().await).await;
}

#[tokio::test]
async fn test_rotate_machine_credential() {
    common::machine::test_rotate_machine_credential(&setup().await).await;
}

#[tokio::test]
async fn test_revoke_machine_credential_is_scoped() {
    common::machine::test_revoke_machine_credential_is_scoped(&setup().await).await;
}

#[tokio::test]
async fn test_cascade_revokes_grace_period_credentials() {
    common::machine::test_cascade_revokes_grace_period_credentials(&setup().await).await;
}

#[tokio::test]
async fn test_projects_count_and_listing() {
    common::project::test_projects_count_and_listing(&setup().await).await;
}

#[tokio::test]
async fn test_oauth2_clients_by_project_paging() {
    common::project::test_oauth2_clients_by_project_paging(&setup().await).await;
}

#[tokio::test]
async fn test_machine_users_by_client_and_project() {
    common::machine::test_machine_users_by_client_and_project(&setup().await).await;
}

#[tokio::test]
async fn test_machine_credentials_listing_and_expiry() {
    common::machine::test_machine_credentials_listing_and_expiry(&setup().await).await;
}

#[tokio::test]
async fn test_impersonation_grants() {
    common::machine::test_impersonation_grants(&setup().await).await;
}

#[tokio::test]
async fn test_device_by_fingerprint() {
    common::device::test_device_by_fingerprint(&setup().await).await;
}

#[tokio::test]
async fn test_enabled_providers_and_identities_by_profile() {
    common::upstream::test_enabled_providers_and_identities_by_profile(&setup().await).await;
}

#[tokio::test]
async fn test_delete_outbound_dlq_entry() {
    common::cleanup::test_delete_outbound_dlq_entry(&setup().await).await;
}

#[tokio::test]
async fn test_cleanup_expired_device_auth_codes() {
    common::cleanup::test_cleanup_expired_device_auth_codes(&setup().await).await;
}

#[tokio::test]
async fn test_delete_expired_magic_link_sessions() {
    common::cleanup::test_delete_expired_magic_link_sessions(&setup().await).await;
}

#[tokio::test]
async fn test_delete_expired_reset_sessions() {
    common::cleanup::test_delete_expired_reset_sessions(&setup().await).await;
}

#[tokio::test]
async fn test_decay_ip_reputation() {
    let backend = setup().await;
    let pool = backend.pool().clone();
    let age = move |ip: String| {
        let pool = pool.clone();
        Box::pin(async move {
            sqlx::query(
                "UPDATE ip_reputation SET updated_at = NOW() - INTERVAL '2 hours' WHERE ip = $1",
            )
            .bind(ip)
            .execute(&pool)
            .await
            .unwrap();
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
    };
    common::cleanup::test_decay_ip_reputation(&backend, &age).await;
}

#[tokio::test]
async fn test_flow_configs() {
    common::config::test_flow_configs(&setup().await).await;
}

#[tokio::test]
async fn test_email_provider_config() {
    common::config::test_email_provider_config(&setup().await).await;
}

#[tokio::test]
async fn test_create_session_never_replaces() {
    common::session::test_create_session_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_record_authentication_keeps_ended_session_ended() {
    common::session::test_record_authentication_keeps_ended_session_ended(&setup().await).await;
}

#[tokio::test]
async fn test_record_authentication_is_compare_and_swap() {
    common::session::test_record_authentication_is_compare_and_swap(&setup().await).await;
}

#[tokio::test]
async fn test_record_authentication_refuses_expired_session() {
    common::session::test_record_authentication_refuses_expired_session(&setup().await).await;
}

#[tokio::test]
async fn test_create_pat_never_replaces() {
    common::test_create_pat_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_create_pat_active_limit_under_concurrency() {
    common::test_create_pat_active_limit_under_concurrency(&setup().await).await;
}

#[tokio::test]
async fn test_record_pat_use_only_when_usable() {
    common::test_record_pat_use_only_when_usable(&setup().await).await;
}

#[tokio::test]
async fn test_pat_listing_and_profile_revocation() {
    common::test_pat_listing_and_profile_revocation(&setup().await).await;
}

#[tokio::test]
async fn test_revoke_unused_pats() {
    common::test_revoke_unused_pats(&setup().await).await;
}

#[tokio::test]
async fn test_credential_deletion() {
    common::test_credential_deletion(&setup().await).await;
}

#[tokio::test]
async fn test_create_credential_never_replaces() {
    common::test_create_credential_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_credential_label_only_on_active() {
    common::test_credential_label_only_on_active(&setup().await).await;
}

#[tokio::test]
async fn test_change_password_is_compare_and_swap() {
    common::test_change_password_is_compare_and_swap(&setup().await).await;
}

#[tokio::test]
async fn test_webauthn_user_handle_is_created_once() {
    common::webauthn_user_handle::test_user_handle_is_created_once(&setup().await).await;
}

#[tokio::test]
async fn test_webauthn_concurrent_enrollments_agree_on_one_handle() {
    common::webauthn_user_handle::test_concurrent_enrollments_agree_on_one_handle(&setup().await)
        .await;
}

#[tokio::test]
async fn test_webauthn_user_handle_resolves_only_at_its_rp() {
    common::webauthn_user_handle::test_user_handle_resolves_only_at_its_rp(&setup().await).await;
}

#[tokio::test]
async fn test_webauthn_user_handle_is_unique_per_rp() {
    common::webauthn_user_handle::test_user_handle_is_unique_per_rp(&setup().await).await;
}

#[tokio::test]
async fn test_webauthn_user_handle_needs_a_profile() {
    common::webauthn_user_handle::test_user_handle_needs_a_profile(&setup().await).await;
}

#[tokio::test]
async fn test_history_is_empty_until_written() {
    common::password_history::test_history_is_empty_until_written(&setup().await).await;
}

#[tokio::test]
async fn test_history_epoch_is_prepared_once() {
    common::password_history::test_history_epoch_is_prepared_once(&setup().await).await;
}

#[tokio::test]
async fn test_registration_writes_first_history() {
    common::password_history::test_registration_writes_first_history(&setup().await).await;
}

#[tokio::test]
async fn test_history_commit_is_compare_and_swap() {
    common::password_history::test_history_commit_is_compare_and_swap(&setup().await).await;
}

#[tokio::test]
async fn test_history_retains_depth() {
    common::password_history::test_history_retains_depth(&setup().await).await;
}

#[tokio::test]
async fn test_reset_history_is_compare_and_swap() {
    common::password_history::test_reset_history_is_compare_and_swap(&setup().await).await;
}

#[tokio::test]
async fn test_history_of_another_owner_is_refused() {
    common::password_history::test_history_of_another_owner_is_refused(&setup().await).await;
}

#[tokio::test]
async fn test_reseal_credential_data_keeps_status() {
    common::test_reseal_credential_data_keeps_status(&setup().await).await;
}

#[tokio::test]
async fn test_replace_password_swaps_only_password() {
    common::test_replace_password_swaps_only_password(&setup().await).await;
}

#[tokio::test]
async fn test_replace_recovery_codes_swaps_only_the_set() {
    common::test_replace_recovery_codes_swaps_only_the_set(&setup().await).await;
}

#[tokio::test]
async fn test_end_legacy_migration_is_one_write() {
    common::test_end_legacy_migration_is_one_write(&setup().await).await;
}

#[tokio::test]
async fn test_profile_metadata_roundtrip() {
    common::test_profile_metadata_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_delete_profile_grant() {
    common::test_delete_profile_grant(&setup().await).await;
}

#[tokio::test]
async fn test_profile_lifecycle_scans() {
    common::test_profile_lifecycle_scans(&setup().await).await;
}

#[tokio::test]
async fn test_set_primary_profile_email() {
    common::test_set_primary_profile_email(&setup().await).await;
}

#[tokio::test]
async fn test_enroll_credential_stores_factor_with_codes() {
    common::test_enroll_credential_stores_factor_with_codes(&setup().await).await;
}

// ─── Profile CRUD (shared) ───

#[tokio::test]
async fn test_profile_create_and_get() {
    common::test_profile_create_and_get(&setup().await).await;
}

#[tokio::test]
async fn test_profile_get_by_username() {
    common::test_profile_get_by_username(&setup().await).await;
}

#[tokio::test]
async fn test_profile_get_by_email() {
    common::test_profile_get_by_email(&setup().await).await;
}

#[tokio::test]
async fn test_profile_get_nonexistent() {
    common::test_profile_get_nonexistent(&setup().await).await;
}

#[tokio::test]
async fn test_profile_get_by_email_not_found() {
    common::test_profile_get_by_email_not_found(&setup().await).await;
}

#[tokio::test]
async fn test_profile_get_by_username_not_found() {
    common::test_profile_get_by_username_not_found(&setup().await).await;
}

#[tokio::test]
async fn test_profile_update() {
    common::test_profile_update(&setup().await).await;
}

#[tokio::test]
async fn test_profile_delete() {
    common::test_profile_delete(&setup().await).await;
}

#[tokio::test]
async fn test_profile_list() {
    common::test_profile_list(&setup().await).await;
}

#[tokio::test]
async fn test_profile_list_pages_cover_each_profile_once() {
    common::test_profile_list_pages_cover_each_profile_once(&setup().await).await;
}

#[tokio::test]
async fn test_profile_username_uniqueness() {
    common::test_profile_username_uniqueness(&setup().await).await;
}

#[tokio::test]
async fn test_profile_phone_roundtrip() {
    common::test_profile_phone_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_profile_email_roundtrip() {
    common::test_profile_email_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_get_profile_by_email_via_join() {
    common::test_get_profile_by_email_via_join(&setup().await).await;
}

#[tokio::test]
async fn test_multiple_phones_per_profile() {
    common::test_multiple_phones_per_profile(&setup().await).await;
}

#[tokio::test]
async fn test_phone_extension() {
    common::test_phone_extension(&setup().await).await;
}

// ─── Principal CRUD (shared) ───

#[tokio::test]
async fn test_principal_save_and_get() {
    common::test_principal_save_and_get(&setup().await).await;
}

#[tokio::test]
async fn test_principal_list_by_profile() {
    common::test_principal_list_by_profile(&setup().await).await;
}

#[tokio::test]
async fn test_principal_get_profile_by_principal() {
    common::test_principal_get_profile_by_principal(&setup().await).await;
}

#[tokio::test]
async fn test_principal_delete() {
    common::test_principal_delete(&setup().await).await;
}

#[tokio::test]
async fn test_principal_username_federated() {
    common::test_principal_username_federated(&setup().await).await;
}

#[tokio::test]
async fn test_principal_source_field_roundtrip() {
    common::test_principal_source_field_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_principal_source_contact_fk_roundtrip() {
    common::test_principal_source_contact_fk_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_principal_quarantine_roundtrip() {
    common::test_principal_quarantine_roundtrip(&setup().await).await;
}

// ─── Principal Contestation Model ───

#[tokio::test]
async fn test_principal_get_by_value() {
    common::test_principal_get_by_value(&setup().await).await;
}

#[tokio::test]
async fn test_principal_bindings_crud() {
    common::test_principal_bindings_crud(&setup().await).await;
}

#[tokio::test]
async fn test_principal_count_active_bindings() {
    common::test_principal_count_active_bindings(&setup().await).await;
}

// ─── Session CRUD (shared) ───

#[tokio::test]
async fn test_session_save_and_get() {
    common::test_session_save_and_get(&setup().await).await;
}

#[tokio::test]
async fn test_session_found_by_browser_secret() {
    common::browser_session::test_session_found_by_browser_secret(&setup().await).await;
}

#[tokio::test]
async fn test_browser_secret_is_unique() {
    common::browser_session::test_browser_secret_is_unique(&setup().await).await;
}

#[tokio::test]
async fn test_ending_a_session_ends_what_it_authenticated() {
    common::browser_session::test_ending_a_session_ends_what_it_authenticated(&setup().await).await;
}

#[tokio::test]
async fn test_touch_session_keeps_latest_activity() {
    common::browser_session::test_touch_session_keeps_latest_activity(std::sync::Arc::new(
        setup().await,
    ))
    .await;
}

#[tokio::test]
async fn test_session_delete() {
    common::test_session_delete(&setup().await).await;
}

#[tokio::test]
async fn test_session_delete_by_profile() {
    common::test_session_delete_by_profile(&setup().await).await;
}

#[tokio::test]
async fn test_session_list_by_profile() {
    common::test_session_list_by_profile(&setup().await).await;
}

#[tokio::test]
async fn test_session_get_nonexistent() {
    common::test_session_get_nonexistent(&setup().await).await;
}

// ─── Project CRUD (shared) ───

#[tokio::test]
async fn test_ensure_system_project() {
    common::test_ensure_system_project(&setup().await).await;
}

#[tokio::test]
async fn test_cannot_delete_system_project() {
    common::test_cannot_delete_system_project(&setup().await).await;
}

// ─── OAuth2 Client CRUD (shared) ───

#[tokio::test]
async fn test_oauth2_client_save_and_get() {
    common::test_oauth2_client_save_and_get(&setup().await).await;
}

#[tokio::test]
async fn test_oauth2_client_update() {
    common::test_oauth2_client_update(&setup().await).await;
}

#[tokio::test]
async fn test_oauth2_client_settings_roundtrip() {
    common::test_oauth2_client_settings_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_oauth2_client_update_keeps_deleted_deleted() {
    common::test_oauth2_client_update_keeps_deleted_deleted(&setup().await).await;
}

#[tokio::test]
async fn test_oauth2_client_update_is_compare_and_swap() {
    common::test_oauth2_client_update_is_compare_and_swap(&setup().await).await;
}

#[tokio::test]
async fn test_oauth2_client_create_never_replaces() {
    common::test_oauth2_client_create_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_oauth2_client_concurrent_create() {
    common::test_oauth2_client_concurrent_create(&setup().await).await;
}

#[tokio::test]
async fn test_oauth2_client_full_roundtrip() {
    common::test_oauth2_client_full_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_oauth2_client_keys_rotate() {
    common::test_oauth2_client_keys_rotate(&setup().await).await;
}

// ─── Initial access tokens and dynamic registration (shared) ───

#[tokio::test]
async fn test_iat_save_get_list_revoke() {
    common::test_iat_save_get_list_revoke(&setup().await).await;
}

#[tokio::test]
async fn test_register_dynamic_client() {
    common::test_register_dynamic_client(&setup().await).await;
}

#[tokio::test]
async fn test_register_dynamic_client_conflict_counts_nothing() {
    common::test_register_dynamic_client_conflict_counts_nothing(&setup().await).await;
}

#[tokio::test]
async fn test_register_dynamic_client_concurrent_limit() {
    common::test_register_dynamic_client_concurrent_limit(&setup().await).await;
}

// ─── Audit chain (shared) ───

#[tokio::test]
async fn test_audit_chain_concurrent_appends() {
    let backend = setup().await;
    common::test_audit_chain_concurrent_appends(std::sync::Arc::new(
        sid_storage::audit_log::PostgresAuditLog::new(backend.pool().clone()),
    ))
    .await;
}

#[tokio::test]
async fn test_audit_actor_types_round_trip() {
    let backend = setup().await;
    let log = sid_storage::audit_log::PostgresAuditLog::new(backend.pool().clone());
    common::audit_retention::test_audit_actor_types_round_trip(&log).await;
}

#[tokio::test]
async fn test_audit_retention_keeps_chains_verifiable() {
    let backend = setup().await;
    let pool = backend.pool().clone();
    let log = sid_storage::audit_log::PostgresAuditLog::new(pool.clone());
    common::audit_retention::test_audit_retention_keeps_chains_verifiable(
        &backend,
        &log,
        |r: sid_core::models::audit::AuditRecord| {
            let pool = pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO audit_records (id, timestamp, chain_id, sequence, actor_id,
                        actor_type, action, resource, outcome, metadata, ip_address, device_id,
                        prev_hash, hash)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
                )
                .bind(&r.id)
                .bind(r.timestamp)
                .bind(&r.chain_id)
                .bind(r.sequence as i64)
                .bind(&r.actor_id)
                .bind(r.actor_type.to_string())
                .bind(&r.action)
                .bind(&r.resource)
                .bind(r.outcome.to_string())
                .bind(&r.metadata)
                .bind(&r.ip_address)
                .bind(&r.device_id)
                .bind(&r.prev_hash)
                .bind(&r.hash)
                .execute(&pool)
                .await
                .unwrap();
            }
        },
    )
    .await;
}

/// Retention works on the installation's own schema: an expired partition
/// that only another installation's schema in the same database holds is
/// neither listed nor dropped, and does not fail this installation's run.
/// Partitions were listed by bare table name across every schema, so the
/// other schema's month was counted in this one's and the run failed.
#[tokio::test]
async fn test_audit_retention_stays_in_its_schema() {
    let (own, own_schema) = isolated("retention_own").await;
    let (other, other_schema) = isolated("retention_other").await;
    let outcome = tokio::spawn({
        let (own, other, other_schema) = (own.clone(), other.clone(), other_schema.clone());
        async move {
            let month = chrono::NaiveDate::from_ymd_opt(2001, 1, 1).unwrap();
            assert!(other.ensure_audit_partition(month).await.unwrap());

            let cut_before = "2002-01-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap();
            own.drop_expired_audit_records(cut_before, common::test_audit())
                .await
                .expect("retention of this installation's schema");

            let kept: Option<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT to_regclass('\"{other_schema}\".audit_records_2001_01')::text"
            )))
            .fetch_one(other.pool())
            .await
            .unwrap();
            assert!(kept.is_some(), "another schema's partition was dropped");
        }
    })
    .await;
    finish_isolated(&other, &other_schema, Ok(())).await;
    finish_isolated(&own, &own_schema, outcome).await;
}

/// A month's partition is created in the installation's own schema even when
/// another installation's schema in the same database already has that
/// month. The existence check matched the bare partition name in any schema,
/// so this installation got no partition for the month.
#[tokio::test]
async fn test_audit_partition_is_created_in_its_schema() {
    let (own, own_schema) = isolated("partition_own").await;
    let (other, other_schema) = isolated("partition_other").await;
    let outcome = tokio::spawn({
        let (own, other, own_schema) = (own.clone(), other.clone(), own_schema.clone());
        async move {
            let month = chrono::NaiveDate::from_ymd_opt(2001, 1, 1).unwrap();
            assert!(other.ensure_audit_partition(month).await.unwrap());

            assert!(
                own.ensure_audit_partition(month).await.unwrap(),
                "reported as already existing"
            );
            let created: Option<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT to_regclass('\"{own_schema}\".audit_records_2001_01')::text"
            )))
            .fetch_one(own.pool())
            .await
            .unwrap();
            assert!(created.is_some(), "no partition in this schema");
            assert!(!own.ensure_audit_partition(month).await.unwrap());
        }
    })
    .await;
    finish_isolated(&other, &other_schema, Ok(())).await;
    finish_isolated(&own, &own_schema, outcome).await;
}

// ─── Account closure (shared) ───

#[tokio::test]
async fn test_closure_request_roundtrip() {
    common::test_closure_request_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_closure_request_moves_with_profile() {
    common::test_closure_request_moves_with_profile(&setup().await).await;
}

// ─── Field-encryption key versions, credential paging (shared) ───

#[tokio::test]
async fn test_key_version_insert_once() {
    common::test_key_version_insert_once(&setup().await).await;
}

#[tokio::test]
async fn test_key_version_concurrent_insert() {
    common::test_key_version_concurrent_insert(&setup().await).await;
}

#[tokio::test]
async fn test_instance_secret_insert_once() {
    common::test_instance_secret_insert_once(&setup().await).await;
}

/// A migrated schema of its own, for a scenario about the installation as a
/// whole (its first administrator, its organization) that the shared schema,
/// used by concurrent tests, cannot give.
async fn isolated(prefix: &str) -> (PostgresBackend, String) {
    let schema = format!("{prefix}_{}", uuid::Uuid::now_v7().simple());
    let backend = PostgresBackend::new(&database_url(), Some(schema.clone()))
        .await
        .expect("Failed to connect to PostgreSQL. Is the database running?");
    sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
        .await
        .expect("migrations in an isolated schema");
    (backend, schema)
}

/// Drop an [`isolated`] schema, then report the scenario's outcome.
async fn finish_isolated(
    backend: &PostgresBackend,
    schema: &str,
    outcome: Result<(), tokio::task::JoinError>,
) {
    for statement in [
        format!("DROP SCHEMA \"{schema}\" CASCADE"),
        format!("DROP ROLE IF EXISTS \"{schema}_reader\""),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(backend.pool())
            .await
            .unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}

#[tokio::test]
async fn test_instance_organization_and_clients() {
    let (backend, schema) = isolated("org").await;
    let outcome = tokio::spawn({
        let backend = backend.clone();
        async move { common::organization::test_instance_organization_and_clients(&backend).await }
    })
    .await;
    finish_isolated(&backend, &schema, outcome).await;
}

/// Each runs in its own schema: the installation organization has exactly one
/// local issuer.
#[tokio::test]
async fn test_oidc_issuer_registry() {
    let (backend, schema) = isolated("issuer").await;
    let outcome = tokio::spawn({
        let backend = backend.clone();
        async move { common::oidc_issuer::test_oidc_issuer_registry(&backend).await }
    })
    .await;
    finish_isolated(&backend, &schema, outcome).await;
}

#[tokio::test]
async fn test_oidc_issuer_refuses_a_foreign_first_key() {
    let (backend, schema) = isolated("issuerkey").await;
    let outcome =
        tokio::spawn({
            let backend = backend.clone();
            async move {
                common::oidc_issuer::test_oidc_issuer_refuses_a_foreign_first_key(&backend).await
            }
        })
        .await;
    finish_isolated(&backend, &schema, outcome).await;
}

#[tokio::test]
async fn test_application_roles_are_stored_together() {
    common::application::test_application_roles_are_stored_together(&setup().await).await;
}

#[tokio::test]
async fn test_concurrent_indicator_registration() {
    common::application::test_concurrent_indicator_registration(&setup().await).await;
}

#[tokio::test]
async fn test_system_integration_exists_once() {
    common::application::test_system_integration_exists_once(&setup().await).await;
}

#[tokio::test]
async fn test_application_update_and_list() {
    common::application::test_application_update_and_list(&setup().await).await;
}

#[tokio::test]
async fn test_resource_update_and_retirement() {
    common::application::test_resource_update_and_retirement(&setup().await).await;
}

#[tokio::test]
async fn test_resource_access() {
    common::application::test_resource_access(&setup().await).await;
}

#[tokio::test]
async fn test_machine_user_resource_access() {
    common::application::test_machine_user_resource_access(&setup().await).await;
}

#[tokio::test]
async fn test_resource_listing_and_import() {
    common::application::test_resource_listing_and_import(&setup().await).await;
}

#[tokio::test]
async fn test_client_default_resource() {
    common::application::test_client_default_resource(&setup().await).await;
}

#[tokio::test]
async fn test_oidc_issuer_requires_its_organization() {
    let backend = setup().await;
    common::oidc_issuer::test_oidc_issuer_requires_its_organization(&backend).await;
}

/// Runs in its own schema: the shared schema holds administrators from
/// other tests, and the scenario is an instance's first claim.
#[tokio::test]
async fn test_admin_claim_consumed_once() {
    let (backend, schema) = isolated("claim").await;
    let outcome = tokio::spawn({
        let backend = backend.clone();
        async move { common::admin_claim::test_admin_claim_consumed_once(&backend).await }
    })
    .await;
    finish_isolated(&backend, &schema, outcome).await;
}

/// Runs in its own schema: the scenario is an instance's first claim.
#[tokio::test]
async fn test_registration_claims_instance() {
    let (backend, schema) = isolated("regclaim").await;
    let outcome = tokio::spawn({
        let backend = backend.clone();
        async move { common::admin_claim::test_registration_claims_instance(&backend).await }
    })
    .await;
    finish_isolated(&backend, &schema, outcome).await;
}

/// Runs in its own schema: the shared schema holds administrators from other
/// tests, and the scenario counts the administrators left.
#[tokio::test]
async fn test_last_administrator_cannot_request_closure() {
    let (backend, schema) = isolated("lastadmin").await;
    let outcome = tokio::spawn({
        let backend = backend.clone();
        async move {
            common::admin_claim::test_last_administrator_cannot_request_closure(&backend).await
        }
    })
    .await;
    finish_isolated(&backend, &schema, outcome).await;
}

#[tokio::test]
async fn test_list_credentials_by_type_pages() {
    common::test_list_credentials_by_type_pages(&setup().await).await;
}

#[tokio::test]
async fn test_oauth2_client_not_found() {
    common::test_oauth2_client_not_found(&setup().await).await;
}

// ─── Refresh Token CRUD (shared) ───

#[tokio::test]
async fn test_refresh_token_save_and_get() {
    common::test_refresh_token_save_and_get(&setup().await).await;
}

#[tokio::test]
async fn test_refresh_token_revoke() {
    common::test_refresh_token_revoke(&setup().await).await;
}

#[tokio::test]
async fn test_rotate_refresh_token() {
    common::test_rotate_refresh_token(&setup().await).await;
}

#[tokio::test]
async fn test_rotate_after_sign_out_is_refused() {
    common::test_rotate_after_sign_out_is_refused(&setup().await).await;
}

#[tokio::test]
async fn test_refresh_token_revoke_by_session() {
    common::test_refresh_token_revoke_by_session(&setup().await).await;
}

// ─── Durable work (shared) ───

#[tokio::test]
async fn test_work_enqueue_is_idempotent() {
    common::work::test_work_enqueue_is_idempotent(&setup().await).await;
}

#[tokio::test]
async fn test_work_capacity_is_enforced_per_kind() {
    common::work::test_work_capacity_is_enforced_per_kind(&setup().await).await;
}

#[tokio::test]
async fn test_work_lease_fences_stale_worker() {
    common::work::test_work_lease_fences_stale_worker(&setup().await).await;
}

#[tokio::test]
async fn test_work_live_lease_is_exclusive() {
    common::work::test_work_live_lease_is_exclusive(&setup().await).await;
}

#[tokio::test]
async fn test_work_retries_then_fails() {
    common::work::test_work_retries_then_fails(&setup().await).await;
}

#[tokio::test]
async fn test_work_expired_and_future_are_not_claimed() {
    common::work::test_work_expired_and_future_are_not_claimed(&setup().await).await;
}

#[tokio::test]
async fn test_work_abandoned_last_attempt_fails() {
    common::work::test_work_abandoned_last_attempt_fails(&setup().await).await;
}

#[tokio::test]
async fn test_work_concurrent_claims_do_not_overlap() {
    common::work::test_work_concurrent_claims_do_not_overlap(&setup().await).await;
}

#[tokio::test]
async fn test_work_concurrent_enqueue_stores_once() {
    common::work::test_work_concurrent_enqueue_stores_once(&setup().await).await;
}

#[tokio::test]
async fn test_work_dead_letter_alert_commits_with_failure() {
    common::work::test_work_dead_letter_alert_commits_with_failure(&setup().await).await;
}

#[tokio::test]
async fn test_mutation_commits_owed_work() {
    common::work::test_mutation_commits_owed_work(&setup().await).await;
}

#[tokio::test]
async fn test_session_end_owes_client_logout() {
    common::work::test_session_end_owes_client_logout(&setup().await).await;
}

#[tokio::test]
async fn test_revoke_credential_keeps_last_primary() {
    common::test_revoke_credential_keeps_last_primary(&setup().await).await;
}

#[tokio::test]
async fn test_scim_outbound_roundtrip() {
    common::test_scim_outbound_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_password_reset_completes_once() {
    common::test_password_reset_completes_once(&setup().await).await;
}

#[tokio::test]
async fn test_integrity_counts_ignore_group_assignments() {
    common::test_integrity_counts_ignore_group_assignments(&setup().await).await;
}

#[tokio::test]
async fn test_login_history_signals() {
    common::test_login_history_signals(&setup().await).await;
}

#[tokio::test]
async fn test_security_signals_persist() {
    common::test_security_signals_persist(&setup().await).await;
}

#[tokio::test]
async fn test_device_attestation_roundtrip() {
    common::test_device_attestation_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_revoked_key_clears_hardware_attestation() {
    common::test_revoked_key_clears_hardware_attestation(&setup().await).await;
}

#[tokio::test]
async fn test_create_device_never_replaces() {
    common::device::test_create_device_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_rename_device_keeps_trust() {
    common::device::test_rename_device_keeps_trust(&setup().await).await;
}

#[tokio::test]
async fn test_device_trust_changes() {
    common::device::test_device_trust_changes(&setup().await).await;
}

#[tokio::test]
async fn test_device_trust_limit_under_concurrency() {
    common::device::test_device_trust_limit_under_concurrency(&setup().await).await;
}

#[tokio::test]
async fn test_access_request_decided_once() {
    common::test_access_request_decided_once(&setup().await).await;
}

#[tokio::test]
async fn test_access_request_approval_grants_the_role() {
    common::test_access_request_approval_grants_the_role(&setup().await).await;
}

#[tokio::test]
async fn test_notification_preferences_roundtrip() {
    common::test_notification_preferences_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_registration_source_roundtrip() {
    common::test_registration_source_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_invite_lifecycle() {
    common::test_invite_lifecycle(&setup().await).await;
}

#[tokio::test]
async fn test_invite_list_pages_cover_each_invite_once() {
    common::test_invite_list_pages_cover_each_invite_once(&setup().await).await;
}

#[tokio::test]
async fn test_invite_search() {
    common::test_invite_search(&setup().await).await;
}

#[tokio::test]
async fn test_invite_single_use_under_concurrency() {
    common::test_invite_single_use_under_concurrency(&setup().await).await;
}

#[tokio::test]
async fn test_consent_roundtrip() {
    common::test_consent_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_refresh_token_save_never_replaces() {
    common::test_refresh_token_save_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_device_auth_create_and_get() {
    common::device_auth::test_device_auth_create_and_get(&setup().await).await;
}

#[tokio::test]
async fn test_device_auth_decided_once() {
    common::device_auth::test_device_auth_decided_once(&setup().await).await;
}

#[tokio::test]
async fn test_device_poll_interval() {
    common::device_auth::test_device_poll_interval(&setup().await).await;
}

#[tokio::test]
async fn test_device_code_redeemed_once() {
    common::device_auth::test_device_code_redeemed_once(&setup().await).await;
}

#[tokio::test]
async fn test_create_consent_never_replaces() {
    common::consent::test_create_consent_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_change_claim_grant() {
    common::consent::test_change_claim_grant(&setup().await).await;
}

#[tokio::test]
async fn test_claim_grant_keeps_ended_consent_ended() {
    common::consent::test_claim_grant_keeps_ended_consent_ended(&setup().await).await;
}

#[tokio::test]
async fn test_claim_grants_under_concurrency() {
    common::consent::test_claim_grants_under_concurrency(&setup().await).await;
}

#[tokio::test]
async fn test_role_roundtrip() {
    common::test_role_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_project_write_contract() {
    common::test_project_write_contract(&setup().await).await;
}

#[tokio::test]
async fn test_flow_actions_listed_by_point_in_order() {
    common::flow_action::test_flow_actions_listed_by_point_in_order(&setup().await).await;
}

#[tokio::test]
async fn test_flow_action_write_contract() {
    common::flow_action::test_flow_action_write_contract(&setup().await).await;
}

#[tokio::test]
async fn test_branding_draft_write_contract() {
    common::branding::test_branding_draft_write_contract(&setup().await).await;
}

#[tokio::test]
async fn test_branding_publish_contract() {
    common::branding::test_branding_publish_contract(&setup().await).await;
}

#[tokio::test]
async fn test_branding_concurrent_publish() {
    common::branding::test_branding_concurrent_publish(&setup().await).await;
}

#[tokio::test]
async fn test_upstream_provider_write_contract() {
    common::upstream::test_upstream_provider_write_contract(&setup().await).await;
}

#[tokio::test]
async fn test_upstream_identity_never_relinked() {
    common::upstream::test_upstream_identity_never_relinked(&setup().await).await;
}

#[tokio::test]
async fn test_record_upstream_login_counts_every_login() {
    common::upstream::test_record_upstream_login_counts_every_login(&setup().await).await;
}

#[tokio::test]
async fn test_profile_grant_write_contract() {
    common::test_profile_grant_write_contract(&setup().await).await;
}

#[tokio::test]
async fn test_ensure_system_project_concurrent() {
    common::test_ensure_system_project_concurrent(&setup().await).await;
}

#[tokio::test]
async fn test_cedar_policy_write_contract() {
    common::test_cedar_policy_write_contract(&setup().await).await;
}

#[tokio::test]
async fn test_cedar_policy_concurrent_update() {
    common::test_cedar_policy_concurrent_update(&setup().await).await;
}

#[tokio::test]
async fn test_expired_role_assignments_owe_event() {
    common::work::test_expired_role_assignments_owe_event(&setup().await).await;
}

#[tokio::test]
async fn test_work_export_import_round_trip() {
    common::work::test_work_export_import_round_trip(&setup().await).await;
}

#[tokio::test]
async fn test_magic_link_consumed_once() {
    common::work::test_magic_link_consumed_once(&setup().await).await;
}

#[tokio::test]
async fn test_session_limit_evicts_oldest() {
    common::work::test_session_limit_evicts_oldest(&setup().await).await;
}

#[tokio::test]
async fn test_removing_shared_principal_keeps_other_holder() {
    common::test_removing_shared_principal_keeps_other_holder(&setup().await).await;
}

// ─── Principal assignment ───

#[tokio::test]
async fn test_claim_does_not_change_assignment() {
    common::principal_assignment::test_claim_does_not_change_assignment(&setup().await).await;
}

#[tokio::test]
async fn test_first_use_assigns_sole_claimant() {
    common::principal_assignment::test_first_use_assigns_sole_claimant(&setup().await).await;
}

#[tokio::test]
async fn test_proof_expiry_keeps_assignment() {
    common::principal_assignment::test_proof_expiry_keeps_assignment(&setup().await).await;
}

#[tokio::test]
async fn test_claim_with_proof_does_not_transfer() {
    common::principal_assignment::test_claim_with_proof_does_not_transfer(&setup().await).await;
}

#[tokio::test]
async fn test_login_handle_claim_is_conflict() {
    common::principal_assignment::test_login_handle_claim_is_conflict(&setup().await).await;
}

#[tokio::test]
async fn test_claimant_view_carries_no_proof() {
    common::principal_assignment::test_claimant_view_carries_no_proof(&setup().await).await;
}

#[tokio::test]
async fn test_release_elects_nobody() {
    common::principal_assignment::test_release_elects_nobody(&setup().await).await;
}

#[tokio::test]
async fn test_claimant_leaving_keeps_assignment() {
    common::principal_assignment::test_claimant_leaving_keeps_assignment(&setup().await).await;
}

#[tokio::test]
async fn test_profile_by_principal_is_assigned_holder() {
    common::principal_assignment::test_profile_by_principal_is_assigned_holder(&setup().await)
        .await;
}

// ─── Service bindings ───

#[tokio::test]
async fn test_binding_is_stable() {
    common::service_binding::test_binding_is_stable(&setup().await).await;
}

#[tokio::test]
async fn test_bindings_are_pairwise() {
    common::service_binding::test_bindings_are_pairwise(&setup().await).await;
}

#[tokio::test]
async fn test_concurrent_first_use_allocates_once() {
    common::service_binding::test_concurrent_first_use_allocates_once(&setup().await).await;
}

#[tokio::test]
async fn test_concurrent_scopes_get_distinct_indexes() {
    common::service_binding::test_concurrent_scopes_get_distinct_indexes(&setup().await).await;
}

#[tokio::test]
async fn test_binding_import_keeps_identity() {
    common::service_binding::test_binding_import_keeps_identity(&setup().await).await;
}

#[tokio::test]
async fn test_binding_import_conflict() {
    common::service_binding::test_binding_import_conflict(&setup().await).await;
}

#[tokio::test]
async fn test_binding_needs_profile() {
    common::service_binding::test_binding_needs_profile(&setup().await).await;
}

// ─── Durable operation results ───

#[tokio::test]
async fn test_operation_completion_commits_with_effect() {
    common::operation::test_operation_completion_commits_with_effect(&setup().await).await;
}

#[tokio::test]
async fn test_completed_operation_commits_nothing() {
    common::operation::test_completed_operation_commits_nothing(&setup().await).await;
}

#[tokio::test]
async fn test_concurrent_duplicate_operation_commits_once() {
    common::operation::test_concurrent_duplicate_operation_commits_once(&setup().await).await;
}

#[tokio::test]
async fn test_operation_results_travel_between_stores() {
    common::operation::test_operation_results_travel_between_stores(&setup().await).await;
}

#[tokio::test]
async fn test_failed_mutation_records_no_completion() {
    common::operation::test_failed_mutation_records_no_completion(&setup().await).await;
}

// ─── Session step-up ───

#[tokio::test]
async fn test_session_elevation_roundtrip() {
    common::session_elevation::test_session_elevation_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_session_base_level_refuses_step_up_levels() {
    common::session_elevation::test_session_base_level_refuses_step_up_levels(&setup().await).await;
}

// ─── Data export jobs ───

#[tokio::test]
async fn test_export_job_roundtrip() {
    common::export_job::test_export_job_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_export_job_status_transitions() {
    common::export_job::test_export_job_status_transitions(&setup().await).await;
}

#[tokio::test]
async fn test_export_job_commits_owed_work() {
    common::export_job::test_export_job_commits_owed_work(&setup().await).await;
}

// ─── Directory (SCIM) writes ───

#[tokio::test]
async fn test_directory_user_create_stores_everything() {
    common::directory::test_directory_user_create_stores_everything(&setup().await).await;
}

#[tokio::test]
async fn test_directory_user_create_taken_login_writes_nothing() {
    common::directory::test_directory_user_create_taken_login_writes_nothing(&setup().await).await;
}

#[tokio::test]
async fn test_directory_user_concurrent_create_single_winner() {
    common::directory::test_directory_user_concurrent_create_single_winner(&setup().await).await;
}

#[tokio::test]
async fn test_directory_user_update_applies_every_change() {
    common::directory::test_directory_user_update_applies_every_change(&setup().await).await;
}

#[tokio::test]
async fn test_directory_user_update_missing_writes_nothing() {
    common::directory::test_directory_user_update_missing_writes_nothing(&setup().await).await;
}

#[tokio::test]
async fn test_directory_user_deprovision_ends_access() {
    common::directory::test_directory_user_deprovision_ends_access(&setup().await).await;
}

#[tokio::test]
async fn test_directory_group_writes() {
    common::directory::test_directory_group_writes(&setup().await).await;
}

// ─── Background job locks (two instances: two pools on one database) ───

#[tokio::test]
async fn test_job_lock_exclusive_across_instances() {
    common::job_lock::test_job_lock_exclusive_across_instances(&setup().await, &setup().await)
        .await;
}

#[tokio::test]
async fn test_dropped_job_lock_is_freed() {
    common::job_lock::test_dropped_job_lock_is_freed(&setup().await, &setup().await).await;
}

#[tokio::test]
async fn test_job_locks_are_per_job() {
    common::job_lock::test_job_locks_are_per_job(&setup().await, &setup().await).await;
}

/// Shared-database mode (schema isolation): every migration runs in the
/// configured schema, which ends with the read-only `profiles_view` the
/// application reads through, granted to the `<schema>_reader` role.
#[tokio::test]
async fn test_schema_isolation_exposes_profiles_view() {
    let schema = format!("iso_{}", uuid::Uuid::now_v7().simple());
    let reader = format!("{schema}_reader");
    let backend = PostgresBackend::new(&database_url(), Some(schema.clone()))
        .await
        .expect("Failed to connect to PostgreSQL. Is the database running?");

    let migrated = sid_storage::migrator::run_migrations(backend.pool(), Some(&schema)).await;

    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns
         WHERE table_schema = $1 AND table_name = 'profiles_view'
         ORDER BY ordinal_position",
    )
    .bind(&schema)
    .fetch_all(backend.pool())
    .await
    .unwrap();
    let granted: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.role_table_grants
         WHERE grantee = $1 AND table_schema = $2 AND table_name = 'profiles_view'
           AND privilege_type = 'SELECT')",
    )
    .bind(&reader)
    .bind(&schema)
    .fetch_one(backend.pool())
    .await
    .unwrap();

    for statement in [
        format!("DROP SCHEMA \"{schema}\" CASCADE"),
        format!("DROP ROLE IF EXISTS \"{reader}\""),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(backend.pool())
            .await
            .unwrap();
    }

    migrated.expect("migrations in an isolated schema");
    assert_eq!(
        columns,
        [
            "id",
            "display_name",
            "email",
            "profile_status",
            "created_at",
            "updated_at"
        ]
    );
    assert!(granted, "the reader role can SELECT the view");
}

/// An earlier dead-letter row becomes a failed back-channel logout the
/// delivery handler can read, and the dead-letter table goes. Run in a
/// schema of its own, as the database stood before the change.
#[tokio::test]
async fn test_logout_dead_letters_become_failed_work() {
    use sid_core::models::{LOGOUT_DELIVERY_KIND, LogoutDelivery, WorkState};
    use sqlx::{Connection, Row};

    let mut conn = sqlx::PgConnection::connect(&database_url())
        .await
        .expect("Failed to connect to PostgreSQL. Is the database running?");
    let schema = format!("dlq_{}", uuid::Uuid::now_v7().simple());
    for statement in [
        format!("CREATE SCHEMA \"{schema}\""),
        format!("SET search_path TO \"{schema}\""),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&mut conn)
            .await
            .unwrap();
    }
    for sql in [
        include_str!("../../../migrations/20260316_001_logout_dlq.sql"),
        include_str!("../../../migrations/20260923_009_durable_work.sql"),
    ] {
        sqlx::raw_sql(sql).execute(&mut conn).await.unwrap();
    }
    let with_session = uuid::Uuid::now_v7();
    let without_session = uuid::Uuid::now_v7();
    for (id, session) in [(with_session, Some("s-1")), (without_session, None)] {
        sqlx::query(
            "INSERT INTO logout_dlq (id, client_id, logout_uri, profile_id, session_id,
                attempts, last_error)
             VALUES ($1, 'rp', 'https://rp.sid.example.com/logout', 'p-1', $2, 6, 'HTTP 500')",
        )
        .bind(id)
        .bind(session)
        .execute(&mut conn)
        .await
        .unwrap();
    }

    sqlx::raw_sql(include_str!(
        "../../../migrations/20260923_010_logout_dlq_into_durable_work.sql"
    ))
    .execute(&mut conn)
    .await
    .unwrap();

    let table: Option<String> = sqlx::query_scalar("SELECT to_regclass('logout_dlq')::text")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert!(table.is_none(), "the dead-letter table is still there");
    let row = sqlx::query(
        "SELECT kind, state, attempts, last_error, payload FROM durable_work WHERE id = $1",
    )
    .bind(with_session)
    .fetch_one(&mut conn)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("kind"), LOGOUT_DELIVERY_KIND);
    assert_eq!(row.get::<String, _>("state"), WorkState::Failed.as_str());
    assert_eq!(row.get::<i32, _>("attempts"), 6);
    assert_eq!(row.get::<String, _>("last_error"), "HTTP 500");
    let delivery: LogoutDelivery =
        serde_json::from_slice(&row.get::<Vec<u8>, _>("payload")).unwrap();
    assert_eq!(
        delivery,
        LogoutDelivery {
            client_id: "rp".into(),
            profile_id: "p-1".into(),
            session_id: "s-1".into(),
        }
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM durable_work")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert_eq!(count, 2, "a dead-letter row was lost");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&mut conn)
    .await
    .unwrap();
}

// ─── Durable work in a service's own database (PgWorkStore) ───

/// A standalone work store over the same test database, with only its own
/// schema ensured, as a delivery service opens it.
async fn work_store() -> sid_storage::PgWorkStore {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("Failed to connect to PostgreSQL. Is the database running?");
    let store = sid_storage::PgWorkStore::new(pool);
    store.ensure_schema().await.expect("work schema");
    store
}

#[tokio::test]
async fn test_work_store_enqueue_is_idempotent() {
    common::work::test_work_enqueue_is_idempotent(&work_store().await).await;
}

#[tokio::test]
async fn test_work_store_capacity_is_enforced_per_kind() {
    common::work::test_work_capacity_is_enforced_per_kind(&work_store().await).await;
}

#[tokio::test]
async fn test_work_store_lease_fences_stale_worker() {
    common::work::test_work_lease_fences_stale_worker(&work_store().await).await;
}

#[tokio::test]
async fn test_work_store_live_lease_is_exclusive() {
    common::work::test_work_live_lease_is_exclusive(&work_store().await).await;
}

#[tokio::test]
async fn test_work_store_retries_then_fails() {
    common::work::test_work_retries_then_fails(&work_store().await).await;
}

#[tokio::test]
async fn test_work_store_dead_letter_alert_commits_with_failure() {
    common::work::test_work_dead_letter_alert_commits_with_failure(&work_store().await).await;
}

#[tokio::test]
async fn test_work_store_expired_and_future_are_not_claimed() {
    common::work::test_work_expired_and_future_are_not_claimed(&work_store().await).await;
}

#[tokio::test]
async fn test_work_store_abandoned_last_attempt_fails() {
    common::work::test_work_abandoned_last_attempt_fails(&work_store().await).await;
}

#[tokio::test]
async fn test_work_store_concurrent_claims_do_not_overlap() {
    common::work::test_work_concurrent_claims_do_not_overlap(&work_store().await).await;
}

#[tokio::test]
async fn test_work_store_concurrent_enqueue_stores_once() {
    common::work::test_work_concurrent_enqueue_stores_once(&work_store().await).await;
}

#[tokio::test]
async fn test_work_store_export_import_round_trip() {
    common::work::test_work_export_import_round_trip(&work_store().await).await;
}

// ─── Authorization Code CRUD (shared) ───

#[tokio::test]
async fn test_auth_code_save_and_get() {
    common::test_auth_code_save_and_get(&setup().await).await;
}

#[tokio::test]
async fn test_auth_code_redeem_once() {
    common::test_auth_code_redeem_once(&setup().await).await;
}

#[tokio::test]
async fn test_auth_code_create_never_replaces() {
    common::test_auth_code_create_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_auth_code_concurrent_redeem() {
    common::test_auth_code_concurrent_redeem(&setup().await).await;
}

#[tokio::test]
async fn test_auth_code_not_found() {
    common::test_auth_code_not_found(&setup().await).await;
}

// ─── Magic Link (shared) ───

#[tokio::test]
async fn test_magic_link_crud() {
    common::test_magic_link_crud(&setup().await).await;
}

#[tokio::test]
async fn test_create_role_never_replaces() {
    common::role::test_create_role_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_update_role_is_compare_and_swap() {
    common::role::test_update_role_is_compare_and_swap(&setup().await).await;
}

#[tokio::test]
async fn test_create_role_assignment_never_replaces() {
    common::role::test_create_role_assignment_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_administrative_assignment() {
    common::role::test_administrative_assignment(&setup().await).await;
}

#[tokio::test]
async fn test_fenced_assignment() {
    common::role::test_fenced_assignment(&setup().await).await;
}

#[tokio::test]
async fn test_grantor_never_joins_its_group() {
    common::role::test_grantor_never_joins_its_group(&setup().await).await;
}

#[tokio::test]
async fn test_fenced_role_edit() {
    common::role::test_fenced_role_edit(&setup().await).await;
}

#[tokio::test]
async fn test_oauth_client_role_assignment() {
    common::role::test_oauth_client_role_assignment(&setup().await).await;
}

#[tokio::test]
async fn test_connector_role_assignment() {
    common::role::test_connector_role_assignment(&setup().await).await;
}

#[tokio::test]
async fn test_roles_by_project_and_name() {
    common::role::test_roles_by_project_and_name(&setup().await).await;
}

#[tokio::test]
async fn test_role_assignments_by_principal() {
    common::role::test_role_assignments_by_principal(&setup().await).await;
}

#[tokio::test]
async fn test_expiring_role_assignments() {
    common::role::test_expiring_role_assignments(&setup().await).await;
}

#[tokio::test]
async fn test_cedar_policies_by_project() {
    common::role::test_cedar_policies_by_project(&setup().await).await;
}

#[tokio::test]
async fn test_create_group_never_replaces() {
    common::group::test_create_group_never_replaces(&setup().await).await;
}

#[tokio::test]
async fn test_set_group_description_keeps_deleted_deleted() {
    common::group::test_set_group_description_keeps_deleted_deleted(&setup().await).await;
}

#[tokio::test]
async fn test_group_membership_roundtrip() {
    common::group::test_group_membership_roundtrip(&setup().await).await;
}

#[tokio::test]
async fn test_add_to_group_never_duplicates() {
    common::group::test_add_to_group_never_duplicates(&setup().await).await;
}

#[tokio::test]
async fn test_reset_session_create_never_replaces() {
    common::test_reset_session_create_never_replaces(&setup().await).await;
}

// ─── PAT (shared) ───

#[tokio::test]
async fn test_pat_crud() {
    common::test_pat_crud(&setup().await).await;
}

#[tokio::test]
async fn test_credential_policy_evidence_roundtrip() {
    common::test_credential_policy_evidence_roundtrip(&setup().await).await;
}

// ─── Notification Preferences ───

#[tokio::test]
async fn test_notification_preferences_save_and_get() {
    let backend = setup().await;
    let audit_log = std::sync::Arc::new(sid_storage::audit_log::PostgresAuditLog::new(
        backend.pool().clone(),
    ));
    let backend = backend.with_audit_log(audit_log);

    // Create profile first.
    let profile =
        sid_core::models::Profile::new(Some(format!("notif-test-{}", uuid::Uuid::now_v7())));
    backend
        .create_profile(
            &profile,
            sid_core::models::AuditEntry::system("test", "create").into(),
        )
        .await
        .unwrap();

    // No preferences yet → returns None.
    let prefs = backend
        .get_notification_preferences(profile.id)
        .await
        .unwrap();
    assert!(prefs.is_none());

    // Save preferences.
    let prefs = sid_core::models::notification::NotificationPreferences::defaults(profile.id);
    backend
        .save_notification_preferences(
            &prefs,
            sid_core::models::AuditEntry::system("test", "save_prefs").into(),
        )
        .await
        .unwrap();

    // Get preferences.
    let loaded = backend
        .get_notification_preferences(profile.id)
        .await
        .unwrap()
        .expect("Preferences should exist after save");
    assert_eq!(loaded.profile_id, profile.id);
    assert_eq!(loaded.categories.len(), 4);

    // Verify security_alerts is present.
    assert!(loaded.categories.iter().any(
        |c| c.category == sid_core::models::notification::NotificationCategory::SecurityAlerts
    ));
}

#[tokio::test]
async fn test_notification_preferences_upsert() {
    let backend = setup().await;
    let audit_log = std::sync::Arc::new(sid_storage::audit_log::PostgresAuditLog::new(
        backend.pool().clone(),
    ));
    let backend = backend.with_audit_log(audit_log);

    let profile =
        sid_core::models::Profile::new(Some(format!("notif-upsert-{}", uuid::Uuid::now_v7())));
    backend
        .create_profile(
            &profile,
            sid_core::models::AuditEntry::system("test", "create").into(),
        )
        .await
        .unwrap();

    // Save defaults.
    let prefs = sid_core::models::notification::NotificationPreferences::defaults(profile.id);
    backend
        .save_notification_preferences(
            &prefs,
            sid_core::models::AuditEntry::system("test", "save_v1").into(),
        )
        .await
        .unwrap();

    // Update: disable login notifications.
    let mut updated = prefs.clone();
    if let Some(cat) = updated.categories.iter_mut().find(|c| {
        c.category == sid_core::models::notification::NotificationCategory::LoginNotifications
    }) {
        cat.enabled = false;
    }
    updated.updated_at = chrono::Utc::now();
    backend
        .save_notification_preferences(
            &updated,
            sid_core::models::AuditEntry::system("test", "save_v2").into(),
        )
        .await
        .unwrap();

    // Verify update.
    let loaded = backend
        .get_notification_preferences(profile.id)
        .await
        .unwrap()
        .unwrap();
    let login_cat = loaded
        .categories
        .iter()
        .find(|c| {
            c.category == sid_core::models::notification::NotificationCategory::LoginNotifications
        })
        .unwrap();
    assert!(!login_cat.enabled);
}

// ─── Audit Log Partitioning ───

#[tokio::test]
async fn test_audit_records_partitioned_table_exists() {
    let backend = setup().await;
    let pool = backend.pool();

    // Verify audit_records is a partitioned table. The name resolves through
    // this connection's search path: a bare `relname` match would also find
    // the copies other tests create in their own schemas and drop
    // concurrently.
    let row: (String,) = sqlx::query_as("SELECT pg_get_partkeydef('audit_records'::regclass)")
        .fetch_one(pool)
        .await
        .unwrap();

    assert!(
        row.0.contains("timestamp"),
        "audit_records should be partitioned by timestamp, got: {}",
        row.0
    );
}

#[tokio::test]
async fn test_audit_insert_lands_in_partition() {
    let backend = setup().await;
    let pool = backend.pool();

    // Insert an audit record with a known timestamp (current month).
    let record_id = uuid::Uuid::now_v7().to_string();
    let now = chrono::Utc::now();
    let hash = format!("testhash_{}", record_id);

    sqlx::query(
        "INSERT INTO audit_records (id, timestamp, chain_id, sequence, actor_id, actor_type,
         action, resource, outcome, prev_hash, hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(&record_id)
    .bind(now)
    .bind("profile:test_partition")
    .bind(1i64)
    .bind("system")
    .bind("system")
    .bind("test.partition")
    .bind("test-resource")
    .bind("success")
    .bind("genesis")
    .bind(&hash)
    .execute(pool)
    .await
    .unwrap();

    // Verify we can read it back from the partitioned table.
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_records WHERE id = $1")
        .bind(&record_id)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1);

    // Verify the record is in a specific partition (not default).
    let partition: (String,) =
        sqlx::query_as("SELECT tableoid::regclass::text FROM audit_records WHERE id = $1")
            .bind(&record_id)
            .fetch_one(pool)
            .await
            .unwrap();

    // Should be in a monthly partition like 'audit_records_2026_03', not 'audit_records_default'.
    assert!(
        partition.0.starts_with("audit_records_2026_"),
        "Record should be in monthly partition, got: {}",
        partition.0
    );
    assert_ne!(
        partition.0, "audit_records_default",
        "Record should NOT be in default partition"
    );
}

/// Replicas that run partition maintenance at the same moment all succeed and
/// exactly one creates the month: the existence check and the creation are
/// one step, not a check another caller can pass before the table appears.
#[tokio::test]
async fn test_audit_create_partition_concurrent_callers() {
    let backend = setup().await;
    let pool = backend.pool().clone();
    // A month no earlier run of this test created: the database outlives runs.
    let year = 3000 + i32::try_from(uuid::Uuid::now_v7().as_u128() % 5000).unwrap();

    let mut callers = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let pool = pool.clone();
        callers.spawn(async move {
            sqlx::query_scalar::<_, String>("SELECT create_audit_partition($1, 7)")
                .bind(year)
                .fetch_one(&pool)
                .await
        });
    }
    let mut created = 0;
    while let Some(outcome) = callers.join_next().await {
        let outcome = outcome
            .expect("caller task")
            .expect("a concurrent caller must not fail");
        if outcome.ends_with("(created)") {
            created += 1;
        }
    }
    assert_eq!(created, 1, "exactly one caller creates the partition");
}

#[tokio::test]
async fn test_audit_create_partition_function() {
    let backend = setup().await;
    let pool = backend.pool();

    // Ensure partition doesn't exist from prior test runs.
    let _ = sqlx::query("DROP TABLE IF EXISTS audit_records_2027_01")
        .execute(pool)
        .await;

    // Call create_audit_partition for 2027-01 (doesn't exist yet).
    let result: (String,) = sqlx::query_as("SELECT create_audit_partition(2027, 1)")
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(
        result.0.contains("created"),
        "Expected partition creation, got: {}",
        result.0
    );

    // Calling again should return "already exists".
    let result2: (String,) = sqlx::query_as("SELECT create_audit_partition(2027, 1)")
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(
        result2.0.contains("already exists"),
        "Expected already exists, got: {}",
        result2.0
    );

    // Insert into the new partition.
    let record_id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO audit_records (id, timestamp, chain_id, sequence, actor_id, actor_type,
         action, resource, outcome, prev_hash, hash)
         VALUES ($1, '2027-01-15'::timestamptz, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&record_id)
    .bind("profile:test_2027")
    .bind(1i64)
    .bind("system")
    .bind("system")
    .bind("test.future")
    .bind("test-resource")
    .bind("success")
    .bind("genesis")
    .bind(format!("hash_{}", record_id))
    .execute(pool)
    .await
    .unwrap();

    let partition: (String,) =
        sqlx::query_as("SELECT tableoid::regclass::text FROM audit_records WHERE id = $1")
            .bind(&record_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(partition.0, "audit_records_2027_01");
}

#[tokio::test]
async fn test_audit_append_only_trigger_on_partitioned() {
    let backend = setup().await;
    let pool = backend.pool();

    // Insert a record.
    let record_id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO audit_records (id, timestamp, chain_id, sequence, actor_id, actor_type,
         action, resource, outcome, prev_hash, hash)
         VALUES ($1, now(), $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&record_id)
    .bind("profile:test_immutable")
    .bind(1i64)
    .bind("system")
    .bind("system")
    .bind("test.immutable")
    .bind("test-resource")
    .bind("success")
    .bind("genesis")
    .bind(format!("hash_{}", record_id))
    .execute(pool)
    .await
    .unwrap();

    // UPDATE should fail (append-only trigger).
    let update_result = sqlx::query("UPDATE audit_records SET outcome = 'tampered' WHERE id = $1")
        .bind(&record_id)
        .execute(pool)
        .await;

    assert!(
        update_result.is_err(),
        "UPDATE on audit_records should fail (append-only)"
    );

    // DELETE should fail (append-only trigger).
    let delete_result = sqlx::query("DELETE FROM audit_records WHERE id = $1")
        .bind(&record_id)
        .execute(pool)
        .await;

    assert!(
        delete_result.is_err(),
        "DELETE on audit_records should fail (append-only)"
    );
}

// ─── BlobStore (PostgresBlobStore) ───

#[tokio::test]
async fn test_blob_put_and_get() {
    use sid_core::models::{AuditEntry, EncryptedBlob, Profile};
    use sid_plugin::blob_store::BlobStore;
    use sid_storage::PostgresBlobStore;

    let backend = setup().await;
    let blob_store = PostgresBlobStore::new(backend.pool().clone());

    let profile = Profile::new(Some(format!("blob-test-{}", uuid::Uuid::now_v7())));
    backend
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Initial upload (expected_version = 0).
    let blob = EncryptedBlob {
        ciphertext: b"encrypted-profile-data".to_vec(),
        nonce: [42u8; 12],
        version: 0,
        updated_at: chrono::Utc::now(),
    };
    let v1 = blob_store.put_blob(&profile.id, blob, 0).await.unwrap();
    assert_eq!(v1, 1);

    // Retrieve.
    let retrieved = blob_store.get_blob(&profile.id).await.unwrap().unwrap();
    assert_eq!(retrieved.ciphertext, b"encrypted-profile-data");
    assert_eq!(retrieved.version, 1);
    assert_eq!(retrieved.nonce, [42u8; 12]);
}

#[tokio::test]
async fn test_blob_optimistic_locking() {
    use sid_core::models::{AuditEntry, BlobError, EncryptedBlob, Profile};
    use sid_plugin::blob_store::BlobStore;
    use sid_storage::PostgresBlobStore;

    let backend = setup().await;
    let blob_store = PostgresBlobStore::new(backend.pool().clone());

    let profile = Profile::new(Some(format!("blob-lock-{}", uuid::Uuid::now_v7())));
    backend
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Upload v1.
    let blob = EncryptedBlob {
        ciphertext: b"v1".to_vec(),
        nonce: [0u8; 12],
        version: 0,
        updated_at: chrono::Utc::now(),
    };
    blob_store.put_blob(&profile.id, blob, 0).await.unwrap();

    // Update with correct version.
    let blob_v2 = EncryptedBlob {
        ciphertext: b"v2".to_vec(),
        nonce: [1u8; 12],
        version: 0,
        updated_at: chrono::Utc::now(),
    };
    let v2 = blob_store.put_blob(&profile.id, blob_v2, 1).await.unwrap();
    assert_eq!(v2, 2);

    // Update with WRONG version → conflict.
    let blob_bad = EncryptedBlob {
        ciphertext: b"bad".to_vec(),
        nonce: [2u8; 12],
        version: 0,
        updated_at: chrono::Utc::now(),
    };
    let result = blob_store.put_blob(&profile.id, blob_bad, 1).await;
    assert!(matches!(result, Err(BlobError::VersionConflict { .. })));
}

#[tokio::test]
async fn test_blob_delete_and_metadata() {
    use sid_core::models::{AuditEntry, BlobStorageStatus, EncryptedBlob, Profile};
    use sid_plugin::blob_store::BlobStore;
    use sid_storage::PostgresBlobStore;

    let backend = setup().await;
    let blob_store = PostgresBlobStore::new(backend.pool().clone());

    let profile = Profile::new(Some(format!("blob-del-{}", uuid::Uuid::now_v7())));
    backend
        .create_profile(&profile, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    // Upload.
    let blob = EncryptedBlob {
        ciphertext: b"to-delete".to_vec(),
        nonce: [0u8; 12],
        version: 0,
        updated_at: chrono::Utc::now(),
    };
    blob_store.put_blob(&profile.id, blob, 0).await.unwrap();

    // Metadata before delete.
    let meta = blob_store
        .blob_metadata(&profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(meta.version, 1);
    assert_eq!(meta.storage_status, BlobStorageStatus::Local);

    // Delete.
    blob_store.delete_blob(&profile.id).await.unwrap();

    // get_blob returns None (soft deleted).
    assert!(blob_store.get_blob(&profile.id).await.unwrap().is_none());

    // Metadata shows Deleted status.
    let meta = blob_store
        .blob_metadata(&profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(meta.storage_status, BlobStorageStatus::Deleted);
}

#[tokio::test]
async fn test_blob_nonexistent_returns_none() {
    use sid_core::models::ProfileId;
    use sid_plugin::blob_store::BlobStore;
    use sid_storage::PostgresBlobStore;

    let backend = setup().await;
    let blob_store = PostgresBlobStore::new(backend.pool().clone());

    let pid = ProfileId::generate();
    assert!(blob_store.get_blob(&pid).await.unwrap().is_none());
    assert!(blob_store.blob_metadata(&pid).await.unwrap().is_none());
}

// ─── EP-6 Audit Wiring Verification ───

/// Verify that previously non-audited write methods now produce audit records.
/// Tests: create_oauth2_client, create_role, create_group, add_to_group, create_role_assignment.
#[tokio::test]
async fn test_ep6_audit_wiring_produces_records() {
    let backend = setup().await;
    let audit_log = std::sync::Arc::new(sid_storage::audit_log::PostgresAuditLog::new(
        backend.pool().clone(),
    ));
    let backend = backend.with_audit_log(audit_log.clone());

    let audit: sid_core::models::MutationContext =
        sid_core::models::AuditEntry::system("ep6_test", "verify_wiring").into();

    // 1. create_oauth2_client produces an audit entry
    backend.ensure_system_project(audit.clone()).await.unwrap();
    let client = common::create_test_oauth2_client(&format!("ep6-audit-{}", uuid::Uuid::now_v7()));
    let app = common::application::application_of(&client);
    backend
        .create_application(&app, None, None, audit.clone())
        .await
        .unwrap();
    let chain_id = format!("application:{}", app.id);
    assert!(
        audit_log
            .verify_chain(&chain_id)
            .await
            .unwrap()
            .records_verified
            > 0,
        "create_application should produce audit entry for chain '{chain_id}'",
    );
    backend
        .create_oauth2_client(&client, audit.clone())
        .await
        .unwrap();

    // Verify audit chain exists for oauth2_client
    let chain_id = format!("oauth2_client:{}", client.client_id);
    let chain_result = audit_log.verify_chain(&chain_id).await.unwrap();
    assert!(
        chain_result.records_verified > 0,
        "create_oauth2_client should produce audit entry for chain '{}'",
        chain_id,
    );

    // 2. create_group
    let group = sid_core::models::Group {
        id: sid_core::models::GroupId(uuid::Uuid::now_v7()),
        project_id: sid_core::models::ProjectId::system(),
        parent_group_id: None,
        name: format!("ep6-group-{}", uuid::Uuid::now_v7()),
        description: Some("EP6 test group".into()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    backend.create_group(&group, audit.clone()).await.unwrap();
    let chain_id = format!("group:{}", group.id.0);
    let chain_result = audit_log.verify_chain(&chain_id).await.unwrap();
    assert!(
        chain_result.records_verified > 0,
        "create_group should produce audit entry for chain '{}'",
        chain_id,
    );

    // 4. delete_oauth2_client — was _audit, now should audit
    backend
        .delete_oauth2_client(&client.client_id, audit.clone())
        .await
        .unwrap();
    let chain_id = format!("oauth2_client:{}", client.client_id);
    let chain_result = audit_log.verify_chain(&chain_id).await.unwrap();
    assert!(
        chain_result.records_verified >= 2,
        "delete_oauth2_client should add second audit entry (save + delete), got {}",
        chain_result.records_verified,
    );
}

// ─── Password Reset Session CRUD ───

#[tokio::test]
async fn test_reset_session_save_get_update() {
    let backend = setup().await;
    let audit = common::test_audit();

    let profile = common::create_test_profile("reset_test");
    backend
        .create_profile(&profile, audit.clone())
        .await
        .unwrap();

    let session = sid_core::models::PasswordResetSession::new(
        profile.id,
        "reset@sid.example.com".into(),
        "sha256hash123".into(),
    );
    backend
        .create_reset_session(&session, audit.clone())
        .await
        .unwrap();

    // Get
    let loaded = backend
        .get_reset_session(session.id)
        .await
        .unwrap()
        .expect("session should exist");
    assert_eq!(loaded.profile_id, profile.id);
    assert_eq!(loaded.email, "reset@sid.example.com");
    assert_eq!(loaded.status, sid_core::models::ResetSessionStatus::Pending);

    // Verify
    assert!(
        backend
            .verify_reset_session(session.id, audit.clone())
            .await
            .unwrap()
    );

    let updated = backend
        .get_reset_session(session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        updated.status,
        sid_core::models::ResetSessionStatus::Verified
    );
    assert!(updated.verified_at.is_some());

    // Count active
    let count = backend
        .count_active_reset_sessions(profile.id)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

/// EP-6 Regression: verify audit record is written IN the same transaction as data.
/// After save_profile, both profile AND audit record must exist. If audit were
/// written outside the tx (the old bug), a crash between data commit and audit
/// write would leave data without audit — undetectable without this test.
#[tokio::test]
async fn test_ep6_audit_transactional_with_data() {
    let backend = setup().await;
    let audit_log = std::sync::Arc::new(sid_storage::audit_log::PostgresAuditLog::new(
        backend.pool().clone(),
    ));
    let backend = backend.with_audit_log(audit_log.clone());

    let uid = uuid::Uuid::now_v7();
    let profile = sid_core::models::Profile::new(Some(format!("ep6-tx-{uid}")));
    let audit: sid_core::models::MutationContext =
        sid_core::models::AuditEntry::system("ep6_tx_test", "save_profile").into();

    // Save profile — data + audit should be atomic.
    backend.create_profile(&profile, audit).await.unwrap();

    // Verify data exists.
    let loaded = backend.get_profile(profile.id).await.unwrap();
    assert!(loaded.is_some(), "profile should exist after save");

    // Verify audit exists for the same chain.
    let chain_id = format!("profile:{}", profile.id);
    let records = audit_log.query(&chain_id, None, None).await.unwrap();
    assert_eq!(
        records.len(),
        1,
        "exactly one audit record should exist after save_profile"
    );
    assert_eq!(records[0].action, "ep6_tx_test");
    assert_eq!(records[0].resource, "save_profile");

    // Verify chain integrity.
    let verify = audit_log.verify_chain(&chain_id).await.unwrap();
    assert!(verify.valid, "audit chain should be valid");
    assert_eq!(verify.records_verified, 1);
}

/// EP-6 Regression: multiple operations on same entity produce valid hash chain.
#[tokio::test]
async fn test_ep6_audit_chain_integrity_after_update() {
    let backend = setup().await;
    let audit_log = std::sync::Arc::new(sid_storage::audit_log::PostgresAuditLog::new(
        backend.pool().clone(),
    ));
    let backend = backend.with_audit_log(audit_log.clone());

    let uid = uuid::Uuid::now_v7();
    let mut profile = sid_core::models::Profile::new(Some(format!("ep6-chain-{uid}")));

    // Create.
    backend
        .create_profile(
            &profile,
            sid_core::models::AuditEntry::system("create", "ep6_chain_test").into(),
        )
        .await
        .unwrap();

    // Update.
    profile.given_name = Some("Updated".to_string());
    assert!(
        backend
            .update_profile(
                &profile,
                sid_core::models::AuditEntry::system("update", "ep6_chain_test").into(),
            )
            .await
            .unwrap()
    );

    // Delete.
    backend
        .delete_profile(
            profile.id,
            sid_core::models::AuditEntry::system("delete", "ep6_chain_test").into(),
        )
        .await
        .unwrap();

    // Verify chain: 3 records, valid hash chain.
    let chain_id = format!("profile:{}", profile.id);
    let records = audit_log.query(&chain_id, None, None).await.unwrap();
    assert_eq!(
        records.len(),
        3,
        "3 audit records expected (create+update+delete)"
    );
    assert_eq!(records[0].action, "create");
    assert_eq!(records[1].action, "update");
    assert_eq!(records[2].action, "delete");

    let verify = audit_log.verify_chain(&chain_id).await.unwrap();
    assert!(
        verify.valid,
        "audit chain should be valid after 3 operations"
    );
    assert_eq!(verify.records_verified, 3);
}

// ── Profile nullable username (#823) ─────────────────────────────

#[tokio::test]
async fn test_pg_profile_nullable_username_roundtrip() {
    let backend = setup().await;
    let storage: &dyn StorageBackend = &backend;

    // Profile with username = None (email-only registration).
    let profile = sid_core::models::Profile::new(None::<String>);
    assert!(profile.username.is_none());

    storage
        .create_profile(
            &profile,
            sid_core::models::AuditEntry::system("test", "create_profile").into(),
        )
        .await
        .expect("save profile with null username");

    let loaded = storage
        .get_profile(profile.id)
        .await
        .expect("get profile")
        .expect("profile should exist");

    assert!(loaded.username.is_none(), "loaded username should be None");
    assert_eq!(loaded.id, profile.id);
    assert_eq!(loaded.profile_type, profile.profile_type);
}

#[tokio::test]
async fn test_pg_profile_with_username_roundtrip() {
    let backend = setup().await;
    let storage: &dyn StorageBackend = &backend;

    let username = format!("alice-{}", uuid::Uuid::now_v7().simple());
    let profile = sid_core::models::Profile::new(Some(&username));

    storage
        .create_profile(
            &profile,
            sid_core::models::AuditEntry::system("test", "create_profile").into(),
        )
        .await
        .expect("save profile with username");

    let loaded = storage
        .get_profile(profile.id)
        .await
        .expect("get profile")
        .expect("profile should exist");

    assert_eq!(loaded.username.as_deref(), Some(username.as_str()));
}

// ─── Email policy revisions ───

#[tokio::test]
async fn test_email_key_written_only_under_the_active_revision() {
    common::email_policy::test_email_key_written_only_under_the_active_revision(&setup().await)
        .await;
}

/// The cutover on a database written before email policy revisions: each
/// historical email assignment is kept, quarantined with a recorded reason,
/// and the installation's active revision is the current one.
#[tokio::test]
async fn test_email_policy_cutover_quarantines_legacy_keys() {
    let schema = format!("email_cutover_{}", uuid::Uuid::now_v7().simple());
    let backend = PostgresBackend::new(&database_url(), Some(schema.clone()))
        .await
        .expect("Failed to connect to PostgreSQL. Is the database running?");
    sid_storage::migrator::run_migrations_through(
        backend.pool(),
        Some(&schema),
        "20261005_052_role_assignment_ceiling",
    )
    .await
    .expect("migrations through 052");

    let domain = "cutover.sid.example.com";
    let mut legacy = Vec::new();
    for row in common::email_policy::legacy_rows(domain) {
        let profile = common::create_test_profile("cutover");
        backend
            .create_profile(&profile, common::test_audit())
            .await
            .unwrap();
        let contact_id = match &row.contact {
            Some(address) => Some(legacy_contact(&backend, profile.id, address).await),
            None => None,
        };
        let principal_id = uuid::Uuid::now_v7();
        sqlx::query(
            "INSERT INTO principals (id, principal_type, value, verified, verified_at,
                 assigned_profile_id, assignment_revision, created_at, updated_at)
             VALUES ($1, 'email', $2, $3, CASE WHEN $3 THEN NOW() END, $4, 1, NOW(), NOW())",
        )
        .bind(principal_id)
        .bind(&row.key)
        .bind(row.verified)
        .bind(profile.id)
        .execute(backend.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO principal_bindings (id, principal_id, profile_id, is_primary,
                 source_field, source_email_id, created_at)
             VALUES ($1, $2, $3, TRUE, 'email', $4, NOW())",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(principal_id)
        .bind(profile.id)
        .bind(contact_id)
        .execute(backend.pool())
        .await
        .unwrap();
        legacy.push((row.key, profile.id));
    }

    sid_storage::migrator::run_migrations(backend.pool(), Some(&schema))
        .await
        .expect("the cutover migration");

    let dispositions: Vec<(String, String)> =
        sqlx::query_as("SELECT disposition, reason FROM email_policy_dispositions")
            .fetch_all(backend.pool())
            .await
            .unwrap();
    assert_eq!(dispositions.len(), legacy.len());
    assert!(
        dispositions
            .iter()
            .all(|(d, r)| d == "quarantined" && r == "no_source_evidence")
    );
    let active: i64 = sqlx::query_scalar(
        "SELECT revision FROM email_policy_activations WHERE scope = 'installation'",
    )
    .fetch_one(backend.pool())
    .await
    .unwrap();
    assert_eq!(active, sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION);

    common::email_policy::legacy_keys_are_quarantined(&backend, &legacy, domain).await;
    common::email_policy::legacy_keys_are_reconciled(&backend, &legacy).await;
    let migrated: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_policy_dispositions WHERE disposition = 'migrated'",
    )
    .fetch_one(backend.pool())
    .await
    .unwrap();
    assert_eq!(migrated, 2, "the repaired key and the race winner");

    // The scratch schema goes with the test; the shared database stays clean.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(backend.pool())
    .await
    .unwrap();
}

/// A contact row as the old code wrote it.
async fn legacy_contact(
    backend: &PostgresBackend,
    profile: sid_core::models::ProfileId,
    address: &str,
) -> uuid::Uuid {
    let now = chrono::Utc::now();
    let contact = sid_core::models::ProfileEmail {
        id: sid_core::models::ProfileEmailId::new(),
        profile_id: profile,
        email: address.to_string(),
        label: sid_core::models::EmailLabel::Personal,
        custom_label: None,
        is_primary: true,
        verified: false,
        verified_at: None,
        created_at: now,
        updated_at: now,
    };
    backend
        .create_profile_email(&contact, common::test_audit())
        .await
        .unwrap();
    contact.id.0
}
