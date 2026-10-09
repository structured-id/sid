// SPDX-License-Identifier: AGPL-3.0-only
//! Integration tests for SQLite backend.
//!
//! These tests use in-memory SQLite — no external dependencies.
//! Run with: cargo test --test sqlite_integration --features storage-sqlite
#![cfg(feature = "storage-sqlite")]

mod common;

use sid_storage::sqlite::SqliteBackend;

async fn setup() -> SqliteBackend {
    SqliteBackend::new_in_memory()
        .await
        .expect("Failed to create in-memory SQLite backend")
}

// ─── Backend identity ───

#[tokio::test]
async fn test_backend_name() {
    use sid_plugin::storage::StorageBackend;
    assert_eq!(setup().await.name(), "sqlite_sqlx");
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
            // The engine stores times as RFC 3339 text with milliseconds.
            let past = (chrono::Utc::now() - chrono::Duration::hours(2))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            sqlx::query("UPDATE ip_reputation SET updated_at = ? WHERE ip = ?")
                .bind(past)
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
async fn test_history_archive_preserves_lifecycle() {
    common::password_history::test_history_archive_preserves_lifecycle(&setup().await).await;
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

#[tokio::test]
async fn test_credential_policy_evidence_roundtrip() {
    common::test_credential_policy_evidence_roundtrip(&setup().await).await;
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
        sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone()),
    ))
    .await;
}

#[tokio::test]
async fn test_audit_actor_types_round_trip() {
    let backend = setup().await;
    let log = sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone());
    common::audit_retention::test_audit_actor_types_round_trip(&log).await;
}

#[tokio::test]
async fn test_audit_retention_keeps_chains_verifiable() {
    let backend = setup().await;
    let pool = backend.pool().clone();
    let log = sid_storage::sqlite::SqliteAuditLog::new(pool.clone());
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
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&r.id)
                .bind(
                    r.timestamp
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                )
                .bind(&r.chain_id)
                .bind(r.sequence as i64)
                .bind(&r.actor_id)
                .bind(r.actor_type.to_string())
                .bind(&r.action)
                .bind(&r.resource)
                .bind(r.outcome.to_string())
                .bind(r.metadata.to_string())
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

#[tokio::test]
async fn test_instance_organization_and_clients() {
    common::organization::test_instance_organization_and_clients(&setup().await).await;
}

#[tokio::test]
async fn test_admin_claim_consumed_once() {
    common::admin_claim::test_admin_claim_consumed_once(&setup().await).await;
}

#[tokio::test]
async fn test_registration_claims_instance() {
    common::admin_claim::test_registration_claims_instance(&setup().await).await;
}

#[tokio::test]
async fn test_last_administrator_cannot_request_closure() {
    common::admin_claim::test_last_administrator_cannot_request_closure(&setup().await).await;
}

#[tokio::test]
async fn test_oidc_issuer_registry() {
    common::oidc_issuer::test_oidc_issuer_registry(&setup().await).await;
}

#[tokio::test]
async fn test_oidc_issuer_refuses_a_foreign_first_key() {
    common::oidc_issuer::test_oidc_issuer_refuses_a_foreign_first_key(&setup().await).await;
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
    common::oidc_issuer::test_oidc_issuer_requires_its_organization(&setup().await).await;
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

// ─── Background job locks (two instances: two backends on one file) ───

/// Two backends opened on one database file, as two processes would.
async fn two_instances() -> (tempfile::TempDir, SqliteBackend, SqliteBackend) {
    let dir = tempfile::tempdir().unwrap();
    let path = format!("sqlite://{}", dir.path().join("sid.db").display());
    let a = SqliteBackend::new(&path).await.unwrap();
    let b = SqliteBackend::new(&path).await.unwrap();
    (dir, a, b)
}

#[tokio::test]
async fn test_job_lock_exclusive_across_instances() {
    let (_dir, a, b) = two_instances().await;
    common::job_lock::test_job_lock_exclusive_across_instances(&a, &b).await;
}

#[tokio::test]
async fn test_dropped_job_lock_is_freed() {
    let (_dir, a, b) = two_instances().await;
    common::job_lock::test_dropped_job_lock_is_freed(&a, &b).await;
}

#[tokio::test]
async fn test_job_locks_are_per_job() {
    let (_dir, a, b) = two_instances().await;
    common::job_lock::test_job_locks_are_per_job(&a, &b).await;
}

#[tokio::test]
async fn test_mutation_commits_owed_work() {
    common::work::test_mutation_commits_owed_work(&setup().await).await;
}

/// Every mutation records its audit entry in the database's own audit chain,
/// in its transaction: there is no configuration in which it goes unaudited.
#[tokio::test]
async fn test_mutation_is_always_audited() {
    use sid_plugin::audit::AuditLog;
    use sid_plugin::storage::StorageBackend;
    use sid_storage::sqlite::SqliteAuditLog;

    let backend = setup().await;
    let profile = common::create_test_profile("audited");
    backend
        .create_profile(&profile, common::test_audit())
        .await
        .unwrap();
    backend
        .delete_profile(profile.id, common::test_audit())
        .await
        .unwrap();

    let log = SqliteAuditLog::new(backend.pool().clone());
    let chain = format!("profile:{}", profile.id);
    assert_eq!(log.query(&chain, None, None).await.unwrap().len(), 2);
    assert!(log.verify_chain(&chain).await.unwrap().valid);
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

// ─── SQLite-only: Audit log chain ───

#[tokio::test]
async fn test_audit_log_chain() {
    use sid_core::models::AuditEntry;
    use sid_core::models::audit::compute_record_hash;
    use sid_plugin::audit::AuditLog;
    use sid_storage::sqlite::SqliteAuditLog;

    let backend = setup().await;
    let audit_log = SqliteAuditLog::new(backend.pool().clone());

    let entry1 = AuditEntry::system("profile.created", "profile:abc123");
    let r1 = audit_log.log("profile:abc123", entry1).await.unwrap();
    assert_eq!(r1.sequence, 1);
    assert_eq!(r1.prev_hash, "genesis");
    assert!(!r1.hash.is_empty());

    let entry2 = AuditEntry::system("profile.updated", "profile:abc123");
    let r2 = audit_log.log("profile:abc123", entry2).await.unwrap();
    assert_eq!(r2.sequence, 2);
    assert_eq!(r2.prev_hash, r1.hash);

    let records = audit_log.query("profile:abc123", None, None).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].action, "profile.created");
    assert_eq!(records[1].action, "profile.updated");

    for record in &records {
        let recomputed = compute_record_hash(record);
        assert_eq!(
            record.hash, recomputed,
            "Hash mismatch for record {} (seq {}). timestamp stored={:?}",
            record.id, record.sequence, record.timestamp
        );
    }

    assert_eq!(records[1].prev_hash, records[0].hash);

    let result = audit_log.verify_chain("profile:abc123").await.unwrap();
    assert!(result.valid, "Chain should be valid");
    assert_eq!(result.records_verified, 2);
}

#[tokio::test]
async fn test_audit_log_parallel_chains() {
    use sid_core::models::AuditEntry;
    use sid_plugin::audit::AuditLog;
    use sid_storage::sqlite::SqliteAuditLog;

    let backend = setup().await;
    let audit_log = SqliteAuditLog::new(backend.pool().clone());

    let ra = audit_log
        .log("chain_A", AuditEntry::system("a1", "res"))
        .await
        .unwrap();
    let rb = audit_log
        .log("chain_B", AuditEntry::system("b1", "res"))
        .await
        .unwrap();

    assert_eq!(ra.sequence, 1);
    assert_eq!(rb.sequence, 1);
    assert_eq!(ra.prev_hash, "genesis");
    assert_eq!(rb.prev_hash, "genesis");
}

// ─── Email policy revisions ───

#[tokio::test]
async fn test_email_key_written_only_under_the_active_revision() {
    common::email_policy::test_email_key_written_only_under_the_active_revision(&setup().await)
        .await;
}

/// The cutover on a database file written before email policy revisions
/// (schema version 1), opened by the build that has them: each historical
/// email assignment is kept, quarantined with a recorded reason, and the
/// installation's active revision is the current one.
#[tokio::test]
async fn test_email_policy_cutover_quarantines_legacy_keys() {
    use sid_plugin::storage::StorageBackend;

    let dir = tempfile::tempdir().unwrap();
    let path = format!("sqlite://{}", dir.path().join("sid.db").display());
    let domain = "cutover.sid.example.com";
    let mut legacy = Vec::new();
    {
        let old = SqliteBackend::new_through(&path, 1)
            .await
            .expect("a version 1 file");
        for row in common::email_policy::legacy_rows(domain) {
            let profile = common::create_test_profile("cutover");
            old.create_profile(&profile, common::test_audit())
                .await
                .unwrap();
            let contact_id = match &row.contact {
                Some(address) => Some(legacy_contact(&old, profile.id, address).await),
                None => None,
            };
            let principal_id = uuid::Uuid::now_v7().to_string();
            sqlx::query(
                "INSERT INTO principals (id, principal_type, value, verified, verified_at,
                     assigned_profile_id, assignment_revision)
                 VALUES (?, 'email', ?, ?, CASE WHEN ? THEN '2026-01-01T00:00:00Z' END, ?, 1)",
            )
            .bind(&principal_id)
            .bind(&row.key)
            .bind(row.verified)
            .bind(row.verified)
            .bind(profile.id.to_string())
            .execute(old.pool())
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO principal_bindings (id, principal_id, profile_id, is_primary,
                     source_field, source_email_id)
                 VALUES (?, ?, ?, 1, 'email', ?)",
            )
            .bind(uuid::Uuid::now_v7().to_string())
            .bind(&principal_id)
            .bind(profile.id.to_string())
            .bind(contact_id)
            .execute(old.pool())
            .await
            .unwrap();
            legacy.push((row.key, profile.id));
        }
        old.pool().close().await;
    }

    let backend = SqliteBackend::new(&path).await.expect("the upgraded file");
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
}

/// A contact row as the old code wrote it.
async fn legacy_contact(
    backend: &SqliteBackend,
    profile: sid_core::models::ProfileId,
    address: &str,
) -> String {
    use sid_plugin::storage::StorageBackend;

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
    contact.id.0.to_string()
}
