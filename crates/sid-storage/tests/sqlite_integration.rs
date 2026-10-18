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
async fn test_history_archive_preserves_lifecycle() {
    common::password_history::test_history_archive_preserves_lifecycle(&setup().await).await;
}

#[tokio::test]
async fn test_registration_writes_first_history() {
    common::password_history::test_registration_writes_first_history(&setup().await).await;
}

#[tokio::test]
async fn test_history_age_retention() {
    common::password_history::test_history_age_retention(&setup().await).await;
}

#[tokio::test]
async fn test_reset_history_is_compare_and_swap() {
    common::password_history::test_reset_history_is_compare_and_swap(&setup().await).await;
}

#[tokio::test]
async fn test_history_write_cutoff_fences_registration_and_reset() {
    common::password_history::test_history_write_cutoff_fences_registration_and_reset(
        &setup().await,
    )
    .await;
}

// ─── Credential store conformance ───

/// Run credential store conformance `scenario` against this backend. Each
/// gets its own in-memory database, so the store-wide history write cutoff
/// one raises reaches no other.
macro_rules! credential_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test]
        async fn $scenario() {
            let backend = setup().await;
            sid_plugin::conformance::credential_store::$scenario(
                &common::credential_conformance::ProfileCredentials(&backend),
            )
            .await;
        }
    )*};
}

// ─── Operation result conformance ───

/// Run operation result conformance `scenario`; each one uses namespaces of
/// its own.
macro_rules! operation_result_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test]
        async fn $scenario() {
            sid_plugin::conformance::operation_result_store::$scenario(&setup().await).await;
        }
    )*};
}

mod operation_result_store {
    use super::*;

    operation_result_store!(
        recorded_outcome_resolves,
        completed_key_records_nothing,
        concurrent_outcomes_record_once,
        results_travel_between_stores,
        results_are_purged_by_method,
    );
}

// ─── Instance secret conformance ───

/// Run instance secret conformance `scenario` against a fresh database.
macro_rules! instance_secret_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test]
        async fn $scenario() {
            sid_plugin::conformance::instance_secret_store::$scenario(&setup().await).await;
        }
    )*};
}

mod instance_secret_store {
    use super::*;

    instance_secret_store!(
        secret_is_absent_until_stored,
        first_value_is_kept,
        concurrent_inserts_agree,
    );
}

// ─── Sign-in history conformance ───

/// Run sign-in history conformance `scenario` against this backend.
macro_rules! sign_in_history {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test]
        async fn $scenario() {
            let backend = setup().await;
            sid_plugin::conformance::sign_in_history::$scenario(
                &common::sign_in_history_conformance::ProfileSignIns(&backend),
            )
            .await;
        }
    )*};
}

mod sign_in_history {
    use super::*;

    sign_in_history!(
        most_recent_session_is_the_latest,
        seen_address_and_device_are_per_account,
        location_is_designated_at_threshold,
    );
}

// ─── Principal store conformance ───

/// Run principal store conformance `scenario` against this backend.
macro_rules! principal_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test]
        async fn $scenario() {
            let backend = setup().await;
            sid_plugin::conformance::principal_store::$scenario(
                &common::principal_conformance::ProfilePrincipals(&backend),
            )
            .await;
        }
    )*};
}

mod principal_store {
    use super::*;

    principal_store!(
        held_principal_resolves_its_owner,
        unknown_principal_resolves_nobody,
        other_type_resolves_nobody,
        other_key_revision_resolves_nobody,
        released_principal_resolves_nobody,
    );
}

mod credential_store {
    use super::*;

    credential_store!(
        revoke_keeps_last_primary,
        credential_deletion,
        single_active_password,
        replace_credential_data_is_compare_and_swap,
        mark_used_only_when_active,
        create_never_replaces,
        label_only_on_active,
        change_password_is_compare_and_swap,
        reseal_keeps_status,
        replace_password_swaps_only_password,
        replace_recovery_codes_swaps_only_the_set,
        policy_evidence_roundtrip,
        enroll_stores_factor_with_codes,
        history_is_empty_until_written,
        history_rotation_is_published_by_its_commit,
        history_descriptor_conflict_writes_nothing,
        history_commit_is_compare_and_swap,
        history_retains_depth,
        history_of_another_owner_is_refused,
        history_write_cutoff_fences_commits,
        history_write_cutoff_races_a_commit,
        user_handle_is_created_once,
        concurrent_enrollments_agree_on_one_handle,
        user_handle_resolves_only_at_its_rp,
        user_handle_is_unique_per_rp,
        user_handle_needs_an_owner,
    );
}

#[tokio::test]
async fn test_write_cutoff_only_rises() {
    common::history_keys::test_write_cutoff_only_rises(&setup().await.history_keys()).await;
}

// ─── History evaluator's key store ───

#[tokio::test]
async fn test_first_epoch_never_resets_a_history() {
    common::history_keys::test_first_epoch_never_resets_a_history(&setup().await.history_keys())
        .await;
}

#[tokio::test]
async fn test_epoch_is_ensured_once() {
    common::history_keys::test_epoch_is_ensured_once(&setup().await.history_keys()).await;
}

#[tokio::test]
async fn test_owner_domains_are_separate() {
    common::history_keys::test_owner_domains_are_separate(&setup().await.history_keys()).await;
}

#[tokio::test]
async fn test_epoch_rotation() {
    common::history_keys::test_epoch_rotation(&setup().await.history_keys()).await;
}

#[tokio::test]
async fn test_lifecycle_follows_the_live_set() {
    common::history_keys::test_lifecycle_follows_the_live_set(&setup().await.history_keys()).await;
}

#[tokio::test]
async fn test_stale_live_set_cannot_retire() {
    common::history_keys::test_stale_live_set_cannot_retire(&setup().await.history_keys()).await;
}

#[tokio::test]
async fn test_key_archive_round_trip() {
    common::history_keys::test_key_archive_round_trip(&setup().await.history_keys()).await;
}

#[tokio::test]
async fn test_abandoned_enrollment_is_reclaimed() {
    common::history_keys::test_abandoned_enrollment_is_reclaimed(&setup().await.history_keys())
        .await;
}

#[tokio::test]
async fn test_cleanup_races_preparation() {
    common::history_keys::test_cleanup_races_preparation(&setup().await.history_keys()).await;
}

#[tokio::test]
async fn test_abandoned_fences_are_compacted() {
    common::history_keys::test_abandoned_fences_are_compacted(&setup().await.history_keys()).await;
}

#[tokio::test]
async fn test_purged_owner_keeps_nothing() {
    common::history_keys::test_purged_owner_keeps_nothing(&setup().await.history_keys()).await;
}

#[tokio::test]
async fn test_history_key_versions_are_insert_only() {
    common::history_keys::test_history_key_versions_are_insert_only(&setup().await.history_keys())
        .await;
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

// ─── User directory query ───

/// Seed plain profiles until `backend` holds at least `n`, in one
/// transaction and without audit: a scenario that needs only their number
/// does not pay for ten thousand audited writes. Every field but the id is
/// that of a new profile.
async fn seed_profiles(backend: &SqliteBackend, n: u64) {
    use sid_plugin::storage::StorageBackend;
    let shortfall = n.saturating_sub(backend.count_profiles().await.unwrap());
    let like = sid_core::models::Profile::new(None::<String>);
    // The store's own timestamp form (RFC 3339, microseconds, `Z`).
    let at = like
        .created_at
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let mut tx = backend.pool().begin().await.unwrap();
    for _ in 0..shortfall {
        sqlx::query(
            "INSERT INTO profiles (
                id, profile_type, roles, status, visibility, max_assurance,
                migration_pending, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(uuid::Uuid::now_v7().to_string())
        .bind(like.profile_type.as_str())
        .bind(like.roles.join(" "))
        .bind(like.status.as_str())
        .bind(like.visibility.as_str())
        .bind(like.max_assurance.as_str())
        .bind(like.migration_pending)
        .bind(&at)
        .bind(&at)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn test_directory_finds_a_user_beyond_ten_thousand() {
    let backend = setup().await;
    seed_profiles(&backend, common::directory_query::DIRECTORY_BEYOND).await;
    common::directory_query::test_directory_finds_a_user_beyond_ten_thousand(&backend).await;
}

#[tokio::test]
async fn test_directory_filters_before_pagination() {
    common::directory_query::test_directory_filters_before_pagination(&setup().await).await;
}

#[tokio::test]
async fn test_directory_comparison_semantics() {
    common::directory_query::test_directory_comparison_semantics(&setup().await).await;
}

#[tokio::test]
async fn test_directory_users_carry_their_attributes() {
    common::directory_query::test_directory_users_carry_their_attributes(&setup().await).await;
}

#[tokio::test]
async fn test_directory_omits_retired_profiles() {
    common::directory_query::test_directory_omits_retired_profiles(&setup().await).await;
}

#[tokio::test]
async fn test_directory_folds_unicode_case() {
    common::directory_query::test_directory_folds_unicode_case(&setup().await).await;
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
async fn test_ending_a_session_ends_what_it_authenticated() {
    common::browser_session::test_ending_a_session_ends_what_it_authenticated(&setup().await).await;
}

// ─── Client and resource registry conformance ───

/// Run registry conformance `scenario` against this backend.
macro_rules! client_registry {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test]
        async fn $scenario() {
            let backend = setup().await;
            sid_plugin::conformance::client_registry::$scenario(
                &common::registry_conformance::AdminRegistry(&backend),
            )
            .await;
        }
    )*};
}

mod client_registry {
    use super::*;

    client_registry!(
        client_found_by_id,
        resource_found_by_id_and_indicator,
        retired_resource_still_found,
        resource_access_exact,
    );
}

// ─── Grant store conformance ───

/// Run grant store conformance `scenario` against this backend.
macro_rules! grant_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test]
        async fn $scenario() {
            let backend = setup().await;
            sid_plugin::conformance::grant_store::$scenario(
                &common::grant_conformance::ProfileGrants(&backend),
            )
            .await;
        }
    )*};
}

mod grant_store {
    use super::*;

    grant_store!(
        session_create_never_replaces,
        session_end,
        session_end_ends_what_it_authenticated,
        session_end_takes_refresh_tokens,
        session_limit_evicts_oldest,
        session_found_by_browser_secret,
        touch_session_keeps_latest_activity,
        auth_code_roundtrip,
        auth_code_redeem_once,
        auth_code_concurrent_redeem,
        refresh_token_roundtrip,
        rotate_refresh_token,
        rotate_after_sign_out_is_refused,
        concurrent_rotation,
    );
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
async fn test_instance_organization_and_clients() {
    common::organization::test_instance_organization_and_clients(&setup().await).await;
}

#[tokio::test]
async fn test_enrollment_policy_stored_and_replaced() {
    common::enrollment_policy::test_enrollment_policy_stored_and_replaced(&setup().await).await;
}

#[tokio::test]
async fn test_registration_admitted_by_the_stored_policy() {
    common::enrollment_policy::test_registration_admitted_by_the_stored_policy(&setup().await)
        .await;
}

#[tokio::test]
async fn test_kept_mode_and_domains_enforced() {
    common::enrollment_policy::test_kept_mode_and_domains_enforced(&setup().await).await;
}

#[tokio::test]
async fn test_admission_records_its_source() {
    common::enrollment_policy::test_admission_records_its_source(&setup().await).await;
}

#[tokio::test]
async fn test_invite_spent_once_by_concurrent_registrations() {
    let backend = setup().await;
    let log = sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone());
    common::enrollment_policy::test_invite_spent_once_by_concurrent_registrations(&backend, &log)
        .await;
}

#[tokio::test]
async fn test_enrollment_policy_keeps_invite_range() {
    common::enrollment_policy::test_enrollment_policy_keeps_invite_range(&setup().await).await;
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
async fn test_central_management_refuses_local_claims() {
    common::admin_claim::test_central_management_refuses_local_claims(&setup().await).await;
}

#[tokio::test]
async fn test_claimed_installation_stays_self_managed() {
    common::admin_claim::test_claimed_installation_stays_self_managed(&setup().await).await;
}

#[tokio::test]
async fn test_adoption_races_claim() {
    common::admin_claim::test_adoption_races_claim(&setup().await).await;
}

#[tokio::test]
async fn test_last_administrator_cannot_request_closure() {
    common::admin_claim::test_last_administrator_cannot_request_closure(&setup().await).await;
}

// ─── Issuer store conformance ───

/// Run issuer store conformance `scenario`, each on a fresh database: the
/// installation organization has exactly one local issuer.
macro_rules! issuer_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test]
        async fn $scenario() {
            let backend = setup().await;
            sid_plugin::conformance::issuer_store::$scenario(
                &common::issuer_conformance::InstanceIssuers(&backend),
            )
            .await;
        }
    )*};
}

mod issuer_store {
    use super::*;

    issuer_store!(
        issuer_provisioned_once,
        foreign_first_key_refused,
        unknown_handle_names_nothing,
        unknown_organization_refused,
    );
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
async fn test_list_credentials_by_type_pages() {
    common::test_list_credentials_by_type_pages(&setup().await).await;
}

#[tokio::test]
async fn test_oauth2_client_not_found() {
    common::test_oauth2_client_not_found(&setup().await).await;
}

// ─── Durable work ───

/// Run work store conformance `scenario` against this backend.
macro_rules! work_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test]
        async fn $scenario() {
            sid_plugin::conformance::work_store::$scenario(&setup().await).await;
        }
    )*};
}

mod work_store {
    use super::*;

    work_store!(
        enqueue_is_idempotent,
        concurrent_enqueue_stores_once,
        capacity_is_enforced_per_kind,
        capacity_holds_under_concurrency,
        ended_work_is_purged,
        live_lease_is_exclusive,
        lease_fences_stale_worker,
        retries_then_fails,
        dead_letter_alert_commits_with_failure,
        expired_and_future_are_not_claimed,
        abandoned_last_attempt_fails,
        concurrent_claims_do_not_overlap,
        export_import_round_trip,
    );
}

#[tokio::test]
async fn test_session_end_owes_client_logout() {
    common::work::test_session_end_owes_client_logout(&setup().await).await;
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

#[tokio::test]
async fn test_sign_in_routes_only_the_holder() {
    common::principal_assignment::test_sign_in_routes_only_the_holder(&setup().await).await;
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
async fn test_terminal_abort_races_the_commit() {
    common::operation::test_terminal_abort_races_the_commit(&setup().await).await;
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
