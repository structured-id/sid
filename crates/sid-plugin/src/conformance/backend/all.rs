// SPDX-License-Identifier: AGPL-3.0-only
//! One entry point to the complete storage contract: a harness names a function
//! that builds its backend and gets one test per scenario, each on a backend of
//! its own.
//!
//! ```ignore
//! async fn setup() -> MyBackend { /* a new store */ }
//! sid_plugin::storage_conformance!(setup);
//! ```
//!
//! Scenarios that need more than a backend (several instances, an audit log, a
//! way to age a row, ten thousand seeded profiles) take that from the harness
//! and are run by it.

/// One test per scenario of `$module`.
#[doc(hidden)]
#[macro_export]
macro_rules! __storage_scenarios {
    ($setup:ident, $module:ident: $($scenario:ident)*) => {
        mod $module {
            $(
                #[tokio::test]
                async fn $scenario() {
                    $crate::conformance::backend::$module::$scenario(&super::$setup().await).await;
                }
            )*
        }
    };
}

/// One test per scenario of the storage contract; see the [module](self).
#[macro_export]
macro_rules! storage_conformance {
    ($setup:ident) => {
        mod storage_contract {
            use super::$setup;

            mod shared {
                $crate::__storage_shared_scenarios!(super::super::$setup);
            }

            $crate::__storage_scenarios!($setup, admin_claim:
                test_last_administrator_cannot_request_closure
                test_last_administrator_assignment_is_kept
                test_closing_administrator_is_not_counted
                test_registration_claims_instance
                test_central_management_refuses_local_claims
                test_claimed_installation_stays_self_managed
                test_adoption_races_claim
                test_admin_claim_consumed_once
            );
            $crate::__storage_scenarios!($setup, application:
                test_application_roles_are_stored_together
                test_concurrent_indicator_registration
                test_system_integration_exists_once
                test_application_update_and_list
                test_resource_update_and_retirement
                test_resource_access
                test_machine_user_resource_access
                test_resource_listing_and_import
                test_client_default_resource
            );
            $crate::__storage_scenarios!($setup, branding:
                test_branding_draft_write_contract
                test_branding_publish_contract
                test_branding_concurrent_publish
            );
            $crate::__storage_scenarios!($setup, browser_session:
                test_ending_a_session_ends_what_it_authenticated
            );
            $crate::__storage_scenarios!($setup, cleanup:
                test_delete_outbound_dlq_entry
                test_cleanup_expired_device_auth_codes
                test_delete_expired_magic_link_sessions
                test_delete_expired_reset_sessions
            );
            $crate::__storage_scenarios!($setup, config:
                test_flow_configs
                test_email_provider_config
            );
            $crate::__storage_scenarios!($setup, consent:
                test_create_consent_never_replaces
                test_change_claim_grant
                test_claim_grant_keeps_ended_consent_ended
                test_claim_grants_under_concurrency
            );
            $crate::__storage_scenarios!($setup, device:
                test_create_device_never_replaces
                test_rename_device_keeps_trust
                test_device_trust_changes
                test_device_trust_limit_under_concurrency
                test_device_by_fingerprint
            );
            $crate::__storage_scenarios!($setup, device_auth:
                test_device_auth_create_and_get
                test_device_auth_decided_once
                test_device_poll_interval
                test_device_code_redeemed_once
            );
            $crate::__storage_scenarios!($setup, directory:
                test_directory_user_create_stores_everything
                test_directory_user_create_taken_login_writes_nothing
                test_directory_user_concurrent_create_single_winner
                test_directory_user_update_applies_every_change
                test_directory_user_update_missing_writes_nothing
                test_directory_user_deprovision_ends_access
                test_directory_group_writes
            );
            $crate::__storage_scenarios!($setup, directory_query:
                test_directory_filters_before_pagination
                test_directory_comparison_semantics
                test_directory_folds_unicode_case
                test_directory_users_carry_their_attributes
                test_directory_omits_retired_profiles
            );
            $crate::__storage_scenarios!($setup, email_policy:
                test_email_key_written_only_under_the_active_revision
            );
            $crate::__storage_scenarios!($setup, enrollment_policy:
                test_kept_mode_and_domains_enforced
                test_registration_admitted_by_the_stored_policy
                test_admission_records_its_source
                test_invite_creator_and_redemptions
                test_enrollment_policy_stored_and_replaced
                test_enrollment_policy_keeps_invite_range
            );
            $crate::__storage_scenarios!($setup, export_job:
                test_export_job_roundtrip
                test_export_job_status_transitions
                test_export_job_commits_owed_work
            );
            $crate::__storage_scenarios!($setup, flow_action:
                test_flow_actions_listed_by_point_in_order
                test_flow_action_write_contract
            );
            $crate::__storage_scenarios!($setup, group:
                test_create_group_never_replaces
                test_group_membership_roundtrip
                test_add_to_group_never_duplicates
                test_set_group_description_keeps_deleted_deleted
            );
            $crate::__storage_scenarios!($setup, machine:
                test_create_machine_user_never_replaces
                test_update_machine_user_keeps_status
                test_transition_machine_user_is_compare_and_swap
                test_add_machine_credential_never_replaces
                test_add_machine_credential_limit_under_concurrency
                test_rotate_machine_credential
                test_revoke_machine_credential_is_scoped
                test_cascade_revokes_grace_period_credentials
                test_machine_users_by_client_and_project
                test_machine_credentials_listing_and_expiry
                test_impersonation_grants
            );
            $crate::__storage_scenarios!($setup, operation:
                test_operation_completion_commits_with_effect
                test_completed_operation_commits_nothing
                test_concurrent_duplicate_operation_commits_once
                test_operation_results_travel_between_stores
                test_terminal_abort_races_the_commit
                test_failed_mutation_records_no_completion
            );
            $crate::__storage_scenarios!($setup, organization:
                test_instance_organization_and_clients
            );
            $crate::__storage_scenarios!($setup, principal_assignment:
                test_claim_does_not_change_assignment
                test_claim_with_proof_does_not_transfer
                test_claimant_view_carries_no_proof
                test_login_handle_claim_is_conflict
                test_first_use_assigns_sole_claimant
                test_proof_expiry_keeps_assignment
                test_release_elects_nobody
                test_claimant_leaving_keeps_assignment
                test_sign_in_routes_only_the_holder
                test_profile_by_principal_is_assigned_holder
            );
            $crate::__storage_scenarios!($setup, project:
                test_projects_count_and_listing
                test_oauth2_clients_by_project_paging
            );
            $crate::__storage_scenarios!($setup, provisioning_connector:
                test_create_connector_never_replaces
                test_rename_connector_is_revision_checked
                test_transition_connector
                test_add_credential
                test_rotate_credential
                test_revoke_credential_is_scoped
                test_find_and_list
                test_client_id_and_credential_kind
                test_connector_fence_holds_writes_to_current_authority
                test_connector_fence_races_a_disable
            );
            $crate::__storage_scenarios!($setup, role:
                test_create_role_never_replaces
                test_update_role_is_compare_and_swap
                test_oauth_client_role_assignment
                test_connector_role_assignment
                test_roles_by_project_and_name
                test_role_assignments_by_principal
                test_expiring_role_assignments
                test_cedar_policies_by_scope
                test_administrative_assignment
                test_fenced_assignment
                test_grantor_never_joins_its_group
                test_fenced_role_edit
                test_create_role_assignment_never_replaces
            );
            $crate::__storage_scenarios!($setup, service_binding:
                test_binding_is_stable
                test_bindings_are_pairwise
                test_concurrent_first_use_allocates_once
                test_concurrent_scopes_get_distinct_indexes
                test_binding_import_keeps_identity
                test_binding_import_conflict
                test_binding_needs_profile
            );
            $crate::__storage_scenarios!($setup, session:
                test_create_session_never_replaces
                test_record_authentication_keeps_ended_session_ended
                test_record_authentication_is_compare_and_swap
                test_record_authentication_refuses_expired_session
            );
            $crate::__storage_scenarios!($setup, session_elevation:
                test_session_elevation_roundtrip
                test_session_base_level_refuses_step_up_levels
            );
            $crate::__storage_scenarios!($setup, upstream:
                test_upstream_provider_write_contract
                test_upstream_identity_never_relinked
                test_record_upstream_login_counts_every_login
                test_enabled_providers_and_identities_by_profile
            );
            $crate::__storage_scenarios!($setup, work:
                test_magic_link_consumed_once
                test_session_limit_evicts_oldest
                test_session_end_owes_client_logout
                test_expired_role_assignments_owe_event
                test_mutation_commits_owed_work
            );
        }
    };
}

/// One test per scenario kept directly in [`backend`](super).
#[doc(hidden)]
#[macro_export]
macro_rules! __storage_shared_scenarios {
    ($setup:path) => {
        $crate::__storage_shared_scenarios!(@tests $setup;
            test_profile_create_and_get test_profile_get_by_username test_profile_get_by_email
            test_profile_get_nonexistent test_profile_get_by_email_not_found
            test_profile_get_by_username_not_found test_profile_update test_profile_delete
            test_profile_list test_profile_list_pages_cover_each_profile_once
            test_profile_username_uniqueness test_session_save_and_get test_role_roundtrip
            test_cedar_policy_write_contract test_project_write_contract
            test_profile_grant_write_contract test_ensure_system_project_concurrent
            test_cedar_policy_concurrent_update test_consent_roundtrip
            test_invite_list_pages_cover_each_invite_once test_invite_lifecycle test_invite_search
            test_registration_source_roundtrip test_access_request_decided_once
            test_access_request_approval_grants_the_role test_device_attestation_roundtrip
            test_revoked_key_clears_hardware_attestation test_security_signals_persist
            test_login_history_signals test_integrity_counts_ignore_group_assignments
            test_password_reset_completes_once test_scim_outbound_roundtrip
            test_notification_preferences_roundtrip test_invite_single_use_under_concurrency
            test_session_delete_by_profile test_session_get_nonexistent test_ensure_system_project
            test_cannot_delete_system_project test_oauth2_client_save_and_get
            test_oauth2_client_update test_oauth2_client_settings_roundtrip
            test_oauth2_client_keys_rotate test_oauth2_client_update_keeps_deleted_deleted
            test_oauth2_client_update_is_compare_and_swap test_oauth2_client_create_never_replaces
            test_oauth2_client_concurrent_create test_oauth2_client_full_roundtrip
            test_iat_save_get_list_revoke test_register_dynamic_client
            test_register_dynamic_client_conflict_counts_nothing
            test_register_dynamic_client_concurrent_limit test_closure_request_roundtrip
            test_closure_request_moves_with_profile test_key_version_insert_once
            test_key_version_concurrent_insert test_list_credentials_by_type_pages
            test_oauth2_client_not_found test_refresh_token_save_never_replaces
            test_magic_link_crud test_reset_session_create_never_replaces test_pat_crud
            test_create_pat_never_replaces test_create_pat_active_limit_under_concurrency
            test_record_pat_use_only_when_usable test_pat_listing_and_profile_revocation
            test_revoke_unused_pats test_principal_save_and_get test_principal_list_by_profile
            test_principal_get_profile_by_principal test_principal_delete
            test_principal_username_federated test_principal_source_field_roundtrip
            test_principal_source_contact_fk_roundtrip test_principal_quarantine_roundtrip
            test_principal_get_by_value test_principal_bindings_crud
            test_principal_count_active_bindings test_removing_shared_principal_keeps_other_holder
            test_profile_phone_roundtrip test_profile_email_roundtrip
            test_get_profile_by_email_via_join test_multiple_phones_per_profile
            test_phone_extension test_register_profile_commits_all
            test_register_profile_without_credential test_register_profile_without_username
            test_register_profile_conflict_writes_nothing test_end_legacy_migration_is_one_write
            test_profile_metadata_roundtrip test_delete_profile_grant
            test_profile_lifecycle_scans test_set_primary_profile_email
            test_register_profile_concurrent_single_winner
        );
    };
    (@tests $setup:path; $($scenario:ident)*) => {
        $(
            #[tokio::test]
            async fn $scenario() {
                $crate::conformance::backend::$scenario(&$setup().await).await;
            }
        )*
    };
}
