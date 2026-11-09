// SPDX-License-Identifier: AGPL-3.0-only
//! The storage conformance scenarios against SID's CoordiNode backend, over
//! a CoordiNode database in memory.
//!
//! Run with: cargo nextest run -p sid-storage --features storage-coordinode --test coordinode_integration
#![cfg(feature = "storage-coordinode")]

use std::sync::Arc;

use sid_storage::coordinode::CoordinodeBackend;

async fn setup() -> CoordinodeBackend {
    store().await.0
}

/// A fresh backend with the host's handle on its database.
async fn store() -> harness::Store {
    let db = Arc::new(coordinode_embed::Database::open_in_memory().expect("CoordiNode in memory"));
    let backend = CoordinodeBackend::new(db.clone())
        .await
        .expect("SID's schema in CoordiNode");
    harness::Store(backend, db)
}

// The complete storage contract, one test per scenario.
sid_plugin::storage_conformance!(setup);

/// The capability harnesses over this backend: registration goes through
/// the administrative application API, owners are Profiles.
mod harness {
    use async_trait::async_trait;
    use chrono::{SubsecRound, Utc};
    use sid_core::models::{
        Application, ApplicationId, IssuerId, OAuth2Client, OrgId, Principal,
        PrincipalAssignmentFence, PrincipalType, ProfileId, ProjectId, ProtectedResource,
        ResourceAccess, ResourceId,
    };
    use sid_plugin::SignInHistoryStore;
    use sid_plugin::conformance::backend::application::{
        grant_resource, instance_issuer, store_client,
    };
    use sid_plugin::conformance::backend::{
        create_test_profile, create_test_session, instance_org, test_audit,
    };
    use sid_plugin::conformance::client_registry::RegistryHarness;
    use sid_plugin::conformance::credential_store::CredentialHarness;
    use sid_plugin::conformance::sign_in_history::SignInHistoryHarness;
    use std::sync::Arc;

    use sid_plugin::conformance::grant_store::{
        AssignmentHarness, GrantHarness, LoginPolicyHarness, OwnerStatusHarness,
    };
    use sid_plugin::conformance::issuer_store::IssuerHarness;
    use sid_plugin::{
        ClientResourceRegistry, CredentialStore, GrantStore, IssuerStore, StorageBackend,
    };
    use sid_storage::coordinode::CoordinodeBackend;

    /// The backend and the host's handle on the database it is in.
    pub struct Store(pub CoordinodeBackend, pub Arc<coordinode_embed::Database>);

    #[async_trait]
    impl LoginPolicyHarness for Store {
        async fn advance_login_policy(&self) -> i64 {
            // A host's policy write: its own transaction on the database,
            // committing the epoch with whatever the host wrote.
            let (backend, db) = (self.0.clone(), self.1.clone());
            tokio::task::spawn_blocking(move || {
                // A host runs its write again when a concurrent commit
                // conflicts with it, as every CoordiNode writer does.
                for _ in 0..64 {
                    let tx = db.begin_transaction().expect("a host transaction");
                    let epoch = match backend.advance_login_policy_epoch_in(tx) {
                        Ok(epoch) => epoch,
                        Err(_) => {
                            db.rollback_transaction(tx).ok();
                            continue;
                        }
                    };
                    match db.commit_transaction(tx) {
                        Ok(_) => return epoch,
                        Err(
                            coordinode_embed::DatabaseError::TransactionConflict { .. }
                            | coordinode_embed::DatabaseError::RevisionMismatch { .. },
                        ) => continue,
                        Err(e) => panic!("the policy write failed: {e}"),
                    }
                }
                panic!("the policy write kept conflicting")
            })
            .await
            .expect("the host's write")
        }
    }

    #[async_trait]
    impl GrantHarness for Store {
        type Owner = ProfileId;

        fn store(&self) -> &dyn GrantStore<Owner = ProfileId> {
            &self.0
        }

        fn credentials(&self) -> &dyn CredentialStore<Owner = ProfileId> {
            &self.0
        }

        async fn owner(&self) -> ProfileId {
            let profile = create_test_profile("grant");
            self.0
                .create_profile(&profile, test_audit())
                .await
                .expect("a test profile");
            profile.id
        }

        async fn resource(&self) -> ResourceId {
            grant_resource(&self.0).await
        }
    }

    #[async_trait]
    impl OwnerStatusHarness for Store {
        async fn suspend(&self, owner: &ProfileId) {
            let mut profile = self
                .0
                .get_profile(*owner)
                .await
                .unwrap()
                .expect("the owner's profile");
            profile.status = sid_core::models::ProfileStatus::Suspended;
            assert!(
                self.0.update_profile(&profile, test_audit()).await.unwrap(),
                "the suspension applies"
            );
        }
    }

    #[async_trait]
    impl AssignmentHarness for Store {
        async fn assign(&self, owner: &ProfileId) -> PrincipalAssignmentFence {
            let principal = Principal::new_federated_subject(
                *owner,
                "https://central.sid.example.com/i/c",
                &uuid::Uuid::now_v7().to_string(),
            );
            self.0
                .save_principal(&principal, test_audit())
                .await
                .expect("the assignment");
            let stored = self
                .0
                .get_principal_by_value(PrincipalType::FederatedSubject, &principal.value)
                .await
                .unwrap()
                .expect("the stored principal");
            PrincipalAssignmentFence::of(&stored).expect("assigned to its owner")
        }

        async fn release(&self, fence: &PrincipalAssignmentFence) {
            assert!(
                self.0
                    .unbind_principal(fence.principal, fence.profile, test_audit())
                    .await
                    .unwrap(),
                "the release applies"
            );
        }
    }

    #[async_trait]
    impl CredentialHarness for Store {
        type Owner = ProfileId;

        fn store(&self) -> &dyn CredentialStore<Owner = ProfileId> {
            &self.0
        }

        async fn owner(&self) -> ProfileId {
            let profile = create_test_profile("credential");
            self.0
                .create_profile(&profile, test_audit())
                .await
                .expect("a test profile");
            profile.id
        }

        fn missing_owner(&self) -> ProfileId {
            ProfileId::generate()
        }
    }

    #[async_trait]
    impl SignInHistoryHarness for Store {
        type Owner = ProfileId;

        fn store(&self) -> &dyn SignInHistoryStore<Owner = ProfileId> {
            &self.0
        }

        async fn owner(&self) -> ProfileId {
            let profile = create_test_profile("sign_in");
            self.0
                .create_profile(&profile, test_audit())
                .await
                .expect("a test profile");
            profile.id
        }

        async fn sign_in(
            &self,
            owner: &ProfileId,
            ip: Option<std::net::IpAddr>,
            device: Option<uuid::Uuid>,
        ) {
            let mut session = create_test_session(*owner);
            session.ip_address = ip;
            session.device_id = device;
            self.0
                .create_session_atomic(&session, 0, None, test_audit())
                .await
                .expect("a stored session");
        }

        async fn begin_sign_in(
            &self,
            owner: &ProfileId,
            ip: std::net::IpAddr,
            device: Option<uuid::Uuid>,
        ) {
            let mut pending = sid_core::models::Session::new_awaiting_second_factor(
                *owner,
                Some(ip),
                sid_core::models::AuthLevel::Basic,
                vec!["pwd".into()],
            );
            pending.device_id = device;
            self.0
                .create_session_atomic(&pending, 0, None, test_audit())
                .await
                .expect("a stored pending context");
        }
    }

    #[async_trait]
    impl IssuerHarness for Store {
        fn store(&self) -> &dyn IssuerStore {
            &self.0
        }

        async fn organization(&self) -> OrgId {
            instance_org(&self.0).await
        }
    }

    fn application(id: ApplicationId, name: &str) -> Application {
        let now = Utc::now().trunc_subsecs(3);
        Application {
            id,
            project_id: ProjectId::SYSTEM,
            name: name.to_owned(),
            system: None,
            revision: 0,
            created_at: now,
            updated_at: now,
        }
    }

    #[async_trait]
    impl RegistryHarness for Store {
        fn registry(&self) -> &dyn ClientResourceRegistry {
            &self.0
        }

        async fn issuer(&self) -> IssuerId {
            instance_issuer(&self.0).await
        }

        async fn other_issuer(&self) -> IssuerId {
            IssuerId::generate()
        }

        async fn organization(&self) -> OrgId {
            instance_org(&self.0).await
        }

        async fn register_client(&self, client: &OAuth2Client) {
            assert!(client.default_resource.is_none());
            store_client(&self.0, client, test_audit()).await.unwrap();
        }

        async fn register_resource(&self, resource: &ProtectedResource) {
            let app_id = resource
                .application_id
                .expect("a registered resource names its application");
            self.0
                .create_application(
                    &application(app_id, "Conformance resource"),
                    None,
                    Some(resource),
                    test_audit(),
                )
                .await
                .unwrap();
        }

        async fn grant_access(&self, access: &ResourceAccess) {
            self.0
                .set_resource_access(access, test_audit())
                .await
                .unwrap();
        }

        async fn set_default_resource(&self, client: &str, resource: ResourceId) {
            let mut stored = self
                .0
                .get_oauth2_client(client)
                .await
                .unwrap()
                .expect("a registered client");
            stored.default_resource = Some(resource);
            assert!(
                self.0
                    .update_oauth2_client(&stored, test_audit())
                    .await
                    .unwrap()
            );
        }

        async fn retire_resource(&self, resource: ResourceId) {
            let app_id = self
                .0
                .get_protected_resource(resource)
                .await
                .unwrap()
                .and_then(|r| r.application_id)
                .expect("an active resource with its application");
            assert!(
                self.0
                    .delete_application(app_id, test_audit())
                    .await
                    .unwrap()
            );
        }
    }
}

/// Run capability conformance `scenario` of `$module` on a fresh store.
macro_rules! capability {
    ($module:ident: $($scenario:ident),* $(,)?) => {
        mod $module {
            use super::*;
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn $scenario() {
                    sid_plugin::conformance::$module::$scenario(&store().await).await;
                }
            )*
        }
    };
}

capability!(grant_store:
    session_refused_once_its_owner_is_suspended,
    a_pending_context_takes_no_session_slot,
    a_pending_context_evicts_no_session,
    a_pending_context_completes_once,
    a_login_policy_fence_is_never_ignored,
    session_commits_only_under_the_current_login_policy,
    auth_code_commits_only_under_the_current_login_policy,
    a_policy_write_serializes_with_its_sessions,
    an_assignment_proof_is_never_ignored,
    a_session_commits_only_under_its_current_assignment,
    session_refused_after_its_password_changed,
    session_fence_is_the_owners_credential,
    session_fence_serializes_with_a_reset,
    session_fence_serializes_with_a_revocation,
    session_create_never_replaces,
    session_end,
    sessions_listed_per_owner,
    session_end_ends_what_it_authenticated,
    session_end_takes_refresh_tokens,
    session_limit_evicts_oldest,
    session_found_by_browser_secret,
    touch_session_keeps_latest_activity,
    auth_code_roundtrip,
    auth_code_needs_its_authorizing_session,
    auth_code_redeem_once,
    auth_code_concurrent_redeem,
    refresh_token_roundtrip,
    rotate_refresh_token,
    rotate_after_sign_out_is_refused,
    concurrent_rotation,
    native_generation_names_its_credentials,
    native_generation_commits_with_its_session,
    native_generation_rotates_once,
    native_redelivery_ends_with_its_window,
    concurrent_native_rotation,
    native_generations_end_with_their_session,
    session_grants_move_as_stored,
);

capability!(client_registry:
    client_found_by_id,
    resource_found_by_id_and_indicator,
    retired_resource_still_found,
    resource_access_exact,
);

capability!(credential_store:
    revoke_keeps_last_primary,
    credential_deletion,
    single_active_password,
    replace_credential_data_is_compare_and_swap,
    mark_used_only_when_active,
    create_never_replaces,
    label_only_on_active,
    spend_commits_with_its_mutation,
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

capability!(sign_in_history:
    most_recent_session_is_the_latest,
    a_session_without_an_address_is_no_location,
    an_ipv6_address_keeps_its_width,
    seen_address_and_device_are_per_account,
    an_unfinished_sign_in_is_no_history,
    location_is_designated_at_threshold,
);

capability!(issuer_store:
    issuer_provisioned_once,
    foreign_first_key_refused,
    unknown_handle_names_nothing,
    unknown_organization_refused,
    issuer_restored_as_stored,
    issuer_restore_never_replaces,
);

/// Run work store conformance `scenario` against this backend.
macro_rules! work_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test(flavor = "multi_thread")]
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
        work_of_a_kind_is_reported,
        live_lease_is_exclusive,
        lease_fences_stale_worker,
        retries_then_fails,
        dead_letter_alert_commits_with_failure,
        expired_and_future_are_not_claimed,
        abandoned_last_attempt_fails,
        concurrent_claims_do_not_overlap,
        export_import_round_trip,
        completion_commits_with_follow_up_work,
        stale_completion_owes_nothing,
        completion_refused_for_capacity_owes_nothing,
        concurrent_completions_hold_capacity,
    );
}

/// Run operation result conformance `scenario`; each one uses namespaces of
/// its own.
macro_rules! operation_result_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test(flavor = "multi_thread")]
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
        a_result_is_kept_no_longer_than_its_retention,
        operation_periods_bound_admission,
        a_keyed_creation_binds_one_identifier,
        a_bound_key_completes_only_its_own_command,
        a_binding_lives_with_its_completion,
        bindings_travel_between_stores,
        an_oversized_result_is_refused,
    );

    /// A store of its own with a period capacity of 8.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_full_period_refuses_new_completions() {
        let harness::Store(backend, db) = store().await;
        tokio::task::spawn_blocking(move || {
            db.execute_cypher_shared(
                "MATCH (s:SidOperationState) WHERE s.id = 1 SET s.capacity = 8",
                None,
                None,
                None,
                None,
            )
            .expect("a host write");
        })
        .await
        .unwrap();
        sid_plugin::conformance::operation_result_store::a_full_period_refuses_new_completions(
            &backend,
        )
        .await;
    }
}

/// Run ceremony state conformance `scenario`; each one uses namespaces of
/// its own.
macro_rules! ceremony_state {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test(flavor = "multi_thread")]
        async fn $scenario() {
            sid_plugin::conformance::ceremony_state::$scenario(&setup().await).await;
        }
    )*};
}

mod ceremony_state {
    use super::*;

    ceremony_state!(
        state_is_taken_once,
        concurrent_takers_get_it_once,
        expired_state_is_refused_at_use,
        put_replaces,
        replace_applies_only_to_what_was_read,
        concurrent_replacements_apply_once,
        key_is_admitted_once,
        concurrent_admissions_succeed_once,
        records_move_with_their_deadlines,
        events_count_within_their_window,
        concurrent_events_are_counted_once,
        counts_are_read_and_cleared,
        admission_is_confirmed_only_to_its_holder,
        concurrent_holders_admit_once,
    );
}

/// Run instance secret conformance `scenario` against a fresh store.
macro_rules! instance_secret_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test(flavor = "multi_thread")]
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

/// The race `operation_periods_bound_admission` runs once, many times over:
/// commits under a period racing its retirement are each refused or dropped
/// with it, never left behind. CoordiNode checks only writes and pinned reads
/// at commit, so this is the race its snapshot isolation could lose.
#[tokio::test(flavor = "multi_thread")]
async fn commits_racing_retirement_are_never_left_behind() {
    use chrono::{Duration, Utc};
    use sid_core::models::{
        AuditEntry, MutationContext, OperationCompletion, OperationKey, OperationPeriodRefusal,
    };
    use sid_plugin::OperationResultStore;

    let store = setup().await;
    let t0 = Utc::now() - Duration::days(30);
    for round in 0..16 {
        let at = t0 + Duration::hours(2 * round);
        let period = store
            .current_operation_period(at, Duration::hours(1))
            .await
            .unwrap();
        let ns = format!("race:{round}");
        let keys: Vec<OperationKey> = (0..4)
            .map(|_| OperationKey::parse(&uuid::Uuid::new_v4().to_string()).unwrap())
            .collect();
        let commit = |key: &OperationKey| {
            store.record_outcome(
                MutationContext::from(AuditEntry::system("race", "operation_result"))
                    .with_operation(
                        OperationCompletion::new(&ns, key.clone(), "keyed", b"in", vec![])
                            .in_period(period.period),
                    ),
            )
        };
        let (commits, retired) = tokio::join!(
            futures::future::join_all(keys.iter().map(commit)),
            store.retire_operation_periods(period.accepted_until + Duration::milliseconds(1)),
        );
        assert!(retired.unwrap() >= 1);
        for result in commits {
            if let Err(e) = result {
                assert!(
                    matches!(
                        e,
                        sid_core::Error::OperationPeriodRefused(OperationPeriodRefusal::Retired)
                    ),
                    "{e:?}"
                );
            }
        }
        for key in &keys {
            assert!(
                store
                    .get_operation_result(&ns, key)
                    .await
                    .unwrap()
                    .is_none(),
                "round {round}: a completion outlived its retired period"
            );
        }
        assert!(
            !store
                .export_operation_results()
                .await
                .unwrap()
                .iter()
                .any(|r| r.completion.namespace == ns),
            "round {round}: exported under a retired period"
        );
    }
}

/// Run history key store conformance `scenario` on a database of its own, so
/// store-wide state (the write cutoff, fence compaction) is its own.
macro_rules! history_key_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test(flavor = "multi_thread")]
        async fn $scenario() {
            sid_plugin::conformance::history_key_store::$scenario(&setup().await.history_keys())
                .await;
        }
    )*};
}

mod history_key_store {
    use super::*;

    history_key_store!(
        write_cutoff_only_rises,
        first_epoch_never_resets_a_history,
        epoch_is_ensured_once,
        ensures_of_a_known_owner_agree,
        owner_domains_are_separate,
        epoch_rotation,
        lifecycle_follows_the_live_set,
        stale_live_set_cannot_retire,
        key_archive_round_trip,
        key_records_round_trip,
        abandoned_enrollment_is_reclaimed,
        cleanup_races_preparation,
        abandoned_fences_are_compacted,
        purged_owner_keeps_nothing,
        key_versions_are_insert_only,
    );
}

/// The principal store harness the SQL backends use: owners are Profiles.
mod common {
    pub use sid_plugin::conformance::backend::*;

    #[path = "../common/principal_conformance.rs"]
    pub mod principal_conformance;
}

/// Run principal store conformance `scenario` against this backend.
macro_rules! principal_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test(flavor = "multi_thread")]
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

/// Regression: a store whose operation period state was written before the
/// policy held its bounds opened, then failed every keyed commit. It is
/// refused at opening.
#[tokio::test(flavor = "multi_thread")]
async fn opening_refuses_operation_state_of_an_earlier_schema() {
    let db = Arc::new(coordinode_embed::Database::open_in_memory().expect("CoordiNode in memory"));
    let host = db.clone();
    tokio::task::spawn_blocking(move || {
        host.execute_cypher_shared(
            "CREATE (s:SidOperationState {id: 1, issued_through: 0, acceptance_seconds: 3600,
                retention_seconds: 86400})",
            None,
            None,
            None,
            None,
        )
        .expect("a host write");
    })
    .await
    .unwrap();
    let refused = CoordinodeBackend::new(db).await;
    assert!(
        matches!(refused, Err(sid_core::Error::Storage(_))),
        "an earlier operation state was taken"
    );
}

/// A store holding records that break a constraint SID relies on (written
/// past SID, here two profiles with one username) is refused at opening:
/// SID never serves without the uniqueness its writers rely on.
#[tokio::test(flavor = "multi_thread")]
async fn opening_refuses_a_store_that_cannot_hold_the_schema() {
    let db = Arc::new(coordinode_embed::Database::open_in_memory().expect("CoordiNode in memory"));
    let host = db.clone();
    tokio::task::spawn_blocking(move || {
        for _ in 0..2 {
            host.execute_cypher_shared(
                "CREATE (p:SidProfile {id: 'twin', username: 'twin'})",
                None,
                None,
                None,
                None,
            )
            .expect("a host write");
        }
    })
    .await
    .unwrap();
    let refused = CoordinodeBackend::new(db).await;
    assert!(
        matches!(refused, Err(sid_core::Error::Storage(_))),
        "the store was served without its constraints: {:?}",
        refused.err()
    );
}

/// What the store owes across a restart and across the host's backup and
/// restore, on databases kept in files.
mod recovery {
    use sid_plugin::conformance::backend::{backup, namespace, restart};

    use super::*;

    async fn open(
        path: std::path::PathBuf,
    ) -> (CoordinodeBackend, Arc<coordinode_embed::Database>) {
        let db = tokio::task::spawn_blocking(move || coordinode_embed::Database::open(path))
            .await
            .expect("the opening")
            .expect("CoordiNode in a directory");
        let db = Arc::new(db);
        let backend = CoordinodeBackend::new(db.clone())
            .await
            .expect("SID's schema in CoordiNode");
        (backend, db)
    }

    /// The process that committed is gone: its database closes and opens
    /// again from its files.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_commit_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        restart::test_commit_survives_restart(|| {
            let path = path.clone();
            async move { open(path).await.0 }
        })
        .await;
    }

    /// The host's own procedure: a binary export of one snapshot, restored
    /// into a new database that SID then opens.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_restore_returns_the_backed_up_state() {
        let (live_dir, restored_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (live, db) = open(live_dir.path().to_path_buf()).await;
        let restored_path = restored_dir.path().to_path_buf();
        backup::test_restore_returns_the_backed_up_state(
            &live,
            &live,
            || async move {
                tokio::task::spawn_blocking(move || {
                    let snapshot = db.engine().snapshot();
                    let mut dump = Vec::new();
                    coordinode_embed::backup::export::export_binary(
                        db.engine(),
                        &db.interner().expect("the field dictionary"),
                        1,
                        &snapshot,
                        &mut dump,
                    )
                    .expect("the backup");
                    dump
                })
                .await
                .expect("the backup task")
            },
            |dump: Vec<u8>| async move {
                let target = restored_path.clone();
                tokio::task::spawn_blocking(move || {
                    let db = coordinode_embed::Database::open(target).expect("a new database");
                    db.restore(
                        coordinode_embed::backup::BackupFormat::Binary,
                        &dump,
                        &coordinode_embed::backup::restore::RestoreOptions::default(),
                    )
                    .expect("the restore");
                })
                .await
                .expect("the restore task");
                let (restored, _) = open(restored_path).await;
                (restored.clone(), restored)
            },
        )
        .await;
    }

    /// Two installations, each in a database of its own. Native namespaces
    /// inside one CoordiNode database, and their refusal of another
    /// installation's account, wait for the database to provide them.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_instances_are_isolated() {
        let (a, b) = (store().await, store().await);
        namespace::test_instances_are_isolated(&a.0, &b.0).await;
    }
}

/// Two instances of SID on one host database, as two processes sharing it.
async fn two_instances() -> (CoordinodeBackend, CoordinodeBackend) {
    let db = Arc::new(coordinode_embed::Database::open_in_memory().expect("CoordiNode in memory"));
    let a = CoordinodeBackend::new(db.clone())
        .await
        .expect("first instance");
    let b = CoordinodeBackend::new(db).await.expect("second instance");
    (a, b)
}

mod job_lock {
    use super::*;
    use sid_plugin::conformance::backend::job_lock;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_job_lock_exclusive_across_instances() {
        let (a, b) = two_instances().await;
        job_lock::test_job_lock_exclusive_across_instances(&a, &b).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dropped_job_lock_is_freed() {
        let (a, b) = two_instances().await;
        job_lock::test_dropped_job_lock_is_freed(&a, &b).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_job_locks_are_per_job() {
        let (a, b) = two_instances().await;
        job_lock::test_job_locks_are_per_job(&a, &b).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_job_lock_taken_once() {
        let (a, b) = two_instances().await;
        job_lock::test_concurrent_job_lock_taken_once(&a, &b).await;
    }
}

mod audit_retention {
    use std::collections::HashMap;

    use coordinode_core::graph::types::Value;
    use sid_core::models::audit::AuditRecord;
    use sid_plugin::conformance::backend::audit_retention;

    use super::*;

    /// Store `r` as it stands, as the backend keeps a record, in a host
    /// transaction: no operation records the past.
    async fn insert(db: Arc<coordinode_embed::Database>, r: AuditRecord) {
        tokio::task::spawn_blocking(move || {
            let id = uuid::Uuid::parse_str(&r.id).expect("record id");
            let params: HashMap<String, Value> = [
                ("id", Value::Binary(id.as_bytes().to_vec())),
                ("at", Value::Int(r.timestamp.timestamp_micros())),
                ("chain", Value::String(r.chain_id.clone())),
                ("sequence", Value::Int(i64::try_from(r.sequence).unwrap())),
                ("actor_id", Value::String(r.actor_id.clone())),
                ("actor_type", Value::String(r.actor_type.to_string())),
                ("action", Value::String(r.action.clone())),
                ("resource", Value::String(r.resource.clone())),
                ("outcome", Value::String(r.outcome.to_string())),
                (
                    "metadata",
                    Value::Document(rmpv::ext::to_value(&r.metadata).expect("metadata")),
                ),
                ("ip", Value::Null),
                ("device_id", Value::Null),
                ("prev_hash", Value::String(r.prev_hash.clone())),
                ("hash", Value::String(r.hash.clone())),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
            let tx = db.begin_transaction().expect("a host transaction");
            db.execute_in_transaction(
                tx,
                "CREATE (r:SidAuditRecord {id: $id, at: $at, chain: $chain, sequence: $sequence,
                    actor_id: $actor_id, actor_type: $actor_type, action: $action,
                    resource: $resource, outcome: $outcome, metadata: $metadata, ip: $ip,
                    device_id: $device_id, prev_hash: $prev_hash, hash: $hash})",
                Some(params),
            )
            .expect("the record is written");
            db.commit_transaction(tx).expect("the record commits");
        })
        .await
        .expect("the host's write");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_audit_retention_keeps_chains_verifiable() {
        let store = store().await;
        let db = store.1.clone();
        audit_retention::test_audit_retention_keeps_chains_verifiable(&store.0, &store.0, |r| {
            insert(db.clone(), r)
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_audit_actor_types_round_trip() {
        audit_retention::test_audit_actor_types_round_trip(&setup().await).await;
    }
}

mod audit_chain {
    use super::*;
    use sid_plugin::conformance::backend;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_audit_chain_links_records() {
        backend::audit_chain::test_audit_chain_links_records(&setup().await).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_audit_chains_are_independent() {
        backend::audit_chain::test_audit_chains_are_independent(&setup().await).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_audit_chain_moves_as_stored() {
        backend::audit_chain::test_audit_chain_moves_as_stored(&setup().await).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_audit_chain_concurrent_appends() {
        backend::test_audit_chain_concurrent_appends(Arc::new(setup().await)).await;
    }
}
