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

// The scenarios of the storage contract run in sqlite_contract.rs; the tests
// here need more than a backend (its pool, two instances on one file, an
// audit log, a restart).

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
        a_result_is_kept_no_longer_than_its_retention,
        operation_periods_bound_admission,
        a_keyed_creation_binds_one_identifier,
        a_bound_key_completes_only_its_own_command,
        a_binding_lives_with_its_completion,
        bindings_travel_between_stores,
        an_oversized_result_is_refused,
        concurrent_imports_under_one_period_all_land,
    );

    /// A store of its own with a period capacity of 8.
    #[tokio::test]
    async fn a_full_period_refuses_new_completions() {
        let backend = setup().await;
        sqlx::query("UPDATE operation_period_state SET capacity = 8 WHERE id = 1")
            .execute(backend.pool())
            .await
            .unwrap();
        sid_plugin::conformance::operation_result_store::a_full_period_refuses_new_completions(
            &backend,
        )
        .await;
    }
}

// ─── Ceremony state conformance ───

/// Run ceremony state conformance `scenario`; each one uses namespaces of
/// its own.
macro_rules! ceremony_state {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test]
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
        an_unfinished_sign_in_is_no_history,
        a_session_without_an_address_is_no_location,
        an_ipv6_address_keeps_its_width,
    );
}

/// An address column holds 4 or 16 bytes, whatever reaches it.
#[tokio::test]
async fn test_address_columns_hold_one_host() {
    let backend = setup().await;
    let event = |ip: Vec<u8>| {
        sqlx::query(
            "INSERT INTO anomaly_events (id, rule_id, profile_id, ip_address, description,
                 risk_score, reaction, timestamp)
             VALUES (?, 'r', '', ?, '', 0, '', '2026-01-01T00:00:00Z')",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(ip)
        .execute(backend.pool())
    };
    assert!(event(vec![10, 0, 0]).await.is_err(), "3 bytes");
    assert!(event(vec![0; 5]).await.is_err(), "5 bytes");
    event(vec![10, 0, 0, 1]).await.expect("IPv4");
    event(vec![0; 16]).await.expect("IPv6");
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
}

// ─── History evaluator's key store ───

/// Run history key store conformance `scenario` against a database of its
/// own, so store-wide state (the write cutoff, fence compaction) is its own.
macro_rules! history_key_store {
    ($($scenario:ident),* $(,)?) => {$(
        #[tokio::test]
        async fn $scenario() {
            sid_plugin::conformance::history_key_store::$scenario(&setup().await.history_keys())
                .await;
        }
    )*};
}

history_key_store!(
    write_cutoff_only_rises,
    first_epoch_never_resets_a_history,
    epoch_is_ensured_once,
    ensures_of_a_known_owner_agree,
    owner_domains_are_separate,
    epoch_rotation,
    window_selects_without_retiring,
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
        .bind(uuid::Uuid::now_v7())
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
                &common::grant_conformance::ProfileGrants::sqlite(&backend),
            )
            .await;
        }
    )*};
}

mod grant_store {
    use super::*;

    grant_store!(
        session_refused_once_its_owner_is_suspended,
        a_pending_context_takes_no_session_slot,
        a_pending_context_evicts_no_session,
        a_pending_context_completes_once,
        session_commits_only_under_the_current_login_policy,
        auth_code_commits_only_under_the_current_login_policy,
        a_policy_write_serializes_with_its_sessions,
        a_login_policy_fence_is_never_ignored,
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
                .bind(r.ip_address.map(|ip| match ip {
                    std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                    std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
                }))
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

#[tokio::test]
async fn test_invite_spent_once_by_concurrent_registrations() {
    let backend = setup().await;
    let log = sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone());
    common::enrollment_policy::test_invite_spent_once_by_concurrent_registrations(&backend, &log)
        .await;
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
        issuer_restored_as_stored,
        issuer_restore_never_replaces,
    );
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
        concurrent_enqueues_of_a_kind_are_all_stored,
        claim_carries_creation_and_due_times,
        ended_work_is_purged,
        work_of_a_kind_is_reported,
        live_lease_is_exclusive,
        lease_fences_stale_worker,
        retries_then_fails,
        dead_letter_alert_commits_with_failure,
        expired_and_future_are_not_claimed,
        abandoned_last_attempt_fails,
        concurrent_claims_do_not_overlap,
        a_kind_named_twice_claims_each_item_once,
        export_import_round_trip,
        completion_commits_with_follow_up_work,
        stale_completion_owes_nothing,
        completion_owing_a_stored_child_keeps_it,
        concurrent_completions_owing_work_all_commit,
    );
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

/// While `holder` keeps the file's write lock past `ttl`, `write` on `waiter`
/// waits for it; its outcome, evaluated once it holds the lock.
async fn after_a_held_lock<T>(
    holder: &SqliteBackend,
    ttl: std::time::Duration,
    write: impl std::future::Future<Output = T>,
) -> T {
    let held = holder.pool().begin_with("BEGIN IMMEDIATE").await.unwrap();
    let release = async {
        tokio::time::sleep(ttl * 3).await;
        held.commit().await.unwrap();
    };
    let (outcome, ()) = tokio::join!(write, release);
    outcome
}

/// A ceremony state that expires while its replacement waits for another
/// process's write lock is not replaced: its expiry is read when the write
/// holds the lock, not when it was asked for.
#[tokio::test]
async fn test_ceremony_state_expiring_behind_a_lock_is_not_replaced() {
    use sid_plugin::CeremonyStateStore;
    let (_dir, a, b) = two_instances().await;
    let ttl = std::time::Duration::from_millis(300);
    a.put_ceremony_state("lock", "k", b"v1", ttl).await.unwrap();
    let replaced = after_a_held_lock(
        &a,
        ttl,
        b.replace_ceremony_state("lock", "k", b"v1", b"v2", ttl),
    )
    .await
    .unwrap();
    assert!(!replaced, "an expired state was advanced");
}

/// Likewise a count whose window ends while the event waits for the lock
/// opens a new window instead of adding to the ended one.
#[tokio::test]
async fn test_ceremony_count_window_ending_behind_a_lock_restarts() {
    use sid_plugin::CeremonyStateStore;
    let (_dir, a, b) = two_instances().await;
    let window = std::time::Duration::from_millis(300);
    a.count_in_window("lock", "k", window).await.unwrap();
    let count = after_a_held_lock(&a, window, b.count_in_window("lock", "k", window))
        .await
        .unwrap();
    assert_eq!(count, 1, "an ended window was added to");
}

#[tokio::test]
async fn test_commit_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = format!("sqlite://{}", dir.path().join("sid.db").display());
    let open = || async { SqliteBackend::new(&path).await.unwrap() };
    common::restart::test_commit_survives_restart(open).await;
}

/// On SQLite an instance's namespace is its own database file. The file is
/// separated by the host's file access, not by an account inside SQLite, so
/// SQLite qualifies the engine-level isolation and offers no native
/// namespace refusal.
#[tokio::test]
async fn test_instances_are_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let open = |name: &str| {
        let path = format!("sqlite://{}", dir.path().join(name).display());
        async move { SqliteBackend::new(&path).await.unwrap() }
    };
    let (a, b) = (open("a.db").await, open("b.db").await);
    common::namespace::test_instances_are_isolated(&a, &b).await;
}

/// SQLite's online copy, `VACUUM INTO`, is the backup; the restore opens a
/// store on the copied file.
#[tokio::test]
async fn test_restore_returns_the_backed_up_state() {
    let dir = tempfile::tempdir().unwrap();
    let live_path = dir.path().join("sid.db");
    let copy = dir.path().join("backup.db");
    let live = SqliteBackend::new(&format!("sqlite://{}", live_path.display()))
        .await
        .unwrap();
    let log = sid_storage::sqlite::SqliteAuditLog::new(live.pool().clone());
    let pool = live.pool().clone();
    common::backup::test_restore_returns_the_backed_up_state(
        &live,
        &log,
        || async {
            sqlx::query("VACUUM INTO ?")
                .bind(copy.display().to_string())
                .execute(&pool)
                .await
                .unwrap();
            copy.clone()
        },
        |copy: std::path::PathBuf| async move {
            let restored = SqliteBackend::new(&format!("sqlite://{}", copy.display()))
                .await
                .unwrap();
            let log = sid_storage::sqlite::SqliteAuditLog::new(restored.pool().clone());
            (restored, log)
        },
    )
    .await;
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

#[tokio::test(flavor = "multi_thread")]
async fn test_concurrent_job_lock_taken_once() {
    let (_dir, a, b) = two_instances().await;
    common::job_lock::test_concurrent_job_lock_taken_once(&a, &b).await;
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

// ─── Audit chain, notification preferences, profiles ───

#[tokio::test]
async fn test_audit_chain_links_records() {
    let backend = setup().await;
    let log = sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone());
    common::audit_chain::test_audit_chain_links_records(&log).await;
}

#[tokio::test]
async fn test_audit_chains_are_independent() {
    let backend = setup().await;
    let log = sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone());
    common::audit_chain::test_audit_chains_are_independent(&log).await;
}

#[tokio::test]
async fn test_audit_chain_moves_as_stored() {
    let backend = setup().await;
    let log = sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone());
    common::audit_chain::test_audit_chain_moves_as_stored(&log).await;
}

#[tokio::test]
async fn test_mutations_leave_their_audit_chain() {
    let backend = setup().await;
    let log = sid_storage::sqlite::SqliteAuditLog::new(backend.pool().clone());
    common::audit_chain::test_mutations_leave_their_audit_chain(&backend, &log).await;
}

#[tokio::test]
async fn test_notification_preferences_round_trip() {
    common::notification::test_notification_preferences_round_trip(&setup().await).await;
}

#[tokio::test]
async fn test_notification_preferences_replace() {
    common::notification::test_notification_preferences_replace(&setup().await).await;
}

#[tokio::test]
async fn test_profile_without_username_round_trip() {
    common::test_profile_without_username_round_trip(&setup().await).await;
}

// ─── Email policy revisions ───

/// Keys written under a revision that is no longer active are kept,
/// quarantined with a recorded reason, and can be repaired.
#[tokio::test]
async fn test_stale_email_keys_are_quarantined_and_reconciled() {
    use common::email_policy::{STALE_REVISION, stale_rows};
    use sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION;
    use sid_plugin::storage::StorageBackend;

    let backend = SqliteBackend::new_in_memory().await.unwrap();
    let domain = "stale.sid.example.com";
    let activate = |revision: i64| {
        sqlx::query("UPDATE email_policy_activations SET revision = ? WHERE scope = 'installation'")
            .bind(revision)
    };
    activate(STALE_REVISION)
        .execute(backend.pool())
        .await
        .unwrap();
    let mut stale = Vec::new();
    for row in stale_rows(domain) {
        let profile = common::create_test_profile("stale");
        backend
            .create_profile(&profile, common::test_audit())
            .await
            .unwrap();
        let contact_id = match &row.contact {
            Some(address) => Some(stale_contact(&backend, profile.id, address).await),
            None => None,
        };
        let principal_id = uuid::Uuid::now_v7();
        sqlx::query(
            "INSERT INTO principals (id, principal_type, value, verified, verified_at,
                 assigned_profile_id, assignment_revision, email_policy_revision)
             VALUES (?, 'email', ?, ?, CASE WHEN ? THEN '2026-01-01T00:00:00Z' END, ?, 1, ?)",
        )
        .bind(principal_id)
        .bind(&row.key)
        .bind(row.verified)
        .bind(row.verified)
        .bind(profile.id)
        .bind(STALE_REVISION)
        .execute(backend.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO principal_bindings (id, principal_id, profile_id, is_primary,
                 source_field, source_email_id)
             VALUES (?, ?, ?, 1, 'email', ?)",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(principal_id)
        .bind(profile.id)
        .bind(contact_id)
        .execute(backend.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO email_policy_dispositions
                 (principal_id, from_revision, to_revision, disposition, reason)
             VALUES (?, ?, ?, 'quarantined', 'no_source_evidence')",
        )
        .bind(principal_id)
        .bind(STALE_REVISION)
        .bind(INSTALLATION_EMAIL_POLICY_REVISION)
        .execute(backend.pool())
        .await
        .unwrap();
        stale.push((row.key, profile.id));
    }
    activate(INSTALLATION_EMAIL_POLICY_REVISION)
        .execute(backend.pool())
        .await
        .unwrap();

    common::email_policy::stale_keys_are_quarantined(&backend, &stale, domain).await;
    common::email_policy::stale_keys_are_reconciled(&backend, &stale).await;
    let migrated: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_policy_dispositions WHERE disposition = 'migrated'",
    )
    .fetch_one(backend.pool())
    .await
    .unwrap();
    assert_eq!(migrated, 2, "the repaired key and the race winner");
}

/// A contact row of a stale key.
async fn stale_contact(
    backend: &SqliteBackend,
    profile: sid_core::models::ProfileId,
    address: &str,
) -> uuid::Uuid {
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
    contact.id.0
}
