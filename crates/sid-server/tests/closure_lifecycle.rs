// SPDX-License-Identifier: AGPL-3.0-only
//! Account closure actually executes (GDPR Art. 17) on PostgreSQL.
//!
//! A closure request moves a profile to a closing state; nothing used to act
//! on it afterwards, so personal data was never deleted. These tests pin the
//! lifecycle job: due closures execute, pending and legally held ones wait,
//! and a closed profile is purged only when its principal quarantine is over.

use std::sync::Arc;

use chrono::{Duration, Utc};
use sid_authn::account_closure::AccountClosureService;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_core::models::{
    AuditEntry, ClosureMode, LegalHold, Principal, Profile, ProfileId, ProfileStatus, Session,
};
use sid_plugin::StorageBackend;
use sid_server::background_tasks::{execute_due_closures, purge_closed_profiles};

async fn setup() -> (Arc<dyn StorageBackend>, AccountClosureService, sqlx::PgPool) {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string());
    let backend = sid_storage::PostgresBackend::new(&url, None)
        .await
        .expect("PostgreSQL on port 54399 (docker-compose.test.yml)");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");
    let pool = backend.pool().clone();
    let storage: Arc<dyn StorageBackend> = Arc::new(backend);
    let cascade = Arc::new(RevocationCascadeService::new(
        storage.clone(),
        Arc::new(RevocationCache::new(
            std::time::Duration::from_secs(900),
            Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        )),
    ));
    let closures = AccountClosureService::new(storage.clone(), cascade);
    (storage, closures, pool)
}

/// An active profile with an email principal and a live session, whose
/// closure has been requested; returns it with its email.
async fn closing_profile(
    storage: &Arc<dyn StorageBackend>,
    closures: &AccountClosureService,
) -> (ProfileId, String, Session) {
    let tag = uuid::Uuid::now_v7().simple().to_string();
    let profile = Profile::new(Some(&format!("closing-{tag}")));
    storage
        .create_profile(&profile, AuditEntry::system("test", "p").into())
        .await
        .unwrap();
    let email = format!("closing-{tag}@sid.example.com");
    storage
        .save_principal(
            &Principal::new_email(profile.id, &email),
            AuditEntry::system("test", "e").into(),
        )
        .await
        .unwrap();
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        Utc::now() + Duration::hours(1),
    );
    storage
        .create_session(&session, AuditEntry::system("test", "s").into())
        .await
        .unwrap();
    closures
        .request_closure(profile.id, ClosureMode::Voluntary, profile.id)
        .await
        .unwrap();
    (profile.id, email, session)
}

/// Move the profile's grace period end to `end`, as time passing would; no
/// operation moves it, so the harness writes the column.
async fn set_grace_end(pool: &sqlx::PgPool, pid: ProfileId, end: chrono::DateTime<Utc>) {
    let moved =
        sqlx::query("UPDATE closure_requests SET grace_period_end = $2 WHERE profile_id = $1")
            .bind(pid)
            .bind(end)
            .execute(pool)
            .await
            .unwrap();
    assert_eq!(moved.rows_affected(), 1);
}

async fn status(storage: &Arc<dyn StorageBackend>, pid: ProfileId) -> ProfileStatus {
    storage.get_profile(pid).await.unwrap().unwrap().status
}

/// A closure whose grace period has ended is executed: the profile is
/// closed, its sessions end, its login handles are removed.
#[tokio::test]
async fn due_closure_is_executed() {
    let (storage, closures, pool) = setup().await;
    let (pid, email, session) = closing_profile(&storage, &closures).await;
    set_grace_end(&pool, pid, Utc::now() - Duration::minutes(1)).await;

    execute_due_closures(storage.as_ref(), &closures).await;

    assert_eq!(status(&storage, pid).await, ProfileStatus::Closed);
    assert!(storage.get_session(session.id).await.unwrap().is_none());
    assert!(
        storage
            .get_principals_by_profile(pid)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .get_profile_by_principal(sid_core::models::PrincipalType::Email, &email)
            .await
            .unwrap()
            .is_none()
    );
}

/// A closure still inside its grace period, or frozen by a legal hold, waits.
#[tokio::test]
async fn pending_or_held_closure_waits() {
    let (storage, closures, pool) = setup().await;
    let (pending, _, _) = closing_profile(&storage, &closures).await;
    let (held, _, _) = closing_profile(&storage, &closures).await;
    // The hold is placed before the grace period ends: other tests run the
    // executor concurrently against the same database.
    // No CE operation places a hold, so the harness writes the column.
    let hold = LegalHold {
        court_reference: "case-1".into(),
        reason: None,
        placed_at: Utc::now(),
        expected_end: None,
        placed_by: held,
        reviewing_counsel: None,
        previous_status: ProfileStatus::ClosureRequested,
    };
    sqlx::query("UPDATE closure_requests SET legal_hold = $2 WHERE profile_id = $1")
        .bind(held)
        .bind(serde_json::to_value(&hold).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        storage
            .get_closure_request(held)
            .await
            .unwrap()
            .unwrap()
            .legal_hold
            .is_some(),
        "legal hold must be stored"
    );
    set_grace_end(&pool, held, Utc::now() - Duration::minutes(1)).await;

    execute_due_closures(storage.as_ref(), &closures).await;

    assert_eq!(
        status(&storage, pending).await,
        ProfileStatus::ClosureRequested
    );
    assert_eq!(
        status(&storage, held).await,
        ProfileStatus::ClosureRequested
    );
}

/// A closure stored as Closed whose erasure stopped part-way (the process
/// died after the status was stored) is finished by the next run: no closed
/// account keeps its login handles or sessions.
#[tokio::test]
async fn interrupted_erasure_is_finished() {
    let (storage, closures, _) = setup().await;
    let (pid, email, session) = closing_profile(&storage, &closures).await;
    let mut closed = storage.get_profile(pid).await.unwrap().unwrap();
    closed.status = ProfileStatus::Closed;
    assert!(
        storage
            .update_profile(&closed, AuditEntry::system("test", "closed").into())
            .await
            .unwrap()
    );
    assert!(closures.erasure_pending(pid).await.unwrap());

    execute_due_closures(storage.as_ref(), &closures).await;

    assert!(!closures.erasure_pending(pid).await.unwrap());
    assert!(storage.get_session(session.id).await.unwrap().is_none());
    assert!(
        storage
            .get_profile_by_principal(sid_core::models::PrincipalType::Email, &email)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(status(&storage, pid).await, ProfileStatus::Closed);
}

/// Two replicas executing the same due closure at once both succeed: the one
/// that loses the race finds the profile Closed and finishes its erasure,
/// rather than failing a closure that took place.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_execution_of_one_closure_succeeds() {
    let (storage, closures, pool) = setup().await;
    let closures = std::sync::Arc::new(closures);
    for _ in 0..8 {
        let (pid, _, session) = closing_profile(&storage, &closures).await;
        set_grace_end(&pool, pid, Utc::now() - Duration::minutes(1)).await;

        let runs: Vec<_> = (0..2)
            .map(|_| {
                let closures = closures.clone();
                tokio::spawn(async move { closures.execute_closure(pid).await })
            })
            .collect();
        for run in runs {
            run.await.unwrap().unwrap();
        }

        assert_eq!(status(&storage, pid).await, ProfileStatus::Closed);
        assert!(!closures.erasure_pending(pid).await.unwrap());
        assert!(storage.get_session(session.id).await.unwrap().is_none());
    }
}

/// Once a closure has executed it cannot be cancelled: the account stays
/// Closed instead of reopening without its data.
#[tokio::test]
async fn executed_closure_cannot_be_cancelled() {
    let (storage, closures, pool) = setup().await;
    let (pid, _, _) = closing_profile(&storage, &closures).await;
    set_grace_end(&pool, pid, Utc::now() - Duration::minutes(1)).await;
    closures.execute_closure(pid).await.unwrap();

    let err = closures.cancel_closure(pid, pid).await.unwrap_err();
    assert!(matches!(err, sid_core::Error::InvalidState(_)), "{err:?}");
    assert_eq!(status(&storage, pid).await, ProfileStatus::Closed);
}

/// Each cancellation counts: a new request keeps the count of the ones
/// before it, so the yearly limit on cancel/re-request cycles holds.
#[tokio::test]
async fn cancel_limit_survives_new_requests() {
    let (storage, closures, _) = setup().await;
    let (pid, _, _) = closing_profile(&storage, &closures).await;
    for cycle in 0..sid_core::models::MAX_CANCEL_CYCLES_PER_YEAR {
        if cycle > 0 {
            closures
                .request_closure(pid, ClosureMode::Voluntary, pid)
                .await
                .unwrap();
        }
        closures.cancel_closure(pid, pid).await.unwrap();
    }
    assert_eq!(
        storage
            .get_closure_request(pid)
            .await
            .unwrap()
            .unwrap()
            .cancel_count,
        sid_core::models::MAX_CANCEL_CYCLES_PER_YEAR
    );
    let err = closures
        .request_closure(pid, ClosureMode::Voluntary, pid)
        .await
        .expect_err("a request past the cancel limit");
    assert!(matches!(err, sid_core::Error::RateLimited(_)), "{err:?}");
    assert_eq!(status(&storage, pid).await, ProfileStatus::Active);
}

/// A closed profile is purged only once its principal quarantine is over,
/// and its purge owes the destruction of its password-history keys.
#[tokio::test]
async fn closed_profile_is_purged_at_quarantine_end() {
    let (storage, closures, pool) = setup().await;
    // The installation's authority, as the shared database may already hold.
    storage
        .insert_instance_organization(
            &sid_core::models::Organization::implicit_community("sid.example.com"),
            AuditEntry::system("test", "org").into(),
        )
        .await
        .unwrap();
    let org = storage.instance_organization().await.unwrap().unwrap();
    let (recent, _, _) = closing_profile(&storage, &closures).await;
    let (old, _, _) = closing_profile(&storage, &closures).await;
    set_grace_end(&pool, recent, Utc::now() - Duration::minutes(1)).await;
    set_grace_end(&pool, old, Utc::now() - Duration::minutes(1)).await;
    execute_due_closures(storage.as_ref(), &closures).await;
    set_grace_end(&pool, old, Utc::now() - Duration::days(91)).await;

    purge_closed_profiles(storage.as_ref()).await;

    assert_eq!(status(&storage, recent).await, ProfileStatus::Closed);
    assert_eq!(status(&storage, old).await, ProfileStatus::Purged);
    let purge_of = |profile| {
        sid_core::models::OwnerPurge {
            owner_domain: sid_authn::password_history::owner_domain(org.id.as_bytes(), profile),
        }
        .work()
        .id
    };
    assert!(
        storage.get_work(purge_of(old)).await.unwrap().is_some(),
        "the purged owner's history keys are owed their destruction"
    );
    assert!(storage.get_work(purge_of(recent)).await.unwrap().is_none());
}
