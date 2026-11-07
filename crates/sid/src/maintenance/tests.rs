use super::*;
use chrono::Duration as Days;

fn make_profile(migration_pending: bool, started_days_ago: Option<i64>) -> Profile {
    let now = Utc::now();
    Profile {
        id: ProfileId::generate(),
        profile_type: sid_core::models::ProfileType::Personal,
        username: Some("test".to_string()),
        given_name: Some("Test".to_string()),
        family_name: Some("User".to_string()),
        middle_name: None,
        honorific_prefix: None,
        honorific_suffix: None,
        roles: vec![],
        status: ProfileStatus::Active,
        visibility: sid_core::models::ProfileVisibility::Private,
        max_assurance: sid_core::models::ProfileAssurance::Anonymous,
        manager_id: None,
        migration_pending,
        migration_started_at: started_days_ago.map(|d| now - Days::days(d)),
        migration_completed_at: None,
        revision: 0,
        created_at: now - Days::days(started_days_ago.unwrap_or(0)),
        updated_at: now,
    }
}

#[test]
fn test_is_migration_expired_within_deadline() {
    let profile = make_profile(true, Some(30));
    assert!(!is_migration_expired(&profile, 180, Utc::now()));
}

#[test]
fn test_is_migration_expired_past_deadline() {
    let profile = make_profile(true, Some(200));
    assert!(is_migration_expired(&profile, 180, Utc::now()));
}

#[test]
fn test_is_migration_expired_exactly_at_deadline() {
    let profile = make_profile(true, Some(180));
    assert!(is_migration_expired(&profile, 180, Utc::now()));
}

#[test]
fn test_is_migration_expired_uses_created_at_fallback() {
    // No migration_started_at: counted from created_at.
    let mut profile = make_profile(true, None);
    profile.migration_started_at = None;
    profile.created_at = Utc::now() - Days::days(200);
    assert!(is_migration_expired(&profile, 180, Utc::now()));
}

#[test]
fn test_is_migration_expired_created_recently() {
    let mut profile = make_profile(true, None);
    profile.migration_started_at = None;
    profile.created_at = Utc::now() - Days::days(10);
    assert!(!is_migration_expired(&profile, 180, Utc::now()));
}

#[test]
fn test_default_deadline_days_constant() {
    assert_eq!(DEFAULT_MIGRATION_DEADLINE_DAYS, 180);
}

/// Unset retention is a year, archived: records are kept until an archive
/// holds them.
#[test]
fn audit_retention_defaults_to_a_year_archived() {
    assert_eq!(
        AuditRetention::default(),
        AuditRetention {
            days: 365,
            action: RetentionAction::Archive
        }
    );
}

/// The periodic purge removes ceremony state and admissions past their
/// deadline and keeps live ones: database deadlines reclaim nothing by
/// themselves, so without it every proof and code leaves a row forever.
#[tokio::test]
async fn ceremony_state_purge_removes_only_expired_entries() {
    use sid_plugin::{CeremonyStateStore, InProcessCeremonyState, SingleUseAdmissions};
    let store = InProcessCeremonyState::new();
    let brief = std::time::Duration::from_millis(5);
    let long = std::time::Duration::from_secs(600);
    store
        .put_ceremony_state("ns", "lapsed", b"v", brief)
        .await
        .unwrap();
    store.admit_once("ns", "lapsed-jti", brief).await.unwrap();
    store
        .put_ceremony_state("ns", "live", b"v", long)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    assert_eq!(purge_ceremony_state(&store).await, 2);
    assert_eq!(
        store.read_ceremony_state("ns", "live").await.unwrap(),
        Some(b"v".to_vec())
    );
    assert_eq!(purge_ceremony_state(&store).await, 0);
}

/// The same alert gets the same id, so a repeated hourly scan relays an
/// expiry once; another alert gets another id.
#[test]
fn credential_alert_ids_follow_the_alert() {
    assert_eq!(
        credential_alert_id("expired:kid_a"),
        credential_alert_id("expired:kid_a")
    );
    assert_ne!(
        credential_alert_id("expired:kid_a"),
        credential_alert_id("expiring:kid_a:3")
    );
}

/// A job lock records whether it was freed.
struct Held(Arc<std::sync::atomic::AtomicBool>);

#[async_trait::async_trait]
impl sid_plugin::storage::JobLockHolder for Held {
    async fn release(self: Box<Self>) -> sid_core::Result<()> {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// A lock that arrives after a drain began frees itself without starting the
/// run, so a drain waiting on a pooled connection does not prolong shutdown
/// by a whole job; before a drain the run goes ahead and frees the lock.
#[tokio::test]
async fn a_lock_taken_after_a_drain_starts_no_run() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let runs = Arc::new(AtomicUsize::new(0));
    let counted = runs.clone();
    let job = Job::exclusive(
        "late_lock",
        std::time::Duration::from_secs(60),
        FirstRun::AtStart,
        9_002,
        Arc::new(move || {
            let counted = counted.clone();
            Box::pin(async move {
                counted.fetch_add(1, Ordering::SeqCst);
            })
        }),
    );
    let (drain, stop) = watch::channel(false);

    let freed = Arc::new(AtomicBool::new(false));
    run_held(
        &job,
        sid_plugin::storage::JobLock::new(Held(freed.clone())),
        &stop,
    )
    .await;
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    assert!(freed.load(Ordering::SeqCst));

    drain.send(true).unwrap();
    let freed = Arc::new(AtomicBool::new(false));
    run_held(
        &job,
        sid_plugin::storage::JobLock::new(Held(freed.clone())),
        &stop,
    )
    .await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "a run started after the drain"
    );
    assert!(freed.load(Ordering::SeqCst), "the late lock stayed held");
}

/// Deleting a profile owes its history keys' purge in the deletion's
/// transaction, under the profile's domain in this installation.
#[tokio::test]
async fn a_profile_deletion_owes_its_purge() {
    use sid_core::models::{AuditEntry, MutationContext, Organization, WorkState};
    use sid_plugin::WorkStore;
    let storage = sid_storage::sqlite::SqliteBackend::new_in_memory()
        .await
        .unwrap();
    let org = Organization::implicit_community("sid.example.com");
    storage
        .insert_instance_organization(&org, AuditEntry::system("test", "org").into())
        .await
        .unwrap();
    let profile = Profile::new(Some("purged-owner"));
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();

    let purge = owner_purge(&storage, profile.id)
        .await
        .unwrap()
        .expect("an installation with an authority owes the purge");
    let expected = OwnerPurge {
        owner_domain: sid_authn::password_history::owner_domain(org.id.as_bytes(), profile.id),
    }
    .work();
    assert_eq!(purge.id, expected.id);
    storage
        .delete_profile(
            profile.id,
            MutationContext::from(AuditEntry::system("test", "delete")).with_work(purge.clone()),
        )
        .await
        .unwrap();
    let owed = storage.get_work(purge.id).await.unwrap().unwrap();
    assert_eq!(owed.state, WorkState::Pending);
}

/// Before the installation has an authority there is no history domain, so
/// no key, and nothing is owed.
#[tokio::test]
async fn nothing_is_owed_without_an_authority() {
    let storage = sid_storage::sqlite::SqliteBackend::new_in_memory()
        .await
        .unwrap();
    assert!(
        owner_purge(&storage, ProfileId::generate())
            .await
            .unwrap()
            .is_none()
    );
}
