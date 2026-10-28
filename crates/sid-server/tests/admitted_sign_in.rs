// SPDX-License-Identifier: AGPL-3.0-only
//! A sign-in on a trusted issuer's accepted evidence, on PostgreSQL (54399,
//! `DATABASE_URL`): it completes as every sign-in does, under the sign-in
//! rules and the security policy weighing the attested authentication, and
//! the browser gets the IdP session cookie. The session records the
//! attested methods and authentication time, never a local method.

mod common;

use std::sync::Arc;

use chrono::{Duration, Utc};
use sid_core::models::session::{AcceptedEvidence, AuthLevel, ELEVATION_TTL_MINUTES};
use sid_core::models::{AuditEntry, EnrollmentMode, Profile, SecurityPolicy};
use sid_plugin::storage::StorageBackend;

/// The application each sign-in continues to.
const CLIENT: &str = "an-application";

async fn storage() -> Arc<dyn StorageBackend> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sid:sid_dev@localhost:54399/sid".to_string());
    let backend = sid_storage::PostgresBackend::new(&url, None)
        .await
        .expect("PostgreSQL on port 54399 (docker-compose.test.yml)");
    sid_storage::migrator::run_migrations(backend.pool(), None)
        .await
        .expect("migrations");
    Arc::new(backend)
}

/// The authority over `storage` under a policy requiring `min_acr`.
fn authority(
    storage: Arc<dyn StorageBackend>,
    min_acr: AuthLevel,
) -> Arc<sid_server::grpc::auth_service::AuthServiceImpl> {
    let mut policy = SecurityPolicy::ce_default();
    policy.auth.min_acr = min_acr;
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    common::auth_service_over(storage, cache, Some(policy), Some(EnrollmentMode::Open))
}

async fn profile(storage: &dyn StorageBackend) -> Profile {
    let profile = Profile::new(Some(&format!(
        "admitted{}",
        &uuid::Uuid::now_v7().simple().to_string()[16..]
    )));
    storage
        .create_profile(
            &profile,
            AuditEntry::system("profile.create", profile.id.to_string()).into(),
        )
        .await
        .unwrap();
    profile
}

fn evidence(acr: &str, amr: &[&str], age: Duration) -> AcceptedEvidence {
    AcceptedEvidence::new(
        Some(acr),
        amr.iter().map(|m| (*m).to_owned()).collect(),
        Utc::now() - age,
    )
}

// Evidence meeting the policy signs the Profile in: the browser gets the IdP
// session cookie and no token, and the stored session carries the attested
// level, methods and authentication time.
#[tokio::test]
async fn sufficient_evidence_signs_in_with_the_cookie() {
    let storage = storage().await;
    let auth = authority(storage.clone(), AuthLevel::Standard);
    let profile = profile(storage.as_ref()).await;
    let accepted = evidence(
        "urn:sid:acr:standard",
        &["pwd", "otp"],
        Duration::minutes(2),
    );
    let authentication = accepted.authentication(Utc::now()).unwrap();

    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("user-agent", "test-agent".parse().unwrap());
    let signed_in = auth
        .complete_admitted_sign_in(&request, &profile, &authentication, CLIENT, None)
        .await
        .unwrap();
    let sid_authn::sign_in_delivery::Delivery::Cookie(cookie) = &signed_in.delivery else {
        panic!("the browser gets its cookie");
    };
    assert!(cookie.starts_with("__Host-sid_session="), "{cookie}");

    let sessions = storage.list_sessions(&profile.id).await.unwrap();
    let session = sessions
        .iter()
        .find(|s| s.id.to_string() == signed_in.session_id)
        .expect("the session is stored");
    assert_eq!(session.assurance_level, AuthLevel::Standard);
    assert_eq!(session.amr, ["pwd", "otp"]);
    assert_eq!(
        session.authenticated_at.timestamp(),
        accepted.auth_time.timestamp()
    );
}

// Regression guard: evidence short of the policy is refused as a local
// sign-in short of it would be, and stores no session; one-factor evidence
// does not pass as MFA.
#[tokio::test]
async fn insufficient_evidence_is_refused() {
    let storage = storage().await;
    let auth = authority(storage.clone(), AuthLevel::Standard);
    let profile = profile(storage.as_ref()).await;
    let authentication = evidence("urn:sid:acr:basic", &["pwd"], Duration::minutes(1))
        .authentication(Utc::now())
        .unwrap();
    let refused = auth
        .complete_admitted_sign_in(
            &tonic::Request::new(()),
            &profile,
            &authentication,
            CLIENT,
            None,
        )
        .await
        .err()
        .expect("refused");
    assert_eq!(
        common::error_reason(&refused).as_deref(),
        Some("STEP_UP_REQUIRED")
    );
    assert!(storage.list_sessions(&profile.id).await.unwrap().is_empty());
}

// An Elevated attestation satisfies an Elevated policy only within the
// step-up window counted from its authentication time: once it has passed,
// the same evidence admitted later is refused.
#[tokio::test]
async fn an_elevated_policy_needs_the_window_of_the_real_authentication() {
    let storage = storage().await;
    let auth = authority(storage.clone(), AuthLevel::Elevated);
    let profile = profile(storage.as_ref()).await;

    let fresh = evidence(
        "urn:sid:acr:elevated",
        &["hwk", "pop", "mfa"],
        Duration::minutes(1),
    )
    .authentication(Utc::now())
    .unwrap();
    let signed_in = auth
        .complete_admitted_sign_in(&tonic::Request::new(()), &profile, &fresh, CLIENT, None)
        .await
        .unwrap();
    let sessions = storage.list_sessions(&profile.id).await.unwrap();
    let session = sessions
        .iter()
        .find(|s| s.id.to_string() == signed_in.session_id)
        .unwrap();
    let elevation = session.elevation.expect("the step-up");
    assert_eq!(elevation.level, AuthLevel::Elevated);
    assert!(elevation.until <= Utc::now() + Duration::minutes(ELEVATION_TTL_MINUTES));

    let stale = evidence(
        "urn:sid:acr:elevated",
        &["hwk", "pop", "mfa"],
        Duration::minutes(ELEVATION_TTL_MINUTES + 1),
    )
    .authentication(Utc::now())
    .unwrap();
    let refused = auth
        .complete_admitted_sign_in(&tonic::Request::new(()), &profile, &stale, CLIENT, None)
        .await
        .err()
        .expect("refused past the window");
    assert_eq!(
        common::error_reason(&refused).as_deref(),
        Some("STEP_UP_REQUIRED")
    );
}

// Regression guard: a suspended Profile is not signed in on any evidence.
#[tokio::test]
async fn a_suspended_profile_is_not_signed_in() {
    let storage = storage().await;
    let auth = authority(storage.clone(), AuthLevel::Basic);
    let mut profile = profile(storage.as_ref()).await;
    profile.status = sid_core::models::ProfileStatus::Suspended;
    assert!(
        storage
            .update_profile(
                &profile,
                AuditEntry::system("profile.suspend", profile.id.to_string()).into(),
            )
            .await
            .unwrap()
    );
    let authentication = evidence(
        "urn:sid:acr:standard",
        &["pwd", "otp"],
        Duration::minutes(1),
    )
    .authentication(Utc::now())
    .unwrap();
    let refused = auth
        .complete_admitted_sign_in(
            &tonic::Request::new(()),
            &profile,
            &authentication,
            CLIENT,
            None,
        )
        .await
        .err()
        .expect("refused");
    assert_eq!(
        common::error_reason(&refused).as_deref(),
        Some("AUTHENTICATION_FAILED")
    );
    assert!(storage.list_sessions(&profile.id).await.unwrap().is_empty());
}

/// A host operation's reference, unique per test.
fn operation() -> String {
    format!("entry-{}", uuid::Uuid::now_v7().simple())
}

fn completion(
    operation: &str,
    deadline: chrono::DateTime<Utc>,
) -> sid_server::grpc::auth_service::AdmittedCompletion<'_> {
    sid_server::grpc::auth_service::AdmittedCompletion {
        operation,
        deadline,
    }
}

fn cookie(signed_in: &sid_authn::sign_in_delivery::SignedIn) -> String {
    let sid_authn::sign_in_delivery::Delivery::Cookie(cookie) = &signed_in.delivery else {
        panic!("the browser gets its cookie");
    };
    cookie.split(';').next().unwrap().to_owned()
}

fn basic() -> sid_core::models::session::SessionAuthentication {
    evidence("urn:sid:acr:basic", &["pwd"], Duration::minutes(1))
        .authentication(Utc::now())
        .unwrap()
}

// A repeat of the operation an admitted sign-in completed (its response was
// lost) gets the same live session and the same cookie again; no second
// session is created, its authentication time is unchanged.
#[tokio::test]
async fn a_repeated_operation_gets_the_same_session_again() {
    let storage = storage().await;
    let auth = authority(storage.clone(), AuthLevel::Basic);
    let profile = profile(storage.as_ref()).await;
    let op = operation();
    let deadline = Utc::now() + Duration::minutes(10);
    let request = tonic::Request::new(());

    let first = auth
        .complete_admitted_sign_in(
            &request,
            &profile,
            &basic(),
            CLIENT,
            Some(completion(&op, deadline)),
        )
        .await
        .unwrap();
    let again = auth
        .complete_admitted_sign_in(
            &request,
            &profile,
            &basic(),
            CLIENT,
            Some(completion(&op, deadline)),
        )
        .await
        .unwrap();
    assert_eq!(again.session_id, first.session_id);
    assert_eq!(cookie(&again), cookie(&first));
    let sessions = storage.list_sessions(&profile.id).await.unwrap();
    assert_eq!(sessions.len(), 1);
}

// Concurrent repeats of one operation commit one session; every answer that
// succeeds names it.
#[tokio::test]
async fn concurrent_repeats_commit_one_session() {
    let storage = storage().await;
    let auth = authority(storage.clone(), AuthLevel::Basic);
    let profile = profile(storage.as_ref()).await;
    let op = operation();
    let deadline = Utc::now() + Duration::minutes(10);
    let request = tonic::Request::new(());
    let authentication = basic();
    let (a, b) = tokio::join!(
        auth.complete_admitted_sign_in(
            &request,
            &profile,
            &authentication,
            CLIENT,
            Some(completion(&op, deadline))
        ),
        auth.complete_admitted_sign_in(
            &request,
            &profile,
            &authentication,
            CLIENT,
            Some(completion(&op, deadline))
        )
    );
    let sessions = storage.list_sessions(&profile.id).await.unwrap();
    assert_eq!(sessions.len(), 1);
    for answer in [a, b].into_iter().flatten() {
        assert_eq!(answer.session_id, sessions[0].id.to_string());
    }
}

// An operation repeated for another Profile than the one it signed in gets
// nothing: never the first Profile's session, and no session of its own.
// Before, the retained cookie of the first Profile was delivered.
#[tokio::test]
async fn a_repeat_for_another_profile_gets_nothing() {
    let storage = storage().await;
    let auth = authority(storage.clone(), AuthLevel::Basic);
    let first = profile(storage.as_ref()).await;
    let other = profile(storage.as_ref()).await;
    let op = operation();
    let deadline = Utc::now() + Duration::minutes(10);
    let request = tonic::Request::new(());
    auth.complete_admitted_sign_in(
        &request,
        &first,
        &basic(),
        CLIENT,
        Some(completion(&op, deadline)),
    )
    .await
    .unwrap();

    let refused = auth
        .complete_admitted_sign_in(
            &request,
            &other,
            &basic(),
            CLIENT,
            Some(completion(&op, deadline)),
        )
        .await
        .err()
        .expect("another Profile's repeat is refused");
    assert_eq!(
        common::error_reason(&refused).as_deref(),
        Some("AUTHENTICATION_FAILED")
    );
    assert!(storage.list_sessions(&other.id).await.unwrap().is_empty());
}

// A sign-in whose evicted sessions could not be revoked everywhere is not
// delivered, on its own answer or on a repeat: the evicted sessions' tokens
// would stay usable on other replicas. Before, the failure became a delivered
// sign-in through the repeat path.
#[tokio::test]
async fn a_sign_in_whose_evictions_did_not_propagate_is_not_delivered() {
    let storage = storage().await;
    let mut policy = SecurityPolicy::ce_default();
    policy.session.max_concurrent_sessions = 1;
    let outage = Arc::new(common::RevocationOutage {
        inner: Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        down: std::sync::atomic::AtomicBool::new(false),
    });
    let revocation = Arc::new(sid_authn::revocation_cache::RevocationCache::new(
        std::time::Duration::from_secs(900),
        outage.clone(),
    ));
    let auth = common::auth_service_revoking(
        storage.clone(),
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        Some(policy),
        Some(EnrollmentMode::Open),
        None,
        revocation,
    );
    let profile = profile(storage.as_ref()).await;
    let request = tonic::Request::new(());
    auth.complete_admitted_sign_in(&request, &profile, &basic(), CLIENT, None)
        .await
        .expect("the session to evict");

    outage.down.store(true, std::sync::atomic::Ordering::SeqCst);
    let op = operation();
    let deadline = Utc::now() + Duration::minutes(10);
    let refused = auth
        .complete_admitted_sign_in(
            &request,
            &profile,
            &basic(),
            CLIENT,
            Some(completion(&op, deadline)),
        )
        .await
        .err()
        .expect("the eviction could not be revoked");
    assert_eq!(refused.code(), tonic::Code::Unavailable, "{refused:?}");

    outage
        .down
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(
        auth.complete_admitted_sign_in(
            &request,
            &profile,
            &basic(),
            CLIENT,
            Some(completion(&op, deadline)),
        )
        .await
        .is_err(),
        "a repeat delivers nothing whose evictions were not revoked"
    );
}

// A committed sign-in whose finish was never recorded (the process stopped
// before it, or the mark could not be written) is not left behind: a repeat
// after the finish's bound ends its undelivered session, so it holds no
// session slot, and refuses so the entry starts again. Before, the session
// stayed live and unreachable until it expired.
#[tokio::test]
async fn an_unfinished_sign_in_leaves_no_live_session_behind() {
    let storage = storage().await;
    let mut policy = SecurityPolicy::ce_default();
    policy.session.max_concurrent_sessions = 1;
    let outage = Arc::new(common::RevocationOutage {
        inner: Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        down: std::sync::atomic::AtomicBool::new(false),
    });
    let revocation = Arc::new(sid_authn::revocation_cache::RevocationCache::new(
        std::time::Duration::from_secs(900),
        outage.clone(),
    ));
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let auth = common::auth_service_revoking(
        storage.clone(),
        cache.clone(),
        Some(policy.clone()),
        Some(EnrollmentMode::Open),
        None,
        revocation.clone(),
    );
    // The same authority later, when any unfinished commit is past its finish.
    let later = Arc::try_unwrap(common::auth_service_revoking(
        storage.clone(),
        cache,
        Some(policy),
        Some(EnrollmentMode::Open),
        None,
        revocation,
    ))
    .ok()
    .expect("the only handle")
    .with_admitted_finish_bound(std::time::Duration::ZERO);
    let profile = profile(storage.as_ref()).await;
    let request = tonic::Request::new(());
    auth.complete_admitted_sign_in(&request, &profile, &basic(), CLIENT, None)
        .await
        .unwrap();
    outage.down.store(true, std::sync::atomic::Ordering::SeqCst);
    let op = operation();
    let deadline = Utc::now() + Duration::minutes(10);
    auth.complete_admitted_sign_in(
        &request,
        &profile,
        &basic(),
        CLIENT,
        Some(completion(&op, deadline)),
    )
    .await
    .err()
    .expect("its eviction could not be revoked");
    outage
        .down
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(storage.list_sessions(&profile.id).await.unwrap().len(), 1);

    later
        .complete_admitted_sign_in(
            &request,
            &profile,
            &basic(),
            CLIENT,
            Some(completion(&op, deadline)),
        )
        .await
        .err()
        .expect("an unfinished sign-in is not delivered");
    assert!(
        storage.list_sessions(&profile.id).await.unwrap().is_empty(),
        "the undelivered session is ended"
    );
}

// A repeat is judged by the rules in force now: once the account is locked
// out the retained session is not delivered again. Before, a repeat skipped
// the sign-in rules and got the cookie.
#[tokio::test]
async fn a_repeat_after_a_lockout_is_refused() {
    let storage = storage().await;
    let cache: Arc<dyn sid_plugin::cache::CacheBackend> =
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let mut policy = SecurityPolicy::ce_default();
    policy.auth.min_acr = AuthLevel::Basic;
    let auth = common::auth_service_over(
        storage.clone(),
        cache.clone(),
        Some(policy),
        Some(EnrollmentMode::Open),
    );
    let profile = profile(storage.as_ref()).await;
    let op = operation();
    let deadline = Utc::now() + Duration::minutes(10);
    let request = tonic::Request::new(());
    auth.complete_admitted_sign_in(
        &request,
        &profile,
        &basic(),
        CLIENT,
        Some(completion(&op, deadline)),
    )
    .await
    .unwrap();

    let detector = sid_authn::anomaly::AnomalyDetector::ce_default(cache);
    for _ in 0..5 {
        detector
            .record_failed_attempt(&profile.id.to_string())
            .await
            .unwrap();
    }
    let refused = auth
        .complete_admitted_sign_in(
            &request,
            &profile,
            &basic(),
            CLIENT,
            Some(completion(&op, deadline)),
        )
        .await
        .err()
        .expect("a locked-out account gets nothing again");
    assert_eq!(
        refused.code(),
        tonic::Code::ResourceExhausted,
        "{refused:?}"
    );
}

// Nothing is delivered again for a session that ended, a Profile suspended
// since, or after the operation's deadline; no replacement session appears.
#[tokio::test]
async fn an_ended_suspended_or_late_operation_is_not_delivered_again() {
    let storage = storage().await;
    let auth = authority(storage.clone(), AuthLevel::Basic);
    let request = tonic::Request::new(());

    // Ended.
    let profile_a = profile(storage.as_ref()).await;
    let op = operation();
    let deadline = Utc::now() + Duration::minutes(10);
    let first = auth
        .complete_admitted_sign_in(
            &request,
            &profile_a,
            &basic(),
            CLIENT,
            Some(completion(&op, deadline)),
        )
        .await
        .unwrap();
    storage
        .delete_session(
            first.session_id.parse().unwrap(),
            &sid_core::models::SessionEnd::new(
                sid_core::models::RevocationReason::UserRequested,
                "test",
            ),
            AuditEntry::system("session.end", "test").into(),
        )
        .await
        .unwrap();
    let refused = auth
        .complete_admitted_sign_in(
            &request,
            &profile_a,
            &basic(),
            CLIENT,
            Some(completion(&op, deadline)),
        )
        .await
        .err()
        .expect("an ended session is not delivered again");
    assert_eq!(
        common::error_reason(&refused).as_deref(),
        Some("AUTHENTICATION_FAILED")
    );
    assert!(
        storage
            .list_sessions(&profile_a.id)
            .await
            .unwrap()
            .is_empty()
    );

    // Suspended after the commit; the host still holds the active copy it
    // looked up before.
    let profile_b = profile(storage.as_ref()).await;
    let op = operation();
    auth.complete_admitted_sign_in(
        &request,
        &profile_b,
        &basic(),
        CLIENT,
        Some(completion(&op, deadline)),
    )
    .await
    .unwrap();
    let mut suspended = storage.get_profile(profile_b.id).await.unwrap().unwrap();
    suspended.status = sid_core::models::ProfileStatus::Suspended;
    assert!(
        storage
            .update_profile(
                &suspended,
                AuditEntry::system("profile.suspend", "test").into()
            )
            .await
            .unwrap()
    );
    let refused = auth
        .complete_admitted_sign_in(
            &request,
            &profile_b,
            &basic(),
            CLIENT,
            Some(completion(&op, deadline)),
        )
        .await
        .err()
        .expect("a suspended Profile's session is not delivered again");
    assert_eq!(
        common::error_reason(&refused).as_deref(),
        Some("AUTHENTICATION_FAILED")
    );
    assert_eq!(storage.list_sessions(&profile_b.id).await.unwrap().len(), 1);

    // Late.
    let profile_c = profile(storage.as_ref()).await;
    let op = operation();
    let past = Utc::now() - Duration::seconds(1);
    auth.complete_admitted_sign_in(
        &request,
        &profile_c,
        &basic(),
        CLIENT,
        Some(completion(&op, past)),
    )
    .await
    .unwrap();
    let refused = auth
        .complete_admitted_sign_in(
            &request,
            &profile_c,
            &basic(),
            CLIENT,
            Some(completion(&op, past)),
        )
        .await
        .err()
        .expect("past its deadline nothing is delivered again");
    assert_eq!(
        common::error_reason(&refused).as_deref(),
        Some("AUTHENTICATION_FAILED")
    );
    assert_eq!(storage.list_sessions(&profile_c.id).await.unwrap().len(), 1);
}
