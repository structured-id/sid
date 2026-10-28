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

    let signed_in = auth
        .complete_admitted_sign_in(&profile, None, Some("test-agent"), &authentication)
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
        .complete_admitted_sign_in(&profile, None, None, &authentication)
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
        .complete_admitted_sign_in(&profile, None, None, &fresh)
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
        .complete_admitted_sign_in(&profile, None, None, &stale)
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
        .complete_admitted_sign_in(&profile, None, None, &authentication)
        .await
        .err()
        .expect("refused");
    assert_eq!(
        common::error_reason(&refused).as_deref(),
        Some("AUTHENTICATION_FAILED")
    );
    assert!(storage.list_sessions(&profile.id).await.unwrap().is_empty());
}
