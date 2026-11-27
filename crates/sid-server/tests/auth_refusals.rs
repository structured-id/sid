// SPDX-License-Identifier: AGPL-3.0-only
//! Sign-in refusals that must not tell whether an account exists or what it
//! holds, and password guesses that must count toward the lockout.

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use common::{LEGACY_PASSWORD as RIGHT, error_reason, legacy_password, test_profile};
use sid_core::models::{Credential, Profile};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request, Status};

fn legacy_start(principal: &str, password: &str) -> Request<LegacyMigrateStartRequest> {
    Request::new(LegacyMigrateStartRequest {
        principal: principal.to_string(),
        password: password.to_string(),
        opaque_registration_request: vec![],
    })
}

/// A profile whose password is the legacy hash of [`RIGHT`].
fn with_legacy_password(profile: &Profile) -> Credential {
    legacy_password(profile.id)
}

fn assert_authentication_failed(status: &Status) {
    assert_eq!(status.code(), Code::Unauthenticated, "{status:?}");
    assert_eq!(
        error_reason(status).as_deref(),
        Some("AUTHENTICATION_FAILED")
    );
}

/// Regression: a migration attempt for an account without a legacy hash was
/// refused with FAILED_PRECONDITION, unlike an unknown account or a wrong
/// password, so the answer told the account exists and how its password is
/// stored. All three now read the same.
#[tokio::test]
async fn test_legacy_migration_answers_alike_whatever_the_account() {
    let with_legacy = test_profile();
    let without = Profile::new(Some("mallory"));
    let svc = TestServices::new(
        MockStorage::new()
            .with_login_profile(with_legacy.clone())
            .with_login_profile(without.clone())
            .with_credential(with_legacy_password(&with_legacy)),
    );

    for (principal, password) in [("alice", "wrong"), ("mallory", "any"), ("nobody", "any")] {
        let err = svc
            .auth
            .legacy_migrate_start(legacy_start(principal, password))
            .await
            .unwrap_err();
        assert_authentication_failed(&err);
    }
}

/// The password was verified and the request went on to its OPAQUE part:
/// the empty registration request is the first thing refused after it.
fn assert_password_accepted(status: &Status) {
    assert_eq!(status.code(), Code::InvalidArgument, "{status:?}");
}

/// The account's user name principal is found in any case and spacing: the
/// identifier is normalized before the lookup.
#[tokio::test]
async fn test_account_found_by_the_normalized_name() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_login_profile(profile.clone())
            .with_credential(with_legacy_password(&profile)),
    );

    let err = svc
        .auth
        .legacy_migrate_start(legacy_start("  Alice ", RIGHT))
        .await
        .unwrap_err();
    assert_password_accepted(&err);
}

/// Regression: a profile without a principal was found by matching its
/// stored user name or email against the identifier as typed (raw, any
/// status), a second sign-in route beside the principals. Sign-in resolves
/// principals only; such a profile is answered like an unknown account.
#[tokio::test]
async fn test_profile_without_principal_is_not_a_sign_in_route() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_credential(with_legacy_password(&profile)),
    );

    let err = svc
        .auth
        .legacy_migrate_start(legacy_start("alice", RIGHT))
        .await
        .unwrap_err();
    assert_authentication_failed(&err);
}

/// A suspended account is answered like an unknown one, its right password
/// included.
#[tokio::test]
async fn test_suspended_account_answers_like_unknown() {
    let mut profile = test_profile();
    profile.status = sid_core::models::ProfileStatus::Suspended;
    let svc = TestServices::new(
        MockStorage::new()
            .with_login_profile(profile.clone())
            .with_credential(with_legacy_password(&profile)),
    );

    let err = svc
        .auth
        .legacy_migrate_start(legacy_start("alice", RIGHT))
        .await
        .unwrap_err();
    assert_authentication_failed(&err);
}

/// Regression: a wrong legacy password was never counted, so legacy hashes
/// could be guessed without a lockout. After the limit the account is
/// locked like any sign-in, the right password included.
#[tokio::test]
async fn test_legacy_migration_guesses_reach_the_lockout() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_login_profile(profile.clone())
            .with_credential(with_legacy_password(&profile)),
    );

    for _ in 0..5 {
        let err = svc
            .auth
            .legacy_migrate_start(legacy_start("alice", "wrong"))
            .await
            .unwrap_err();
        assert_authentication_failed(&err);
    }
    let locked = svc
        .auth
        .legacy_migrate_start(legacy_start("alice", RIGHT))
        .await
        .unwrap_err();
    assert_eq!(locked.code(), Code::ResourceExhausted, "{locked:?}");
    assert_eq!(
        error_reason(&locked).as_deref(),
        Some("RATE_LIMIT_EXCEEDED")
    );
}

/// The authentication service over `svc`'s store and cache, as an
/// installation that offers no sign-in with an imported password builds it.
fn withholding_imported_passwords(
    svc: &TestServices,
) -> sid_server::grpc::auth_service::AuthServiceImpl {
    std::sync::Arc::into_inner(common::auth_service_over(
        svc.storage.clone(),
        svc.cache.clone(),
        None,
    ))
    .expect("the service is not shared yet")
    .without_imported_password_sign_in()
}

fn assert_not_offered(status: &Status) {
    assert_eq!(status.code(), Code::FailedPrecondition, "{status:?}");
    assert_eq!(
        error_reason(status).as_deref(),
        Some("FEATURE_NOT_CONFIGURED")
    );
}

/// An installation that withholds sign-in with an imported password refuses
/// its start before any password work: wrong guesses past the lockout limit
/// are not counted, so the account still signs in where the capability is
/// offered over the same store.
/// Bug prevented: a withheld sign-in route that still verifies a guess and
/// counts it against the account.
#[tokio::test]
async fn test_withheld_imported_password_start_counts_no_guess() {
    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_login_profile(profile.clone())
            .with_credential(with_legacy_password(&profile)),
    );
    let withholding = withholding_imported_passwords(&svc);

    for password in ["wrong", "wrong", "wrong", "wrong", "wrong", "wrong", RIGHT] {
        let err = withholding
            .legacy_migrate_start(legacy_start("alice", password))
            .await
            .unwrap_err();
        assert_not_offered(&err);
    }
    let err = svc
        .auth
        .legacy_migrate_start(legacy_start("alice", RIGHT))
        .await
        .unwrap_err();
    assert_password_accepted(&err);
}

/// A migration started before the capability was withheld is not finished
/// either: the finish is refused before the migration is consumed, the
/// account keeps its imported password, and the same finish completes where
/// the capability is offered.
/// Bug prevented: a withheld route closed at its first step only, so a
/// migration already under way still replaces the credential.
#[tokio::test]
async fn test_withheld_imported_password_finish_changes_nothing() {
    use sid_core::models::CredentialType;

    let profile = test_profile();
    let svc = TestServices::new(
        MockStorage::new()
            .with_login_profile(profile.clone())
            .with_credential(with_legacy_password(&profile)),
    );
    let client = common::zkpp_client::start(RIGHT.as_bytes());
    let started = svc
        .auth
        .legacy_migrate_start(Request::new(LegacyMigrateStartRequest {
            principal: "alice".to_string(),
            password: RIGHT.to_string(),
            opaque_registration_request: client.request.clone(),
        }))
        .await
        .expect("the migration starts where it is offered")
        .into_inner();
    let record = common::zkpp_client::finish(
        client,
        RIGHT.as_bytes(),
        &started.opaque_registration_response,
    );
    let finish = || {
        Request::new(LegacyMigrateFinishRequest {
            upgrade_id: started.upgrade_id.clone(),
            opaque_registration_record: record.clone(),
        })
    };

    let err = withholding_imported_passwords(&svc)
        .legacy_migrate_finish(finish())
        .await
        .unwrap_err();
    assert_not_offered(&err);
    let imported = svc
        .storage
        .get_credentials_by_profile(profile.id, Some(CredentialType::LegacyHash))
        .await
        .unwrap();
    assert_eq!(imported.len(), 1, "the imported password was replaced");

    svc.auth
        .legacy_migrate_finish(finish())
        .await
        .expect("the same migration finishes where it is offered");
}

/// Regression: an account without passkeys was answered NOT_FOUND at the
/// start of a passkey sign-in, an unknown account AUTHENTICATION_FAILED, so
/// the answer told the account exists. Both now read the same.
#[tokio::test]
async fn test_passkey_sign_in_start_answers_alike_without_passkeys() {
    let profile = test_profile();
    let svc = TestServices::new(MockStorage::new().with_login_profile(profile.clone()));

    for principal in ["alice", "nobody"] {
        let err = svc
            .auth
            .web_authn_authentication_start(Request::new(WebAuthnAuthenticationStartRequest {
                principal: Some(principal.to_string()),
            }))
            .await
            .unwrap_err();
        assert_authentication_failed(&err);
    }
}
