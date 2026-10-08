// SPDX-License-Identifier: AGPL-3.0-only
//! OPAQUE login: the answers do not tell whether an account exists or
//! whether a guessed password was right, attempts are limited before any
//! password work, and a login never brings back a revoked password.

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use common::opaque_client::{login, register, start_login, try_start_login};
use sid_core::models::credential::CredentialStatus;
use sid_core::models::{AuditEntry, CredentialType, NewRegistration, Profile};
use sid_proto::sid::v1::auth_service_server::AuthService;
use tonic::{Code, Request};

const PASSWORD: &[u8] = b"login-strong-password-2026";
const WRONG: &[u8] = b"not-the-password";

/// Attempts allowed before a lockout (the detector's default configuration).
const MAX_ATTEMPTS: usize = 5;

/// An account held by a profile that has no password (passkey-only,
/// provisioned) answers a password login exactly like an unknown identifier.
#[tokio::test]
async fn profile_without_password_fails_like_an_unknown_principal() {
    let svc = TestServices::new(MockStorage::new());
    svc.storage
        .register_profile(
            &NewRegistration::new(
                Profile::new(None::<String>),
                sid_core::models::SignupIdentifier::Email {
                    key: "passkey-only@sid.example.com",
                    address: "passkey-only@sid.example.com",
                    revision: sid_core::models::INSTALLATION_EMAIL_POLICY_REVISION,
                },
                None,
            )
            .unwrap(),
            AuditEntry::system("test", "provision").into(),
        )
        .await
        .unwrap();

    // Both starts are answered: a refusal at start would itself tell them apart.
    try_start_login(&svc, "passkey-only@sid.example.com", PASSWORD)
        .await
        .expect("start answered for an account without a password");
    let without_password = login(&svc, "passkey-only@sid.example.com", PASSWORD)
        .await
        .unwrap_err();
    let unknown = login(&svc, "nobody@sid.example.com", PASSWORD)
        .await
        .unwrap_err();

    assert_eq!(unknown.code(), Code::Unauthenticated);
    assert_eq!(without_password.code(), unknown.code());
    assert_eq!(without_password.message(), unknown.message());
}

/// After repeated failures the account is locked before any password work,
/// and during the lockout the right password gets the same answer as a wrong
/// one: the lockout neither lets guessing continue nor confirms a guess.
#[tokio::test]
async fn lockout_is_checked_before_the_password() {
    let svc = TestServices::new(MockStorage::new());
    register(&svc, &svc, "locked@sid.example.com", PASSWORD).await;
    for _ in 0..MAX_ATTEMPTS {
        let err = login(&svc, "locked@sid.example.com", WRONG)
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    let right = try_start_login(&svc, "locked@sid.example.com", PASSWORD)
        .await
        .unwrap_err();
    let wrong = try_start_login(&svc, "locked@sid.example.com", WRONG)
        .await
        .unwrap_err();

    assert_eq!(right.code(), Code::ResourceExhausted);
    assert_eq!(wrong.code(), right.code());
    assert_eq!(wrong.message(), right.message());
}

/// An identifier nobody holds is locked after the same number of failures,
/// so the lockout does not reveal which identifiers exist.
#[tokio::test]
async fn unknown_principal_is_locked_like_an_account() {
    let svc = TestServices::new(MockStorage::new());
    for _ in 0..MAX_ATTEMPTS {
        login(&svc, "ghost@sid.example.com", WRONG)
            .await
            .unwrap_err();
    }

    let err = try_start_login(&svc, "ghost@sid.example.com", WRONG)
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::ResourceExhausted);
}

/// A password revoked while its login is in flight does not sign in, and the
/// login does not bring it back to active.
#[tokio::test]
async fn password_revoked_mid_login_stays_revoked() {
    let svc = TestServices::new(MockStorage::new());
    register(&svc, &svc, "revoke-mid@sid.example.com", PASSWORD).await;
    let finish = start_login(&svc, "revoke-mid@sid.example.com", PASSWORD).await;

    let profile_id = svc
        .storage
        .get_profile_by_email("revoke-mid@sid.example.com")
        .await
        .unwrap()
        .unwrap()
        .id;
    let mut credential = svc
        .storage
        .get_credentials_by_profile(profile_id, Some(CredentialType::Opaque))
        .await
        .unwrap()
        .remove(0);
    credential.status = CredentialStatus::Revoked;
    svc.mock_storage.set_credential(&credential);

    let err = svc
        .auth
        .opaque_login_finish(Request::new(finish))
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::Unauthenticated);
    let stored = svc
        .storage
        .get_credentials_by_profile(profile_id, Some(CredentialType::Opaque))
        .await
        .unwrap();
    assert!(stored.iter().all(|c| c.status == CredentialStatus::Revoked));
}

/// A successful login records when the password was last used.
#[tokio::test]
async fn login_records_last_use() {
    let svc = TestServices::new(MockStorage::new());
    register(&svc, &svc, "used@sid.example.com", PASSWORD).await;

    login(&svc, "used@sid.example.com", PASSWORD).await.unwrap();

    let profile_id = svc
        .storage
        .get_profile_by_email("used@sid.example.com")
        .await
        .unwrap()
        .unwrap()
        .id;
    let stored = svc
        .storage
        .get_credentials_by_profile(profile_id, Some(CredentialType::Opaque))
        .await
        .unwrap();
    assert!(stored[0].last_used_at.is_some());
}
