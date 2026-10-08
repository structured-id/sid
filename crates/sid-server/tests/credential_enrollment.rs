// SPDX-License-Identifier: AGPL-3.0-only
//! Credential enrollment authority on an existing account: a provisional
//! (mailbox-only) session binds nothing, an account protected by a strong
//! factor is not extended from a weaker session, and a password-only account
//! enrolls its first strong factor without a factor it never had.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, authenticated_session, stored_session_token};
use sid_core::grpc_error::extract_error_info;
use sid_core::models::{AuditEntry, AuthLevel, Credential, CredentialType, Profile, Session};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request, Status};

fn authed<T>(msg: T, bearer: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    req
}

/// An account holding credentials of `types`.
async fn account(types: &[CredentialType]) -> (TestServices, Profile) {
    let profile = Profile::new(Some("enrolling"));
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    for t in types {
        svc.storage
            .create_credential(
                &Credential::new(profile.id, *t, vec![7], None),
                AuditEntry::system("test", "credential").into(),
            )
            .await
            .unwrap();
    }
    (svc, profile)
}

async fn start_passkey(svc: &TestServices, bearer: &str) -> Result<(), Status> {
    svc.auth
        .web_authn_registration_start(authed(Default::default(), bearer))
        .await
        .map(|_| ())
}

async fn start_totp(svc: &TestServices, bearer: &str) -> Result<(), Status> {
    svc.auth
        .start_totp_enrollment(authed(StartTotpEnrollmentRequest::default(), bearer))
        .await
        .map(|_| ())
}

fn assert_mfa_required(result: Result<(), Status>, continuation: &str) {
    let status = result.expect_err("enrollment refused");
    assert_eq!(status.code(), Code::FailedPrecondition, "{status:?}");
    let (reason, _, metadata) = extract_error_info(&status).expect("ErrorInfo");
    assert_eq!(reason, "MFA_REQUIRED");
    assert_eq!(
        metadata.get("continuation").map(String::as_str),
        Some(continuation)
    );
}

/// Mailbox possession (email OTP, magic link) binds no credential to an
/// existing account: an attacker reading the mailbox cannot add a passkey
/// or an authenticator app and keep access.
#[tokio::test]
async fn provisional_session_binds_nothing() {
    let (svc, profile) = account(&[CredentialType::Opaque]).await;
    let bearer = stored_session_token(
        &svc,
        &profile,
        Session::new_provisional(profile.id, "127.0.0.1".into()),
    )
    .await;

    assert_mfa_required(start_passkey(&svc, &bearer).await, "authenticate");
    assert_mfa_required(start_totp(&svc, &bearer).await, "authenticate");
    // New recovery codes would step the session up and open the rest.
    let codes = svc
        .auth
        .generate_recovery_codes(authed(GenerateRecoveryCodesRequest::default(), &bearer))
        .await
        .map(|_| ());
    assert_mfa_required(codes, "authenticate");
}

/// An account protected by a passkey is not extended from a password-only
/// session: the email reset → new password → new passkey path is closed.
#[tokio::test]
async fn password_session_cannot_extend_strong_account() {
    let (svc, profile) = account(&[CredentialType::Opaque, CredentialType::WebAuthn]).await;
    let bearer = stored_session_token(
        &svc,
        &profile,
        authenticated_session(&profile, AuthLevel::Basic, 1),
    )
    .await;

    let refused = start_passkey(&svc, &bearer).await;
    let (_, _, metadata) = extract_error_info(refused.as_ref().unwrap_err()).unwrap();
    assert_eq!(
        metadata.get("required_acr").map(String::as_str),
        Some("urn:sid:acr:standard")
    );
    assert_mfa_required(refused, "step_up");
    assert_mfa_required(start_totp(&svc, &bearer).await, "step_up");
}

/// A password-only session cannot revoke the strong factor either, which
/// would lower the account and let the next passkey through.
#[tokio::test]
async fn password_session_cannot_revoke_strong_factor() {
    use sid_proto::sid::v1::identity_service_server::IdentityService;

    let (svc, profile) = account(&[CredentialType::Opaque, CredentialType::WebAuthn]).await;
    let bearer = stored_session_token(
        &svc,
        &profile,
        authenticated_session(&profile, AuthLevel::Basic, 1),
    )
    .await;
    let passkey = svc
        .storage
        .get_credentials_by_profile(profile.id, Some(CredentialType::WebAuthn))
        .await
        .unwrap()
        .remove(0);

    let revoke = svc
        .identity
        .revoke_credential(authed(
            RevokeCredentialRequest {
                credential_id: passkey.id.0.to_string(),
            },
            &bearer,
        ))
        .await
        .map(|_| ());
    assert_mfa_required(revoke, "step_up");
    let still = svc
        .storage
        .get_credential(passkey.id)
        .await
        .unwrap()
        .unwrap();
    assert!(still.status.is_active(), "the passkey was revoked");
}

/// A password-only account enrolls its first strong factor after a password
/// login, with no second factor demanded that it never had.
#[tokio::test]
async fn password_only_account_enrolls_first_factor() {
    let (svc, profile) = account(&[CredentialType::Opaque]).await;
    let bearer = stored_session_token(
        &svc,
        &profile,
        authenticated_session(&profile, AuthLevel::Basic, 1),
    )
    .await;

    start_passkey(&svc, &bearer).await.expect("first passkey");
    start_totp(&svc, &bearer).await.expect("first TOTP");
}

/// A fresh sufficient authentication is reused; an old one is repeated.
#[tokio::test]
async fn freshness_decides_reuse() {
    let (svc, profile) = account(&[CredentialType::Opaque, CredentialType::Totp]).await;
    let fresh = stored_session_token(
        &svc,
        &profile,
        authenticated_session(&profile, AuthLevel::Standard, 5),
    )
    .await;
    start_passkey(&svc, &fresh)
        .await
        .expect("fresh step-up reused");

    let stale = stored_session_token(
        &svc,
        &profile,
        authenticated_session(&profile, AuthLevel::Standard, 120),
    )
    .await;
    assert_mfa_required(start_passkey(&svc, &stale).await, "reauthenticate");
}

/// The finish re-checks against the account as it is then: a strong factor
/// added after the start raises what the finish requires.
#[tokio::test]
async fn finish_rechecks_current_state() {
    use sid_authn::webauthn::soft_authenticator::SoftAuthenticator;

    let (svc, profile) = account(&[CredentialType::Opaque]).await;
    let bearer = stored_session_token(
        &svc,
        &profile,
        authenticated_session(&profile, AuthLevel::Basic, 1),
    )
    .await;
    let start = svc
        .auth
        .web_authn_registration_start(authed(Default::default(), &bearer))
        .await
        .unwrap()
        .into_inner();
    svc.storage
        .create_credential(
            &Credential::new(profile.id, CredentialType::Totp, vec![7], None),
            AuditEntry::system("test", "credential").into(),
        )
        .await
        .unwrap();

    let mut key = SoftAuthenticator::new("https://sid.example.com", "sid.example.com");
    let finish = svc
        .auth
        .web_authn_registration_finish(authed(
            WebAuthnRegistrationFinishRequest {
                credential: key.register(&start.options),
                ..Default::default()
            },
            &bearer,
        ))
        .await
        .map(|_| ());
    assert_mfa_required(finish, "step_up");
    let passkeys = svc
        .storage
        .get_credentials_by_profile(profile.id, Some(CredentialType::WebAuthn))
        .await
        .unwrap();
    assert!(passkeys.is_empty(), "the refused passkey was stored");
}
