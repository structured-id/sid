// SPDX-License-Identifier: AGPL-3.0-only
//! A TOTP code is accepted once: RFC 6238 §5.2 requires the verifier to
//! refuse a second use of a code after it was accepted, anywhere within its
//! validity window and on any path that takes it.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_token_with_session, test_profile};
use sid_core::models::session::Session;
use sid_core::models::{AuditEntry, Credential, CredentialData, CredentialType, Profile};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::Request;

fn authed<T>(body: T, bearer: &str) -> Request<T> {
    let mut req = Request::new(body);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    req
}

/// A profile with a stored TOTP seed and a session signed in two hours ago.
async fn enrolled(svc: &TestServices, profile: &Profile, seed: &[u8]) -> (String, Session) {
    let mut session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.authenticated_at = chrono::Utc::now() - chrono::Duration::hours(2);
    let (bearer, session) =
        issue_token_with_session(&svc.jwt, profile, &["openid".to_string()], session);
    svc.storage
        .create_session(
            &session,
            AuditEntry::user(profile.id.to_string(), "test", session.id.to_string()).into(),
        )
        .await
        .unwrap();
    let credential = Credential::new(
        profile.id,
        CredentialType::Totp,
        CredentialData::new(common::sealed_totp_seed(profile.id, seed).await),
        None,
    );
    svc.storage
        .create_credential(&credential, AuditEntry::system("test", "totp").into())
        .await
        .unwrap();
    (bearer, session)
}

async fn verify(svc: &TestServices, bearer: &str, code: &str) -> Result<(), tonic::Status> {
    svc.auth
        .verify_totp(authed(
            VerifyTotpRequest {
                code: code.to_string(),
            },
            bearer,
        ))
        .await
        .map(|_| ())
}

/// The same code verifies once.
#[tokio::test]
async fn code_is_accepted_once() {
    let profile = test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let seed = sid_authn::generate_secret();
    let (bearer, _) = enrolled(&svc, &profile, &seed).await;
    let code = sid_authn::generate_current_totp(&seed);

    verify(&svc, &bearer, &code).await.expect("first use");
    let err = verify(&svc, &bearer, &code)
        .await
        .expect_err("a code was accepted twice");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

/// A code spent on MFA verification does not also complete a step-up.
#[tokio::test]
async fn code_spent_on_mfa_does_not_step_up() {
    let profile = test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let seed = sid_authn::generate_secret();
    let (bearer, session) = enrolled(&svc, &profile, &seed).await;
    let code = sid_authn::generate_current_totp(&seed);

    verify(&svc, &bearer, &code).await.expect("first use");
    let err = svc
        .auth
        .complete_step_up(authed(
            CompleteStepUpRequest {
                session_id: session.id.to_string(),
                method: StepUpMethod::Totp as i32,
                challenge_id: String::new(),
                proof: Some(complete_step_up_request::Proof::TotpCode(code)),
            },
            &bearer,
        ))
        .await
        .expect_err("a spent code completed a step-up");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

/// The code that confirmed enrollment cannot be used again to sign in.
#[tokio::test]
async fn enrollment_code_cannot_be_reused() {
    let profile = test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let session = Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let (bearer, session) =
        issue_token_with_session(&svc.jwt, &profile, &["openid".to_string()], session);
    svc.storage
        .create_session(
            &session,
            AuditEntry::user(profile.id.to_string(), "test", session.id.to_string()).into(),
        )
        .await
        .unwrap();

    let challenge = svc
        .auth
        .start_totp_enrollment(authed(StartTotpEnrollmentRequest {}, &bearer))
        .await
        .unwrap()
        .into_inner();
    let seed = sid_authn::base32_decode(&challenge.secret).unwrap();
    let code = sid_authn::generate_current_totp(&seed);
    svc.auth
        .finish_totp_enrollment(authed(
            FinishTotpEnrollmentRequest { code: code.clone() },
            &bearer,
        ))
        .await
        .unwrap();

    assert!(verify(&svc, &bearer, &code).await.is_err());
}
