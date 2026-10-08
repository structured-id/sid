// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization of `AuthService::RequestStepUp`: step-up always works on the
//! caller's own session. A session id in the request cannot point it at
//! someone else's session, which would reveal that user's enrolled factors and
//! start a WebAuthn challenge over their passkeys.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_token_with_session, test_profile};
use sid_core::models::{Credential, CredentialType, Profile, Session};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request};

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn session_of(profile: &Profile) -> Session {
    Session::new(
        profile.id,
        "127.0.0.1".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
}

/// Regression (#881): without a token nothing is answered.
#[tokio::test]
async fn test_request_step_up_requires_a_token() {
    let victim = test_profile();
    let session = session_of(&victim);
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(victim.clone())
            .with_session(session.clone()),
    );
    let err = svc
        .auth
        .request_step_up(Request::new(RequestStepUpRequest {
            session_id: session.id.to_string(),
            ..Default::default()
        }))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), Code::Unauthenticated);
}

/// Regression (#881): another user naming the victim's session is refused and
/// learns nothing about the victim's factors.
#[tokio::test]
async fn test_request_step_up_refuses_a_foreign_session() {
    let victim = test_profile();
    let attacker = Profile::new(Some("mallory"));
    let victim_session = session_of(&victim);
    let attacker_session = session_of(&attacker);
    let totp = Credential::new(victim.id, CredentialType::Totp, vec![1u8; 20], None);
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(victim.clone())
            .with_profile(attacker.clone())
            .with_session(victim_session.clone())
            .with_session(attacker_session.clone())
            .with_credential(totp),
    );
    let (token, _) = issue_token_with_session(
        &svc.jwt,
        &attacker,
        &["openid".to_string()],
        attacker_session,
    );
    let err = svc
        .auth
        .request_step_up(authed(
            RequestStepUpRequest {
                session_id: victim_session.id.to_string(),
                ..Default::default()
            },
            &token,
        ))
        .await
        .expect_err("foreign session");
    assert_eq!(err.code(), Code::PermissionDenied);
}

/// The owner queries the step-up methods of their own session.
#[tokio::test]
async fn test_request_step_up_answers_the_own_session() {
    let owner = test_profile();
    let session = session_of(&owner);
    let totp = Credential::new(owner.id, CredentialType::Totp, vec![1u8; 20], None);
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(owner.clone())
            .with_session(session.clone())
            .with_credential(totp),
    );
    let (token, _) =
        issue_token_with_session(&svc.jwt, &owner, &["openid".to_string()], session.clone());
    let challenge = svc
        .auth
        .request_step_up(authed(
            RequestStepUpRequest {
                session_id: session.id.to_string(),
                ..Default::default()
            },
            &token,
        ))
        .await
        .expect("own session")
        .into_inner();
    assert!(
        challenge
            .allowed_methods
            .contains(&(StepUpMethod::Totp as i32))
    );
}
