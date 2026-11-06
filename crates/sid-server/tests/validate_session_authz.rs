// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization of `AuthService::ValidateSession`: a session id alone does not
//! reveal whose session it is. The caller authenticates; only the owner or an
//! administrator learns the ProfileId and validity.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token, issue_token, test_profile};
use sid_core::models::{Profile, Session};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request};

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

struct Fixture {
    svc: TestServices,
    owner: Profile,
    other: Profile,
    session: Session,
}

fn fixture() -> Fixture {
    let owner = test_profile();
    let other = Profile::new(Some("mallory"));
    let session = Session::new(
        owner.id,
        None,
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let storage = MockStorage::new()
        .with_profile(owner.clone())
        .with_profile(other.clone())
        .with_session(session.clone());
    Fixture {
        svc: TestServices::new(storage),
        owner,
        other,
        session,
    }
}

fn validate(session: &Session) -> ValidateSessionRequest {
    ValidateSessionRequest {
        session_id: Some(session.id.into()),
    }
}

/// Regression:without a token the RPC answers nothing.
#[tokio::test]
async fn test_validate_session_requires_a_token() {
    let f = fixture();
    let err = f
        .svc
        .auth
        .validate_session(Request::new(validate(&f.session)))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), Code::Unauthenticated);
}

/// Regression:another user learns neither the owner nor the validity
/// of someone else's session.
#[tokio::test]
async fn test_validate_session_hides_a_foreign_session() {
    let f = fixture();
    let token = issue_token(&f.svc.jwt, &f.other, &["openid".to_string()]);
    let resp = f
        .svc
        .auth
        .validate_session(authed(validate(&f.session), &token))
        .await
        .expect("answered")
        .into_inner();
    assert!(!resp.valid);
    assert!(resp.profile_id.is_none());
    assert!(resp.expires_at.is_none());
}

/// The owner and an administrator see the session.
#[tokio::test]
async fn test_validate_session_answers_the_owner_and_an_administrator() {
    let f = fixture();
    for token in [
        issue_token(&f.svc.jwt, &f.owner, &["openid".to_string()]),
        issue_admin_token(&f.svc.jwt, f.other.id),
    ] {
        let resp = f
            .svc
            .auth
            .validate_session(authed(validate(&f.session), &token))
            .await
            .expect("answered")
            .into_inner();
        assert!(resp.valid);
        assert_eq!(resp.profile_id, Some(f.owner.id.into()));
        assert!(resp.expires_at.is_some());
    }
}

/// Regression: an expired session was answered with its owner and expiry
/// although the contract sets both only for a valid session. The owner
/// learns it is no longer valid, and nothing more.
#[tokio::test]
async fn test_validate_session_names_no_owner_of_an_expired_session() {
    let owner = test_profile();
    let session = Session::new(
        owner.id,
        None,
        chrono::Utc::now() - chrono::Duration::minutes(1),
    );
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(owner.clone())
            .with_session(session.clone()),
    );
    let token = issue_token(&svc.jwt, &owner, &["openid".to_string()]);
    let resp = svc
        .auth
        .validate_session(authed(validate(&session), &token))
        .await
        .expect("answered")
        .into_inner();
    assert!(!resp.valid);
    assert!(resp.profile_id.is_none());
    assert!(resp.expires_at.is_none());
}
