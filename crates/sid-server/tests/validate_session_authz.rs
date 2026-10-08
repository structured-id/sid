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
        "127.0.0.1".to_string(),
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
        session_id: session.id.to_string(),
    }
}

/// Regression (#881): without a token the RPC answers nothing.
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

/// Regression (#881): another user learns neither the owner nor the validity
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
        assert_eq!(resp.profile_id, Some(f.owner.id.to_string()));
    }
}
