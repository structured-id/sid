// SPDX-License-Identifier: AGPL-3.0-only
//! Ceremonies across replicas: a login or registration started on one
//! replica finishes on another, exactly once, and an unknown principal is
//! refused at finish exactly like a wrong password. A token revoked on one
//! replica is refused by the other.

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use common::opaque_client::{register, start_login};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::Request;

const PASSWORD: &[u8] = b"replica-strong-password-2026";

/// An access token the installation's issuer gives the confidential client
/// for a profile registered through `svc` under `email`.
async fn application_token(svc: &TestServices, email: &str) -> String {
    register(svc, svc, email, PASSWORD).await;
    let profile = svc
        .storage
        .get_profile_by_email(email)
        .await
        .unwrap()
        .expect("registered profile");
    common::issue_application_token_to(
        svc,
        &profile,
        &["openid".to_string()],
        common::CONFIDENTIAL_CLIENT,
    )
    .await
}

/// Two replicas over one store holding the confidential client, which may
/// inspect the tokens of the resource its tokens are for; the permission is
/// granted once, through one replica.
async fn replicas() -> (TestServices, TestServices) {
    let (a, b) =
        TestServices::replicas(MockStorage::new().with_client(common::confidential_client())).await;
    common::grant_inspection(
        &a,
        sid_core::models::RoleAssignmentPrincipal::OAuthClient(common::CONFIDENTIAL_CLIENT.into()),
        common::userinfo_resource(&a).await,
    )
    .await;
    (a, b)
}

/// Whether `svc` reports `token` active to the confidential client.
async fn active_at(svc: &TestServices, token: &str) -> bool {
    svc.auth
        .o_auth2_introspect(common::as_client(
            OAuth2IntrospectRequest {
                token: token.to_string(),
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            common::CONFIDENTIAL_CLIENT,
            common::CONFIDENTIAL_SECRET,
        ))
        .await
        .unwrap()
        .into_inner()
        .active
}

/// `token` revoked at `svc` by the client it was issued to.
async fn revoke_at(svc: &TestServices, token: &str) {
    svc.auth
        .o_auth2_revoke(common::as_client(
            OAuth2RevokeRequest {
                token: token.to_string(),
                issuer_handle: svc.issuer.handle.to_string(),
                ..Default::default()
            },
            common::CONFIDENTIAL_CLIENT,
            common::CONFIDENTIAL_SECRET,
        ))
        .await
        .unwrap();
}

/// A registration and a login started on one replica finish on the other,
/// and a password registered through one replica signs in through the other.
#[tokio::test]
async fn opaque_ceremonies_finish_on_another_replica() {
    let (a, b) = TestServices::replicas(MockStorage::new()).await;
    register(&a, &b, "replica@sid.example.com", PASSWORD).await;

    let finish = start_login(&b, "replica@sid.example.com", PASSWORD).await;
    let signed_in = a
        .auth
        .opaque_login_finish(Request::new(finish))
        .await
        .unwrap()
        .into_inner();

    assert!(!signed_in.access_token.is_empty());
}

/// A password registered before a restart signs in after it: the restarted
/// process loads the same OPAQUE server setup instead of creating a new one.
#[tokio::test]
async fn password_survives_a_restart() {
    let (a, _) = TestServices::replicas(MockStorage::new()).await;
    register(&a, &a, "restart@sid.example.com", PASSWORD).await;

    let after = a.restarted().await;
    let finish = start_login(&after, "restart@sid.example.com", PASSWORD).await;
    let signed_in = after
        .auth
        .opaque_login_finish(Request::new(finish))
        .await
        .unwrap()
        .into_inner();

    assert!(!signed_in.access_token.is_empty());
}

/// The login state is consumed once across replicas: the same finish sent
/// again, to either replica, is refused.
#[tokio::test]
async fn opaque_login_state_is_single_use_across_replicas() {
    let (a, b) = TestServices::replicas(MockStorage::new()).await;
    register(&a, &a, "once@sid.example.com", PASSWORD).await;
    let finish = start_login(&a, "once@sid.example.com", PASSWORD).await;

    b.auth
        .opaque_login_finish(Request::new(finish.clone()))
        .await
        .unwrap();
    let replay = a
        .auth
        .opaque_login_finish(Request::new(finish))
        .await
        .unwrap_err();

    // A consumed state reads as an expired sign-in: start again.
    assert_eq!(replay.code(), tonic::Code::FailedPrecondition);
    let details = tonic_types::StatusExt::get_error_details(&replay);
    assert_eq!(details.error_info().unwrap().reason, "INVALID_STATE");
    assert_eq!(
        details.precondition_failure().unwrap().violations[0].subject,
        "sign-in"
    );
}

/// An access token revoked on one replica stops being active on the other
/// replica, which never saw the revocation request.
#[tokio::test]
async fn revocation_on_one_replica_reaches_the_other() {
    let (a, b) = replicas().await;
    let token = application_token(&a, "revoked@sid.example.com").await;
    assert!(
        active_at(&b, &token).await,
        "issued token is active everywhere"
    );

    revoke_at(&a, &token).await;

    // Propagation is asynchronous; it must land well within a second.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while active_at(&b, &token).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "revocation never reached the other replica"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A replica started after a token was revoked (scale-out, rollout, restart)
/// refuses it too, although it never received the revocation message.
#[tokio::test]
async fn revocation_before_a_replica_starts_holds_there() {
    let (a, _) = replicas().await;
    let token = application_token(&a, "late@sid.example.com").await;
    revoke_at(&a, &token).await;

    let late = a.restarted().await;
    assert!(
        !active_at(&late, &token).await,
        "a replica started after the revocation accepts the token"
    );
}

/// A login for a principal nobody holds is refused at finish with the same
/// answer as a wrong password, so the finish does not reveal whether the
/// account exists.
#[tokio::test]
async fn unknown_principal_fails_like_a_wrong_password() {
    let (a, b) = TestServices::replicas(MockStorage::new()).await;
    register(&a, &a, "known@sid.example.com", PASSWORD).await;

    let wrong_password = start_login(&a, "known@sid.example.com", b"not-the-password").await;
    let known = b
        .auth
        .opaque_login_finish(Request::new(wrong_password))
        .await
        .unwrap_err();
    let unknown = b
        .auth
        .opaque_login_finish(Request::new(
            start_login(&a, "nobody@sid.example.com", PASSWORD).await,
        ))
        .await
        .unwrap_err();

    assert_eq!(known.code(), tonic::Code::Unauthenticated);
    assert_eq!(unknown.code(), known.code());
    assert_eq!(unknown.message(), known.message());
}
