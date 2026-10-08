// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization of RealmService: only an administrator reads or replaces the
//! email provider. Whoever controls it receives every outgoing magic link and
//! reset email, so an unverified header must not be enough.

mod common;

use common::mock_storage::MockStorage;
use common::{issue_admin_token, issue_token, test_jwt, test_revocation};
use sid_core::models::Profile;
use sid_proto::sid::v1::admin::EmailSettings;
use sid_proto::sid::v1::admin::realm_service_server::RealmService;
use sid_server::grpc::realm_service::RealmServiceImpl;
use std::sync::Arc;
use tonic::{Code, Request};

fn service() -> RealmServiceImpl {
    RealmServiceImpl::new(
        Arc::new(MockStorage::new()),
        test_jwt(),
        test_revocation(),
        common::test_key_manager(),
    )
}

fn attacker_smtp() -> EmailSettings {
    EmailSettings {
        smtp_host: "smtp.attacker.example.com".to_string(),
        smtp_port: 587,
        from_address: "noreply@sid.example.com".to_string(),
        ..Default::default()
    }
}

fn with_header<T>(msg: T, name: &'static str, value: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(name, value.parse().unwrap());
    req
}

/// Regression:an arbitrary `x-admin-profile-id` or `authorization`
/// value is not an administrator.
#[tokio::test]
async fn test_realm_refuses_an_unverified_header() {
    let svc = service();
    let err = svc
        .update_email_settings(with_header(
            attacker_smtp(),
            "x-admin-profile-id",
            "anything",
        ))
        .await
        .expect_err("unverified header");
    assert_eq!(err.code(), Code::Unauthenticated);

    let err = svc
        .update_email_settings(with_header(attacker_smtp(), "authorization", "Bearer x"))
        .await
        .expect_err("invalid token");
    assert_eq!(err.code(), Code::Unauthenticated);

    let err = svc
        .get_email_settings(Request::new(()))
        .await
        .expect_err("no token");
    assert_eq!(err.code(), Code::Unauthenticated);
}

/// Regression:a signed-in user without the administrator role cannot
/// replace the email provider.
#[tokio::test]
async fn test_realm_refuses_a_non_admin() {
    let svc = service();
    let user = Profile::new(Some("mallory"));
    let token = issue_token(&test_jwt(), &user, &["openid".to_string()]);
    let err = svc
        .update_email_settings(with_header(
            attacker_smtp(),
            "authorization",
            &format!("Bearer {token}"),
        ))
        .await
        .expect_err("not an administrator");
    assert_eq!(err.code(), Code::PermissionDenied);
}

/// An administrator replaces the email provider.
#[tokio::test]
async fn test_realm_allows_an_administrator() {
    let svc = service();
    let token = issue_admin_token(&test_jwt(), sid_core::models::ProfileId::generate());
    svc.update_email_settings(with_header(
        attacker_smtp(),
        "authorization",
        &format!("Bearer {token}"),
    ))
    .await
    .expect("admin updates");
}
