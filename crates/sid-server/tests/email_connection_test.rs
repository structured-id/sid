// SPDX-License-Identifier: AGPL-3.0-only
//! The email provider connection test answers with a status: OK when the
//! provider accepts the connection, and a canonical refusal saying why not
//! otherwise, never a success flag with the provider's text.

mod common;

use common::mock_storage::MockStorage;
use common::{error_reason, issue_admin_token, test_jwt, test_key_manager, test_revocation};
use secrecy::SecretBox;
use sid_core::models::{AuditEntry, EmailProviderConfig, SmtpAuthMethod, SmtpEncryption};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::admin::realm_service_server::RealmService;
use sid_server::grpc::realm_service::RealmServiceImpl;
use std::sync::Arc;
use tonic::{Code, Request};

fn admin<T>(msg: T) -> Request<T> {
    let token = issue_admin_token(&test_jwt(), sid_core::models::ProfileId::generate());
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn services() -> (RealmServiceImpl, Arc<MockStorage>) {
    let storage = Arc::new(MockStorage::new());
    let svc = RealmServiceImpl::new(
        storage.clone(),
        test_jwt(),
        test_revocation(),
        test_key_manager(),
    );
    (svc, storage)
}

/// A provider without credentials, so nothing needs sealing.
fn provider(host: &str, port: u16, auth_type: SmtpAuthMethod) -> EmailProviderConfig {
    EmailProviderConfig {
        smtp_host: host.into(),
        smtp_port: port,
        from_address: "noreply@sid.example.com".into(),
        from_display_name: String::new(),
        reply_to: String::new(),
        encryption: SmtpEncryption::None,
        auth_type,
        username: String::new(),
        password: SecretBox::new(Box::new(String::new())),
        xoauth2: None,
    }
}

async fn store(storage: &MockStorage, cfg: &EmailProviderConfig) {
    storage
        .upsert_email_provider_config(cfg, AuditEntry::system("test", "email").into())
        .await
        .unwrap();
}

/// Regression: without a provider the test was a bare FAILED_PRECONDITION
/// without a reason. It is FEATURE_NOT_CONFIGURED naming email.
#[tokio::test]
async fn no_provider_is_feature_not_configured() {
    let (svc, _) = services();
    let err = svc
        .test_email_connection(admin(()))
        .await
        .expect_err("no provider");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(
        error_reason(&err).as_deref(),
        Some("FEATURE_NOT_CONFIGURED")
    );
}

/// Regression: a provider that does not answer was OK with `success: false`
/// and its error text. It is DEPENDENCY_UNAVAILABLE with a retry delay.
#[tokio::test]
async fn unreachable_provider_is_unavailable() {
    let (svc, storage) = services();
    store(&storage, &provider("127.0.0.1", 1, SmtpAuthMethod::None)).await;
    let err = svc
        .test_email_connection(admin(()))
        .await
        .expect_err("nothing listens on port 1");
    assert_eq!(err.code(), Code::Unavailable);
    assert_eq!(
        error_reason(&err).as_deref(),
        Some("DEPENDENCY_UNAVAILABLE")
    );
    assert!(sid_core::grpc_error::extract_retry_delay(&err).is_some());
}

/// Regression: a stored XOAUTH2 configuration without its provider details
/// was OK with `success: false`. It is INVALID_STATE: the stored
/// configuration cannot be used until an administrator completes it.
#[tokio::test]
async fn incomplete_xoauth2_is_invalid_state() {
    let (svc, storage) = services();
    store(
        &storage,
        &provider("smtp.office365.com", 587, SmtpAuthMethod::XOAuth2),
    )
    .await;
    let err = svc
        .test_email_connection(admin(()))
        .await
        .expect_err("xoauth2 without its provider");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(error_reason(&err).as_deref(), Some("INVALID_STATE"));
}

/// Settings this build does not implement are FEATURE_NOT_AVAILABLE with a
/// reason, not a bare UNIMPLEMENTED.
#[tokio::test]
async fn unimplemented_settings_name_the_feature() {
    let (svc, _) = services();
    let err = svc
        .get_session_config(admin(()))
        .await
        .expect_err("not in this build");
    assert_eq!(err.code(), Code::Unimplemented);
    assert_eq!(error_reason(&err).as_deref(), Some("FEATURE_NOT_AVAILABLE"));
}
