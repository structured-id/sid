// SPDX-License-Identifier: AGPL-3.0-only
//! The email provider's credentials are stored only sealed under the key
//! manager (SMTP password, XOAUTH2 client secret and service-account key):
//! whoever holds them sends mail as the instance, so a database dump must not
//! yield them.

mod common;

use common::mock_storage::MockStorage;
use common::{issue_admin_token, test_jwt, test_key_manager, test_revocation};
use secrecy::{ExposeSecret, SecretBox};
use sid_core::models::{AuditEntry, EmailProviderConfig, SmtpAuthMethod, SmtpEncryption};
use sid_plugin::StorageBackend;
use sid_proto::sid::v1::admin::realm_service_server::RealmService;
use sid_proto::sid::v1::admin::{EmailSettings, SmtpAuthType, XoAuth2ProviderType};
use sid_server::grpc::realm_service::{
    RealmServiceImpl, SMTP_PASSWORD_CONTEXT, XOAUTH2_CLIENT_SECRET_CONTEXT,
};
use std::sync::Arc;
use tonic::Request;

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

/// The stored value holds `plain` only sealed for `context`.
async fn assert_sealed(stored: &str, context: &str, plain: &str) {
    assert!(!stored.contains(plain), "the credential is stored in clear");
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, stored)
        .expect("stored as encoded sealed bytes");
    let opened = sid_authn::sealed_secret::open(test_key_manager().as_ref(), context, &bytes)
        .await
        .expect("sealed for its field");
    assert_eq!(opened.secret.as_slice(), plain.as_bytes());
}

/// An SMTP password is stored sealed, and a later update that leaves it out
/// keeps the same password.
#[tokio::test]
async fn smtp_password_is_stored_sealed() {
    let (svc, storage) = services();
    svc.update_email_settings(admin(EmailSettings {
        smtp_host: "smtp.sid.example.com".into(),
        smtp_port: 587,
        from_address: "noreply@sid.example.com".into(),
        auth_type: SmtpAuthType::UsernamePassword as i32,
        username: "mailer".into(),
        password: "correct horse battery".into(),
        ..Default::default()
    }))
    .await
    .unwrap();
    let stored = storage.get_email_provider_config().await.unwrap().unwrap();
    assert_sealed(
        stored.password.expose_secret(),
        SMTP_PASSWORD_CONTEXT,
        "correct horse battery",
    )
    .await;

    // Updating the host without a password keeps the stored one.
    svc.update_email_settings(admin(EmailSettings {
        smtp_host: "smtp2.sid.example.com".into(),
        smtp_port: 587,
        from_address: "noreply@sid.example.com".into(),
        auth_type: SmtpAuthType::UsernamePassword as i32,
        username: "mailer".into(),
        ..Default::default()
    }))
    .await
    .unwrap();
    let stored = storage.get_email_provider_config().await.unwrap().unwrap();
    assert_sealed(
        stored.password.expose_secret(),
        SMTP_PASSWORD_CONTEXT,
        "correct horse battery",
    )
    .await;
}

/// An XOAUTH2 client secret is stored sealed for its own field.
#[tokio::test]
async fn xoauth2_client_secret_is_stored_sealed() {
    let (svc, storage) = services();
    svc.update_email_settings(admin(EmailSettings {
        smtp_host: "smtp.office365.com".into(),
        smtp_port: 587,
        from_address: "noreply@sid.example.com".into(),
        auth_type: SmtpAuthType::Xoauth2 as i32,
        username: "mailer@sid.example.com".into(),
        xoauth2_provider: XoAuth2ProviderType::Xoauth2ProviderTypeM365 as i32,
        xoauth2_client_id: "client".into(),
        xoauth2_client_secret: "xoauth-secret-value".into(),
        ..Default::default()
    }))
    .await
    .unwrap();
    let stored = storage.get_email_provider_config().await.unwrap().unwrap();
    let x = stored.xoauth2.expect("xoauth2 stored");
    assert_sealed(
        x.client_secret.expose_secret(),
        XOAUTH2_CLIENT_SECRET_CONTEXT,
        "xoauth-secret-value",
    )
    .await;
}

/// A credential stored in clear (or sealed for another field) is refused
/// rather than used to send mail.
#[tokio::test]
async fn unsealed_stored_credential_is_refused() {
    let (svc, storage) = services();
    storage
        .upsert_email_provider_config(
            &EmailProviderConfig {
                smtp_host: "smtp.sid.example.com".into(),
                smtp_port: 587,
                from_address: "noreply@sid.example.com".into(),
                from_display_name: String::new(),
                reply_to: String::new(),
                encryption: SmtpEncryption::Starttls,
                auth_type: SmtpAuthMethod::UsernamePassword,
                username: "mailer".into(),
                password: SecretBox::new(Box::new("plain-password".into())),
                xoauth2: None,
            },
            AuditEntry::system("test", "email").into(),
        )
        .await
        .unwrap();
    let err = svc
        .test_email_connection(admin(()))
        .await
        .expect_err("a clear credential was used");
    assert_eq!(err.code(), tonic::Code::Internal);
}
