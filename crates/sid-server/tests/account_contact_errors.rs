// SPDX-License-Identifier: AGPL-3.0-only
//! Refusals of the AccountService phone and email RPCs: another profile's
//! record is not found, the same as one that does not exist, and both name
//! the record in ResourceInfo.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_token, test_profile};
use sid_core::models::AuditEntry;
use sid_proto::sid::v1::account::account_service_server::AccountService;
use sid_proto::sid::v1::account::*;
use tonic::{Code, Request};
use tonic_types::StatusExt;

fn authed_request<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

/// Two signed-in profiles; the first owns one phone and one email.
async fn owner_and_stranger() -> (TestServices, String, String, String) {
    let svc = TestServices::new(MockStorage::new());
    let owner = test_profile();
    let stranger = sid_core::models::Profile::new(Some("mallory"));
    for p in [&owner, &stranger] {
        svc.storage
            .create_profile(p, AuditEntry::system("test", "setup").into())
            .await
            .unwrap();
    }
    let owner_token = issue_token(&svc.jwt, &owner, &["openid".to_string()]);
    let stranger_token = issue_token(&svc.jwt, &stranger, &["openid".to_string()]);
    let phone = svc
        .account
        .add_phone(authed_request(
            AddPhoneRequest {
                e164: 380_501_234_567,
                ..Default::default()
            },
            &owner_token,
        ))
        .await
        .unwrap()
        .into_inner();
    let email = svc
        .account
        .add_email(authed_request(
            AddEmailRequest {
                email: "owner@sid.example.com".to_string(),
                ..Default::default()
            },
            &owner_token,
        ))
        .await
        .unwrap()
        .into_inner();
    (svc, stranger_token, phone.id, email.id)
}

/// Removing another profile's phone is PHONE_NOT_FOUND and leaves it stored.
#[tokio::test]
async fn test_removing_a_foreign_phone_is_phone_not_found() {
    let (svc, stranger, phone_id, _) = owner_and_stranger().await;
    let err = svc
        .account
        .remove_phone(authed_request(
            RemovePhoneRequest {
                phone_id: phone_id.clone(),
            },
            &stranger,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    let details = err.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "PHONE_NOT_FOUND");
    assert_eq!(details.resource_info().unwrap().resource_name, phone_id);
    let id = sid_core::models::profile_phone::ProfilePhoneId(phone_id.parse().unwrap());
    assert!(svc.storage.get_profile_phone(id).await.unwrap().is_some());
}

/// Making another profile's email primary is EMAIL_NOT_FOUND.
#[tokio::test]
async fn test_foreign_email_is_email_not_found() {
    let (svc, stranger, _, email_id) = owner_and_stranger().await;
    let err = svc
        .account
        .set_primary_email(authed_request(
            SetPrimaryEmailRequest {
                email_id: email_id.clone(),
            },
            &stranger,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    let details = err.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "EMAIL_NOT_FOUND");
    assert_eq!(details.resource_info().unwrap().resource_name, email_id);
}

/// Regression: an added email was lowercased (and otherwise unchecked), so
/// mail went to another spelling than the one given and malformed text was
/// stored as an address. The contact keeps the validated spelling; a
/// malformed address is a BadRequest violation on `email`.
#[tokio::test]
async fn test_added_email_keeps_its_spelling_and_is_validated() {
    let (svc, stranger, _, _) = owner_and_stranger().await;
    let added = svc
        .account
        .add_email(authed_request(
            AddEmailRequest {
                email: "Mallory.Work+News@SID.example.com".to_string(),
                ..Default::default()
            },
            &stranger,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(added.email, "Mallory.Work+News@sid.example.com");

    for malformed in ["not an address", "a@", "a..b@sid.example.com"] {
        let err = svc
            .account
            .add_email(authed_request(
                AddEmailRequest {
                    email: malformed.to_string(),
                    ..Default::default()
                },
                &stranger,
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{malformed}");
        assert_eq!(
            err.get_error_details()
                .bad_request()
                .unwrap()
                .field_violations[0]
                .field,
            "email"
        );
    }
}

/// A malformed phone identifier is a BadRequest violation on `phone_id`.
#[tokio::test]
async fn test_malformed_phone_id_is_invalid_field() {
    let (svc, stranger, _, _) = owner_and_stranger().await;
    let err = svc
        .account
        .remove_phone(authed_request(
            RemovePhoneRequest {
                phone_id: "not-a-uuid".to_string(),
            },
            &stranger,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    let details = err.get_error_details();
    assert_eq!(details.error_info().unwrap().reason, "INVALID_FIELD_VALUE");
    assert_eq!(
        details.bad_request().unwrap().field_violations[0].field,
        "phone_id"
    );
}
