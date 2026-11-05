// SPDX-License-Identifier: AGPL-3.0-only
//! UpdateCredential changes the label of an active credential only: a revoked
//! credential answers as absent and keeps its state.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, fresh_token};
use sid_core::models::credential::CredentialStatus;
use sid_core::models::{Credential, CredentialType, Profile};
use sid_proto::sid::v1::UpdateCredentialRequest;
use sid_proto::sid::v1::identity_service_server::IdentityService;
use tonic::{Code, Request};

/// `msg` as one new command of `token`'s (a method that promises a safe
/// retry takes an operation key).
fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    common::name_new_command(req.metadata_mut());
    req
}

fn rename(credential: &Credential, label: &str, token: &str) -> Request<UpdateCredentialRequest> {
    authed(
        UpdateCredentialRequest {
            credential_id: Some(common::wire_credential_id(credential.id)),
            label: Some(label.to_string()),
        },
        token,
    )
}

/// An update that names no label changes nothing and is still its command's
/// outcome: a retry of it after a rename answers as the first did, and a
/// key already used for another command is a conflict on it too.
#[tokio::test]
async fn test_an_update_without_a_label_is_recorded_for_its_retry() {
    let profile = Profile::new(Some("unchanged"));
    let credential = Credential::new(profile.id, CredentialType::Totp, vec![1], Some("a".into()));
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_credential(credential.clone()),
    );
    let token = fresh_token(&svc, &profile).await;
    let keyed = |label: Option<&str>, key: &str| {
        let mut req = Request::new(UpdateCredentialRequest {
            credential_id: Some(common::wire_credential_id(credential.id)),
            label: label.map(str::to_owned),
        });
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        common::name_command(req.metadata_mut(), key);
        req
    };
    let first = svc
        .identity
        .update_credential(keyed(None, "k-nothing"))
        .await
        .unwrap()
        .into_inner();
    svc.identity
        .update_credential(keyed(Some("renamed"), "k-rename"))
        .await
        .unwrap();
    let retried = svc
        .identity
        .update_credential(keyed(None, "k-nothing"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(retried, first, "the retry answers as the first attempt");
    let reused = svc
        .identity
        .update_credential(keyed(None, "k-rename"))
        .await
        .unwrap_err();
    assert_eq!(reused.code(), Code::AlreadyExists, "{reused:?}");
}

/// The owner renames an active credential; renaming a revoked one is refused
/// as not found, and its label and status stay as they were.
#[tokio::test]
async fn test_rename_applies_only_to_active_credential() {
    let profile = Profile::new(Some("renaming"));
    let active = Credential::new(profile.id, CredentialType::Totp, vec![1], Some("a".into()));
    let mut revoked = Credential::new(profile.id, CredentialType::Totp, vec![2], Some("r".into()));
    revoked.status = CredentialStatus::Revoked;
    let svc = TestServices::new(
        MockStorage::new()
            .with_profile(profile.clone())
            .with_credential(active.clone())
            .with_credential(revoked.clone()),
    );
    let token = fresh_token(&svc, &profile).await;

    svc.identity
        .update_credential(rename(&active, "phone", &token))
        .await
        .unwrap();
    let refused = svc
        .identity
        .update_credential(rename(&revoked, "revived", &token))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::NotFound);

    let stored = svc
        .storage
        .get_credential(active.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.label.as_deref(), Some("phone"));
    let stored = svc
        .storage
        .get_credential(revoked.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.label.as_deref(), Some("r"));
    assert_eq!(stored.status, CredentialStatus::Revoked);
}
