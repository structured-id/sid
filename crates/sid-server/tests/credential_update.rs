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

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn rename(credential: &Credential, label: &str, token: &str) -> Request<UpdateCredentialRequest> {
    authed(
        UpdateCredentialRequest {
            credential_id: credential.id.0.to_string(),
            label: Some(label.to_string()),
        },
        token,
    )
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
