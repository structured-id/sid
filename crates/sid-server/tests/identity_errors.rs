// SPDX-License-Identifier: AGPL-3.0-only
//! IdentityService refusals: each names its cause in ErrorInfo, another
//! profile's record is not found as an unknown one is, and a failed read or
//! an unknown input is refused instead of answered as something else.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, issue_admin_token, issue_token, test_profile};
use sid_core::models::device::MAX_TRUSTED_DEVICES;
use sid_core::models::{
    AuditEntry, Credential, CredentialType, Device, DeviceType, Profile, ProfileId, ProfileStatus,
};
use sid_proto::sid::v1::identity_service_server::IdentityService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request, Status};
use tonic_types::StatusExt;

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn reason(err: &Status) -> String {
    err.get_error_details().error_info().unwrap().reason.clone()
}

/// Services with two signed-in profiles; returns them with their tokens.
async fn owner_and_stranger() -> (TestServices, Profile, String, String) {
    let svc = TestServices::new(MockStorage::new());
    let owner = test_profile();
    let stranger = Profile::new(Some("mallory"));
    for p in [&owner, &stranger] {
        svc.storage
            .create_profile(p, AuditEntry::system("test", "setup").into())
            .await
            .unwrap();
    }
    let owner_token = issue_token(&svc.jwt, &owner, &["openid".to_string()]);
    let stranger_token = issue_token(&svc.jwt, &stranger, &["openid".to_string()]);
    (svc, owner, owner_token, stranger_token)
}

/// A device stored for `profile`, trusted as given.
async fn device(svc: &TestServices, profile: ProfileId, trusted: bool) -> Device {
    let mut d = Device::new(profile, DeviceType::Desktop);
    d.trusted = trusted;
    svc.storage
        .create_device(&d, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    d
}

/// Regression: another profile's device was refused with PERMISSION_DENIED,
/// which told the caller the device exists.
#[tokio::test]
async fn test_foreign_device_is_device_not_found() {
    let (svc, owner, _, stranger) = owner_and_stranger().await;
    let d = device(&svc, owner.id, false).await;
    let err = svc
        .identity
        .get_device(authed(
            GetDeviceRequest {
                device_id: d.id.to_string(),
            },
            &stranger,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(reason(&err), "DEVICE_NOT_FOUND");
    assert_eq!(
        err.get_error_details()
            .resource_info()
            .unwrap()
            .resource_name,
        d.id.to_string()
    );
}

/// Regression: removing a device was audited as the system, not as the user
/// who removed it.
#[tokio::test]
async fn test_device_removal_is_audited_as_the_user() {
    let (svc, owner, owner_token, _) = owner_and_stranger().await;
    let d = device(&svc, owner.id, false).await;
    svc.identity
        .remove_device(authed(
            RemoveDeviceRequest {
                device_id: d.id.to_string(),
            },
            &owner_token,
        ))
        .await
        .unwrap();
    let audits = svc.mock_storage.device_audits();
    let removal = audits.last().unwrap();
    assert_eq!(removal.actor_id, owner.id.to_string());
    assert!(svc.storage.get_device(d.id).await.unwrap().is_none());
}

/// Trusting a device past the limit is QUOTA_EXCEEDED naming the limit, not
/// a state precondition: untrusting another device makes room.
#[tokio::test]
async fn test_trusted_device_limit_is_quota_exceeded() {
    let (svc, owner, owner_token, _) = owner_and_stranger().await;
    for _ in 0..MAX_TRUSTED_DEVICES {
        device(&svc, owner.id, true).await;
    }
    let extra = device(&svc, owner.id, false).await;
    let err = svc
        .identity
        .trust_device(authed(
            TrustDeviceRequest {
                device_id: extra.id.to_string(),
            },
            &owner_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(reason(&err), "QUOTA_EXCEEDED");
    assert_eq!(
        err.get_error_details().quota_failure().unwrap().violations[0].subject,
        "trusted_devices"
    );
}

/// Regression: another profile's credential was refused with
/// PERMISSION_DENIED, which told the caller it exists.
#[tokio::test]
async fn test_foreign_credential_is_credential_not_found() {
    let (svc, owner, _, stranger) = owner_and_stranger().await;
    let cred = Credential::new(owner.id, CredentialType::Totp, vec![1, 2, 3], None);
    svc.storage
        .create_credential(&cred, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    let err = svc
        .identity
        .update_credential(authed(
            UpdateCredentialRequest {
                credential_id: cred.id.0.to_string(),
                label: Some("mine now".to_string()),
            },
            &stranger,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(reason(&err), "CREDENTIAL_NOT_FOUND");
}

/// Regression: a failed read of the profile's passkeys answered "no passkey",
/// so the client prompted (or under the Required mode demanded) a passkey
/// the profile may already have.
#[tokio::test]
async fn test_passkey_prompt_state_fails_when_credentials_are_unreadable() {
    let (svc, _, owner_token, _) = owner_and_stranger().await;
    svc.mock_storage.fail_credential_reads();
    let err = svc
        .identity
        .get_passkey_prompt_state(authed(GetPasskeyPromptStateRequest {}, &owner_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(reason(&err), "INTERNAL_ERROR");
}

/// Regression: an unknown revocation reason was recorded as an administrative
/// revocation and carried out.
#[tokio::test]
async fn test_unknown_revocation_reason_is_refused() {
    let (svc, owner, _, _) = owner_and_stranger().await;
    let admin = issue_admin_token(&svc.jwt, ProfileId::generate());
    let err = svc
        .identity
        .revoke_profile(authed(
            RevokeProfileRequest {
                profile_id: owner.id.to_string(),
                reason: "because".to_string(),
            },
            &admin,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(reason(&err), "INVALID_FIELD_VALUE");
    assert_eq!(
        err.get_error_details()
            .bad_request()
            .unwrap()
            .field_violations[0]
            .field,
        "reason"
    );
    let stored = svc.storage.get_profile(owner.id).await.unwrap().unwrap();
    assert_eq!(stored.status, ProfileStatus::Active);
}

/// Regression: ListProfiles ignored page_token and answered every request
/// with the first page, so an administrator never saw past it.
#[tokio::test]
async fn test_list_profiles_pages_follow_the_token() {
    let (svc, _, _, _) = owner_and_stranger().await;
    let admin = issue_admin_token(&svc.jwt, ProfileId::generate());
    let total = svc.storage.count_profiles().await.unwrap() as usize;
    let mut seen = Vec::new();
    let mut token = String::new();
    loop {
        let page = svc
            .identity
            .list_profiles(authed(
                ListProfilesRequest {
                    page_size: 2,
                    page_token: token.clone(),
                },
                &admin,
            ))
            .await
            .unwrap()
            .into_inner();
        seen.extend(page.profiles.into_iter().map(|p| p.id));
        if page.next_page_token.is_empty() {
            break;
        }
        token = page.next_page_token;
    }
    let distinct: std::collections::BTreeSet<_> = seen.iter().cloned().collect();
    assert_eq!(seen.len(), total, "every profile once");
    assert_eq!(distinct.len(), total);
}

/// A page token the service did not issue is refused, not read as the first
/// page.
#[tokio::test]
async fn test_list_profiles_refuses_a_foreign_token() {
    let svc = TestServices::new(MockStorage::new());
    let admin = issue_admin_token(&svc.jwt, ProfileId::generate());
    for token in ["garbage", "-1", "99999999999999999999"] {
        let err = svc
            .identity
            .list_profiles(authed(
                ListProfilesRequest {
                    page_size: 2,
                    page_token: token.to_string(),
                },
                &admin,
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{token}");
        assert_eq!(reason(&err), "INVALID_FIELD_VALUE", "{token}");
    }
}
