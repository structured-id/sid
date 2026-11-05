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

/// `msg` as one new command of `token`'s (a method that promises a safe
/// retry takes an operation key).
fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    common::name_new_command(req.metadata_mut());
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

/// `cred`'s id as a request names it.
fn wire_credential(cred: &Credential) -> sid_ids_proto::CredentialId {
    common::wire_credential_id(cred.id)
}

/// A TOTP credential stored for `profile`.
async fn credential(svc: &TestServices, profile: ProfileId) -> Credential {
    let cred = Credential::new(profile, CredentialType::Totp, vec![1, 2, 3], None);
    svc.storage
        .create_credential(&cred, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    cred
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
                device_id: Some(d.id.into()),
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
                device_id: Some(d.id.into()),
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
                device_id: Some(extra.id.into()),
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
    let cred = credential(&svc, owner.id).await;
    let err = svc
        .identity
        .update_credential(authed(
            UpdateCredentialRequest {
                credential_id: Some(wire_credential(&cred)),
                label: Some("mine now".to_string()),
            },
            &stranger,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(reason(&err), "CREDENTIAL_NOT_FOUND");
}

/// A self-service listing that names no Profile acts on the caller's own,
/// resolved from its session: the client never sends its own ProfileId.
#[tokio::test]
async fn test_listing_without_a_profile_lists_the_callers_own() {
    let (svc, owner, owner_token, stranger) = owner_and_stranger().await;
    let own = credential(&svc, owner.id).await;
    let listed = svc
        .identity
        .list_credentials(authed(
            ListCredentialsRequest { profile_id: None },
            &owner_token,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.credentials.len(), 1);
    assert_eq!(listed.credentials[0].id, Some(wire_credential(&own)));

    // Another caller's own listing never includes it.
    let theirs = svc
        .identity
        .list_credentials(authed(
            ListCredentialsRequest { profile_id: None },
            &stranger,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(theirs.credentials.is_empty());
}

/// Regression: a session signed in with a User-Agent stores that agent's
/// fingerprint (a version-4 UUID) for the new-device rule; listing it as a
/// managed device id refused it as corruption and failed the whole listing.
/// A fingerprint is no registered device: the listing names none.
#[tokio::test]
async fn test_a_session_fingerprint_is_not_listed_as_a_device() {
    let (svc, owner, owner_token, _) = owner_and_stranger().await;
    let mut session = sid_core::models::Session::new(
        owner.id,
        None,
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    session.device_id = Some(sid_authn::sign_in_security::device_id("Mozilla/5.0"));
    svc.storage
        .create_session(&session, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();

    let listed = svc
        .identity
        .list_sessions(authed(
            ListSessionsRequest { profile_id: None },
            &owner_token,
        ))
        .await
        .expect("the listing answers")
        .into_inner()
        .sessions;
    let found = listed
        .iter()
        .find(|s| s.id == Some(session.id.into()))
        .expect("the session is listed");
    assert_eq!(found.device_id, None);
}

/// Naming another Profile takes administrator authority; a user is refused
/// before anything about that Profile is read.
#[tokio::test]
async fn test_naming_another_profile_takes_admin() {
    let (svc, owner, _, stranger) = owner_and_stranger().await;
    credential(&svc, owner.id).await;
    let err = svc
        .identity
        .list_credentials(authed(
            ListCredentialsRequest {
                profile_id: Some(owner.id.into()),
            },
            &stranger,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);

    let admin = issue_admin_token(&svc.jwt, ProfileId::generate());
    let listed = svc
        .identity
        .list_credentials(authed(
            ListCredentialsRequest {
                profile_id: Some(owner.id.into()),
            },
            &admin,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.credentials.len(), 1);
}

/// A reference that is not a valid identifier of its kind is refused on its
/// field before any lookup, never read as absent (the caller's own).
#[tokio::test]
async fn test_a_malformed_reference_is_refused_on_its_field() {
    let (svc, _, owner_token, _) = owner_and_stranger().await;
    let malformed = sid_ids_proto::ProfileId { value: vec![0; 3] };
    let err = svc
        .identity
        .list_credentials(authed(
            ListCredentialsRequest {
                profile_id: Some(malformed),
            },
            &owner_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        err.get_error_details()
            .bad_request()
            .unwrap()
            .field_violations[0]
            .field,
        "profile_id"
    );

    // A required reference left out is refused on its field too.
    let err = svc
        .identity
        .revoke_credential(authed(
            RevokeCredentialRequest {
                credential_id: None,
            },
            &owner_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        err.get_error_details()
            .bad_request()
            .unwrap()
            .field_violations[0]
            .field,
        "credential_id"
    );
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
                profile_id: Some(owner.id.into()),
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
        seen.extend(
            page.profiles
                .into_iter()
                .map(|p| sid_ids_proto::required(p.id.as_ref()).unwrap()),
        );
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
