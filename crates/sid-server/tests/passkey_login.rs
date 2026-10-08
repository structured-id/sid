// SPDX-License-Identifier: AGPL-3.0-only
//! Passkey sign-in with a software authenticator: what a successful assertion
//! records on the stored credential, which credentials may sign in, and how a
//! discoverable assertion finds its account only through the stored
//! user-handle association.

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use sid_authn::webauthn::soft_authenticator::SoftAuthenticator;
use sid_core::models::{AuditEntry, Credential, CredentialType, Principal, PrincipalType, Profile};
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::{Request, Status};

const ORIGIN: &str = "https://sid.example.com";
const RP: &str = "sid.example.com";
const EMAIL: &str = "passkey@sid.example.com";

fn authed<T>(msg: T, bearer: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    req
}

/// Register a passkey on `key` for `profile`, from a fresh session strong
/// enough to add one next to an existing passkey.
async fn register(svc: &TestServices, profile: &Profile, key: &mut SoftAuthenticator) {
    let session = common::authenticated_session(profile, sid_core::models::AuthLevel::Standard, 0);
    let bearer = common::stored_session_token(svc, profile, session).await;
    let start = svc
        .auth
        .web_authn_registration_start(authed(Default::default(), &bearer))
        .await
        .unwrap()
        .into_inner();
    svc.auth
        .web_authn_registration_finish(authed(
            WebAuthnRegistrationFinishRequest {
                credential: key.register(&start.options),
                ..Default::default()
            },
            &bearer,
        ))
        .await
        .unwrap();
}

/// An account whose email principal signs in with one registered passkey.
async fn account_with_passkey() -> (TestServices, Profile, SoftAuthenticator) {
    let profile = Profile::new(Some("passkey_user"));
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    svc.storage
        .save_principal(
            &Principal::new(profile.id, PrincipalType::Email, EMAIL),
            AuditEntry::system("test", "principal").into(),
        )
        .await
        .unwrap();
    let mut key = SoftAuthenticator::new(ORIGIN, RP);
    register(&svc, &profile, &mut key).await;
    (svc, profile, key)
}

async fn login(
    svc: &TestServices,
    key: &mut SoftAuthenticator,
) -> Result<WebAuthnAuthenticationFinishResponse, Status> {
    let start = svc
        .auth
        .web_authn_authentication_start(Request::new(WebAuthnAuthenticationStartRequest {
            principal: Some(EMAIL.to_string()),
        }))
        .await?
        .into_inner();
    svc.auth
        .web_authn_authentication_finish(Request::new(WebAuthnAuthenticationFinishRequest {
            credential: key.assert(&start.options),
            principal: Some(EMAIL.to_string()),
            ..Default::default()
        }))
        .await
        .map(|r| r.into_inner())
}

/// A sign-in that names no account: the browser picks a discoverable
/// credential and returns its user handle.
async fn discoverable_login(
    svc: &TestServices,
    key: &mut SoftAuthenticator,
) -> Result<WebAuthnAuthenticationFinishResponse, Status> {
    let start = svc
        .auth
        .web_authn_authentication_start(Request::new(WebAuthnAuthenticationStartRequest {
            principal: None,
        }))
        .await?
        .into_inner();
    svc.auth
        .web_authn_authentication_finish(Request::new(WebAuthnAuthenticationFinishRequest {
            credential: key.assert(&start.options),
            ..Default::default()
        }))
        .await
        .map(|r| r.into_inner())
}

async fn passkeys(svc: &TestServices, profile: &Profile) -> Vec<Credential> {
    svc.storage
        .get_credentials_by_profile(profile.id, Some(CredentialType::WebAuthn))
        .await
        .unwrap()
}

async fn passkey(svc: &TestServices, profile: &Profile) -> Credential {
    let mut creds = passkeys(svc, profile).await;
    assert_eq!(creds.len(), 1);
    creds.remove(0)
}

async fn signed_in_profile(
    svc: &TestServices,
    signed_in: &WebAuthnAuthenticationFinishResponse,
) -> sid_core::models::ProfileId {
    let id = sid_core::models::SessionId::parse(&signed_in.session_id).unwrap();
    svc.storage
        .get_session(id)
        .await
        .unwrap()
        .unwrap()
        .profile_id
}

/// Each sign-in stores the authenticator's signature counter and when the
/// credential was used; without it the counter check compares against the
/// registration value forever and a cloned authenticator is never noticed.
#[tokio::test]
async fn test_login_records_counter_and_last_use() {
    let (svc, profile, mut key) = account_with_passkey().await;
    let registered = passkey(&svc, &profile).await;

    login(&svc, &mut key).await.unwrap();
    let after_first = passkey(&svc, &profile).await;
    assert_ne!(
        after_first.data.expose(),
        registered.data.expose(),
        "the counter of the assertion was not stored"
    );
    assert!(after_first.last_used_at.is_some(), "last use not recorded");

    login(&svc, &mut key).await.unwrap();
    assert_ne!(
        passkey(&svc, &profile).await.data.expose(),
        after_first.data.expose()
    );
}

async fn session_amr(
    svc: &TestServices,
    signed_in: &WebAuthnAuthenticationFinishResponse,
) -> Vec<String> {
    let id = sid_core::models::SessionId::parse(&signed_in.session_id).unwrap();
    svc.storage.get_session(id).await.unwrap().unwrap().amr
}

fn amr(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

/// A passkey is recorded as a hardware-bound key (`hwk`, RFC 8176 §2) only
/// with evidence that it is one; a synced passkey is a software-secured key
/// (`swk`), so a site that requires `hwk` is not satisfied by it. The
/// authenticator verified the user, which SID records as `mfa` next to proof
/// of possession (`pop`), never as a biometric or PIN method it did not see.
#[tokio::test]
async fn test_synced_passkey_is_swk() {
    let (svc, _profile, mut key) = account_with_passkey().await;
    let signed_in = login(&svc, &mut key).await.unwrap();
    assert_eq!(
        session_amr(&svc, &signed_in).await,
        amr(&["swk", "pop", "mfa"])
    );
}

/// A device-bound key reached over USB is a hardware-secured key (`hwk`).
#[tokio::test]
async fn test_device_bound_usb_passkey_is_hwk() {
    let profile = Profile::new(Some("passkey_user"));
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    svc.storage
        .save_principal(
            &Principal::new(profile.id, PrincipalType::Email, EMAIL),
            AuditEntry::system("test", "principal").into(),
        )
        .await
        .unwrap();
    let mut key = SoftAuthenticator::new(ORIGIN, RP);
    key.behavior.transports = vec!["usb"];
    key.behavior.backup_eligible = false;
    key.behavior.backed_up = false;
    key.behavior.attachment = "cross-platform";
    register(&svc, &profile, &mut key).await;

    let signed_in = login(&svc, &mut key).await.unwrap();
    assert_eq!(
        session_amr(&svc, &signed_in).await,
        amr(&["hwk", "pop", "mfa"])
    );
}

/// An assertion whose counter is not above the stored one comes from a copy
/// of the key (WebAuthn Level 3 §7.2 step 22): the sign-in is refused.
#[tokio::test]
async fn test_counter_regression_is_refused() {
    let (svc, _profile, mut key) = account_with_passkey().await;
    key.behavior.counter = Some(10);
    login(&svc, &mut key).await.unwrap();
    key.behavior.counter = Some(3);
    let refused = login(&svc, &mut key).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Unauthenticated);
}

/// The account keeps a way to sign in: a TOTP next to the only passkey does
/// not make the passkey removable through either RPC.
#[tokio::test]
async fn test_last_passkey_is_not_removed() {
    use sid_proto::sid::v1::identity_service_server::IdentityService;

    let (svc, profile, _key) = account_with_passkey().await;
    let totp = Credential::new(profile.id, CredentialType::Totp, vec![7], None);
    svc.storage
        .create_credential(&totp, AuditEntry::system("test", "totp").into())
        .await
        .unwrap();
    let only = passkey(&svc, &profile).await;
    // Signed in with the passkey: enough to remove it, were it not the last.
    let session = common::authenticated_session(&profile, sid_core::models::AuthLevel::Standard, 0);
    let bearer = common::stored_session_token(&svc, &profile, session).await;

    let refused = svc
        .identity
        .revoke_credential(authed(
            RevokeCredentialRequest {
                credential_id: only.id.0.to_string(),
            },
            &bearer,
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(passkey(&svc, &profile).await.status.is_active());

    // The TOTP itself can go.
    svc.identity
        .revoke_credential(authed(
            RevokeCredentialRequest {
                credential_id: totp.id.0.to_string(),
            },
            &bearer,
        ))
        .await
        .unwrap();
}

/// A revoked passkey no longer signs in, by identifier or discoverable.
#[tokio::test]
async fn test_revoked_passkey_cannot_sign_in() {
    let (svc, profile, mut key) = account_with_passkey().await;
    let mut stored = passkey(&svc, &profile).await;
    stored.status = sid_core::models::credential::CredentialStatus::Revoked;
    svc.mock_storage.set_credential(&stored);

    assert!(
        login(&svc, &mut key).await.is_err(),
        "a revoked passkey signed in"
    );
    assert!(
        discoverable_login(&svc, &mut key).await.is_err(),
        "a revoked passkey signed in"
    );
}

/// A discoverable passkey signs in its own profile, found through the user
/// handle association at this RP.
#[tokio::test]
async fn test_discoverable_login_finds_the_profile() {
    let (svc, profile, mut key) = account_with_passkey().await;
    let signed_in = discoverable_login(&svc, &mut key).await.unwrap();
    assert_eq!(signed_in_profile(&svc, &signed_in).await, profile.id);
}

/// A returned handle no account holds authenticates nobody and creates no
/// association; another account's handle with this credential is refused.
#[tokio::test]
async fn test_discoverable_login_refuses_unknown_or_other_handles() {
    let (svc, _profile, mut key) = account_with_passkey().await;
    key.behavior.user_handle = Some(vec![0xee; 16]);
    let refused = discoverable_login(&svc, &mut key).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Unauthenticated);
    assert_eq!(
        svc.storage
            .get_profile_by_webauthn_user_handle(
                RP,
                sid_core::models::WebAuthnUserHandle([0xee; 16])
            )
            .await
            .unwrap(),
        None
    );

    // A second account with its own passkey: its handle is real, but this
    // credential is not its.
    let other = Profile::new(Some("other_user"));
    svc.storage
        .create_profile(&other, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    let mut other_key = SoftAuthenticator::new(ORIGIN, RP);
    register(&svc, &other, &mut other_key).await;
    key.behavior.user_handle = Some(other_key.credentials[0].user_handle.clone());
    let refused = discoverable_login(&svc, &mut key).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Unauthenticated);
}

/// Every passkey of a profile carries the same user handle, and two
/// profiles never share one.
#[tokio::test]
async fn test_user_handle_is_one_per_profile() {
    let (svc, profile, key) = account_with_passkey().await;
    let mut second = SoftAuthenticator::new(ORIGIN, RP);
    register(&svc, &profile, &mut second).await;
    assert_eq!(passkeys(&svc, &profile).await.len(), 2);
    assert_eq!(
        key.credentials[0].user_handle,
        second.credentials[0].user_handle
    );
    assert_ne!(
        key.credentials[0].user_handle,
        profile.id.into_uuid().as_bytes().to_vec(),
        "the handle is not the profile id"
    );

    let other = Profile::new(Some("other_user"));
    svc.storage
        .create_profile(&other, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    let mut other_key = SoftAuthenticator::new(ORIGIN, RP);
    register(&svc, &other, &mut other_key).await;
    assert_ne!(
        key.credentials[0].user_handle,
        other_key.credentials[0].user_handle
    );
}

/// Two enrollments started concurrently for one profile get the same user
/// handle.
#[tokio::test]
async fn test_concurrent_enrollments_share_the_handle() {
    let profile = Profile::new(Some("passkey_user"));
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));
    let bearer = common::fresh_token(&svc, &profile).await;
    let (a, b) = tokio::join!(
        svc.auth
            .web_authn_registration_start(authed(Default::default(), &bearer)),
        svc.auth
            .web_authn_registration_start(authed(Default::default(), &bearer)),
    );
    let user_id = |options: &[u8]| {
        let options: serde_json::Value = serde_json::from_slice(options).unwrap();
        options["publicKey"]["user"]["id"].clone()
    };
    assert_eq!(
        user_id(&a.unwrap().into_inner().options),
        user_id(&b.unwrap().into_inner().options)
    );
}
