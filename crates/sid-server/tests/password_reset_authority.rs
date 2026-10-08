// SPDX-License-Identifier: AGPL-3.0-only
//! A password reset proves only the mailbox. It replaces the password, but it
//! does not sign in an account whose established protection is stronger than
//! a password: that sign-in still has to pass the account's second factor.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, test_profile, zkpp_client as client};
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use sha2::{Digest, Sha256};
use sid_core::models::{
    AuditEntry, Credential, CredentialType, PasswordResetSession, Profile, ProfileId,
};
use sid_pake_core::pallas_opaque::PallasCipherSuite;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use std::net::SocketAddr;
use tonic::Request;
use tonic::transport::server::TcpConnectInfo;

const NEW_PASSWORD: &[u8] = b"new battery staple";
const OLD_PASSWORD: &[u8] = b"old battery staple";
const DEVICE: &str = "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0";
const PEER: &str = "203.0.113.7:4321";

/// `message` as the browser on `PEER` sends it: the transport peer and the
/// user agent the server derives the device from.
fn from_device<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("user-agent", DEVICE.parse().unwrap());
    request.extensions_mut().insert(TcpConnectInfo {
        local_addr: None,
        remote_addr: Some(PEER.parse::<SocketAddr>().unwrap()),
    });
    request
}

/// `message` from the device on `PEER`, or from nowhere in particular.
fn request<T>(message: T, device: bool) -> Request<T> {
    if device {
        from_device(message)
    } else {
        Request::new(message)
    }
}

/// A reset of `profile`, verified as the mailbox link verifies it: the
/// verified reset session and the replacement password's history context.
async fn verified_reset(svc: &TestServices, profile: &Profile) -> (String, PasswordHistoryContext) {
    let token = "reset-token";
    let token_hash: String = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let reset = PasswordResetSession::new(profile.id, "alice@sid.example.com".into(), token_hash);
    svc.storage
        .create_reset_session(&reset, AuditEntry::system("test", "setup").into())
        .await
        .unwrap();
    let verified = svc
        .auth
        .verify_password_reset(Request::new(VerifyPasswordResetRequest {
            session_id: reset.id.to_string(),
            token: token.to_string(),
        }))
        .await
        .expect("the mailbox token verifies")
        .into_inner();
    (
        verified.reset_session_id,
        verified.history.expect("the reset's history context"),
    )
}

/// Reset the password of `profile` to `NEW_PASSWORD`: verify, the OPAQUE
/// start under the reset's operation, and the completion with the record.
async fn complete(svc: &TestServices, profile: &Profile) -> CompletePasswordResetResponse {
    complete_as(svc, profile, false).await
}

/// The reset of `complete`, sent from the device on `PEER` when `device`.
async fn complete_as(
    svc: &TestServices,
    profile: &Profile,
    device: bool,
) -> CompletePasswordResetResponse {
    let (reset_session_id, context) = verified_reset(svc, profile).await;
    let started = client::start(NEW_PASSWORD);
    let executed = svc
        .auth
        .execute_password_reset(request(
            ExecutePasswordResetRequest {
                operation_id: context.operation_id.clone(),
                registration_request: started.request.clone(),
            },
            device,
        ))
        .await
        .expect("the OPAQUE start of the replacement password")
        .into_inner();
    svc.auth
        .complete_password_reset(request(
            CompletePasswordResetRequest {
                reset_session_id,
                operation_id: context.operation_id,
                registration_record: client::finish(
                    started,
                    NEW_PASSWORD,
                    &executed.registration_response,
                ),
                proof: None,
            },
            device,
        ))
        .await
        .expect("the reset completes")
        .into_inner()
}

/// Register `principal` with `password` from the device on `PEER`.
async fn register_from_device(svc: &TestServices, principal: &str, password: &[u8]) -> Profile {
    let started = client::start(password);
    let start = svc
        .auth
        .opaque_zkpp_registration_start(from_device(OpaqueZkppRegistrationStartRequest {
            principal: principal.to_string(),
            registration_request: started.request.clone(),
            claim_token: None,
        }))
        .await
        .expect("registration start")
        .into_inner();
    let context = start.history.expect("the registration's history context");
    let done = svc
        .auth
        .opaque_zkpp_registration_finish(from_device(OpaqueZkppRegistrationFinishRequest {
            operation_id: context.operation_id,
            registration_record: client::finish(started, password, &start.registration_response),
            proof: None,
        }))
        .await
        .expect("registration finish")
        .into_inner();
    svc.storage
        .get_profile(ProfileId::parse(&done.profile_id).unwrap())
        .await
        .unwrap()
        .expect("the registered profile")
}

/// Sign `principal` in with `password` from the device on `PEER`.
async fn sign_in_from_device(
    svc: &TestServices,
    principal: &str,
    password: &[u8],
) -> Result<OpaqueLoginFinishResponse, tonic::Status> {
    let login = ClientLogin::<PallasCipherSuite>::start(&mut OsRng, password).unwrap();
    let started = svc
        .auth
        .opaque_login_start(from_device(OpaqueLoginStartRequest {
            principal: principal.to_string(),
            credential_request: login.message.serialize().to_vec(),
        }))
        .await?
        .into_inner();
    let finished = login
        .state
        .finish(
            &mut OsRng,
            password,
            CredentialResponse::deserialize(&started.credential_response).unwrap(),
            ClientLoginFinishParameters::default(),
        )
        .expect("the client recovers its envelope");
    svc.auth
        .opaque_login_finish(from_device(OpaqueLoginFinishRequest {
            principal: principal.to_string(),
            credential_finalization: finished.message.serialize().to_vec(),
            server_login_state: started.server_login_state,
        }))
        .await
        .map(|r| r.into_inner())
}

/// The sign-in a reset makes is a sign-in like any other: it records the
/// client's address and device, so the next sign-in from that device is no
/// stranger to the new-device rule and needs no step-up.
#[tokio::test]
async fn a_reset_signs_in_with_the_clients_address_and_device() {
    let svc = TestServices::new(MockStorage::new().with_system_project());
    let principal = "reset-device@sid.example.com";
    let profile = register_from_device(&svc, principal, OLD_PASSWORD).await;

    let done = complete_as(&svc, &profile, true).await;
    let sessions = svc
        .storage
        .list_sessions_by_profile(profile.id)
        .await
        .unwrap();
    let session = sessions
        .iter()
        .find(|s| s.id.to_string() == done.session_id)
        .expect("the reset's session");
    assert_eq!(session.ip_address, "203.0.113.7");
    assert!(
        session.device_id.is_some(),
        "the reset's session names no device"
    );

    let again = sign_in_from_device(&svc, principal, NEW_PASSWORD)
        .await
        .expect("the same device signs in again without a step-up");
    assert!(!again.access_token.is_empty());
}

/// An account with a second factor: the password is replaced, no session is
/// issued, and none is stored for the profile.
#[tokio::test]
async fn reset_of_account_with_second_factor_signs_nobody_in() {
    let profile = test_profile();
    let storage = MockStorage::new()
        .with_profile(profile.clone())
        .with_credential(Credential::new(
            profile.id,
            CredentialType::Totp,
            vec![1, 2, 3],
            None,
        ));
    let svc = TestServices::new(storage);

    let done = complete(&svc, &profile).await;

    assert!(
        done.access_token.is_empty(),
        "a mailbox proof signed in past the second factor"
    );
    assert!(done.session_id.is_empty());
    assert_eq!(done.expires_in, 0);
    assert!(
        svc.storage
            .list_sessions_by_profile(profile.id)
            .await
            .unwrap()
            .is_empty()
    );
    let passwords = svc
        .storage
        .get_credentials_by_profile(profile.id, Some(CredentialType::Opaque))
        .await
        .unwrap();
    assert_eq!(passwords.len(), 1, "the password was not replaced");
}

/// A password-only account keeps its email reset path: it is signed in with
/// the new password.
#[tokio::test]
async fn reset_of_password_only_account_signs_in() {
    let profile = test_profile();
    let svc = TestServices::new(MockStorage::new().with_profile(profile.clone()));

    let done = complete(&svc, &profile).await;

    assert!(!done.access_token.is_empty());
    assert!(!done.session_id.is_empty());
    assert!(done.expires_in > 0);
}
