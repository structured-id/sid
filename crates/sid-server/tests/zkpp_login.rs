// SPDX-License-Identifier: AGPL-3.0-only
//! A password registered through the ZKPP flow signs in through ordinary
//! OPAQUE login: both run on the one stored server setup under the
//! credential's own OPRF key, the one the client registered against.

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use common::zkpp_client as client;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sid_opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use sid_pake_core::pallas_opaque::PallasCipherSuite;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::Request;

const PASSWORD: &[u8] = b"Str0ngP@ssword1";

/// Register through the ZKPP start/finish pair (no proof: the server allows
/// unverified registration here), then sign in with OPAQUE login, for every
/// kind of login identifier: email, username and phone.
#[tokio::test]
async fn a_zkpp_registered_password_signs_in() {
    let svc = TestServices::with_zkpp_degraded(MockStorage::new().with_system_project());
    for principal in ["zkpp-login@sid.example.com", "zkpp_login", "+380501234567"] {
        register_and_sign_in(&svc, principal, principal).await;
    }
}

/// An identifier is matched in its normal form: a phone registered in one
/// layout signs in typed in another, an email in another case.
#[tokio::test]
async fn a_zkpp_registered_password_signs_in_with_the_identifier_retyped() {
    let svc = TestServices::with_zkpp_degraded(MockStorage::new().with_system_project());
    register_and_sign_in(&svc, "+380 50 765 4321", "+380507654321").await;
    register_and_sign_in(&svc, "Retyped@sid.example.com", "retyped@SID.example.com").await;
}

/// Register `registered` and sign in as `typed`, which names the same account.
async fn register_and_sign_in(svc: &TestServices, registered: &str, typed: &str) {
    let started = client::start(PASSWORD);
    let start = svc
        .auth
        .opaque_zkpp_registration_start(Request::new(OpaqueZkppRegistrationStartRequest {
            principal: registered.to_string(),
            registration_request: started.request.clone(),
            claim_token: None,
        }))
        .await
        .unwrap_or_else(|e| panic!("registration start for {registered}: {e:?}"))
        .into_inner();
    let context = start.history.expect("the registration's history context");
    svc.auth
        .opaque_zkpp_registration_finish(Request::new(OpaqueZkppRegistrationFinishRequest {
            operation_id: context.operation_id,
            registration_record: client::finish(started, PASSWORD, &start.registration_response),
            proof: None,
        }))
        .await
        .expect("registration finish");

    let login = ClientLogin::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), PASSWORD).unwrap();
    let started = svc
        .auth
        .opaque_login_start(Request::new(OpaqueLoginStartRequest {
            principal: typed.to_string(),
            credential_request: login.message.serialize().to_vec(),
        }))
        .await
        .expect("login start")
        .into_inner();
    let finished = login
        .state
        .finish(
            &mut UnwrapErr(SysRng),
            PASSWORD,
            CredentialResponse::deserialize(&started.credential_response).unwrap(),
            ClientLoginFinishParameters::default(),
        )
        .expect("the client recovers its envelope with the server's OPRF key");
    let signed_in = svc
        .auth
        .opaque_login_finish(Request::new(OpaqueLoginFinishRequest {
            principal: typed.to_string(),
            credential_finalization: finished.message.serialize().to_vec(),
            server_login_state: started.server_login_state,
        }))
        .await
        .expect("login finish")
        .into_inner();
    assert!(!signed_in.access_token.is_empty());
}
