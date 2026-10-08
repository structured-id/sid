// SPDX-License-Identifier: AGPL-3.0-only
//! A password registered through the ZKPP flow signs in through ordinary
//! OPAQUE login: both run on the one stored server setup under the
//! credential's own OPRF key, the one the client registered against.

mod common;

use common::TestServices;
use common::mock_storage::MockStorage;
use common::zkpp_client as client;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use sid_pake_core::pallas_opaque::PallasCipherSuite;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::Request;

const PRINCIPAL: &str = "zkpp-login@sid.example.com";
const PASSWORD: &[u8] = b"Str0ngP@ssword1";

/// Register through the ZKPP start/finish pair (no proof: the server allows
/// unverified registration here), then sign in with OPAQUE login.
#[tokio::test]
async fn a_zkpp_registered_password_signs_in() {
    let svc = TestServices::with_zkpp_degraded(MockStorage::new().with_system_project());

    let started = client::start(PASSWORD);
    let start = svc
        .auth
        .opaque_zkpp_registration_start(Request::new(OpaqueZkppRegistrationStartRequest {
            principal: PRINCIPAL.to_string(),
            registration_request: started.request.clone(),
            claim_token: None,
        }))
        .await
        .expect("registration start")
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

    let login = ClientLogin::<PallasCipherSuite>::start(&mut OsRng, PASSWORD).unwrap();
    let started = svc
        .auth
        .opaque_login_start(Request::new(OpaqueLoginStartRequest {
            principal: PRINCIPAL.to_string(),
            credential_request: login.message.serialize().to_vec(),
        }))
        .await
        .expect("login start")
        .into_inner();
    let finished = login
        .state
        .finish(
            &mut OsRng,
            PASSWORD,
            CredentialResponse::deserialize(&started.credential_response).unwrap(),
            ClientLoginFinishParameters::default(),
        )
        .expect("the client recovers its envelope with the server's OPRF key");
    let signed_in = svc
        .auth
        .opaque_login_finish(Request::new(OpaqueLoginFinishRequest {
            principal: PRINCIPAL.to_string(),
            credential_finalization: finished.message.serialize().to_vec(),
            server_login_state: started.server_login_state,
        }))
        .await
        .expect("login finish")
        .into_inner();
    assert!(!signed_in.access_token.is_empty());
}
