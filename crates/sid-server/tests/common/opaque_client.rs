// SPDX-License-Identifier: AGPL-3.0-only
//! The client side of the OPAQUE ceremonies, driven against test services.
#![allow(dead_code)]

use super::TestServices;
use super::zkpp_client;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sid_opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use sid_pake_core::pallas_opaque::PallasCipherSuite;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::Request;

/// Register `principal` with `password`: started on `start`, finished on `finish`.
pub async fn register(
    start: &TestServices,
    finish: &TestServices,
    principal: &str,
    password: &[u8],
) {
    try_register(start, finish, principal, password, None)
        .await
        .expect("registration");
}

/// A whole registration operation presenting `claim_token`, finished
/// without a password proof (the services do not require one); returns the
/// refusal of either step.
pub async fn try_register(
    start: &TestServices,
    finish: &TestServices,
    principal: &str,
    password: &[u8],
    claim_token: Option<&str>,
) -> Result<OpaqueZkppRegistrationFinishResponse, tonic::Status> {
    try_register_invited(start, finish, principal, password, claim_token, None).await
}

/// As [`try_register`], presenting `invite_code`.
pub async fn try_register_invited(
    start: &TestServices,
    finish: &TestServices,
    principal: &str,
    password: &[u8],
    claim_token: Option<&str>,
    invite_code: Option<&str>,
) -> Result<OpaqueZkppRegistrationFinishResponse, tonic::Status> {
    let started = zkpp_client::start(password);
    let prepared = start
        .auth
        .opaque_zkpp_registration_start(Request::new(OpaqueZkppRegistrationStartRequest {
            principal: principal.to_string(),
            registration_request: started.request.clone(),
            claim_token: claim_token.map(str::to_string),
            invite_code: invite_code.map(str::to_string),
        }))
        .await?
        .into_inner();
    let context = prepared
        .history
        .expect("the registration's history context");
    finish
        .auth
        .opaque_zkpp_registration_finish(Request::new(OpaqueZkppRegistrationFinishRequest {
            operation_id: context.operation_id,
            registration_record: zkpp_client::finish(
                started,
                password,
                &prepared.registration_response,
            ),
            proof: None,
        }))
        .await
        .map(|r| r.into_inner())
}

/// Start a login for `principal` with `password` on `start`; returns the
/// finish request the client sends, or the start's refusal.
pub async fn try_start_login(
    start: &TestServices,
    principal: &str,
    password: &[u8],
) -> Result<OpaqueLoginFinishRequest, tonic::Status> {
    let mut rng = UnwrapErr(SysRng);
    let client = ClientLogin::<PallasCipherSuite>::start(&mut rng, password).unwrap();
    let started = start
        .auth
        .opaque_login_start(Request::new(OpaqueLoginStartRequest {
            principal: principal.to_string(),
            credential_request: client.message.serialize().to_vec(),
        }))
        .await?
        .into_inner();
    let response =
        CredentialResponse::<PallasCipherSuite>::deserialize(&started.credential_response).unwrap();
    // A wrong password or a decoy response cannot be finished by the client;
    // it then sends whatever it has, as a real client would.
    let finalization = client
        .state
        .finish(
            &mut rng,
            password,
            response,
            ClientLoginFinishParameters::default(),
        )
        .map(|done| done.message.serialize().to_vec())
        .unwrap_or_else(|_| vec![0u8; 64]);
    Ok(OpaqueLoginFinishRequest {
        principal: principal.to_string(),
        credential_finalization: finalization,
        server_login_state: started.server_login_state,
    })
}

/// [`try_start_login`] that must be accepted.
pub async fn start_login(
    start: &TestServices,
    principal: &str,
    password: &[u8],
) -> OpaqueLoginFinishRequest {
    try_start_login(start, principal, password)
        .await
        .expect("login start")
}

/// A whole login on one replica whose finish carries each of `origins` as an
/// `Origin` header, as a browser page sends it; the whole answer, metadata
/// included.
pub async fn login_with_origins(
    svc: &TestServices,
    principal: &str,
    password: &[u8],
    origins: &[&str],
) -> tonic::Response<OpaqueLoginFinishResponse> {
    let mut finish = Request::new(start_login(svc, principal, password).await);
    for origin in origins {
        finish
            .metadata_mut()
            .append("origin", origin.parse().unwrap());
    }
    svc.auth.opaque_login_finish(finish).await.expect("login")
}

/// A whole login on one replica: start and finish.
pub async fn login(
    svc: &TestServices,
    principal: &str,
    password: &[u8],
) -> Result<OpaqueLoginFinishResponse, tonic::Status> {
    let finish = try_start_login(svc, principal, password).await?;
    svc.auth
        .opaque_login_finish(Request::new(finish))
        .await
        .map(|r| r.into_inner())
}
