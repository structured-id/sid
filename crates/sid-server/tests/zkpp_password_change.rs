// SPDX-License-Identifier: AGPL-3.0-only
//! ZKPP password change against a verifying server: the new password is
//! checked against the owner's retained history, the change replaces the
//! password, its evidence and its OPRF key in one write, and the record the
//! change stores opens only under the password the proof was made for.

mod common;

use common::mock_storage::MockStorage;
use common::{TestServices, zkpp_client as client};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sid_authn::opaque_zkpp::ZkppConfig;
use sid_core::models::{Credential, CredentialId, ProfileId};
use sid_opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use sid_pake_core::pallas_opaque::PallasCipherSuite;
use sid_pake_core::prover::ZkppProver;
use sid_pake_core::verifier::ZkppVerifier;
use sid_proto::sid::v1::auth_service_server::AuthService;
use sid_proto::sid::v1::*;
use tonic::{Code, Request, Status};
use tonic_types::StatusExt;

const PRINCIPAL: &str = "change@sid.example.com";
const OLD: &[u8] = b"OldStr0ngP@ss1";
const NEW: &[u8] = b"NewStr0ngP@ss2";
const WEAK: &[u8] = b"weak";

fn authed<T>(msg: T, bearer: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    req
}

/// The `ErrorInfo.reason` of a refusal.
fn reason(err: &Status) -> String {
    err.get_details_error_info()
        .map(|info| info.reason)
        .unwrap_or_default()
}

/// Register `PRINCIPAL` with `OLD` and a verified proof; returns the services,
/// the stored password and a fresh session token of its profile.
async fn registered(
    prover: &ZkppProver,
    verifier: ZkppVerifier,
) -> (TestServices, Credential, String) {
    let svc = TestServices::with_zkpp(
        MockStorage::new().with_system_project(),
        verifier,
        ZkppConfig {
            require_proof: true,
            policy_version: 1,
        },
    );
    let started = client::start(OLD);
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
    let proof = client::evaluate_and_prove(&svc, prover, OLD, &context, &started).await;
    let done = svc
        .auth
        .opaque_zkpp_registration_finish(Request::new(OpaqueZkppRegistrationFinishRequest {
            operation_id: context.operation_id.clone(),
            registration_record: client::finish(started, OLD, &start.registration_response),
            proof: Some(proof),
        }))
        .await
        .expect("registration finish")
        .into_inner();
    let credential = svc
        .storage
        .get_credential(CredentialId(done.credential_id.parse().unwrap()))
        .await
        .unwrap()
        .unwrap();
    assert!(credential.zkpp_verified, "the registration proof verified");
    let profile = svc
        .storage
        .get_profile(ProfileId::parse(&done.profile_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    let token = common::fresh_token(&svc, &profile).await;
    (svc, credential, token)
}

/// A change up to its finish: the operation's context, the record of the new
/// password and its proof.
struct Changing {
    context: PasswordHistoryContext,
    record: Vec<u8>,
    proof: PasswordRegistrationProof,
}

/// Challenge, OPAQUE start, execute, evaluation and proof of a change of
/// `credential` to `password`.
async fn prepare_change(
    svc: &TestServices,
    prover: &ZkppProver,
    credential: &Credential,
    token: &str,
    password: &[u8],
) -> Result<Changing, Status> {
    let challenge = svc
        .auth
        .password_change_challenge(authed(
            PasswordChangeChallengeRequest {
                credential_id: credential.id.0.to_string(),
            },
            token,
        ))
        .await?
        .into_inner();
    let context = challenge.history.expect("the change's history context");
    let started = client::start(password);
    let executed = svc
        .auth
        .password_change_execute(authed(
            PasswordChangeExecuteRequest {
                operation_id: context.operation_id.clone(),
                credential_id: credential.id.0.to_string(),
                registration_request: started.request.clone(),
            },
            token,
        ))
        .await?
        .into_inner();
    let proof = client::evaluate_and_prove(svc, prover, password, &context, &started).await;
    Ok(Changing {
        context,
        record: client::finish(started, password, &executed.registration_response),
        proof,
    })
}

async fn finish_change(
    svc: &TestServices,
    credential: &Credential,
    token: &str,
    context: &PasswordHistoryContext,
    record: Vec<u8>,
    proof: PasswordRegistrationProof,
) -> Result<(), Status> {
    svc.auth
        .password_change_finish(authed(
            PasswordChangeFinishRequest {
                operation_id: context.operation_id.clone(),
                credential_id: credential.id.0.to_string(),
                registration_record: record,
                proof: Some(proof),
            },
            token,
        ))
        .await?;
    Ok(())
}

/// Change the password of `credential` to `password`, all the way.
async fn change(
    svc: &TestServices,
    prover: &ZkppProver,
    credential: &Credential,
    token: &str,
    password: &[u8],
) -> Result<(), Status> {
    let changing = prepare_change(svc, prover, credential, token, password).await?;
    finish_change(
        svc,
        credential,
        token,
        &changing.context,
        changing.record,
        changing.proof,
    )
    .await
}

/// Sign in as `PRINCIPAL` with `password` through ordinary OPAQUE login.
async fn signs_in(svc: &TestServices, password: &[u8]) -> bool {
    let login = ClientLogin::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), password).unwrap();
    let Ok(started) = svc
        .auth
        .opaque_login_start(Request::new(OpaqueLoginStartRequest {
            principal: PRINCIPAL.to_string(),
            credential_request: login.message.serialize().to_vec(),
        }))
        .await
    else {
        return false;
    };
    let started = started.into_inner();
    let Ok(finished) = login.state.finish(
        &mut UnwrapErr(SysRng),
        password,
        CredentialResponse::deserialize(&started.credential_response).unwrap(),
        ClientLoginFinishParameters::default(),
    ) else {
        return false;
    };
    svc.auth
        .opaque_login_finish(Request::new(OpaqueLoginFinishRequest {
            principal: PRINCIPAL.to_string(),
            credential_finalization: finished.message.serialize().to_vec(),
            server_login_state: started.server_login_state,
        }))
        .await
        .is_ok()
}

/// The new password is compared with the retained history: the current
/// password is refused as reused; another passes, replaces the password with
/// its evidence under its own OPRF key, signs in, and is itself retained.
#[tokio::test]
async fn test_password_change_refuses_the_retained_password() {
    let (prover, verifier) = client::keys(1);
    let (svc, credential, token) = registered(&prover, verifier).await;
    assert!(
        signs_in(&svc, OLD).await,
        "the registered password signs in"
    );

    let reused = change(&svc, &prover, &credential, &token, OLD)
        .await
        .expect_err("the current password passed the history check");
    assert_eq!(
        reused.code(),
        Code::FailedPrecondition,
        "{}",
        reused.message()
    );
    assert_eq!(reason(&reused), "PASSWORD_REUSED");
    assert!(
        signs_in(&svc, OLD).await,
        "a refused change keeps the password"
    );

    change(&svc, &prover, &credential, &token, NEW)
        .await
        .expect("the change to a new password");
    let stored = svc
        .storage
        .get_credential(credential.id)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.zkpp_verified);
    assert_eq!(stored.policy_version, Some(1));
    assert_ne!(
        stored.opaque_credential_identifier, credential.opaque_credential_identifier,
        "the new password has its own OPRF key"
    );
    assert!(signs_in(&svc, NEW).await, "the new password signs in");
    assert!(
        !signs_in(&svc, OLD).await,
        "the old password no longer does"
    );

    let again = change(&svc, &prover, &credential, &token, NEW)
        .await
        .expect_err("the retained new password passed the history check");
    assert_eq!(reason(&again), "PASSWORD_REUSED");
}

/// The server's OPAQUE public key, as every registration response carries it
/// after the evaluated element.
async fn server_public_key(svc: &TestServices) -> Vec<u8> {
    let started =
        ClientRegistration::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), b"any").unwrap();
    let response = svc
        .auth
        .opaque_registration_start(Request::new(OpaqueRegistrationStartRequest {
            principal: "someone-else@sid.example.com".to_string(),
            registration_request: started.message.serialize().to_vec(),
            claim_token: None,
        }))
        .await
        .expect("a registration start")
        .into_inner();
    response.registration_response[32..].to_vec()
}

/// A registration record for `WEAK` whose envelope is under the OPRF key of
/// `PRINCIPAL`'s current password: the login start evaluates any element under
/// that key, and a registration response is that evaluation plus the server's
/// public key. The login state starts with the OPRF client (blind and blinded
/// element), which is the whole registration state.
async fn weak_record_from_login(svc: &TestServices) -> Vec<u8> {
    let login = ClientLogin::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), WEAK).unwrap();
    let started = svc
        .auth
        .opaque_login_start(Request::new(OpaqueLoginStartRequest {
            principal: PRINCIPAL.to_string(),
            credential_request: login.message.serialize().to_vec(),
        }))
        .await
        .expect("login start")
        .into_inner();
    let response = [
        &started.credential_response[..32],
        server_public_key(svc).await.as_slice(),
    ]
    .concat();
    let state =
        ClientRegistration::<PallasCipherSuite>::deserialize(&login.state.serialize()[..64])
            .unwrap();
    state
        .finish(
            &mut UnwrapErr(SysRng),
            WEAK,
            RegistrationResponse::deserialize(&response).unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap()
        .message
        .serialize()
        .to_vec()
}

/// A record for another password cannot become the proved one. The proof is
/// checked, but the record is opaque to the server, so the guarantee is the
/// operation's own OPRF key: it answers no request but the one the proof is
/// bound to, and a record built from another key's answers (the login oracle
/// of the current password) opens under no password once stored.
#[tokio::test]
async fn test_a_record_for_another_password_opens_under_none() {
    let (prover, verifier) = client::keys(1);
    let (svc, credential, token) = registered(&prover, verifier).await;
    let Changing { context, proof, .. } = prepare_change(&svc, &prover, &credential, &token, NEW)
        .await
        .expect("the change up to its finish");

    let second = client::start(WEAK);
    let refused = svc
        .auth
        .password_change_execute(authed(
            PasswordChangeExecuteRequest {
                operation_id: context.operation_id.clone(),
                credential_id: credential.id.0.to_string(),
                registration_request: second.request.clone(),
            },
            &token,
        ))
        .await
        .expect_err("a second request was evaluated under the operation's key");
    assert_eq!(refused.code(), Code::AlreadyExists, "{}", refused.message());

    let record = weak_record_from_login(&svc).await;
    finish_change(&svc, &credential, &token, &context, record, proof)
        .await
        .expect("the finish cannot tell the record apart");
    assert!(
        !signs_in(&svc, WEAK).await,
        "a record for another password opened with it"
    );
    assert!(!signs_in(&svc, NEW).await);
    assert!(!signs_in(&svc, OLD).await);
}
