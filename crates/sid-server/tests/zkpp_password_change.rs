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
use sid_core::models::{
    AuthLevel, Credential, CredentialId, CurrentPasswordRule, ProfileId, SecurityPolicy,
};
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
const THIRD: &[u8] = b"ThirdStr0ngP@ss3";

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
    registered_as(prover, verifier, PRINCIPAL).await
}

/// As [`registered`], for the login identifier `principal`.
async fn registered_as(
    prover: &ZkppProver,
    verifier: ZkppVerifier,
    principal: &str,
) -> (TestServices, Credential, String) {
    registered_with(prover, verifier, principal, SecurityPolicy::ce_default()).await
}

/// As [`registered_as`], on a server under `policy`.
async fn registered_with(
    prover: &ZkppProver,
    verifier: ZkppVerifier,
    principal: &str,
    policy: SecurityPolicy,
) -> (TestServices, Credential, String) {
    let svc = TestServices::with_zkpp_policy(
        MockStorage::new().with_system_project(),
        verifier,
        ZkppConfig {
            require_proof: true,
            policy_version: 1,
        },
        policy,
    );
    let started = client::start(OLD);
    let start = svc
        .auth
        .opaque_zkpp_registration_start(Request::new(OpaqueZkppRegistrationStartRequest {
            principal: principal.to_string(),
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
    assert!(
        credential.policy_evidence.is_verified(),
        "the registration proof verified"
    );
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

/// The OPAQUE context a change's current-password sign-in runs under:
/// ASCII "SID-PASSWORD-CHANGE-v1", the operation id, SHA-256 of the new
/// password's registration request.
fn change_context(operation: &sid_ids_proto::PasswordOperationId, request: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let id = sid_ids_proto::required(Some(operation)).unwrap();
    let mut context = b"SID-PASSWORD-CHANGE-v1".to_vec();
    context.extend_from_slice(id.as_bytes());
    context.extend_from_slice(&sha2::Sha256::digest(request));
    context
}

/// Which context the client finishes its current-password sign-in under.
#[derive(Clone, Copy)]
enum Confirmation {
    /// This change's context: an honest client.
    ThisChange,
    /// The empty context of an ordinary sign-in: a relayed login.
    OrdinarySignIn,
    /// The context of this operation over another registration request.
    AnotherRequest,
}

/// Challenge, OPAQUE start, execute, evaluation and proof of a change of
/// `credential` to `password`, proving `current` as the current password
/// when given.
async fn prepare_change(
    svc: &TestServices,
    prover: &ZkppProver,
    credential: &Credential,
    token: &str,
    current: Option<&[u8]>,
    password: &[u8],
) -> Result<Changing, Status> {
    prepare_change_confirming(
        svc,
        prover,
        credential,
        token,
        current,
        password,
        Confirmation::ThisChange,
    )
    .await
}

/// As [`prepare_change`], finishing the current-password sign-in under the
/// context `confirmation` names.
async fn prepare_change_confirming(
    svc: &TestServices,
    prover: &ZkppProver,
    credential: &Credential,
    token: &str,
    current: Option<&[u8]>,
    password: &[u8],
    confirmation: Confirmation,
) -> Result<Changing, Status> {
    // The new password's request comes first: the challenge fixes it.
    let started = client::start(password);
    let login = current
        .map(|c| ClientLogin::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), c).unwrap());
    let challenge = svc
        .auth
        .password_change_challenge(authed(
            PasswordChangeChallengeRequest {
                credential_id: credential.id.0.to_string(),
                credential_request: login
                    .as_ref()
                    .map(|l| l.message.serialize().to_vec())
                    .unwrap_or_default(),
                registration_request: started.request.clone(),
            },
            token,
        ))
        .await?
        .into_inner();
    let context = challenge.history.expect("the change's history context");
    let operation = context.operation_id.as_ref().expect("an operation id");
    let sign_in_context = match confirmation {
        Confirmation::ThisChange => change_context(operation, &started.request),
        Confirmation::OrdinarySignIn => Vec::new(),
        Confirmation::AnotherRequest => change_context(operation, &client::start(password).request),
    };
    // A wrong current password fails on the client: it sends a KE3 that
    // cannot verify, as a client that skipped its own check would.
    let credential_finalization = match (login, current) {
        (Some(login), Some(current)) => login
            .state
            .finish(
                &mut UnwrapErr(SysRng),
                current,
                CredentialResponse::deserialize(&challenge.credential_response).unwrap(),
                ClientLoginFinishParameters {
                    context: Some(&sign_in_context),
                    ..ClientLoginFinishParameters::default()
                },
            )
            .map(|f| f.message.serialize().to_vec())
            .unwrap_or_else(|_| vec![0; 64]),
        _ => Vec::new(),
    };
    let executed = svc
        .auth
        .password_change_execute(authed(
            PasswordChangeExecuteRequest {
                operation_id: context.operation_id.clone(),
                credential_id: credential.id.0.to_string(),
                credential_finalization,
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

/// Change the password of `credential` from `current` to `password`, all
/// the way.
async fn change(
    svc: &TestServices,
    prover: &ZkppProver,
    credential: &Credential,
    token: &str,
    current: &[u8],
    password: &[u8],
) -> Result<(), Status> {
    let changing = prepare_change(svc, prover, credential, token, Some(current), password).await?;
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
    signs_in_as(svc, PRINCIPAL, password).await
}

/// Sign in as `principal` with `password` through ordinary OPAQUE login.
async fn signs_in_as(svc: &TestServices, principal: &str, password: &[u8]) -> bool {
    let login = ClientLogin::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), password).unwrap();
    let Ok(started) = svc
        .auth
        .opaque_login_start(Request::new(OpaqueLoginStartRequest {
            principal: principal.to_string(),
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
            principal: principal.to_string(),
            credential_finalization: finished.message.serialize().to_vec(),
            server_login_state: started.server_login_state,
        }))
        .await
        .is_ok()
}

/// The proved lifecycle is the same whatever identifier the account signs in
/// with: an account registered with a username or a phone number has its
/// retained password refused, changes to a new one with verified evidence and
/// signs in with it, not with the old one.
#[tokio::test]
async fn test_a_username_or_phone_account_has_the_same_history() {
    for principal in ["change_user", "+380671234567"] {
        let (prover, verifier) = client::keys(1);
        let (svc, credential, token) = registered_as(&prover, verifier, principal).await;
        assert!(signs_in_as(&svc, principal, OLD).await, "{principal}");
        let reused = change(&svc, &prover, &credential, &token, OLD, OLD)
            .await
            .expect_err("the current password passed the history check");
        assert_eq!(reason(&reused), "PASSWORD_REUSED", "{principal}");
        change(&svc, &prover, &credential, &token, OLD, NEW)
            .await
            .unwrap_or_else(|e| panic!("{principal}: {e:?}"));
        let stored = svc
            .storage
            .get_credential(credential.id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.policy_evidence.is_verified(), "{principal}");
        assert!(signs_in_as(&svc, principal, NEW).await, "{principal}");
        assert!(!signs_in_as(&svc, principal, OLD).await, "{principal}");
    }
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

    let reused = change(&svc, &prover, &credential, &token, OLD, OLD)
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

    change(&svc, &prover, &credential, &token, OLD, NEW)
        .await
        .expect("the change to a new password");
    let stored = svc
        .storage
        .get_credential(credential.id)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        stored.policy_evidence,
        sid_core::models::PolicyEvidence::Verified {
            policy_version: 1,
            ..
        }
    ));
    assert_ne!(
        stored.opaque_credential_identifier, credential.opaque_credential_identifier,
        "the new password has its own OPRF key"
    );
    assert!(signs_in(&svc, NEW).await, "the new password signs in");
    assert!(
        !signs_in(&svc, OLD).await,
        "the old password no longer does"
    );

    let again = change(&svc, &prover, &credential, &token, NEW, NEW)
        .await
        .expect_err("the retained new password passed the history check");
    assert_eq!(reason(&again), "PASSWORD_REUSED");
}

/// A change whose response was lost resolves on retry: the exact finish
/// returns the recorded success without a second password installation or a
/// second history entry, and a finish of the same operation with another
/// record is refused, leaving the installed password in place.
#[tokio::test]
async fn test_a_lost_change_response_resolves_without_a_second_write() {
    let (prover, verifier) = client::keys(1);
    let (svc, credential, token) = registered(&prover, verifier).await;
    let changing = prepare_change(&svc, &prover, &credential, &token, Some(OLD), NEW)
        .await
        .unwrap();
    let other_record = {
        let started = client::start(WEAK);
        client::finish(started, WEAK, &server_registration_response(&svc).await)
    };
    finish_change(
        &svc,
        &credential,
        &token,
        &changing.context,
        changing.record.clone(),
        changing.proof.clone(),
    )
    .await
    .expect("the change");
    let installed = svc
        .storage
        .get_credential(credential.id)
        .await
        .unwrap()
        .unwrap();
    let history = svc
        .storage
        .get_password_history(credential.profile_id)
        .await
        .unwrap();

    finish_change(
        &svc,
        &credential,
        &token,
        &changing.context,
        changing.record,
        changing.proof.clone(),
    )
    .await
    .expect("the exact retry returns the recorded result");
    let substituted = finish_change(
        &svc,
        &credential,
        &token,
        &changing.context,
        other_record,
        changing.proof,
    )
    .await
    .expect_err("a retry with another record was accepted");
    // The operation's key is already bound to the first record.
    assert_eq!(reason(&substituted), "OPERATION_KEY_CONFLICT");

    let after = svc
        .storage
        .get_credential(credential.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.data.expose(), installed.data.expose());
    assert_eq!(
        svc.storage
            .get_password_history(credential.profile_id)
            .await
            .unwrap(),
        history,
        "no second entry"
    );
    assert!(signs_in(&svc, NEW).await);
    assert!(!signs_in(&svc, WEAK).await);
}

/// Any registration response of the server, for building a record that is
/// well-formed but belongs to no operation.
async fn server_registration_response(svc: &TestServices) -> Vec<u8> {
    let started = client::start(b"any");
    svc.auth
        .opaque_registration_start(Request::new(OpaqueRegistrationStartRequest {
            principal: "someone-else@sid.example.com".to_string(),
            registration_request: started.request,
            claim_token: None,
        }))
        .await
        .expect("a registration start")
        .into_inner()
        .registration_response
}

/// After a history-key write cutoff (a suspected key compromise), an
/// operation prepared and proved under the withdrawn key cannot write an
/// entry under it: its finish is refused and the password stays. The next
/// operation gets a new key and is compared in two domains, the new key and
/// the withdrawn one that still holds the retained password: the retained
/// password stays refused, a new password is accepted under the new key, and
/// the emptied withdrawn key is kept but no longer selected.
#[tokio::test]
async fn test_a_replaced_history_key_keeps_the_retained_password_refused() {
    use sid_core::models::{AuditEntry, WrappedHistoryKey};
    use sid_plugin::history_keys::HistoryKeyStore;

    let (prover, verifier) = client::keys(1);
    let (prover2, verifier2) = client::keys(2);
    let svc = TestServices::with_zkpp_verifiers(
        MockStorage::new().with_system_project(),
        vec![verifier, verifier2],
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
        .unwrap()
        .into_inner();
    let context = start.history.unwrap();
    let proof = client::evaluate_and_prove(&svc, &prover, OLD, &context, &started).await;
    let done = svc
        .auth
        .opaque_zkpp_registration_finish(Request::new(OpaqueZkppRegistrationFinishRequest {
            operation_id: context.operation_id.clone(),
            registration_record: client::finish(started, OLD, &start.registration_response),
            proof: Some(proof),
        }))
        .await
        .unwrap()
        .into_inner();
    let credential = svc
        .storage
        .get_credential(CredentialId(done.credential_id.parse().unwrap()))
        .await
        .unwrap()
        .unwrap();
    let owner = credential.profile_id;
    let profile = svc.storage.get_profile(owner).await.unwrap().unwrap();
    let token = common::fresh_token(&svc, &profile).await;

    // An operation prepared under the first key, finished after the swap.
    let early = prepare_change(&svc, &prover, &credential, &token, Some(OLD), NEW)
        .await
        .unwrap();

    // The cutoff, raised as a server start raises the configured one: into
    // the credential side's fence and the evaluator's store.
    let original = svc.storage.get_password_history(owner).await.unwrap();
    let replaced = original.active_epoch().unwrap().id;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let cutoff =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    svc.storage
        .raise_history_write_cutoff(cutoff, AuditEntry::system("test", "cutoff").into())
        .await
        .unwrap();
    svc.mock_storage
        .raise_write_cutoff(cutoff, AuditEntry::system("test", "cutoff"))
        .await
        .unwrap();

    let stale = finish_change(
        &svc,
        &credential,
        &token,
        &early.context,
        early.record,
        early.proof,
    )
    .await
    .expect_err("an operation proved under the withdrawn key finished");
    assert_eq!(reason(&stale), "INVALID_STATE");
    assert_eq!(
        stale
            .get_details_precondition_failure()
            .expect("precondition")
            .violations[0]
            .r#type,
        "PASSWORD_HISTORY_WRITE_CUTOFF"
    );
    assert!(signs_in(&svc, OLD).await, "the refusal kept the password");
    assert_eq!(
        svc.storage.get_password_history(owner).await.unwrap(),
        original,
        "and the history"
    );

    let reused = prepare_change(&svc, &prover2, &credential, &token, Some(OLD), OLD)
        .await
        .unwrap();
    assert_eq!(
        reused.context.domains.len(),
        2,
        "the new key and the replaced key holding the retained password"
    );
    let refused = finish_change(
        &svc,
        &credential,
        &token,
        &reused.context,
        reused.record,
        reused.proof,
    )
    .await
    .expect_err("the retained password passed after the key replacement");
    assert_eq!(reason(&refused), "PASSWORD_REUSED");

    change(&svc, &prover2, &credential, &token, OLD, NEW)
        .await
        .expect("a new password under the new key");
    assert!(signs_in(&svc, NEW).await);
    // Depth 1: the replaced key holds no entry any more. It is no longer
    // required, its sealed key is kept, and the next operation is not asked
    // to evaluate under it.
    let after = svc.storage.get_password_history(owner).await.unwrap();
    let new = after.active_epoch().expect("the new key").clone();
    assert_ne!(new.id, replaced);
    assert!(new.created_at >= cutoff, "a key created after the cutoff");
    assert_eq!(
        after
            .required_epochs()
            .iter()
            .map(|e| e.id)
            .collect::<Vec<_>>(),
        vec![new.id],
        "the emptied replaced key is no longer required"
    );
    assert_ne!(
        svc.mock_storage.get_epoch_key(replaced).await.unwrap(),
        Some(WrappedHistoryKey(Vec::new())),
        "retiring a key keeps it"
    );
    let next = prepare_change(&svc, &prover, &credential, &token, Some(NEW), NEW)
        .await
        .unwrap();
    assert_eq!(
        next.context.domains.len(),
        1,
        "the emptied replaced key is not selected"
    );
    let again = finish_change(
        &svc,
        &credential,
        &token,
        &next.context,
        next.record,
        next.proof,
    )
    .await
    .expect_err("the password retained under the new key passed");
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
/// operation's own OPRF key: it answers no request but the one the challenge
/// fixed (execute names none), and a record built from another key's answers
/// (the login oracle of the current password) opens under no password once
/// stored.
#[tokio::test]
async fn test_a_record_for_another_password_opens_under_none() {
    let (prover, verifier) = client::keys(1);
    let (svc, credential, token) = registered(&prover, verifier).await;
    let Changing { context, proof, .. } =
        prepare_change(&svc, &prover, &credential, &token, Some(OLD), NEW)
            .await
            .expect("the change up to its finish");

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

/// The `continuation` metadata of a refusal.
fn continuation(err: &Status) -> String {
    err.get_details_error_info()
        .and_then(|info| info.metadata.get("continuation").cloned())
        .unwrap_or_default()
}

/// How long the caller of `token` may still change without the current password.
async fn required_in(svc: &TestServices, token: &str) -> std::time::Duration {
    let left = svc
        .auth
        .get_password_change_requirement(authed((), token))
        .await
        .expect("the requirement")
        .into_inner();
    std::time::Duration::try_from(left).expect("never negative")
}

/// By default a session alone never replaces the password, however fresh: a
/// change without the current password is refused before anything is
/// prepared, with the continuation that asks for it, and the requirement
/// says it is needed now.
#[tokio::test]
async fn test_a_change_without_the_current_password_is_refused() {
    let (prover, verifier) = client::keys(1);
    let (svc, credential, token) = registered(&prover, verifier).await;
    assert_eq!(required_in(&svc, &token).await, std::time::Duration::ZERO);

    let Err(refused) = prepare_change(&svc, &prover, &credential, &token, None, NEW).await else {
        panic!("a change without the current password was prepared");
    };
    assert_eq!(
        refused.code(),
        Code::FailedPrecondition,
        "{}",
        refused.message()
    );
    assert_eq!(reason(&refused), "STEP_UP_REQUIRED");
    assert_eq!(continuation(&refused), "current_password");
    // The canonical STEP_UP_REQUIRED detail: the method a generic client
    // must add, the password (RFC 8176 `pwd`).
    let violations = refused
        .get_details_precondition_failure()
        .map(|failure| failure.violations)
        .unwrap_or_default();
    assert!(
        violations
            .iter()
            .any(|v| v.r#type == "amr" && v.subject == "pwd"),
        "{violations:?}"
    );
    assert!(signs_in(&svc, OLD).await, "the refusal kept the password");
}

/// A wrong current password is refused like a wrong sign-in, counts toward
/// the sign-in lockout, and changes nothing.
#[tokio::test]
async fn test_a_wrong_current_password_is_refused() {
    let (prover, verifier) = client::keys(1);
    let (svc, credential, token) = registered(&prover, verifier).await;

    let Err(refused) = prepare_change(&svc, &prover, &credential, &token, Some(WEAK), NEW).await
    else {
        panic!("a change with a wrong current password was prepared");
    };
    assert_eq!(
        refused.code(),
        Code::Unauthenticated,
        "{}",
        refused.message()
    );
    assert_eq!(reason(&refused), "AUTHENTICATION_FAILED");
    assert!(signs_in(&svc, OLD).await, "the refusal kept the password");
    assert!(!signs_in(&svc, NEW).await);
}

/// The current password is proved for this change only: a sign-in finished
/// under an ordinary login's empty context (a relayed login) or under this
/// operation's context over another registration request is refused like a
/// wrong password and changes nothing, although the password is right.
#[tokio::test]
async fn test_a_confirmation_for_another_purpose_or_request_is_refused() {
    let (prover, verifier) = client::keys(1);
    let (svc, credential, token) = registered(&prover, verifier).await;

    for confirmation in [Confirmation::OrdinarySignIn, Confirmation::AnotherRequest] {
        let Err(refused) = prepare_change_confirming(
            &svc,
            &prover,
            &credential,
            &token,
            Some(OLD),
            NEW,
            confirmation,
        )
        .await
        else {
            panic!("a confirmation made for something else was accepted");
        };
        assert_eq!(reason(&refused), "AUTHENTICATION_FAILED");
    }
    assert!(signs_in(&svc, OLD).await, "the refusals kept the password");
    assert!(!signs_in(&svc, NEW).await);
    // The honest confirmation of the same change still goes through.
    change(&svc, &prover, &credential, &token, OLD, NEW)
        .await
        .expect("the change's own confirmation");
}

/// The challenge fixes the new password's request: without one there is
/// nothing for the current password to confirm.
#[tokio::test]
async fn test_a_challenge_without_the_new_request_is_refused() {
    let (prover, verifier) = client::keys(1);
    let (svc, credential, token) = registered(&prover, verifier).await;
    let login = ClientLogin::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), OLD).unwrap();
    let refused = svc
        .auth
        .password_change_challenge(authed(
            PasswordChangeChallengeRequest {
                credential_id: credential.id.0.to_string(),
                credential_request: login.message.serialize().to_vec(),
                registration_request: Vec::new(),
            },
            &token,
        ))
        .await
        .expect_err("a challenge without the new request was answered");
    assert_eq!(
        refused.code(),
        Code::InvalidArgument,
        "{}",
        refused.message()
    );
}

/// A change up to its finish without a policy proof, proving `current`: the
/// operation and the record of `password`.
async fn unproved_change(
    svc: &TestServices,
    credential: &Credential,
    token: &str,
    current: &[u8],
    password: &[u8],
) -> (PasswordHistoryContext, Vec<u8>) {
    let started = client::start(password);
    let login = ClientLogin::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), current).unwrap();
    let challenge = svc
        .auth
        .password_change_challenge(authed(
            PasswordChangeChallengeRequest {
                credential_id: credential.id.0.to_string(),
                credential_request: login.message.serialize().to_vec(),
                registration_request: started.request.clone(),
            },
            token,
        ))
        .await
        .expect("challenge")
        .into_inner();
    let context = challenge.history.expect("the change's history context");
    let sign_in_context = change_context(
        context.operation_id.as_ref().expect("an operation id"),
        &started.request,
    );
    let finalization = login
        .state
        .finish(
            &mut UnwrapErr(SysRng),
            current,
            CredentialResponse::deserialize(&challenge.credential_response).unwrap(),
            ClientLoginFinishParameters {
                context: Some(&sign_in_context),
                ..ClientLoginFinishParameters::default()
            },
        )
        .expect("the current password opens the envelope")
        .message
        .serialize()
        .to_vec();
    let executed = svc
        .auth
        .password_change_execute(authed(
            PasswordChangeExecuteRequest {
                operation_id: context.operation_id.clone(),
                credential_id: credential.id.0.to_string(),
                credential_finalization: finalization,
            },
            token,
        ))
        .await
        .expect("execute")
        .into_inner();
    let record = client::finish(started, password, &executed.registration_response);
    (context, record)
}

/// Where policy proofs are optional, nothing but the current-password proof
/// authorizes an unproved change. That proof is of the password it signed in
/// against: a change begun before another change committed must not replace
/// the newer password with its own.
#[tokio::test]
async fn a_change_proved_against_a_replaced_password_does_not_commit() {
    let svc = TestServices::with_zkpp_degraded(MockStorage::new().with_system_project());
    let started = client::start(OLD);
    let start = svc
        .auth
        .opaque_zkpp_registration_start(Request::new(OpaqueZkppRegistrationStartRequest {
            principal: PRINCIPAL.to_string(),
            registration_request: started.request.clone(),
            claim_token: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let done = svc
        .auth
        .opaque_zkpp_registration_finish(Request::new(OpaqueZkppRegistrationFinishRequest {
            operation_id: start.history.unwrap().operation_id,
            registration_record: client::finish(started, OLD, &start.registration_response),
            proof: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let credential = svc
        .storage
        .get_credential(CredentialId(done.credential_id.parse().unwrap()))
        .await
        .unwrap()
        .unwrap();
    let profile = svc
        .storage
        .get_profile(credential.profile_id)
        .await
        .unwrap()
        .unwrap();
    let token = common::fresh_token(&svc, &profile).await;
    let finish = |context: PasswordHistoryContext, record: Vec<u8>| {
        let svc = &svc;
        let credential = &credential;
        let token = &token;
        async move {
            svc.auth
                .password_change_finish(authed(
                    PasswordChangeFinishRequest {
                        operation_id: context.operation_id,
                        credential_id: credential.id.0.to_string(),
                        registration_record: record,
                        proof: None,
                    },
                    token,
                ))
                .await
        }
    };

    let (early, early_record) = unproved_change(&svc, &credential, &token, OLD, NEW).await;
    let (late, late_record) = unproved_change(&svc, &credential, &token, OLD, THIRD).await;
    finish(late, late_record).await.expect("the later change");
    finish(early, early_record)
        .await
        .expect_err("a change proved against the replaced password committed");
    assert!(signs_in(&svc, THIRD).await, "the later password stays");
    assert!(!signs_in(&svc, NEW).await);
}

/// A wrong current password fails on the client at KE2, so a guesser can
/// abandon each try before execute. Every sign-in a change begins therefore
/// counts when its KE2 is issued: after the limit the challenge refuses, so
/// a stolen session cannot guess the password through changes. The budget
/// is the change's own; the account's sign-in stays open.
#[tokio::test]
async fn test_abandoned_current_password_guesses_are_limited() {
    let (prover, verifier) = client::keys(1);
    let (svc, credential, token) = registered(&prover, verifier).await;

    let begin = |guess: &'static [u8]| {
        let svc = &svc;
        let credential = &credential;
        let token = &token;
        async move {
            let login =
                ClientLogin::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), guess).unwrap();
            svc.auth
                .password_change_challenge(authed(
                    PasswordChangeChallengeRequest {
                        credential_id: credential.id.0.to_string(),
                        credential_request: login.message.serialize().to_vec(),
                        registration_request: client::start(NEW).request,
                    },
                    token,
                ))
                .await
        }
    };
    for _ in 0..5 {
        begin(WEAK)
            .await
            .expect("a guess gets its KE2 until the limit");
    }
    let limited = begin(OLD).await.expect_err("the guesses were not counted");
    assert_eq!(
        reason(&limited),
        "RATE_LIMIT_EXCEEDED",
        "{}",
        limited.message()
    );
    assert!(signs_in(&svc, OLD).await, "sign-in has its own budget");
}

/// Under a relaxed rule a recent session changes without the current
/// password, and the requirement counts down to the moment it is needed; a
/// proof sent anyway is accepted. Once the session's authentication is older
/// than the rule, the current password is required again, and proving it
/// still changes the password.
#[tokio::test]
async fn test_a_relaxed_rule_skips_the_current_password_while_recent() {
    let mut policy = SecurityPolicy::ce_default();
    policy.password.change_current_password = CurrentPasswordRule::AfterMinutes(5);
    let (prover, verifier) = client::keys(1);
    let (svc, credential, token) = registered_with(&prover, verifier, PRINCIPAL, policy).await;

    let left = required_in(&svc, &token).await;
    assert!(
        left > std::time::Duration::from_secs(4 * 60)
            && left <= std::time::Duration::from_secs(5 * 60),
        "{left:?}"
    );
    change_without_current(&svc, &prover, &credential, &token, NEW)
        .await
        .expect("a recent session changes without the current password");
    assert!(signs_in(&svc, NEW).await);
    change(&svc, &prover, &credential, &token, NEW, THIRD)
        .await
        .expect("a proof sent when none is required is accepted");
    assert!(signs_in(&svc, THIRD).await);

    let profile = svc
        .storage
        .get_profile(credential.profile_id)
        .await
        .unwrap()
        .unwrap();
    let older = common::stored_session_token(
        &svc,
        &profile,
        common::authenticated_session(&profile, AuthLevel::Basic, 6),
    )
    .await;
    assert_eq!(required_in(&svc, &older).await, std::time::Duration::ZERO);
    let refused = change_without_current(&svc, &prover, &credential, &older, NEW)
        .await
        .expect_err("an older session changed without the current password");
    assert_eq!(reason(&refused), "STEP_UP_REQUIRED");
    change(&svc, &prover, &credential, &older, THIRD, NEW)
        .await
        .expect("proving the current password changes it");
    assert!(signs_in(&svc, NEW).await);
}

/// A change to `password` that does not prove the current password.
async fn change_without_current(
    svc: &TestServices,
    prover: &ZkppProver,
    credential: &Credential,
    token: &str,
    password: &[u8],
) -> Result<(), Status> {
    let changing = prepare_change(svc, prover, credential, token, None, password).await?;
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
