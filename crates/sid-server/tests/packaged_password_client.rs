// SPDX-License-Identifier: AGPL-3.0-only
//! The immutable published TypeScript package against actual SID gRPC.
//! This tests client KSF/proof interoperability, not hostile final-record
//! derivation or database recovery (which have separate acceptance tests).
#![cfg(feature = "client-conformance")]

mod common;

use common::{TestServices, mock_storage::MockStorage, zkpp_client};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sid_authn::opaque_zkpp::ZkppConfig;
use sid_core::models::{AuditEntry, PasswordResetSession, ProfileId};
use sid_proto::sid::v1::auth_service_client::AuthServiceClient;
use sid_proto::sid::v1::auth_service_server::AuthServiceServer;
use sid_proto::sid::v1::authn::password_history_evaluator_service_client::PasswordHistoryEvaluatorServiceClient;
use sid_proto::sid::v1::authn::password_history_evaluator_service_server::PasswordHistoryEvaluatorServiceServer;
use sid_proto::sid::v1::*;
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tonic::{Code, Request, transport::Channel};
use tonic_types::StatusExt;

const FIRST: &str = "FirstStr0ngP@ss1";
const SECOND: &str = "SecondStr0ngP@ss2";
const RESET: &str = "ResetStr0ngP@ss3";

struct Kernel {
    child: tokio::process::Child,
    output: BufReader<tokio::process::ChildStdout>,
}

impl Kernel {
    fn start(adapter: &str) -> Self {
        let mut child = tokio::process::Command::new("node")
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../ci/password-clients")
                    .join(adapter),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("Node and npm ci are required for client conformance");
        let output = BufReader::new(child.stdout.take().unwrap());
        Self { child, output }
    }

    async fn call(&mut self, command: Value) -> Result<Value, String> {
        let input = self.child.stdin.as_mut().unwrap();
        input
            .write_all(serde_json::to_string(&command).unwrap().as_bytes())
            .await
            .unwrap();
        input.write_all(b"\n").await.unwrap();
        input.flush().await.unwrap();
        let mut line = String::new();
        // A hang detector, not a performance bound: one command may be a
        // genuine proof by the single-thread prover on a loaded machine, so it
        // gets the whole test's budget (.config/nextest.toml).
        let n = tokio::time::timeout(Duration::from_secs(300), self.output.read_line(&mut line))
            .await
            .expect("client command timeout")
            .expect("client output");
        assert_ne!(n, 0, "installed client process exited without a result");
        let result: Value = serde_json::from_str(&line).expect("client result JSON");
        if result["ok"] == true {
            Ok(result["result"].clone())
        } else {
            Err(result["error"].as_str().unwrap().to_string())
        }
    }
}

fn bytes(v: Value) -> Vec<u8> {
    serde_json::from_value(v).expect("binary test result")
}

/// The OPAQUE context of a change's current-password sign-in: ASCII
/// "SID-PASSWORD-CHANGE-v1", the operation id, SHA-256 of the new password's
/// registration request.
fn change_context(operation: &sid_ids_proto::PasswordOperationId, request: &[u8]) -> Vec<u8> {
    let id = sid_ids_proto::required(Some(operation)).unwrap();
    let mut context = b"SID-PASSWORD-CHANGE-v1".to_vec();
    context.extend_from_slice(id.as_bytes());
    context.extend_from_slice(&Sha256::digest(request));
    context
}

fn authed<T>(value: T, token: &str) -> Request<T> {
    let mut request = Request::new(value);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

async fn prove(
    kernel: &mut Kernel,
    evaluator: &mut PasswordHistoryEvaluatorServiceClient<Channel>,
    password: &str,
    context: &PasswordHistoryContext,
) -> PasswordRegistrationProof {
    let blinded = bytes(
        kernel
            .call(json!({"method":"history", "password":password,
        "ownerDomain":context.owner_domain}))
            .await
            .unwrap(),
    );
    let answers = evaluator
        .evaluate_password_history(EvaluatePasswordHistoryRequest {
            operation_id: context.operation_id.clone(),
            blinded_input: blinded,
        })
        .await
        .unwrap()
        .into_inner();
    let input = json!({"method":"prove", "password":password,
        "context": {"operationId":context.operation_id.as_ref().unwrap().value,
            "ownerDomain":context.owner_domain, "policyVersion":context.policy_version,
            "domains":context.domains.iter().map(|d| json!({
                "comparisonDomain":d.comparison_domain,"evaluatorPublicKey":d.evaluator_public_key
            })).collect::<Vec<_>>()},
        "evaluations":answers.evaluations.iter().map(|e| {
            let p=e.proof.as_ref().unwrap();
            json!({"evaluatedElement":e.evaluated_element,"proof":{
                "challenge":p.challenge,"response":p.response}})
        }).collect::<Vec<_>>()});
    // A response from a forged evaluator must fail before SNARK work. The
    // official package must authenticate the same real answer it later proves.
    let mut forged = input.clone();
    let old = bytes(forged["evaluations"][0]["proof"]["challenge"].clone());
    let mut other = vec![0u8; 32];
    if old.iter().all(|b| *b == 0) {
        other[0] = 1;
    }
    forged["evaluations"][0]["proof"]["challenge"] = json!(other);
    let error = kernel.call(forged).await.unwrap_err();
    assert!(
        error.contains("evaluator's proof does not verify"),
        "{error}"
    );
    let result = kernel.call(input).await.unwrap();
    // The evaluator's proofs travel with the finish, unchanged, for the
    // history checker.
    PasswordRegistrationProof {
        zkpp_proof: bytes(result["proof"].clone()),
        instances: serde_json::from_value(result["instances"].clone()).unwrap(),
        evaluation_proofs: answers
            .evaluations
            .into_iter()
            .map(|e| e.proof.expect("an evaluation proof"))
            .collect(),
    }
}

async fn login(
    kernel: &mut Kernel,
    auth: &mut AuthServiceClient<Channel>,
    principal: &str,
    password: &str,
) -> Result<String, String> {
    let request = bytes(
        kernel
            .call(json!({"method":"loginStart", "password":password}))
            .await?,
    );
    let response = auth
        .opaque_login_start(OpaqueLoginStartRequest {
            principal: principal.into(),
            credential_request: request,
        })
        .await
        .map_err(|e| e.to_string())?
        .into_inner();
    let finalization = bytes(
        kernel
            .call(json!({"method":"loginFinish","password":password,
        "response":response.credential_response}))
            .await?,
    );
    let done = auth
        .opaque_login_finish(OpaqueLoginFinishRequest {
            principal: principal.into(),
            credential_finalization: finalization,
            server_login_state: response.server_login_state,
        })
        .await
        .map_err(|e| e.to_string())?
        .into_inner();
    assert!(!done.access_token.is_empty());
    Ok(done.access_token)
}

/// A published client must complete every password lifecycle step against
/// the real RPC server; wrong passwords, reused history and proof omission
/// must fail rather than turn into successful unverified installations.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_client_completes_password_lifecycle() {
    password_lifecycle("kernel.mjs").await;
}

/// The same lifecycle and refusals must hold in a real browser, not just Node.
/// Its installed SDK runs the actual browser KSF and prover on the page.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_browser_completes_password_lifecycle() {
    password_lifecycle("browser.mjs").await;
}

async fn password_lifecycle(adapter: &str) {
    let (_, verifier) = zkpp_client::keys(1);
    let svc = TestServices::with_zkpp(
        MockStorage::new().with_system_project(),
        verifier,
        ZkppConfig::default(),
    );
    let storage = svc.storage.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(AuthServiceServer::from_arc(svc.auth))
            .add_service(PasswordHistoryEvaluatorServiceServer::new(svc.evaluator))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = stopped.await;
                },
            ),
    );
    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut auth = AuthServiceClient::new(channel.clone());
    let mut evaluator = PasswordHistoryEvaluatorServiceClient::new(channel);
    let mut kernel = Kernel::start(adapter);
    let principal = format!(
        "published-{}@sid.example.com",
        uuid::Uuid::now_v7().simple()
    );

    // A capable client cannot omit its proof and obtain an account anyway.
    let omitted_principal = format!("omitted-{}@sid.example.com", uuid::Uuid::now_v7().simple());
    let request = bytes(
        kernel
            .call(json!({"method":"start","password":FIRST}))
            .await
            .unwrap(),
    );
    let unproven = auth
        .opaque_zkpp_registration_start(OpaqueZkppRegistrationStartRequest {
            principal: omitted_principal.clone(),
            registration_request: request,
            claim_token: None,
        })
        .await
        .unwrap()
        .into_inner();
    let record = bytes(
        kernel
            .call(json!({"method":"record","password":FIRST,
        "response":unproven.registration_response}))
            .await
            .unwrap(),
    );
    let error = auth
        .opaque_zkpp_registration_finish(OpaqueZkppRegistrationFinishRequest {
            operation_id: unproven.history.unwrap().operation_id,
            registration_record: record,
            proof: None,
        })
        .await
        .unwrap_err();
    assert_eq!(
        error.get_details_error_info().unwrap().reason,
        "REQUIRED_FIELD_MISSING"
    );
    assert!(
        login(&mut kernel, &mut auth, &omitted_principal, FIRST)
            .await
            .is_err()
    );

    let request = bytes(
        kernel
            .call(json!({"method":"start","password":FIRST}))
            .await
            .unwrap(),
    );
    let begun = auth
        .opaque_zkpp_registration_start(OpaqueZkppRegistrationStartRequest {
            principal: principal.clone(),
            registration_request: request,
            claim_token: None,
        })
        .await
        .unwrap()
        .into_inner();
    let context = begun.history.unwrap();
    let proof = prove(&mut kernel, &mut evaluator, FIRST, &context).await;
    let original_proof = proof.clone();
    let record = bytes(
        kernel
            .call(json!({"method":"record","password":FIRST,
        "response":begun.registration_response}))
            .await
            .unwrap(),
    );
    let finish = OpaqueZkppRegistrationFinishRequest {
        operation_id: context.operation_id,
        registration_record: record,
        proof: Some(proof),
    };
    let installed = auth
        .opaque_zkpp_registration_finish(finish.clone())
        .await
        .unwrap()
        .into_inner();
    // A lost success response must not install a second credential on retry.
    let retried = auth
        .opaque_zkpp_registration_finish(finish)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(retried.profile_id, installed.profile_id);
    assert_eq!(retried.credential_id, installed.credential_id);
    let profile_id = ProfileId::parse(&installed.profile_id).unwrap();
    let credential_id = installed.credential_id;
    let original_oprf_id = storage
        .get_credentials_by_profile(profile_id, Some(sid_core::models::CredentialType::Opaque))
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.id.0.to_string() == credential_id)
        .unwrap()
        .opaque_credential_identifier
        .expect("registration persists its operation-specific OPRF identifier");
    let token = login(&mut kernel, &mut auth, &principal, FIRST)
        .await
        .unwrap();
    assert!(
        login(&mut kernel, &mut auth, &principal, "wrong")
            .await
            .is_err()
    );

    // A valid published-client proof belongs to its original owner/operation.
    // Run the other operation's real evaluation step, so refusal cannot be
    // explained merely by a missing step or an unknown operation identifier.
    let other_principal = format!("other-{}@sid.example.com", uuid::Uuid::now_v7().simple());
    let request = bytes(
        kernel
            .call(json!({"method":"start","password":FIRST}))
            .await
            .unwrap(),
    );
    let other = auth
        .opaque_zkpp_registration_start(OpaqueZkppRegistrationStartRequest {
            principal: other_principal.clone(),
            registration_request: request,
            claim_token: None,
        })
        .await
        .unwrap()
        .into_inner();
    let other_context = other.history.unwrap();
    let blinded = bytes(
        kernel
            .call(json!({"method":"history","password":FIRST,
                "ownerDomain":other_context.owner_domain}))
            .await
            .unwrap(),
    );
    evaluator
        .evaluate_password_history(EvaluatePasswordHistoryRequest {
            operation_id: other_context.operation_id.clone(),
            blinded_input: blinded,
        })
        .await
        .unwrap();
    let record = bytes(
        kernel
            .call(json!({"method":"record","password":FIRST,
                "response":other.registration_response}))
            .await
            .unwrap(),
    );
    let error = auth
        .opaque_zkpp_registration_finish(OpaqueZkppRegistrationFinishRequest {
            operation_id: other_context.operation_id,
            registration_record: record,
            proof: Some(original_proof),
        })
        .await
        .unwrap_err();
    assert_eq!(
        error.get_details_error_info().unwrap().reason,
        "PASSWORD_PROOF_INVALID"
    );
    assert_eq!(error.code(), Code::InvalidArgument);
    assert!(
        login(&mut kernel, &mut auth, &other_principal, FIRST)
            .await
            .is_err()
    );

    // The same published prover must not omit the retained-password check.
    // Each change proves the current password (FIRST: the reused attempt
    // changes nothing) with the published client's own sign-in.
    for (password, reused) in [(FIRST, true), (SECOND, false)] {
        // The new password's request comes first: the challenge fixes it and
        // the current-password sign-in is bound to it.
        let request = bytes(
            kernel
                .call(json!({"method":"start","password":password}))
                .await
                .unwrap(),
        );
        let sign_in = bytes(
            kernel
                .call(json!({"method":"loginStart", "password":FIRST}))
                .await
                .unwrap(),
        );
        let challenge = auth
            .password_change_challenge(authed(
                PasswordChangeChallengeRequest {
                    credential_id: credential_id.clone(),
                    credential_request: sign_in,
                    registration_request: request.clone(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let context = challenge.history.unwrap();
        let sign_in_context = change_context(context.operation_id.as_ref().unwrap(), &request);
        let credential_finalization = bytes(
            kernel
                .call(json!({"method":"loginFinish","password":FIRST,
                    "response":challenge.credential_response,
                    "context":sign_in_context}))
                .await
                .unwrap(),
        );
        let executed = auth
            .password_change_execute(authed(
                PasswordChangeExecuteRequest {
                    operation_id: context.operation_id.clone(),
                    credential_id: credential_id.clone(),
                    credential_finalization,
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let proof = prove(&mut kernel, &mut evaluator, password, &context).await;
        let record = bytes(
            kernel
                .call(json!({"method":"record","password":password,
            "response":executed.registration_response}))
                .await
                .unwrap(),
        );
        let result = auth
            .password_change_finish(authed(
                PasswordChangeFinishRequest {
                    operation_id: context.operation_id,
                    credential_id: credential_id.clone(),
                    registration_record: record,
                    proof: Some(proof),
                },
                &token,
            ))
            .await;
        if reused {
            let error = result.unwrap_err();
            assert_eq!(
                error.get_details_error_info().unwrap().reason,
                "PASSWORD_REUSED"
            );
            assert_eq!(error.code(), Code::FailedPrecondition);
            // Rejection must leave the current account credential usable.
            login(&mut kernel, &mut auth, &principal, FIRST)
                .await
                .unwrap();
        } else {
            result.unwrap();
        }
    }
    assert!(
        login(&mut kernel, &mut auth, &principal, FIRST)
            .await
            .is_err()
    );
    login(&mut kernel, &mut auth, &principal, SECOND)
        .await
        .unwrap();
    let credential = storage
        .get_credentials_by_profile(profile_id, Some(sid_core::models::CredentialType::Opaque))
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.credential_type == sid_core::models::CredentialType::Opaque)
        .unwrap();
    assert!(credential.policy_evidence.is_verified());
    // Rotation concerns the OPRF key identifier, not the credential row UUID.
    assert_ne!(
        credential.opaque_credential_identifier.unwrap(),
        original_oprf_id
    );

    // Mailbox verification supplies reset authority, not a new sign-in.
    let reset_secret = "conformance-reset-link";
    let reset = PasswordResetSession::new(
        profile_id,
        principal.clone(),
        Sha256::digest(reset_secret)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    );
    storage
        .create_reset_session(&reset, AuditEntry::system("test", "reset").into())
        .await
        .unwrap();
    let verified = auth
        .verify_password_reset(VerifyPasswordResetRequest {
            session_id: reset.id.to_string(),
            token: reset_secret.into(),
        })
        .await
        .unwrap()
        .into_inner();
    let context = verified.history.unwrap();
    let request = bytes(
        kernel
            .call(json!({"method":"start","password":RESET}))
            .await
            .unwrap(),
    );
    let executed = auth
        .execute_password_reset(ExecutePasswordResetRequest {
            operation_id: context.operation_id.clone(),
            registration_request: request,
        })
        .await
        .unwrap()
        .into_inner();
    let proof = prove(&mut kernel, &mut evaluator, RESET, &context).await;
    let record = bytes(
        kernel
            .call(json!({"method":"record","password":RESET,
        "response":executed.registration_response}))
            .await
            .unwrap(),
    );
    auth.complete_password_reset(CompletePasswordResetRequest {
        reset_session_id: verified.reset_session_id,
        operation_id: context.operation_id,
        registration_record: record,
        proof: Some(proof),
    })
    .await
    .unwrap();
    assert!(
        login(&mut kernel, &mut auth, &principal, SECOND)
            .await
            .is_err()
    );
    login(&mut kernel, &mut auth, &principal, RESET)
        .await
        .unwrap();
    // EOF lets the browser adapter close Chromium and its loopback server.
    drop(kernel.child.stdin.take());
    let exit = tokio::time::timeout(Duration::from_secs(10), kernel.child.wait())
        .await
        .expect("client cleanup timeout")
        .unwrap();
    assert!(exit.success());
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
