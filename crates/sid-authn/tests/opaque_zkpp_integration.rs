// SPDX-License-Identifier: AGPL-3.0-only
//! Integration tests for OPAQUE-ZKPP password installation with private
//! history: the real prover, the VOPRF evaluator, the verifier and the
//! history checker, end to end, and login through the installation's OPAQUE
//! router. In-memory only (no PostgreSQL required).
//!
//! Keygen is expensive, so params/keys are generated once per circuit shape
//! and shared across all tests.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use ff::PrimeField;
use group::GroupEncoding;
use halo2_proofs::{plonk::ProvingKey, poly::commitment::Params};
use opaque_ke::{ClientRegistration, ClientRegistrationStartResult};
use pasta_curves::{pallas, vesta};
use rand::rngs::OsRng;
use secrecy::SecretBox;
use sid_authn::opaque::{OpaqueRouter, PallasOpaque};
use sid_authn::opaque_zkpp::{ZkppConfig, ZkppOpaqueServer};
use sid_authn::password_history::{
    CheckRequest, HistoryCheckError, HistoryChecker, HistoryEvaluator, KsfAdmission,
    OperationDomain, OperationEvaluation, owner_domain,
};
use sid_core::models::{
    HistoryEntry, HistoryEvidence, HistoryKsf, NewHistoryEpoch, PasswordHistory, ProfileId,
};
use sid_keys::{KeyManager, KeyVersionParams, RustCryptoPrimitives, SoftwareKeyManager};
use sid_pake_core::{
    binding::operation_context,
    circuit::{CircuitShape, ZKPP_K},
    history::{blind_request, history_input, random_blind},
    keygen::{generate_params, generate_pk},
    pallas_opaque::PallasCipherSuite,
    prover::{BoundProof, HistoryEvaluation, ZkppProver},
    types::CE_DEFAULT_POLICY,
    verifier::ZkppVerifier,
};
use sid_plugin::crypto::{CurveId, OpaqueOperations, StoredCredential};

/// Cheap KSF: these tests check the relation, not the KSF cost.
const KSF: HistoryKsf = HistoryKsf {
    memory_kib: 64,
    passes: 1,
    lanes: 1,
};
const INSTALLATION: [u8; 16] = [0x5a; 16];

struct ZkppKeys {
    params: Params<vesta::Affine>,
    pk: ProvingKey<vesta::Affine>,
}

fn shape(domains: usize) -> CircuitShape {
    CircuitShape {
        policy: CE_DEFAULT_POLICY,
        history_domains: domains,
    }
}

/// Keys for one and for two comparison domains, generated once.
static KEYS: LazyLock<[ZkppKeys; 2]> = LazyLock::new(|| {
    [1, 2].map(|domains| {
        let params = generate_params(ZKPP_K);
        let pk = generate_pk(&params, shape(domains)).expect("keygen failed");
        ZkppKeys { params, pk }
    })
});

fn keys(domains: usize) -> &'static ZkppKeys {
    &KEYS[domains - 1]
}

fn prover(domains: usize) -> ZkppProver {
    let k = keys(domains);
    ZkppProver::new(k.params.clone(), k.pk.clone(), shape(domains))
}

fn verifier(domains: usize) -> ZkppVerifier {
    let k = keys(domains);
    ZkppVerifier::new(k.params.clone(), k.pk.get_vk().clone(), shape(domains))
}

fn key_manager() -> std::sync::Arc<dyn KeyManager> {
    std::sync::Arc::new(
        SoftwareKeyManager::new(
            SecretBox::new(Box::new([9u8; 32])),
            vec![KeyVersionParams::new(1, vec![1u8; 16], "key-v1")],
            std::sync::Arc::new(RustCryptoPrimitives::new()),
        )
        .expect("test key manager"),
    )
}

/// The installation's OPAQUE router: Pallas primary on a fresh setup.
fn router() -> OpaqueRouter {
    let primary = PallasOpaque::new();
    let setup = primary.create_setup(None).expect("setup");
    let mut verifiers: HashMap<CurveId, Box<dyn OpaqueOperations>> = HashMap::new();
    verifiers.insert(CurveId::Pallas, Box::new(PallasOpaque::new()));
    OpaqueRouter::new(Box::new(primary), verifiers, setup)
}

/// A ZKPP server on `router`'s setup verifying `domains` shapes.
fn server(router: &OpaqueRouter, domains: &[usize], require: bool) -> ZkppOpaqueServer {
    ZkppOpaqueServer::new(
        router,
        domains.iter().map(|d| verifier(*d)).collect(),
        ZkppConfig {
            require_proof: require,
            policy_version: 1,
        },
    )
    .expect("zkpp server")
}

fn checker() -> HistoryChecker {
    HistoryChecker::new(KsfAdmission::new(64, Duration::from_secs(10)))
}

/// A client's OPAQUE registration start for `password`.
fn client_start(password: &[u8]) -> ClientRegistrationStartResult<PallasCipherSuite> {
    ClientRegistration::<PallasCipherSuite>::start(&mut OsRng, password)
        .expect("client registration start failed")
}

/// The OPRF blind the client drew, read from its registration state
/// (`OprfClient` = blind scalar, then the blinded element).
fn client_blind(start: &ClientRegistrationStartResult<PallasCipherSuite>) -> pallas::Scalar {
    let mut repr = <pallas::Scalar as PrimeField>::Repr::default();
    repr.copy_from_slice(&start.state.serialize()[..32]);
    pallas::Scalar::from_repr(repr).expect("the state starts with the blind")
}

/// Finish the client side of a registration against the server's response.
fn client_finish(
    start: ClientRegistrationStartResult<PallasCipherSuite>,
    password: &[u8],
    response: &[u8],
) -> Vec<u8> {
    start
        .state
        .finish(
            &mut OsRng,
            password,
            opaque_ke::RegistrationResponse::<PallasCipherSuite>::deserialize(response).unwrap(),
            opaque_ke::ClientRegistrationFinishParameters::default(),
        )
        .expect("client registration finish failed")
        .message
        .serialize()
        .to_vec()
}

/// Sign in with `password` against `password_file` through `router`; true
/// when both sides end with the same session key.
fn signs_in(router: &OpaqueRouter, password_file: &[u8], password: &[u8], id: &[u8]) -> bool {
    let stored = StoredCredential {
        curve: CurveId::Pallas,
        data: password_file.to_vec(),
    };
    let login = opaque_ke::ClientLogin::<PallasCipherSuite>::start(&mut OsRng, password).unwrap();
    let (response, state) = router
        .login_start(&stored, &login.message.serialize(), id)
        .expect("login start");
    let Ok(finished) = login.state.finish(
        &mut OsRng,
        password,
        opaque_ke::CredentialResponse::<PallasCipherSuite>::deserialize(&response).unwrap(),
        opaque_ke::ClientLoginFinishParameters::default(),
    ) else {
        return false;
    };
    router
        .login_finish(&state, &finished.message.serialize())
        .is_ok_and(|key| key.expose_secret() == finished.session_key.as_slice())
}

/// One password operation of `owner` against `epochs`: the server's domain
/// list and operation id, the client's blinded request and the evaluator's
/// answers, and what the prover needs.
struct Operation {
    id: [u8; 16],
    domains: Vec<OperationDomain>,
    evaluation: OperationEvaluation,
    prover_input: HistoryEvaluation,
}

async fn operation(
    evaluator: &HistoryEvaluator,
    owner: ProfileId,
    epochs: &[&NewHistoryEpoch],
    password: &[u8],
) -> Operation {
    let id = *uuid::Uuid::now_v7().as_bytes();
    let d = pallas::Base::from_repr(owner_domain(&INSTALLATION, owner)).unwrap();
    let r = random_blind(OsRng);
    let b = blind_request(history_input(d, password), r).to_bytes();
    let domains: Vec<_> = epochs
        .iter()
        .map(|e| OperationDomain::of(&e.epoch))
        .collect();
    let keys: Vec<_> = epochs
        .iter()
        .map(|e| (e.epoch.id, owner, e.key.clone()))
        .collect();
    let evaluation = evaluator.evaluate(&b, &keys, &id).await.unwrap();
    let prover_input = HistoryEvaluation {
        d,
        domains: domains
            .iter()
            .map(|dom| pallas::Base::from_repr(dom.comparison_domain).unwrap())
            .collect(),
        r,
        evaluations: evaluation
            .evaluations
            .iter()
            .map(|a| pallas::Affine::from_bytes(&a.evaluated).unwrap())
            .collect(),
    };
    Operation {
        id,
        domains,
        evaluation,
        prover_input,
    }
}

fn prove(
    op: &Operation,
    password: &[u8],
    start: &ClientRegistrationStartResult<PallasCipherSuite>,
) -> BoundProof {
    prover(op.domains.len())
        .prove(
            password,
            client_blind(start),
            &operation_context(&op.id, &start.message.serialize()),
            &op.prover_input,
        )
        .expect("proof generation failed")
}

fn history(epochs: &[&NewHistoryEpoch], entries: &[(usize, [u8; 32])]) -> PasswordHistory {
    PasswordHistory {
        revision: 1,
        epochs: epochs.iter().map(|e| e.epoch.clone()).collect(),
        entries: entries
            .iter()
            .enumerate()
            .map(|(seq, (epoch, entry))| HistoryEntry {
                epoch: epochs[*epoch].epoch.id,
                seq: seq as i64 + 1,
                entry: *entry,
                evidence: HistoryEvidence {
                    operation: uuid::Uuid::now_v7(),
                    policy_version: 1,
                },
                created_at: chrono::Utc::now(),
            })
            .collect(),
    }
}

fn check_request<'a>(
    owner: ProfileId,
    op: &'a Operation,
    history: &'a PasswordHistory,
) -> CheckRequest<'a> {
    CheckRequest {
        owner_domain: owner_domain(&INSTALLATION, owner),
        domains: &op.domains,
        evaluation: &op.evaluation,
        context: &op.id,
        history,
    }
}

/// A registration: the proof verifies against the operation and its request,
/// the checker accepts the new password with one entry, and the installed
/// password signs in.
#[tokio::test]
async fn a_proved_registration_installs_its_first_history_and_signs_in() {
    let router = router();
    let server = server(&router, &[1], true);
    let evaluator = HistoryEvaluator::new(key_manager());
    let owner = ProfileId::generate();
    let epoch = evaluator.new_epoch(owner, KSF).await.unwrap();
    let password = b"Str0ngP@ssword1";
    let id = b"alice@sid.example.com";

    let op = operation(&evaluator, owner, &[&epoch], password).await;
    let start = client_start(password);
    let request = start.message.serialize().to_vec();
    let proof = prove(&op, password, &start);

    let public = server.verify(&proof, &op.id, &request, 1).unwrap();
    let first = history(&[&epoch], &[]);
    let accepted = checker()
        .check(&public, check_request(owner, &op, &first))
        .await
        .unwrap();
    assert_eq!(accepted.new_entries.len(), 1);

    let response = server.opaque_start(&request, id).unwrap();
    let upload = client_finish(start, password, &response);
    let file = server.opaque_finish(&upload).unwrap();
    assert!(signs_in(&router, &file, password, id));
}

/// A password change: the retained password is refused as reused in a
/// fresh operation (new blind, new request); a new password is accepted.
#[tokio::test]
async fn a_change_to_a_retained_password_is_refused() {
    let router = router();
    let server = server(&router, &[1], true);
    let evaluator = HistoryEvaluator::new(key_manager());
    let owner = ProfileId::generate();
    let epoch = evaluator.new_epoch(owner, KSF).await.unwrap();
    let old = b"OldStr0ngP@ss1";

    let op = operation(&evaluator, owner, &[&epoch], old).await;
    let start = client_start(old);
    let public = server
        .verify(
            &prove(&op, old, &start),
            &op.id,
            &start.message.serialize(),
            1,
        )
        .unwrap();
    let entry = checker()
        .check(&public, check_request(owner, &op, &history(&[&epoch], &[])))
        .await
        .unwrap()
        .new_entries[0]
        .1;
    let retained = history(&[&epoch], &[(0, entry)]);

    let op = operation(&evaluator, owner, &[&epoch], old).await;
    let start = client_start(old);
    let public = server
        .verify(
            &prove(&op, old, &start),
            &op.id,
            &start.message.serialize(),
            1,
        )
        .unwrap();
    assert_eq!(
        checker()
            .check(&public, check_request(owner, &op, &retained))
            .await
            .unwrap_err(),
        HistoryCheckError::Reused
    );

    let new = b"NewStr0ngP@ss2";
    let op = operation(&evaluator, owner, &[&epoch], new).await;
    let start = client_start(new);
    let public = server
        .verify(
            &prove(&op, new, &start),
            &op.id,
            &start.message.serialize(),
            1,
        )
        .unwrap();
    assert!(
        checker()
            .check(&public, check_request(owner, &op, &retained))
            .await
            .is_ok()
    );
}

/// A rotation: the operation covers the active epoch and the rotated one
/// that still holds the old password. The password is refused through the
/// rotated domain, a new one is accepted with an entry under the active epoch
/// only, and a proof over two domains is refused by a one-domain verifier.
#[tokio::test]
async fn a_rotated_epoch_still_refuses_its_passwords() {
    let router = router();
    let server = server(&router, &[1, 2], true);
    let evaluator = HistoryEvaluator::new(key_manager());
    let owner = ProfileId::generate();
    let mut rotated = evaluator.new_epoch(owner, KSF).await.unwrap();
    let old = b"OldStr0ngP@ss1";

    let op = operation(&evaluator, owner, &[&rotated], old).await;
    let start = client_start(old);
    let public = server
        .verify(
            &prove(&op, old, &start),
            &op.id,
            &start.message.serialize(),
            1,
        )
        .unwrap();
    let entry = checker()
        .check(
            &public,
            check_request(owner, &op, &history(&[&rotated], &[])),
        )
        .await
        .unwrap()
        .new_entries[0]
        .1;

    rotated.epoch.status = sid_core::models::HistoryEpochUse::CompareOnly;
    let active = evaluator.new_epoch(owner, KSF).await.unwrap();
    let after_rotation = history(&[&active, &rotated], &[(1, entry)]);

    let op = operation(&evaluator, owner, &[&active, &rotated], old).await;
    let start = client_start(old);
    let request = start.message.serialize().to_vec();
    let proof = prove(&op, old, &start);
    assert!(
        server.verify(&proof, &op.id, &request, 1).is_err(),
        "a two-domain proof under a one-domain key"
    );
    let public = server.verify(&proof, &op.id, &request, 2).unwrap();
    assert_eq!(
        checker()
            .check(&public, check_request(owner, &op, &after_rotation))
            .await
            .unwrap_err(),
        HistoryCheckError::Reused
    );

    let new = b"NewStr0ngP@ss2";
    let op = operation(&evaluator, owner, &[&active, &rotated], new).await;
    let start = client_start(new);
    let public = server
        .verify(
            &prove(&op, new, &start),
            &op.id,
            &start.message.serialize(),
            2,
        )
        .unwrap();
    let accepted = checker()
        .check(&public, check_request(owner, &op, &after_rotation))
        .await
        .unwrap();
    assert_eq!(
        accepted
            .new_entries
            .iter()
            .map(|(e, _)| *e)
            .collect::<Vec<_>>(),
        vec![active.epoch.id],
        "new entries go under the active epoch only"
    );
}

/// A password below the server's policy cannot be proven under the server's
/// key: the prover finds no witness meeting its minimums.
#[tokio::test]
async fn a_weak_password_has_no_proof() {
    let evaluator = HistoryEvaluator::new(key_manager());
    let owner = ProfileId::generate();
    let epoch = evaluator.new_epoch(owner, KSF).await.unwrap();
    let password = b"abc";
    let op = operation(&evaluator, owner, &[&epoch], password).await;
    let start = client_start(password);
    assert!(
        prover(1)
            .prove(
                password,
                client_blind(&start),
                &operation_context(&op.id, &start.message.serialize()),
                &op.prover_input,
            )
            .is_err()
    );
}

/// Proof binding: a proof for a strong password, made with a weak
/// request's own blind and bytes, does not verify for that request.
#[tokio::test]
async fn a_proof_for_another_password_than_the_request_is_refused() {
    let router = router();
    let server = server(&router, &[1], true);
    let evaluator = HistoryEvaluator::new(key_manager());
    let owner = ProfileId::generate();
    let epoch = evaluator.new_epoch(owner, KSF).await.unwrap();

    let strong = b"Str0ngPr0ven1";
    let op = operation(&evaluator, owner, &[&epoch], strong).await;
    let weak = client_start(b"weak");
    let weak_request = weak.message.serialize().to_vec();
    let proof = prover(1)
        .prove(
            strong,
            client_blind(&weak),
            &operation_context(&op.id, &weak_request),
            &op.prover_input,
        )
        .expect("proof generation");
    let err = server.verify(&proof, &op.id, &weak_request, 1).unwrap_err();
    assert!(format!("{err}").contains("ZKPP proof verification failed"));
}

/// A proof is bound to its operation and its request: under another
/// request for the same password, or another operation id, it is refused.
#[tokio::test]
async fn a_proof_is_bound_to_its_operation_and_request() {
    let router = router();
    let server = server(&router, &[1], true);
    let evaluator = HistoryEvaluator::new(key_manager());
    let owner = ProfileId::generate();
    let epoch = evaluator.new_epoch(owner, KSF).await.unwrap();
    let password = b"Str0ngP@ssword1";
    let op = operation(&evaluator, owner, &[&epoch], password).await;
    let start = client_start(password);
    let request = start.message.serialize().to_vec();
    let proof = prove(&op, password, &start);
    assert!(server.verify(&proof, &op.id, &request, 1).is_ok());

    let other_request = client_start(password).message.serialize().to_vec();
    assert!(server.verify(&proof, &op.id, &other_request, 1).is_err());
    let other_op = *uuid::Uuid::now_v7().as_bytes();
    assert!(server.verify(&proof, &other_op, &request, 1).is_err());
}

/// Without a proof, where policy allows it, the password installs through
/// OPAQUE alone and signs in; no verifier is needed.
#[test]
fn an_unproven_password_installs_where_allowed() {
    let router = router();
    let server = server(&router, &[], false);
    let password = b"AnyPassword1";
    let id = b"bob@sid.example.com";
    let start = client_start(password);
    let response = server.opaque_start(&start.message.serialize(), id).unwrap();
    let upload = client_finish(start, password, &response);
    let file = server.opaque_finish(&upload).unwrap();
    assert!(signs_in(&router, &file, password, id));
}

/// Proof size and verification time stay within bounds.
#[tokio::test]
async fn proof_size_and_verification_time() {
    let router = router();
    let server = server(&router, &[1], true);
    let evaluator = HistoryEvaluator::new(key_manager());
    let owner = ProfileId::generate();
    let epoch = evaluator.new_epoch(owner, KSF).await.unwrap();
    let password = b"BenchmarkP@ss1";
    let op = operation(&evaluator, owner, &[&epoch], password).await;
    let start = client_start(password);
    let request = start.message.serialize().to_vec();
    let proof = prove(&op, password, &start);

    let proof_size = proof.snark_proof.0.len();
    assert!(proof_size < 15360, "proof size {proof_size} bytes");

    let started = Instant::now();
    server.verify(&proof, &op.id, &request, 1).unwrap();
    let verify_time = started.elapsed();
    eprintln!("proof {proof_size} bytes, verification {verify_time:?}");
    let limit_ms = if cfg!(debug_assertions) { 500 } else { 100 };
    assert!(verify_time.as_millis() < limit_ms, "{verify_time:?}");
}
