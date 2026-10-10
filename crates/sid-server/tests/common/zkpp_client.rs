// SPDX-License-Identifier: AGPL-3.0-only
//! The client side of a password operation, driven against test services:
//! the OPAQUE start, the history request and its evaluation by the services'
//! evaluator, and the proof bound to the operation and the request.
#![allow(dead_code)]

use super::TestServices;
use ff::PrimeField;
use group::GroupEncoding;
use pasta_curves::pallas;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sid_ids::PasswordOperationId;
use sid_opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse};
use sid_pake_core::binding::operation_context;
use sid_pake_core::circuit::{CircuitShape, ZKPP_K};
use sid_pake_core::history::{
    EvaluationProof, blind_request, history_input, random_blind, verify_evaluation,
};
use sid_pake_core::keygen::{generate_params, generate_pk};
use sid_pake_core::pallas_opaque::PallasCipherSuite;
use sid_pake_core::prover::{BoundProof, HistoryEvaluation, ZkppProver};
use sid_pake_core::types::CE_DEFAULT_POLICY;
use sid_pake_core::verifier::ZkppVerifier;
use sid_proto::sid::v1::authn::password_history_evaluator_service_server::PasswordHistoryEvaluatorService;
use sid_proto::sid::v1::authn::{
    EvaluatePasswordHistoryRequest, PasswordHistoryContext, PasswordHistoryEvaluationProof,
    PasswordRegistrationProof,
};
use tonic::Request;

/// A prover and the verifier of the same keys for `domains` comparison
/// domains under the CE policy.
pub fn keys(domains: usize) -> (ZkppProver, ZkppVerifier) {
    let shape = CircuitShape {
        policy: CE_DEFAULT_POLICY,
        history_domains: domains,
    };
    let params = generate_params(ZKPP_K);
    let pk = generate_pk(&params, shape).expect("keygen");
    let verifier = ZkppVerifier::new(params.clone(), pk.get_vk().clone(), shape);
    (ZkppProver::new(params, pk, shape), verifier)
}

/// A client's OPAQUE registration start: the request it sends and the state
/// the proof and the finish read.
pub struct Started {
    pub request: Vec<u8>,
    pub state: ClientRegistration<PallasCipherSuite>,
}

/// The OPRF blind of a registration state (`OprfClient` = the blind, then the
/// blinded element).
fn blind_of(state: &ClientRegistration<PallasCipherSuite>) -> pallas::Scalar {
    let mut repr = <pallas::Scalar as PrimeField>::Repr::default();
    repr.copy_from_slice(&state.serialize()[..32]);
    pallas::Scalar::from_repr(repr).expect("the state starts with the blind")
}

/// Start registering `password`, with a blind the circuit can hold.
pub fn start(password: &[u8]) -> Started {
    loop {
        let started =
            ClientRegistration::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), password)
                .expect("registration start");
        let blind = blind_of(&started.state);
        if bool::from(pallas::Base::from_repr(blind.to_repr()).is_some()) {
            return Started {
                request: started.message.serialize().to_vec(),
                state: started.state,
            };
        }
    }
}

fn array32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32 bytes")
}

fn base(bytes: &[u8]) -> pallas::Base {
    pallas::Base::from_repr(array32(bytes)).expect("a field element")
}

fn scalar(bytes: &[u8]) -> pallas::Scalar {
    pallas::Scalar::from_repr(array32(bytes)).expect("a scalar")
}

fn point(bytes: &[u8]) -> pallas::Affine {
    pallas::Affine::from_bytes(&array32(bytes)).expect("a curve point")
}

/// The operation `context` names.
pub fn operation(context: &PasswordHistoryContext) -> PasswordOperationId {
    sid_ids_proto::required(context.operation_id.as_ref()).expect("an operation id")
}

/// What the evaluator answered: the prover's history input and the
/// evaluator's proofs, relayed unchanged with the finish.
pub struct Evaluated {
    pub history: HistoryEvaluation,
    pub proofs: Vec<PasswordHistoryEvaluationProof>,
}

/// Have the services' evaluator evaluate the history input of `password` for
/// the operation `context`, checking each answer's proof under its domain's
/// key as the client does before proving.
pub async fn evaluate(
    svc: &TestServices,
    password: &[u8],
    context: &PasswordHistoryContext,
) -> Evaluated {
    let d = base(&context.owner_domain);
    let r = random_blind(UnwrapErr(SysRng));
    let b = blind_request(history_input(d, password), r);
    let op = operation(context);
    let answers = svc
        .evaluator
        .evaluate_password_history(Request::new(EvaluatePasswordHistoryRequest {
            operation_id: context.operation_id.clone(),
            blinded_input: b.to_bytes().to_vec(),
        }))
        .await
        .expect("history evaluation")
        .into_inner()
        .evaluations;
    assert_eq!(
        answers.len(),
        context.domains.len(),
        "one answer per comparison domain"
    );
    let evaluations = context
        .domains
        .iter()
        .zip(&answers)
        .map(|(domain, answer)| {
            let z = point(&answer.evaluated_element);
            let proof = answer.proof.as_ref().expect("an evaluation proof");
            assert!(
                verify_evaluation(
                    point(&domain.evaluator_public_key),
                    b,
                    z,
                    op.as_bytes(),
                    &EvaluationProof {
                        c: scalar(&proof.challenge),
                        s: scalar(&proof.response),
                    },
                ),
                "the evaluator's proof verifies under the domain's key"
            );
            z
        })
        .collect();
    Evaluated {
        history: HistoryEvaluation {
            d,
            domains: context
                .domains
                .iter()
                .map(|x| base(&x.comparison_domain))
                .collect(),
            r,
            evaluations,
        },
        proofs: answers
            .into_iter()
            .map(|a| a.proof.expect("an evaluation proof"))
            .collect(),
    }
}

/// The proof of `password` for the operation `context` over the request of
/// `started`, with the `evaluated` history, in its wire form.
pub fn prove(
    prover: &ZkppProver,
    password: &[u8],
    context: &PasswordHistoryContext,
    started: &Started,
    evaluated: &Evaluated,
) -> PasswordRegistrationProof {
    let op = operation(context);
    wire(
        prover
            .prove(
                password,
                blind_of(&started.state),
                &operation_context(op.as_bytes(), &started.request),
                &evaluated.history,
            )
            .expect("prove"),
        evaluated.proofs.clone(),
    )
}

/// Evaluate the history of `password` and prove it: what the client sends
/// with the final record.
pub async fn evaluate_and_prove(
    svc: &TestServices,
    prover: &ZkppProver,
    password: &[u8],
    context: &PasswordHistoryContext,
    started: &Started,
) -> PasswordRegistrationProof {
    let evaluated = evaluate(svc, password, context).await;
    prove(prover, password, context, started, &evaluated)
}

/// The wire form of a bound proof: SNARK bytes and canonical instances, with
/// the evaluator's `proofs` relayed.
pub fn wire(
    proof: BoundProof,
    proofs: Vec<PasswordHistoryEvaluationProof>,
) -> PasswordRegistrationProof {
    PasswordRegistrationProof {
        zkpp_proof: proof.snark_proof.0,
        instances: proof
            .instances
            .iter()
            .map(|i| i.to_repr().to_vec())
            .collect(),
        evaluation_proofs: proofs,
    }
}

/// The registration record of `password` from the server's `response`.
pub fn finish(started: Started, password: &[u8], response: &[u8]) -> Vec<u8> {
    started
        .state
        .finish(
            &mut UnwrapErr(SysRng),
            password,
            RegistrationResponse::deserialize(response).expect("a registration response"),
            ClientRegistrationFinishParameters::default(),
        )
        .expect("registration finish")
        .message
        .serialize()
        .to_vec()
}
