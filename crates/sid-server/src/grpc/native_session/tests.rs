// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use tonic::Code;

fn request_with(proofs: &[&str]) -> Request<()> {
    let mut request = Request::new(());
    for proof in proofs {
        request
            .metadata_mut()
            .append(PROOF_METADATA, proof.parse().unwrap());
    }
    request
}

const ORIGIN: &str = "https://sid.example.com";
const RPC: &str = "/sid.v1.authn.AuthService/OpaqueLoginFinish";

/// No proof: the ceremony completes as before, without a refresh generation.
#[test]
fn no_proof_asks_for_no_renewal() {
    let request = request_with(&[]);
    assert!(
        NativeProof::of(&request, CeremonyClient::Native, ORIGIN, RPC)
            .unwrap()
            .is_none()
    );
}

/// A proof of a direct gRPC call names the issuer's origin and the RPC path,
/// by POST.
#[test]
fn a_proof_names_the_call_as_addressed() {
    let request = request_with(&["proof"]);
    let proof = NativeProof::of(&request, CeremonyClient::Native, ORIGIN, RPC)
        .unwrap()
        .unwrap();
    assert_eq!(proof.proof(), "proof");
    assert_eq!(proof.target().method, "POST");
    assert_eq!(proof.target().uri, format!("{ORIGIN}{RPC}"));
}

/// Two proofs are refused rather than one picked; so is an empty one.
#[test]
fn a_proof_is_presented_once() {
    for proofs in [&["a", "b"][..], &[""][..]] {
        let request = request_with(proofs);
        let refused = NativeProof::of(&request, CeremonyClient::Native, ORIGIN, RPC)
            .err()
            .unwrap();
        assert_eq!(refused.code(), Code::InvalidArgument, "{proofs:?}");
    }
}

/// The browser sign-in page renews by its cookie: a native proof from it is
/// refused, never silently dropped.
#[test]
fn a_browser_sends_no_native_proof() {
    let request = request_with(&["proof"]);
    let refused = NativeProof::of(&request, CeremonyClient::Browser, ORIGIN, RPC)
        .err()
        .unwrap();
    assert_eq!(refused.code(), Code::InvalidArgument);
}

/// Every refusal about the credential or session is the same answer, so a
/// copied credential without its key learns nothing about it.
#[test]
fn credential_refusals_are_one_answer() {
    let answers: Vec<_> = [
        NativeError::UnknownCredential,
        NativeError::KeyMismatch,
        NativeError::Expired,
        NativeError::Reused,
        NativeError::Ended,
    ]
    .into_iter()
    .map(|e| {
        let status = refusal(e);
        (status.code(), status.message().to_owned())
    })
    .collect();
    assert!(answers.iter().all(|a| a == &answers[0]), "{answers:?}");
    assert_eq!(answers[0].0, Code::Unauthenticated);
}

/// An unreachable replay record is a retryable outage, not a bad proof.
#[test]
fn an_unreachable_replay_record_is_unavailable() {
    let status = refusal(NativeError::Proof(DPopError::ReplayStoreUnavailable));
    assert_eq!(status.code(), Code::Unavailable);
    let status = refusal(NativeError::Proof(DPopError::ReplayDetected));
    assert_eq!(status.code(), Code::InvalidArgument);
}
