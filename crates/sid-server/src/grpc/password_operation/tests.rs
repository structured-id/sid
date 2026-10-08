// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use ff::PrimeField;
use pasta_curves::pallas;
use tonic::Code;
use tonic_types::StatusExt;

fn change() -> OperationPurpose {
    OperationPurpose::Change {
        profile_id: ProfileId::generate(),
        credential_id: CredentialId(uuid::Uuid::now_v7()),
    }
}

/// A prepared operation between its steps, as [`PasswordOperations::prepare`]
/// stores it.
fn pending(purpose: OperationPurpose) -> PendingOperation {
    PendingOperation {
        id: PasswordOperationId::generate(),
        purpose,
        owner: ProfileId::generate(),
        decoy: false,
        owner_domain: [1; 32],
        domains: vec![],
        history_revision: 0,
        new_epoch: None,
        policy_version: 3,
        charge_key: "profile:test".to_string(),
        credential_identifier: [7; 16],
        registration_request: None,
        evaluation: None,
    }
}

fn finished(op: PendingOperation, proof_verified: bool) -> FinishedOperation {
    let command = op.finish_command(b"record");
    FinishedOperation {
        operation: op,
        password_file: vec![],
        proof_verified,
        history: None,
        command,
    }
}

/// Every purpose names the method of its durable result, and the finish
/// command is keyed by the operation id in the operations' namespace with the
/// record as its inputs: a retry with another record is another command.
#[test]
fn a_finish_command_is_keyed_by_the_operation_and_its_record() {
    let op = pending(change());
    assert_eq!(op.purpose.method(), "change");
    assert_eq!(
        OperationPurpose::Reset {
            session: ResetSessionId(uuid::Uuid::now_v7()),
        }
        .method(),
        "reset"
    );
    let completion = op.finish_command(b"record").completion(vec![1, 2]);
    assert_eq!(completion.namespace, RESULT_NAMESPACE);
    assert_eq!(
        completion.key,
        OperationKey::parse(&op.id.to_string()).unwrap()
    );
    assert_eq!(completion.method, "change");
    assert_eq!(completion.result, vec![1, 2]);
    assert_ne!(
        op.finish_command(b"other").completion(vec![]).fingerprint,
        completion.fingerprint,
        "another record is another command"
    );
}

/// The credential an operation installs carries the proof's evidence and the
/// operation's own OPRF key; without an accepted proof it is policy-unverified.
#[test]
fn an_installed_credential_carries_its_evidence_and_key() {
    let profile = ProfileId::generate();
    let credential = finished(pending(change()), true).credential(profile, vec![1, 2, 3]);
    assert_eq!(credential.profile_id, profile);
    assert_eq!(credential.credential_type, CredentialType::Opaque);
    assert_eq!(credential.opaque_curve, Some(CurveId::Pallas as u8));
    assert!(credential.zkpp_verified);
    assert_eq!(credential.policy_version, Some(3));
    assert_eq!(credential.opaque_credential_identifier, Some([7; 16]));
    assert_eq!(credential.data.expose(), &[1, 2, 3]);

    let unproven = finished(pending(change()), false).credential(profile, vec![]);
    assert!(!unproven.zkpp_verified);
    assert_eq!(unproven.policy_version, None);
    assert_eq!(unproven.opaque_credential_identifier, Some([7; 16]));
}

/// A proof decodes to its SNARK bytes and canonical field elements; an
/// instance of another length or beyond the field is an invalid argument.
#[test]
fn a_proof_decodes_to_canonical_instances() {
    let x = pallas::Base::from(42u64);
    let proof = decode_proof(PasswordRegistrationProof {
        zkpp_proof: vec![9, 9],
        instances: vec![x.to_repr().to_vec()],
    })
    .unwrap();
    assert_eq!(proof.snark_proof.0, vec![9, 9]);
    assert_eq!(proof.instances, vec![x]);

    let short = decode_proof(PasswordRegistrationProof {
        zkpp_proof: vec![],
        instances: vec![vec![1; 31]],
    })
    .err()
    .expect("a 31-byte instance is refused");
    assert_eq!(short.code(), Code::InvalidArgument);
    let beyond = decode_proof(PasswordRegistrationProof {
        zkpp_proof: vec![],
        instances: vec![vec![0xff; 32]],
    })
    .err()
    .expect("an instance beyond the field is refused");
    assert_eq!(beyond.code(), Code::InvalidArgument);
    for refused in [short, beyond] {
        let violation = &refused
            .get_details_bad_request()
            .expect("field violations")
            .field_violations[0];
        assert_eq!(violation.field, "proof.instances");
    }
}

/// A finish before the operation's OPAQUE start or evaluation is
/// INVALID_STATE naming the step, so the client knows what to run first.
#[test]
fn a_skipped_step_is_invalid_state() {
    let status = step_missing("the operation was not evaluated");
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(
        status.get_details_error_info().unwrap().reason,
        "INVALID_STATE"
    );
    let violation = &status
        .get_details_precondition_failure()
        .expect("precondition")
        .violations[0];
    assert_eq!(violation.r#type, "PASSWORD_OPERATION_STEP");
}

/// A step without an operation id is an invalid argument naming the field; a
/// well-formed id round-trips through the wire.
#[test]
fn an_operation_id_is_required_and_round_trips() {
    let missing = operation_id(None).unwrap_err();
    assert_eq!(missing.code(), Code::InvalidArgument);
    let violations = missing
        .get_details_bad_request()
        .expect("field violations")
        .field_violations;
    assert_eq!(violations[0].field, "operation_id");

    let id = PasswordOperationId::generate();
    let wire: sid_ids_proto::PasswordOperationId = id.into();
    assert_eq!(operation_id(Some(&wire)).unwrap(), id);
}

/// A step whose operation is not pending for it reads as expired, whatever
/// the cause, so it tells nothing about operations the caller does not own.
#[test]
fn a_step_without_its_operation_reads_as_expired() {
    let status = operation_not_pending();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(
        status.get_details_error_info().unwrap().reason,
        "OPERATION_EXPIRED"
    );
}
