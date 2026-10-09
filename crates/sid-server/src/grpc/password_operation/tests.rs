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

/// Reject excessive wire instances before allocating decoded fields. Otherwise
/// the attacker controls decode work before the verifier checks its shape.
#[test]
fn excessive_proof_instances_are_refused_before_decoding() {
    let proof = PasswordRegistrationProof {
        zkpp_proof: vec![],
        instances: vec![
            vec![0; 32];
            sid_pake_core::circuit::instance_count(MAX_HISTORY_DOMAINS) + 1
        ],
    };
    let status = decode_proof(proof)
        .err()
        .expect("excessive instances refused");
    assert_eq!(status.code(), Code::InvalidArgument);
}

/// An aborted RPC must not admit another verifier while its blocking task is
/// still running. A saturated slot never starts the competing job.
#[tokio::test]
async fn cancelled_proof_keeps_capacity_until_work_stops() {
    let permits = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&permits).try_acquire_owned().unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let (stop, stopped) = std::sync::mpsc::channel();
    let task = tokio::spawn(run_proof(permit, move || {
        started.send(()).unwrap();
        stopped.recv().unwrap();
    }));
    ready.await.unwrap();
    assert!(Arc::clone(&permits).try_acquire_owned().is_err());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(Arc::clone(&permits).try_acquire_owned().is_err());
    stop.send(()).unwrap();
    let permit = tokio::time::timeout(Duration::from_secs(2), Arc::clone(&permits).acquire_owned())
        .await
        .expect("finished blocking work releases capacity")
        .unwrap();
    drop(permit);
    assert_eq!(permits.available_permits(), 1);
}

/// Success and panic both release the reservation; a panic becomes an internal
/// refusal, never proof acceptance or permanent capacity loss.
#[tokio::test]
async fn proof_completion_and_panic_release_capacity() {
    let permits = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&permits).try_acquire_owned().unwrap();
    assert_eq!(run_proof(permit, || 7).await.unwrap(), 7);
    assert_eq!(permits.available_permits(), 1);
    let permit = Arc::clone(&permits).try_acquire_owned().unwrap();
    let status = run_proof(permit, || panic!("test verifier panic"))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Internal);
    assert_eq!(permits.available_permits(), 1);
}

/// Exercise the actual finish path with a real proof and sealed operation.
/// Overload must preserve the evaluated operation and accept its exact retry
/// after capacity becomes available, without installing an unverified record.
#[tokio::test]
async fn saturated_finish_preserves_the_operation_for_an_exact_retry() {
    use group::GroupEncoding;
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    use sid_authn::opaque::{OpaqueRouter, PallasOpaque};
    use sid_authn::opaque_zkpp::ZkppConfig;
    use sid_opaque_ke::{
        ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse,
    };
    use sid_pake_core::{
        binding::operation_context,
        circuit::{CircuitShape, ZKPP_K},
        history::{blind_request, history_input, random_blind},
        keygen::{generate_params, generate_pk},
        pallas_opaque::PallasCipherSuite,
        prover::{HistoryEvaluation, ZkppProver},
        types::CE_DEFAULT_POLICY,
        verifier::ZkppVerifier,
    };
    use sid_plugin::crypto::OpaqueOperations;

    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(
        sid_storage::sqlite::SqliteBackend::new(
            dir.path().join("history.sqlite").to_str().unwrap(),
        )
        .await
        .unwrap(),
    );
    let keys = Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([3; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![1; 32], "test")],
            Arc::new(sid_keys::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    );
    let mut ops = PasswordOperations::new(
        storage,
        Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        keys,
        sid_core::models::OrgId::generate(),
    );
    ops.proof_permits = Arc::new(Semaphore::new(1));
    let primary = Box::new(PallasOpaque::new());
    let setup = primary.create_setup(None).unwrap();
    let providers = [(
        CurveId::Pallas,
        Box::new(PallasOpaque::new()) as Box<dyn OpaqueOperations>,
    )]
    .into();
    let router = OpaqueRouter::new(primary, providers, setup);
    let shape = CircuitShape {
        policy: CE_DEFAULT_POLICY,
        history_domains: 1,
    };
    let params = generate_params(ZKPP_K);
    let pk = generate_pk(&params, shape).unwrap();
    let verifier = ZkppVerifier::new(params.clone(), pk.get_vk().clone(), shape);
    let prover = ZkppProver::new(params, pk, shape);
    let zkpp =
        Arc::new(ZkppOpaqueServer::new(&router, vec![verifier], ZkppConfig::default()).unwrap());
    let password = b"Str0ngP@ssword1";
    let start =
        ClientRegistration::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), password).unwrap();
    let request = start.message.serialize().to_vec();
    let blind =
        pallas::Scalar::from_repr(start.state.serialize()[..32].try_into().unwrap()).unwrap();
    let owner = ProfileId::generate();
    let prepared = ops
        .prepare(
            &zkpp,
            change(),
            OperationOwner::New(owner),
            owner.to_string(),
            Some(request.clone()),
        )
        .await
        .unwrap();
    let id = operation_id(prepared.context.operation_id.as_ref()).unwrap();
    let d =
        pallas::Base::from_repr(prepared.context.owner_domain.clone().try_into().unwrap()).unwrap();
    let r = random_blind(UnwrapErr(SysRng));
    let b = blind_request(history_input(d, password), r).to_bytes();
    let mut pending = ops.take(&id).await.unwrap();
    let evaluated = ops.evaluate_taken(&mut pending, &b).await.unwrap();
    ops.store(&pending).await.unwrap();
    let history = HistoryEvaluation {
        d,
        domains: prepared
            .context
            .domains
            .iter()
            .map(|domain| {
                pallas::Base::from_repr(domain.comparison_domain.clone().try_into().unwrap())
                    .unwrap()
            })
            .collect(),
        r,
        evaluations: evaluated
            .evaluations
            .iter()
            .map(|answer| pallas::Affine::from_bytes(&answer.evaluated).unwrap())
            .collect(),
    };
    let proof = prover
        .prove(
            password,
            blind,
            &operation_context(id.as_bytes(), &request),
            &history,
        )
        .unwrap();
    let proof = PasswordRegistrationProof {
        zkpp_proof: proof.snark_proof.0,
        instances: proof
            .instances
            .iter()
            .map(|x| x.to_repr().to_vec())
            .collect(),
    };
    let record = start
        .state
        .finish(
            &mut UnwrapErr(SysRng),
            password,
            RegistrationResponse::deserialize(prepared.registration_response.as_ref().unwrap())
                .unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap()
        .message
        .serialize()
        .to_vec();
    let reservation = Arc::clone(&ops.proof_permits).try_acquire_owned().unwrap();
    // Exact verifier dimensions are checked before admission. Even while
    // saturated, truncated SNARKs or a wrong instance count are invalid input,
    // not a capacity error and never a scheduled verification job.
    for truncate_instances in [false, true] {
        let prepared = ops
            .prepare(
                &zkpp,
                change(),
                OperationOwner::New(owner),
                owner.to_string(),
                Some(request.clone()),
            )
            .await
            .unwrap();
        let malformed_id = operation_id(prepared.context.operation_id.as_ref()).unwrap();
        let mut malformed = proof.clone();
        if truncate_instances {
            malformed.instances.pop().unwrap();
        } else {
            malformed.zkpp_proof.pop().unwrap();
        }
        let refused = ops
            .finish(
                Arc::clone(&zkpp),
                &malformed_id,
                "change",
                &record,
                Some(malformed),
                |_| Ok(()),
            )
            .await;
        let status = match refused {
            Err(status) => status,
            Ok(_) => panic!("malformed shape must refuse"),
        };
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(ops.proof_permits.available_permits(), 0);
    }
    let refused = ops
        .finish(
            Arc::clone(&zkpp),
            &id,
            "change",
            &record,
            Some(proof.clone()),
            |_| Ok(()),
        )
        .await;
    let status = match refused {
        Err(status) => status,
        Ok(_) => panic!("saturation must refuse"),
    };
    assert_eq!(status.code(), Code::Unavailable);
    assert!(status.get_details_retry_info().is_some());
    drop(reservation);
    let result = ops
        .finish(zkpp, &id, "change", &record, Some(proof), |_| Ok(()))
        .await
        .unwrap();
    let Finish::Ready(result) = result else {
        panic!("retry must complete the original operation")
    };
    assert!(result.proof_verified);
    assert_eq!(result.operation.id, id);
    assert_eq!(result.operation.owner, owner);
    assert!(result.history.is_some());
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
