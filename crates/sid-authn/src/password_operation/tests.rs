// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use ff::PrimeField;
use pasta_curves::pallas;
use sid_core::models::{MutationContext, ProfileId};
use sid_plugin::StorageBackend;
use sid_storage::sqlite::SqliteBackend;

/// A purpose of the tests' operations: a change, as a host would name it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Change;

impl OperationPurpose for Change {
    fn method(&self) -> &'static str {
        "change"
    }
}

pub(super) fn change() -> Change {
    Change
}

pub(super) type Operations = PasswordOperations<SqliteBackend, Change>;

/// A key manager over its own master secret.
pub(super) fn manager(master: u8) -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([master; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![1; 32], "test")],
            Arc::new(sid_crypto::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    )
}

pub(super) async fn sqlite() -> Arc<SqliteBackend> {
    Arc::new(SqliteBackend::new_in_memory().await.unwrap())
}

/// The two authorities over one database, as a standalone installation runs
/// them: the evaluator over its own store, sealing history keys and its
/// records with `history_keys`; the credential side sealing its records with
/// `field_keys`, holding no history key.
pub(super) fn split(
    storage: Arc<SqliteBackend>,
    installation: sid_core::models::OrgId,
    history_keys: Arc<dyn sid_keys::KeyManager>,
    field_keys: Arc<dyn sid_keys::KeyManager>,
) -> (Operations, Arc<HistoryEvaluation>) {
    let ceremonies: Arc<dyn CeremonyStateStore> = storage.clone();
    let evaluation = Arc::new(HistoryEvaluation::new(
        Arc::new(storage.history_keys()),
        ceremonies.clone(),
        history_keys,
    ));
    let ops = PasswordOperations::new(
        storage,
        ceremonies,
        field_keys,
        installation,
        evaluation.clone(),
    );
    (ops, evaluation)
}

/// A ZKPP server that verifies no proof and accepts unproven passwords.
pub(super) fn zkpp_without_proofs() -> ZkppOpaqueServer {
    use crate::opaque::{OpaqueRouter, PallasOpaque};
    use crate::opaque_zkpp::ZkppConfig;
    use sid_plugin::crypto::OpaqueOperations;
    let primary = Box::new(PallasOpaque::new());
    let setup = primary.create_setup(None).unwrap();
    let providers = [(
        CurveId::Pallas,
        Box::new(PallasOpaque::new()) as Box<dyn OpaqueOperations>,
    )]
    .into();
    let router = OpaqueRouter::new(primary, providers, setup);
    ZkppOpaqueServer::new(
        &router,
        vec![],
        ZkppConfig {
            require_proof: false,
            policy_version: 1,
        },
    )
    .unwrap()
}

/// A prepared operation between its steps, as [`PasswordOperations::prepare`]
/// stores it.
fn pending(purpose: Change) -> PendingOperation<ProfileId, Change> {
    PendingOperation {
        id: PasswordOperationId::generate(),
        purpose,
        owner: ProfileId::generate(),
        kind: OwnerKind::Existing,
        owner_domain: [1; 32],
        epochs: vec![],
        history_revision: 0,
        depth: 1,
        window: vec![],
        policy_version: 3,
        credential_identifier: [7; 16],
        registration_request: None,
        current_password: CurrentPassword::Absent,
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
    }
}

/// An admission of a fresh operation of `kind` for `owner_domain`.
fn admission(kind: OwnerKind, owner_domain: [u8; 32]) -> HistoryAdmission {
    HistoryAdmission {
        id: PasswordOperationId::generate(),
        owner_domain,
        kind,
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        charge_key: charge_key("profile:test"),
        live: LiveDomains::default(),
        window: vec![],
    }
}

fn finished(
    op: PendingOperation<ProfileId, Change>,
    evidence: PolicyEvidence,
) -> FinishedOperation<ProfileId, Change> {
    let command = op.finish_command(b"record");
    FinishedOperation {
        operation: op,
        password_file: vec![],
        evidence,
        history: None,
        command,
    }
}

/// The finish command is named by the purpose's method and keyed by the
/// operation id in the operations' namespace with the record as its inputs:
/// a retry with another record is another command.
#[test]
fn a_finish_command_is_keyed_by_the_operation_and_its_record() {
    let op = pending(change());
    assert_eq!(op.purpose.method(), "change");
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
    let evidence = PolicyEvidence::Verified {
        policy_version: 3,
        artifact: [4; 32],
    };
    let credential = finished(pending(change()), evidence).credential(profile, vec![1, 2, 3]);
    assert_eq!(credential.profile_id, profile);
    assert_eq!(credential.credential_type, CredentialType::Opaque);
    assert_eq!(credential.opaque_curve, Some(CurveId::Pallas as u8));
    assert_eq!(credential.policy_evidence, evidence);
    assert_eq!(credential.opaque_credential_identifier, Some([7; 16]));
    assert_eq!(credential.data.expose(), &[1, 2, 3]);

    let unproven =
        finished(pending(change()), PolicyEvidence::Unverified).credential(profile, vec![]);
    assert_eq!(unproven.policy_evidence, PolicyEvidence::Unverified);
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
        evaluation_proofs: vec![],
    })
    .unwrap();
    assert_eq!(proof.snark_proof.0, vec![9, 9]);
    assert_eq!(proof.instances, vec![x]);

    let short = decode_proof(PasswordRegistrationProof {
        zkpp_proof: vec![],
        instances: vec![vec![1; 31]],
        evaluation_proofs: vec![],
    })
    .err()
    .expect("a 31-byte instance is refused");
    let beyond = decode_proof(PasswordRegistrationProof {
        zkpp_proof: vec![],
        instances: vec![vec![0xff; 32]],
        evaluation_proofs: vec![],
    })
    .err()
    .expect("an instance beyond the field is refused");
    for refused in [short, beyond] {
        assert_eq!(invalid_field_of(&refused), "proof.instances");
    }
}

/// A host's own refusal of a step, or the operation's.
#[derive(Debug)]
enum HostRefusal {
    NotThisCaller,
    Operation(PasswordOperationError),
}

impl From<PasswordOperationError> for HostRefusal {
    fn from(e: PasswordOperationError) -> Self {
        Self::Operation(e)
    }
}

/// A host that lets every caller take the step.
fn allowed(_: &PendingOperation<ProfileId, Change>) -> Result<(), PasswordOperationError> {
    Ok(())
}

/// The field an invalid-field refusal names; any other refusal fails the
/// test.
fn invalid_field_of(refused: &PasswordOperationError) -> &'static str {
    match refused {
        PasswordOperationError::InvalidField { field, .. } => field,
        other => panic!("not an invalid field: {other:?}"),
    }
}

/// The evaluator's relayed proofs decode to their 32-byte scalars; one of
/// another length is an invalid argument naming the field.
#[test]
fn relayed_proofs_decode_to_their_scalars() {
    let good = PasswordHistoryEvaluationProof {
        challenge: vec![1; 32],
        response: vec![2; 32],
    };
    assert_eq!(
        relayed_proofs(std::slice::from_ref(&good)).unwrap(),
        vec![RelayedProof {
            challenge: [1; 32],
            response: [2; 32],
        }]
    );
    for bad in [
        PasswordHistoryEvaluationProof {
            challenge: vec![1; 31],
            ..good.clone()
        },
        PasswordHistoryEvaluationProof {
            response: vec![],
            ..good.clone()
        },
    ] {
        let refused = relayed_proofs(&[bad]).unwrap_err();
        assert_eq!(invalid_field_of(&refused), "proof.evaluation_proofs");
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
        evaluation_proofs: vec![],
    };
    let refused = decode_proof(proof)
        .err()
        .expect("excessive instances refused");
    assert_eq!(invalid_field_of(&refused), "proof.instances");
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
    let refused = run_proof(permit, || panic!("test verifier panic"))
        .await
        .unwrap_err();
    assert!(
        matches!(refused, PasswordOperationError::Internal),
        "{refused:?}"
    );
    assert_eq!(permits.available_permits(), 1);
}

/// Exercise the actual finish path with real proofs and sealed operations.
/// Overload must preserve the evaluated operation and accept its exact retry
/// after capacity becomes available, without installing an unverified record.
/// While saturated, a wrong proof shape, missing relayed evaluator proofs or
/// another operation's relayed proofs are refused as invalid before any
/// verification is scheduled.
#[tokio::test]
async fn saturated_finish_preserves_the_operation_for_an_exact_retry() {
    use crate::opaque::{OpaqueRouter, PallasOpaque};
    use crate::opaque_zkpp::ZkppConfig;
    use group::GroupEncoding;
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
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
        SqliteBackend::new(dir.path().join("history.sqlite").to_str().unwrap())
            .await
            .unwrap(),
    );
    // Split keys: the whole lifecycle works with history keys the credential
    // side cannot open.
    let (mut ops, evaluation) = split(
        storage,
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(5),
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
    let verifier_artifact = verifier.artifact();
    let prover = ZkppProver::new(params, pk, shape);
    let zkpp =
        Arc::new(ZkppOpaqueServer::new(&router, vec![verifier], ZkppConfig::default()).unwrap());
    let password = b"Str0ngP@ssword1";
    let start =
        ClientRegistration::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), password).unwrap();
    let request = start.message.serialize().to_vec();
    let blind =
        pallas::Scalar::from_repr(start.state.serialize()[..32].try_into().unwrap()).unwrap();

    // A new owner's operation, evaluated and proved as the client does: the
    // proof with the evaluator's proofs relayed.
    let operation = async |owner: ProfileId| {
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
        let d = pallas::Base::from_repr(prepared.context.owner_domain.clone().try_into().unwrap())
            .unwrap();
        let r = random_blind(UnwrapErr(SysRng));
        let b = blind_request(history_input(d, password), r).to_bytes();
        let answers = evaluation.evaluate(&id, &b).await.unwrap();
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
            evaluations: answers
                .iter()
                .map(|a| {
                    pallas::Affine::from_bytes(&a.evaluated_element.clone().try_into().unwrap())
                        .unwrap()
                })
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
            evaluation_proofs: answers.into_iter().map(|a| a.proof.unwrap()).collect(),
        };
        (id, prepared, proof)
    };
    let owner = ProfileId::generate();
    let (id, prepared, proof) = operation(owner).await;
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
    let (other_id, _, other_proof) = operation(ProfileId::generate()).await;
    let reservation = Arc::clone(&ops.proof_permits).try_acquire_owned().unwrap();
    let refused_before_verification = async |id: &PasswordOperationId, proof| {
        let refused = ops
            .finish(
                Arc::clone(&zkpp),
                id,
                "change",
                &record,
                Some(proof),
                allowed,
            )
            .await;
        let refused = match refused {
            Err(refused) => refused,
            Ok(_) => panic!("an invalid submission must refuse"),
        };
        assert!(
            matches!(
                refused,
                StepError::Operation(PasswordOperationError::InvalidProof)
            ),
            "{refused:?}"
        );
        assert_eq!(ops.proof_permits.available_permits(), 0);
    };
    // Exact verifier dimensions are checked before admission. Even while
    // saturated, truncated SNARKs, a wrong instance count or missing
    // evaluator proofs are invalid input, not a capacity error and never a
    // scheduled verification job.
    for malformation in 0..3 {
        let (malformed_id, _, mut malformed) = operation(ProfileId::generate()).await;
        match malformation {
            0 => drop(malformed.instances.pop().unwrap()),
            1 => drop(malformed.zkpp_proof.pop().unwrap()),
            _ => malformed.evaluation_proofs.clear(),
        }
        refused_before_verification(&malformed_id, malformed).await;
    }
    // Another operation's evaluator proofs, relayed with this operation's
    // proof, do not verify for this operation's key and context.
    let mut substituted = other_proof;
    substituted.evaluation_proofs = proof.evaluation_proofs.clone();
    refused_before_verification(&other_id, substituted).await;

    let refused = ops
        .finish(
            Arc::clone(&zkpp),
            &id,
            "change",
            &record,
            Some(proof.clone()),
            allowed,
        )
        .await;
    let refused = match refused {
        Err(refused) => refused,
        Ok(_) => panic!("saturation must refuse"),
    };
    assert!(
        matches!(
            refused,
            StepError::Operation(PasswordOperationError::Unavailable(
                "proof verification capacity"
            ))
        ),
        "{refused:?}"
    );
    drop(reservation);
    let result = ops
        .finish(zkpp, &id, "change", &record, Some(proof), allowed)
        .await
        .unwrap();
    let Finish::Ready(result) = result else {
        panic!("retry must complete the original operation")
    };
    // The verdict names the artifact that accepted it and the operation's policy.
    assert_eq!(
        result.evidence,
        PolicyEvidence::Verified {
            policy_version: 1,
            artifact: verifier_artifact,
        }
    );
    assert_eq!(result.operation.id, id);
    assert_eq!(result.operation.owner, owner);
    let commit = result.history.as_ref().expect("a history commit");
    assert_eq!(
        commit.epochs, result.operation.epochs,
        "the commit publishes the selected epochs' descriptions"
    );
    assert_eq!(commit.entries.len(), 1);
    assert_eq!(commit.entries[0].0, commit.epochs[0].id);
}

/// An operation is kept until the deadline it was prepared with, however
/// many steps store it again: the terminal abort of a registration is due at
/// that deadline, so a step must not find the operation after it. Past the
/// deadline a step's store refuses it as expired.
#[tokio::test]
async fn a_stored_operation_ends_at_its_deadline() {
    let (ops, _) = split(
        sqlite().await,
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let mut op = pending(change());
    op.expires_at = chrono::Utc::now() + chrono::Duration::milliseconds(60);
    ops.store(&op).await.unwrap();
    let op = ops.take(&op.id).await.unwrap();
    ops.store(&op).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    let gone = ops.take(&op.id).await.unwrap_err();
    assert!(
        matches!(gone, PasswordOperationError::NotPending),
        "{gone:?}"
    );

    let late = ops.store(&op).await.unwrap_err();
    assert!(
        matches!(late, PasswordOperationError::NotPending),
        "{late:?}"
    );
    assert!(ops.take(&op.id).await.is_err(), "stored past its deadline");
}

/// A first enrollment's cleanup becomes due only after the operation can no
/// longer commit: its commit deadline (the expiry fixed before the evaluator
/// was asked, plus the finish grace) and the replicas' clock skew, so a
/// finish still verifying past the expiry is never overtaken.
#[tokio::test]
async fn a_registration_cleanup_is_due_after_its_commit_deadline() {
    let storage = sqlite().await;
    let (ops, _) = split(
        storage.clone(),
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let owner = ProfileId::generate();
    let prepared = ops
        .prepare(
            &zkpp_without_proofs(),
            change(),
            OperationOwner::New(owner),
            owner.to_string(),
            None,
        )
        .await
        .unwrap();
    let id = operation_id(prepared.context.operation_id.as_ref()).unwrap();
    let op = ops.take(&id).await.unwrap();
    // The host learns the same deadline the operation keeps.
    assert_eq!(prepared.expires_at, op.expires_at);
    let cleanup =
        sid_plugin::WorkStore::get_work(storage.as_ref(), sid_core::models::WorkId(id.into_uuid()))
            .await
            .unwrap()
            .expect("the admission is owed");
    assert_eq!(
        sid_core::models::password_history::stored_instant(
            commit_deadline(op.expires_at) + sid_core::models::password_history::REPLICA_CLOCK_SKEW
        ),
        cleanup.not_before
    );
}

/// A host step keeps what it changed in the operation, a refused step leaves
/// the operation pending for the next one, and an unknown operation takes
/// no step.
#[tokio::test]
async fn a_host_step_amends_the_pending_operation() {
    let (ops, _) = split(
        sqlite().await,
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let op = pending(change());
    ops.store(&op).await.unwrap();

    let amended = ops
        .amend(&op.id, |pending| {
            pending.registration_request = Some(b"staged".to_vec());
            Ok::<_, PasswordOperationError>(7)
        })
        .await
        .unwrap();
    assert_eq!(amended, 7);

    let refused = ops
        .amend(&op.id, |pending| {
            assert_eq!(
                pending.registration_request.as_deref(),
                Some(&b"staged"[..])
            );
            Err::<(), _>(HostRefusal::NotThisCaller)
        })
        .await
        .unwrap_err();
    assert!(
        matches!(refused, StepError::Host(HostRefusal::NotThisCaller)),
        "{refused:?}"
    );

    let kept = ops.take(&op.id).await.unwrap();
    assert_eq!(kept.registration_request.as_deref(), Some(&b"staged"[..]));
    assert_eq!(kept.expires_at, op.expires_at);

    assert!(
        ops.amend(&PasswordOperationId::generate(), |_| {
            Ok::<(), PasswordOperationError>(())
        })
        .await
        .is_err()
    );
}

/// A finish the host's authorization refuses (another client's ceremony
/// context) takes nothing from the holder: the refusal is returned and the
/// operation stays pending, so an operation id alone cannot end someone
/// else's operation.
#[tokio::test]
async fn a_refused_finish_keeps_the_operation() {
    let (ops, _) = split(
        sqlite().await,
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let zkpp = Arc::new(zkpp_without_proofs());
    let op = pending(change());
    ops.store(&op).await.unwrap();

    let refused = match ops
        .finish(zkpp, &op.id, "change", b"", None, |_| {
            Err(HostRefusal::NotThisCaller)
        })
        .await
    {
        Err(refused) => refused,
        Ok(_) => panic!("a refused caller finishes nothing"),
    };

    assert!(
        matches!(refused, StepError::Host(HostRefusal::NotThisCaller)),
        "{refused:?}"
    );
    let kept = ops.take(&op.id).await.expect("the operation stays pending");
    assert_eq!(kept.expires_at, op.expires_at);
}

/// A finish that the host authorized and that then fails for good (here an
/// operation of a policy no longer accepted) still ends the operation: only
/// a caller's refusal puts it back, never a terminal failure of the holder's
/// own finish, so that failure is not retried forever.
#[tokio::test]
async fn an_authorized_terminal_failure_ends_the_operation() {
    let (ops, _) = split(
        sqlite().await,
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let zkpp = Arc::new(zkpp_without_proofs());
    let mut op = pending(change());
    op.policy_version += 1;
    ops.store(&op).await.unwrap();

    let failed = match ops.finish(zkpp, &op.id, "change", b"", None, allowed).await {
        Err(refused) => refused,
        Ok(_) => panic!("a stale policy finishes nothing"),
    };

    assert!(
        matches!(
            failed,
            StepError::Operation(PasswordOperationError::PolicyChanged)
        ),
        "{failed:?}"
    );
    let gone = ops
        .take(&op.id)
        .await
        .expect_err("a terminal failure leaves nothing to retry");
    assert!(
        matches!(gone, PasswordOperationError::NotPending),
        "{gone:?}"
    );
}

/// Replacing the active policy must invalidate a pending operation before
/// decoding its record or accepting a permitted no-proof replacement. The
/// operation's former version cannot become the new credential's evidence.
#[tokio::test]
async fn a_finish_for_another_policy_is_refused_before_record_decoding() {
    let (ops, _) = split(
        sqlite().await,
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let zkpp = Arc::new(zkpp_without_proofs());
    let op = pending(change());
    ops.store(&op).await.unwrap();
    let result = ops.finish(zkpp, &op.id, "change", b"", None, allowed).await;
    let refused = match result {
        Err(refused) => refused,
        Ok(_) => panic!("another policy must not finish the old operation"),
    };
    assert!(
        matches!(
            refused,
            StepError::Operation(PasswordOperationError::PolicyChanged)
        ),
        "{refused:?}"
    );
}

/// A history key the server cannot open (its external wrapping key is lost
/// or not restored) makes the evaluation unavailable and retryable: no
/// substitute key is generated, the evaluator's store is left as it was and
/// its record of the operation keeps no evaluation.
#[tokio::test]
async fn an_unopenable_history_key_is_unavailable_and_never_replaced() {
    use group::{Curve, Group, GroupEncoding};
    use sid_core::models::Profile;

    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let (_, original) = split(storage.clone(), installation, manager(3), manager(3));
    let profile = Profile::new(Some("keyless"));
    storage
        .create_profile(
            &profile,
            MutationContext::from(AuditEntry::system("test", "key loss")),
        )
        .await
        .unwrap();
    let domain = owner_domain(installation.as_bytes(), profile.id);
    let sealed = original
        .current_epochs(&domain, 0, &original.epoch_policy().await.unwrap())
        .await
        .unwrap();
    let epoch = sealed.active_epoch().unwrap().id;

    // The same database served with another history master key.
    let (restored, restored_evaluation) =
        split(storage.clone(), installation, manager(4), manager(3));
    let prepared = restored
        .prepare(
            &zkpp_without_proofs(),
            change(),
            OperationOwner::Existing(profile.id),
            profile.id.to_string(),
            None,
        )
        .await
        .unwrap();
    let id = operation_id(prepared.context.operation_id.as_ref()).unwrap();
    let blinded = (pallas::Point::generator() * pallas::Scalar::from(5u64))
        .to_affine()
        .to_bytes();
    let refused = restored_evaluation
        .evaluate(&id, &blinded)
        .await
        .unwrap_err();
    assert!(
        matches!(refused, PasswordOperationError::Unavailable(_)),
        "{refused:?}"
    );

    let after = storage
        .history_keys()
        .get_key_epochs(&domain)
        .await
        .unwrap();
    assert_eq!(after, sealed, "no substitute key");
    assert_eq!(after.active_epoch().map(|e| e.id), Some(epoch));
    let record = restored_evaluation
        .ops
        .take(&id.to_string())
        .await
        .unwrap()
        .expect("the evaluator's record");
    assert!(record.evaluation.is_none(), "nothing was evaluated");
}

/// The comparison window is the newest `depth` accepted passwords and nothing
/// else: an operation selects the active epoch plus the epochs holding
/// window entries, one domain (one KSF) per epoch however many of its
/// passwords are in the window. A live epoch holding only passwords outside
/// the window is neither selected nor retired, so a deeper window later
/// reaches it again; the depth an operation was prepared with is kept with
/// it. Depth deletes nothing: every retained password stays.
#[tokio::test]
async fn a_comparison_window_selects_without_deleting() {
    use sid_core::models::{CredentialData, HistoryEpochUse, Profile};

    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let (_, evaluation) = split(storage.clone(), installation, manager(3), manager(3));
    let keys = storage.history_keys();
    let ctx = || MutationContext::from(AuditEntry::system("test", "window"));
    let profile = Profile::new(Some("windowed"));
    storage.create_profile(&profile, ctx()).await.unwrap();
    let password = Credential::new(profile.id, CredentialType::Opaque, b"p0".to_vec(), None);
    storage.create_credential(&password, ctx()).await.unwrap();
    let domain = owner_domain(installation.as_bytes(), profile.id);

    // Three accepted passwords under an epoch made with an outdated KSF.
    let old = evaluation
        .evaluator
        .new_epoch(
            domain,
            HistoryKsf {
                memory_kib: 1024,
                passes: 1,
                lanes: 1,
            },
        )
        .await
        .unwrap();
    keys.create_first_epoch(&old, uuid::Uuid::now_v7(), audit("test"))
        .await
        .unwrap();
    let change_to = async |from: u8, to: u8, epochs: Vec<HistoryEpochDescriptor>| {
        let revision = storage
            .get_password_history(profile.id)
            .await
            .unwrap()
            .revision;
        let mut changed = password.clone();
        changed.data = CredentialData::new(vec![b'p', to]);
        let commit = HistoryCommit {
            owner: profile.id,
            expected_revision: revision,
            entries: vec![(epochs[0].id, [to; 32])],
            epochs,
            evidence: HistoryEvidence {
                operation: uuid::Uuid::now_v7(),
                policy_version: 1,
            },
            retention: 24,
            max_age_days: 0,
        };
        assert!(
            storage
                .change_password(password.id, &[b'p', from], &changed, Some(&commit), ctx())
                .await
                .unwrap()
        );
    };
    for (from, to) in [(b'0', b'1'), (b'1', b'2'), (b'2', b'3')] {
        change_to(from, to, vec![old.epoch.descriptor()]).await;
    }
    // Rotated to the current KSF; two more under the replacement.
    let history = storage.get_password_history(profile.id).await.unwrap();
    let rotated = evaluation
        .current_epochs(
            &domain,
            history.revision,
            &evaluation.epoch_policy().await.unwrap(),
        )
        .await
        .unwrap();
    let current = rotated.active_epoch().unwrap().descriptor();
    for (from, to) in [(b'3', b'4'), (b'4', b'5')] {
        change_to(from, to, vec![current, old.epoch.descriptor()]).await;
    }
    let history = storage.get_password_history(profile.id).await.unwrap();
    assert_eq!(history.entries.len(), 5, "every accepted password kept");

    let prepared = async |depth: u32| {
        let (ops, _) = split(storage.clone(), installation, manager(3), manager(3));
        let ops = ops.with_history_depth(depth, 24).unwrap();
        let prepared = ops
            .prepare(
                &zkpp_without_proofs(),
                change(),
                OperationOwner::Existing(profile.id),
                "profile:window".into(),
                None,
            )
            .await
            .unwrap();
        let id = operation_id(prepared.context.operation_id.as_ref()).unwrap();
        (prepared.context.domains.len(), ops.take(&id).await.unwrap())
    };

    // Depth 2: the two newest, both under the current epoch.
    let (domains, op) = prepared(2).await;
    assert_eq!(domains, 1, "one domain: the old epoch is not evaluated");
    assert_eq!(op.depth, 2);
    assert_eq!(op.window.len(), 2);
    assert!(op.window.iter().all(|(epoch, _)| *epoch == current.id));
    let kept = keys.get_key_epochs(&domain).await.unwrap();
    assert_eq!(
        kept.epochs
            .iter()
            .find(|e| e.id == old.epoch.id)
            .map(|e| e.status),
        Some(HistoryEpochUse::CompareOnly),
        "a key outside the window was retired"
    );

    // Depth 5: all five, in two domains; the old epoch's three passwords
    // cost one domain, not three.
    let (domains, op) = prepared(5).await;
    assert_eq!(domains, 2);
    assert_eq!(op.window.len(), 5);

    // Depth 10, above what is retained: what exists is compared.
    let (domains, op) = prepared(10).await;
    assert_eq!((domains, op.window.len()), (2, 5));

    assert_eq!(
        storage
            .get_password_history(profile.id)
            .await
            .unwrap()
            .entries
            .len(),
        5,
        "a depth deleted nothing"
    );
}

/// The window through whole changes, each proved and checked and committed
/// as a host commits it: five accepted at depth 5; at depth 3 a password
/// outside the window (the fourth newest) is accepted and one inside it
/// refused, and every accepted password stays stored; raised to 5 again, the
/// retained passwords the deeper window reaches are refused once more and
/// one beyond it accepted. Depth deletes nothing at any step.
#[tokio::test]
async fn a_depth_edit_compares_its_window_through_committed_changes() {
    use crate::opaque::{OpaqueRouter, PallasOpaque};
    use crate::opaque_zkpp::ZkppConfig;
    use group::GroupEncoding;
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    use sid_core::models::{CredentialData, Profile};
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

    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let ctx = || MutationContext::from(AuditEntry::system("test", "change"));
    let profile = Profile::new(Some("depth-edit"));
    storage.create_profile(&profile, ctx()).await.unwrap();
    let password = Credential::new(
        profile.id,
        CredentialType::Opaque,
        b"initial".to_vec(),
        None,
    );
    storage.create_credential(&password, ctx()).await.unwrap();

    // One epoch throughout: every comparison is in one domain.
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

    // A change of the profile's password to `new` under `depth`, start to
    // commit, as the client and the host run it.
    let change_to = async |depth: u32, new: &[u8]| -> Result<(), PasswordOperationError> {
        let (ops, evaluation) = split(storage.clone(), installation, manager(3), manager(5));
        let ops = ops.with_history_depth(depth, MAX_HISTORY_DEPTH).unwrap();
        let start =
            ClientRegistration::<PallasCipherSuite>::start(&mut UnwrapErr(SysRng), new).unwrap();
        let request = start.message.serialize().to_vec();
        let blind =
            pallas::Scalar::from_repr(start.state.serialize()[..32].try_into().unwrap()).unwrap();
        let prepared = ops
            .prepare(
                &zkpp,
                change(),
                OperationOwner::Existing(profile.id),
                profile.id.to_string(),
                Some(request.clone()),
            )
            .await?;
        let id = operation_id(prepared.context.operation_id.as_ref()).unwrap();
        let d = pallas::Base::from_repr(prepared.context.owner_domain.clone().try_into().unwrap())
            .unwrap();
        let r = random_blind(UnwrapErr(SysRng));
        let b = blind_request(history_input(d, new), r).to_bytes();
        let answers = evaluation.evaluate(&id, &b).await?;
        let history = HistoryEvaluation {
            d,
            domains: prepared
                .context
                .domains
                .iter()
                .map(|x| {
                    pallas::Base::from_repr(x.comparison_domain.clone().try_into().unwrap())
                        .unwrap()
                })
                .collect(),
            r,
            evaluations: answers
                .iter()
                .map(|a| {
                    pallas::Affine::from_bytes(&a.evaluated_element.clone().try_into().unwrap())
                        .unwrap()
                })
                .collect(),
        };
        let proof = prover
            .prove(
                new,
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
            evaluation_proofs: answers.into_iter().map(|a| a.proof.unwrap()).collect(),
        };
        let record = start
            .state
            .finish(
                &mut UnwrapErr(SysRng),
                new,
                RegistrationResponse::deserialize(prepared.registration_response.as_ref().unwrap())
                    .unwrap(),
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap()
            .message
            .serialize()
            .to_vec();
        let done = match ops
            .finish(
                Arc::clone(&zkpp),
                &id,
                "change",
                &record,
                Some(proof),
                allowed,
            )
            .await
        {
            Ok(Finish::Ready(done)) => *done,
            Ok(Finish::Completed(_)) => panic!("a fresh change completed already"),
            Err(StepError::Operation(refused)) => return Err(refused),
            Err(other) => panic!("{other:?}"),
        };
        let current = storage.get_credential(password.id).await.unwrap().unwrap();
        let mut changed = current.clone();
        changed.data = CredentialData::new(record);
        assert!(
            storage
                .change_password(
                    password.id,
                    current.data.expose(),
                    &changed,
                    done.history.as_ref(),
                    ctx()
                )
                .await
                .unwrap()
        );
        Ok(())
    };
    let retained = async || {
        storage
            .get_password_history(profile.id)
            .await
            .unwrap()
            .entries
            .len()
    };
    let reused = |result: Result<(), PasswordOperationError>| {
        assert!(
            matches!(result, Err(PasswordOperationError::Reused)),
            "{result:?}"
        );
    };

    for p in [
        b"Depth-Pw-1!",
        b"Depth-Pw-2!",
        b"Depth-Pw-3!",
        b"Depth-Pw-4!",
        b"Depth-Pw-5!",
    ] {
        change_to(5, p).await.unwrap();
    }
    assert_eq!(retained().await, 5);

    // Depth 3 compares 5, 4, 3: the second newest-but-three is accepted,
    // and nothing is deleted by the lower depth.
    change_to(3, b"Depth-Pw-2!").await.unwrap();
    assert_eq!(retained().await, 6, "a lower depth deleted nothing");
    reused(change_to(3, b"Depth-Pw-4!").await);
    assert_eq!(retained().await, 6);

    // Raised to 5 the window is 2, 5, 4, 3, 2 again: 3 is refused, 1 is
    // beyond it and accepted.
    reused(change_to(5, b"Depth-Pw-3!").await);
    change_to(5, b"Depth-Pw-1!").await.unwrap();
    assert_eq!(retained().await, 7, "every accepted password is kept");
}

/// An active epoch made under KSF parameters the server no longer uses, or
/// before an operator's cutoff, is replaced when its owner's next operation
/// is prepared, from the revision after the one the credential service
/// reported. The replaced epoch stays selected while the live set names it,
/// so the accepted password is still compared. A replaced epoch without
/// entries is kept while the newest live set predates its replacement (a
/// delayed commit may still put an entry under it) and retired, its key
/// kept, by the first live set after it. A current epoch is never replaced.
#[tokio::test]
async fn a_stale_active_epoch_is_replaced_at_preparation() {
    use sid_core::models::{CredentialData, HistoryEpochUse, HistoryLiveSet, Profile};

    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let (_, evaluation) = split(storage.clone(), installation, manager(3), manager(3));
    let keys = storage.history_keys();
    let ctx = || MutationContext::from(AuditEntry::system("test", "rotation"));
    let profile = Profile::new(Some("rotating"));
    storage.create_profile(&profile, ctx()).await.unwrap();
    let password = Credential::new(profile.id, CredentialType::Opaque, b"p0".to_vec(), None);
    storage.create_credential(&password, ctx()).await.unwrap();
    let domain = owner_domain(installation.as_bytes(), profile.id);

    let old_ksf = HistoryKsf {
        memory_kib: 1024,
        passes: 1,
        lanes: 1,
    };
    let old = evaluation
        .evaluator
        .new_epoch(domain, old_ksf)
        .await
        .unwrap();
    keys.create_first_epoch(&old, uuid::Uuid::now_v7(), audit("test"))
        .await
        .unwrap();
    let change_to =
        async |from: &[u8], to: &[u8], revision, epochs: Vec<HistoryEpochDescriptor>| {
            let mut changed = password.clone();
            changed.data = CredentialData::new(to.to_vec());
            let commit = HistoryCommit {
                owner: profile.id,
                expected_revision: revision,
                entries: vec![(epochs[0].id, [to[1]; 32])],
                epochs,
                evidence: HistoryEvidence {
                    operation: uuid::Uuid::now_v7(),
                    policy_version: 1,
                },
                retention: 2,
                max_age_days: 0,
            };
            assert!(
                storage
                    .change_password(password.id, from, &changed, Some(&commit), ctx())
                    .await
                    .unwrap()
            );
        };
    change_to(b"p0", b"p1", 0, vec![old.epoch.descriptor()]).await;

    // The live set the credential service sends with a preparation.
    let prepare = async |live: HistoryLiveSet| {
        let now = chrono::Utc::now();
        keys.prepare_epochs(
            &sid_core::models::HistoryPreparation {
                owner_domain: domain,
                window: live.live.clone(),
                live,
                operation: uuid::Uuid::now_v7(),
                expires_at: now,
                now,
            },
            audit("test"),
        )
        .await
        .unwrap()
        .iter()
        .map(|e| e.id)
        .collect::<Vec<_>>()
    };

    let history = storage.get_password_history(profile.id).await.unwrap();
    let policy = async || evaluation.epoch_policy().await.unwrap();
    let rotated = evaluation
        .current_epochs(&domain, history.revision, &policy().await)
        .await
        .unwrap();
    let current = rotated.active_epoch().unwrap().clone();
    assert_ne!(current.id, old.epoch.id);
    assert_eq!(current.ksf, HistoryKsf::DEFAULT);
    assert_eq!(
        prepare(HistoryLiveSet::of(&history)).await,
        vec![current.id, old.epoch.id],
        "the accepted password is still compared under its epoch"
    );
    let again = evaluation
        .current_epochs(&domain, history.revision, &policy().await)
        .await
        .unwrap();
    assert_eq!(again, rotated, "a current epoch stays");

    // A compromise cutoff after the current epoch, recorded in the
    // evaluator's store, replaces it too. Instants are whole milliseconds
    // like the epochs', so the replacement is not before it.
    tokio::time::sleep(Duration::from_millis(5)).await;
    let cutoff =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    keys.raise_write_cutoff(cutoff, audit("test"))
        .await
        .unwrap();
    let cut = evaluation
        .current_epochs(&domain, history.revision, &policy().await)
        .await
        .unwrap();
    let replacement = cut.active_epoch().unwrap().clone();
    assert_ne!(replacement.id, current.id);
    assert!(replacement.created_at >= cutoff);
    let key = keys.get_epoch_key(current.id).await.unwrap();
    assert!(key.is_some());

    // The newest live set is the one read before the replacement, which
    // cannot tell whether `current` took an entry since: it is kept, though
    // it holds nothing yet and is no longer selected.
    assert_eq!(
        prepare(HistoryLiveSet::of(&history)).await,
        vec![replacement.id, old.epoch.id]
    );
    let held = keys.get_key_epochs(&domain).await.unwrap();
    assert!(held.epochs.iter().any(|e| e.id == current.id), "kept");

    // A commit under the replacement moves the history on; its live set
    // retires `current`, keeping the sealed key, and `old` still holds an
    // entry.
    change_to(
        b"p1",
        b"p2",
        history.revision,
        vec![replacement.descriptor(), old.epoch.descriptor()],
    )
    .await;
    let history = storage.get_password_history(profile.id).await.unwrap();
    assert_eq!(
        prepare(HistoryLiveSet::of(&history)).await,
        vec![replacement.id, old.epoch.id]
    );
    let after = keys.get_key_epochs(&domain).await.unwrap();
    assert!(!after.epochs.iter().any(|e| e.id == current.id), "retired");
    assert_eq!(
        keys.get_epoch_key(current.id).await.unwrap(),
        key,
        "retirement keeps the sealed key"
    );
    assert_eq!(
        after
            .epochs
            .iter()
            .find(|e| e.id == old.epoch.id)
            .map(|e| e.status),
        Some(HistoryEpochUse::CompareOnly)
    );
}

/// The credential side never holds a history key, and each side's record of
/// an operation is sealed for its own side alone: the credential record keeps
/// only the selected epochs' public descriptions, the new owner's first key
/// is in the evaluator's store before any evaluation, opened only by the
/// history keys, and neither side's keys open the other side's record.
#[tokio::test]
async fn the_sides_share_no_secret_record() {
    let storage = sqlite().await;
    let (history_keys, field_keys) = (manager(3), manager(7));
    let (ops, evaluation) = split(
        storage.clone(),
        sid_core::models::OrgId::generate(),
        history_keys.clone(),
        field_keys.clone(),
    );
    let owner = ProfileId::generate();
    let prepared = ops
        .prepare(
            &zkpp_without_proofs(),
            change(),
            OperationOwner::New(owner),
            owner.to_string(),
            None,
        )
        .await
        .unwrap();
    let id = operation_id(prepared.context.operation_id.as_ref()).unwrap();
    let op = ops.take(&id).await.unwrap();
    assert_eq!(
        prepared.context.domains,
        op.domains().iter().map(domain_message).collect::<Vec<_>>(),
        "the client gets the evaluator's selection"
    );
    let key = storage
        .history_keys()
        .get_epoch_key(op.epochs[0].id)
        .await
        .unwrap()
        .expect("stored before its first evaluation");
    let sealed = sid_keys::EncryptedField::from_bytes(&key.0).unwrap();
    let context = sid_core::models::history_key_context(op.epochs[0].id, &op.owner_domain);
    assert!(field_keys.decrypt(&sealed, &context).await.is_err());
    assert!(history_keys.decrypt(&sealed, &context).await.is_ok());

    ops.store(&op).await.unwrap();
    let evaluator_view = ChallengeStore::<PendingOperation<ProfileId, Change>>::new(
        evaluation.ceremonies.clone(),
        history_keys,
        "password-operation",
        OPERATION_TTL,
    );
    assert!(
        evaluator_view.take(&id.to_string()).await.is_err(),
        "the evaluator's keys open no credential record"
    );
    let credential_view = ChallengeStore::<EvaluatorOperation>::new(
        evaluation.ceremonies.clone(),
        field_keys,
        "password-history-evaluation",
        OPERATION_TTL,
    );
    assert!(
        credential_view.take(&id.to_string()).await.is_err(),
        "the credential side's keys open no evaluator record"
    );
}

/// A new-owner admission never resets or forks a history: for an owner that
/// already has a key it is refused, and the owner keeps its one key.
#[tokio::test]
async fn a_new_owner_admission_never_resets_a_history() {
    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let (ops, _) = split(storage.clone(), installation, manager(3), manager(3));
    let zkpp = zkpp_without_proofs();
    let owner = ProfileId::generate();
    let prepare = async || {
        ops.prepare(
            &zkpp,
            change(),
            OperationOwner::New(owner),
            owner.to_string(),
            None,
        )
        .await
    };
    prepare().await.unwrap();
    let domain = owner_domain(installation.as_bytes(), owner);
    let first = storage
        .history_keys()
        .get_key_epochs(&domain)
        .await
        .unwrap();
    assert_eq!(first.epochs.len(), 1);
    let refused = prepare().await.map(|_| ()).unwrap_err();
    assert!(
        matches!(refused, PasswordOperationError::Unavailable("history keys")),
        "{refused:?}"
    );
    assert_eq!(
        storage
            .history_keys()
            .get_key_epochs(&domain)
            .await
            .unwrap(),
        first,
        "the history keeps its one key"
    );
}

/// An admission repeats exactly or conflicts: an exact repeat returns the
/// original selection; the same operation with another owner, kind, expiry
/// or charge key is refused and leaves the original admission in place.
#[tokio::test]
async fn an_admission_repeats_exactly_or_conflicts() {
    let (_, evaluation) = split(
        sqlite().await,
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let original = admission(OwnerKind::Existing, [4; 32]);
    let selected = evaluation.prepare(&original).await.unwrap();
    assert_eq!(evaluation.prepare(&original).await.unwrap(), selected);
    let changed: [fn(&mut HistoryAdmission); 4] = [
        |a| a.owner_domain = [5; 32],
        |a| a.kind = OwnerKind::Decoy,
        |a| a.expires_at += chrono::Duration::seconds(1),
        |a| a.charge_key = charge_key("profile:other"),
    ];
    for change in changed {
        let mut other = original.clone();
        change(&mut other);
        let refused = evaluation.prepare(&other).await.unwrap_err();
        assert!(
            matches!(refused, PasswordOperationError::Conflict(_)),
            "{refused:?}"
        );
    }
    assert_eq!(
        evaluation.prepare(&original).await.unwrap(),
        selected,
        "the original admission stands"
    );
}

/// An admission is bounded before any key is touched: an expiry that has
/// passed or lies beyond an operation's lifetime, and an empty or overlong
/// charge key, are invalid arguments.
#[tokio::test]
async fn an_admission_outside_its_bounds_is_refused() {
    let storage = sqlite().await;
    let (_, evaluation) = split(
        storage.clone(),
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let bounds: [fn(&mut HistoryAdmission); 4] = [
        |a| a.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1),
        |a| a.expires_at = chrono::Utc::now() + chrono::Duration::hours(1),
        |a| a.charge_key.clear(),
        |a| a.charge_key = "x".repeat(MAX_CHARGE_KEY + 1),
    ];
    for bound in bounds {
        let mut refused = admission(OwnerKind::New, [6; 32]);
        bound(&mut refused);
        let refused = evaluation.prepare(&refused).await.unwrap_err();
        assert!(
            matches!(refused, PasswordOperationError::InvalidField { .. }),
            "{refused:?}"
        );
    }
    assert!(
        storage
            .history_keys()
            .get_key_epochs(&[6; 32])
            .await
            .unwrap()
            .epochs
            .is_empty(),
        "no key was made"
    );
}

/// The credential service sets an admission's expiry on its own clock: one
/// running ahead of the evaluator's by an ordinary skew is still admitted,
/// while an expiry past the lifetime and that skew is not.
#[tokio::test]
async fn an_admission_from_a_clock_slightly_ahead_is_admitted() {
    let storage = sqlite().await;
    let (_, evaluation) = split(
        storage.clone(),
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let ttl = chrono::Duration::from_std(OPERATION_TTL).unwrap();
    let mut ahead = admission(OwnerKind::New, [8; 32]);
    ahead.expires_at = chrono::Utc::now() + ttl + chrono::Duration::seconds(30);
    evaluation
        .prepare(&ahead)
        .await
        .expect("an expiry within the clock-skew tolerance");

    let mut beyond = admission(OwnerKind::New, [9; 32]);
    beyond.expires_at = chrono::Utc::now() + ttl + chrono::Duration::seconds(90);
    let refused = evaluation.prepare(&beyond).await.unwrap_err();
    assert_eq!(invalid_field_of(&refused), "expires_at");
}

/// Concurrent admissions for one owner without a key agree on one: both
/// operations select the same active epoch, and the owner has one.
#[tokio::test]
async fn concurrent_admissions_agree_on_one_key() {
    let storage = sqlite().await;
    let (_, evaluation) = split(
        storage.clone(),
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let (a, b) = (
        admission(OwnerKind::Existing, [8; 32]),
        admission(OwnerKind::Existing, [8; 32]),
    );
    let (ra, rb) = tokio::join!(evaluation.prepare(&a), evaluation.prepare(&b));
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(ra[0].id, rb[0].id);
    assert_eq!(
        storage
            .history_keys()
            .get_key_epochs(&[8; 32])
            .await
            .unwrap()
            .epochs
            .len(),
        1
    );
}

/// The evaluator applies the write cutoff its store records, whatever the
/// replica was started with: after another replica raised it, an operation
/// admitted before is evaluated neither afresh nor from its recorded answer,
/// a repeated admission of it is refused, and a new admission selects a key
/// created after the cutoff.
#[tokio::test]
async fn the_evaluator_applies_the_stored_write_cutoff() {
    use group::{Curve, Group, GroupEncoding};

    let storage = sqlite().await;
    let (_, evaluation) = split(
        storage.clone(),
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let blinded = (pallas::Point::generator() * pallas::Scalar::from(5u64))
        .to_affine()
        .to_bytes();
    let (cached, fresh) = (
        admission(OwnerKind::Existing, [9; 32]),
        admission(OwnerKind::Existing, [9; 32]),
    );
    let before = evaluation.prepare(&cached).await.unwrap();
    assert_eq!(evaluation.prepare(&fresh).await.unwrap(), before);
    evaluation.evaluate(&cached.id, &blinded).await.unwrap();

    // Another replica raises the cutoff in the shared store.
    tokio::time::sleep(Duration::from_millis(5)).await;
    let cutoff =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    storage
        .history_keys()
        .raise_write_cutoff(cutoff, audit("test"))
        .await
        .unwrap();

    let withdrawn = |refused: PasswordOperationError| {
        assert!(
            matches!(refused, PasswordOperationError::HistoryKeyWithdrawn),
            "{refused:?}"
        );
    };
    withdrawn(evaluation.evaluate(&cached.id, &blinded).await.unwrap_err());
    withdrawn(evaluation.evaluate(&fresh.id, &blinded).await.unwrap_err());
    withdrawn(evaluation.prepare(&cached).await.unwrap_err());

    let after = evaluation
        .prepare(&admission(OwnerKind::Existing, [9; 32]))
        .await
        .unwrap();
    assert_ne!(after[0].id, before[0].id);
    assert!(
        after[0].created_at >= cutoff,
        "a key created after the cutoff"
    );
}

/// The selection the credential service accepts is the one its own read of
/// the history requires: the operation's active epoch first (the history's,
/// or a replacement it does not know yet), every epoch that retains an
/// entry, each once, each epoch the history knows with the description it
/// recorded. A new owner gets one epoch and no history; a decoy one epoch.
#[test]
fn a_selection_the_history_does_not_require_is_refused() {
    use sid_core::models::{HistoryEntry, HistoryEpoch, HistoryEpochUse};
    let owner = ProfileId::generate();
    let epoch = |status, key: u8| HistoryEpoch {
        id: HistoryEpochId::generate(),
        owner,
        suite: HistorySuite::PallasPoseidonV1,
        public_key: [key; 32],
        ksf: HistoryKsf::DEFAULT,
        ksf_salt: [key; 32],
        status,
        created_at: chrono::Utc::now(),
    };
    let entry = |epoch: &HistoryEpoch, seq| HistoryEntry {
        epoch: epoch.id,
        seq,
        entry: [9; 32],
        evidence: HistoryEvidence {
            operation: uuid::Uuid::now_v7(),
            policy_version: 1,
        },
        created_at: chrono::Utc::now(),
    };
    let (active, old, emptied) = (
        epoch(HistoryEpochUse::Active, 1),
        epoch(HistoryEpochUse::CompareOnly, 2),
        epoch(HistoryEpochUse::CompareOnly, 4),
    );
    let history = PasswordHistory {
        revision: 4,
        epochs: vec![old.clone(), active.clone(), emptied.clone()],
        entries: vec![entry(&active, 2), entry(&old, 1)],
    };
    let new = epoch(HistoryEpochUse::Active, 3).descriptor();
    let d = |e: &HistoryEpoch| e.descriptor();
    // Compared with every retained password: the deepest window.
    let complete = |kind, epochs: &[HistoryEpochDescriptor], history: &PasswordHistory| {
        selection_is_complete(kind, epochs, history, &history.window(24))
    };
    let existing = OwnerKind::Existing;
    assert!(complete(existing, &[d(&active), d(&old)], &history));
    // An epoch the history knows without entries may be named: it was
    // emptied after the evaluator last heard of it.
    assert!(complete(
        existing,
        &[d(&active), d(&old), d(&emptied)],
        &history
    ));
    // A replacement the history does not know yet comes first, and the
    // epochs holding entries are all still compared.
    assert!(complete(existing, &[new, d(&active), d(&old)], &history));
    let mut changed = d(&old);
    changed.public_key = [7; 32];
    for refused in [
        vec![d(&active)],
        vec![d(&old), d(&active)],
        vec![d(&active), d(&old), d(&old)],
        vec![new, d(&old)],
        vec![d(&active), d(&old), new],
        vec![d(&active), changed],
        vec![],
    ] {
        assert!(!complete(existing, &refused, &history), "{refused:?}");
    }
    assert!(!complete(
        OwnerKind::Decoy,
        &[d(&active), d(&old)],
        &history
    ));
    assert!(complete(OwnerKind::Decoy, &[new], &history));

    let empty = PasswordHistory::default();
    assert!(complete(OwnerKind::New, &[new], &empty));
    assert!(
        !complete(OwnerKind::New, &[new], &history),
        "a history exists"
    );
    assert!(!complete(OwnerKind::New, &[new, d(&old)], &empty));

    // A window of the newest password only: the active epoch suffices, and
    // the epoch holding only an older password is not selected.
    let newest = history.window(1);
    assert_eq!(newest, vec![(active.id, 2)]);
    assert!(selection_is_complete(
        existing,
        &[d(&active)],
        &history,
        &newest
    ));
    assert!(
        !selection_is_complete(existing, &[d(&active), d(&old)], &history, &newest),
        "an epoch holding only passwords outside the window"
    );
}

/// A registration start for a held identifier must look like any other to
/// the client, which checks every evaluation proof against the domain key it
/// was given. The decoy's answer verifies under the decoy domain's key for
/// this operation, as a real one does; otherwise the failed check tells the
/// client that the identifier is taken.
#[tokio::test]
async fn a_decoy_evaluation_verifies_under_its_domain_key() {
    use group::{Curve, Group, GroupEncoding};

    let (ops, evaluation) = split(
        sqlite().await,
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(5),
    );
    let prepared = ops
        .prepare(
            &zkpp_without_proofs(),
            change(),
            OperationOwner::Decoy(ProfileId::generate()),
            "decoy".into(),
            None,
        )
        .await
        .unwrap();
    let id = operation_id(prepared.context.operation_id.as_ref()).unwrap();
    let blinded = (pallas::Point::generator() * pallas::Scalar::from(5u64)).to_affine();
    let answers = evaluation.evaluate(&id, &blinded.to_bytes()).await.unwrap();
    assert_eq!(answers.len(), prepared.context.domains.len());
    for (domain, answer) in prepared.context.domains.iter().zip(&answers) {
        let point = |bytes: &[u8]| pallas::Affine::from_bytes(&bytes.try_into().unwrap()).unwrap();
        let scalar = |bytes: &[u8]| pallas::Scalar::from_repr(bytes.try_into().unwrap()).unwrap();
        let proof = answer.proof.as_ref().unwrap();
        assert!(
            sid_pake_core::history::verify_evaluation(
                point(&domain.evaluator_public_key),
                blinded,
                point(&answer.evaluated_element),
                id.as_bytes(),
                &sid_pake_core::history::EvaluationProof {
                    c: scalar(&proof.challenge),
                    s: scalar(&proof.response),
                },
            ),
            "a decoy's evaluation verifies like a real one"
        );
    }
}

/// A registration start for a held identifier costs what one for a new owner
/// does, so its timing does not tell the identifier is taken: the decoy's
/// preparation seals and stores a first key under its own throwaway domain,
/// its evaluation reads that stored key, and the decoy's abort (it never
/// commits) reclaims the key like any abandoned first enrollment's.
#[tokio::test]
async fn a_decoy_does_the_work_of_a_first_enrollment() {
    use group::{Curve, Group, GroupEncoding};

    let storage = sqlite().await;
    let (ops, evaluation) = split(
        storage.clone(),
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(5),
    );
    let prepared = ops
        .prepare(
            &zkpp_without_proofs(),
            change(),
            OperationOwner::Decoy(ProfileId::generate()),
            "decoy".into(),
            None,
        )
        .await
        .unwrap();
    let domain: [u8; 32] = prepared.context.owner_domain.clone().try_into().unwrap();
    let stored = storage
        .history_keys()
        .get_key_epochs(&domain)
        .await
        .unwrap();
    assert_eq!(stored.epochs.len(), 1, "one sealed first key, stored");
    assert_eq!(
        prepared.context.domains[0].evaluator_public_key,
        stored.epochs[0].public_key.to_vec(),
        "the decoy is evaluated under the stored key"
    );
    let id = operation_id(prepared.context.operation_id.as_ref()).unwrap();
    let blinded = (pallas::Point::generator() * pallas::Scalar::from(5u64)).to_affine();
    evaluation.evaluate(&id, &blinded.to_bytes()).await.unwrap();

    assert_eq!(
        evaluation
            .abandon_enrollment(&domain, id.into_uuid())
            .await
            .unwrap(),
        EnrollmentCleanup::Reclaimed
    );
    assert!(
        storage
            .history_keys()
            .get_key_epochs(&domain)
            .await
            .unwrap()
            .epochs
            .is_empty(),
        "the abort reclaimed the decoy's key"
    );
}

/// The evaluator evaluates only operations it admitted, and only while they
/// can commit: the credential service's record of an operation does not make
/// it evaluable, an expired admission is not evaluated, and neither is
/// charged.
#[tokio::test]
async fn only_an_admitted_live_operation_is_evaluated() {
    let (ops, evaluation) = split(
        sqlite().await,
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let op = pending(change());
    ops.store(&op).await.unwrap();
    let refused = evaluation.evaluate(&op.id, &[2; 32]).await.unwrap_err();
    assert!(
        matches!(refused, PasswordOperationError::NotPending),
        "{refused:?}"
    );

    // A record past its deadline is not even stored.
    let expired_id = PasswordOperationId::generate();
    let late = evaluation
        .store(
            &expired_id,
            &EvaluatorOperation {
                owner_domain: [1; 32],
                kind: OwnerKind::Existing,
                expires_at: chrono::Utc::now() - chrono::Duration::seconds(1),
                charge_key: charge_key("profile:test"),
                epochs: vec![],
                evaluation: None,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(late, PasswordOperationError::NotPending),
        "{late:?}"
    );
    let refused = evaluation
        .evaluate(&expired_id, &[2; 32])
        .await
        .unwrap_err();
    assert!(
        matches!(refused, PasswordOperationError::NotPending),
        "{refused:?}"
    );
    assert_eq!(
        evaluation
            .ceremonies
            .count_in_window(
                "password-history-evaluations",
                &charge_key("profile:test").to_string(),
                EVALUATION_WINDOW,
            )
            .await
            .unwrap(),
        1,
        "the refused evaluations were not charged"
    );
}

/// A charge key is a fixed-length digest of the actor, whatever its length,
/// and different actors are charged apart.
#[test]
fn a_charge_key_is_bounded_and_per_actor() {
    let long = "registration:".to_owned() + &"x".repeat(1000);
    assert!(charge_key(&long).len() <= MAX_CHARGE_KEY);
    assert_eq!(charge_key("a"), charge_key("a"));
    assert_ne!(charge_key("a"), charge_key("b"));
}

/// A step without an operation id is refused as naming no operation; a
/// well-formed id round-trips through the wire.
#[test]
fn an_operation_id_is_required_and_round_trips() {
    let missing = operation_id(None).unwrap_err();
    assert!(
        matches!(missing, PasswordOperationError::InvalidOperationId(_)),
        "{missing:?}"
    );

    let id = PasswordOperationId::generate();
    let wire: sid_ids_proto::PasswordOperationId = id.into();
    assert_eq!(operation_id(Some(&wire)).unwrap(), id);
}

/// The live set the credential service sends names the owner's epochs by
/// their comparison domains: the evaluator maps each to its own epoch and
/// refuses a domain it did not issue for the owner or a domain named twice,
/// retaining every key instead of guessing; a negative revision or more
/// domains than an operation holds is refused before any key is read.
#[test]
fn the_evaluator_maps_the_live_set_to_its_own_epochs() {
    use sid_core::models::{HistoryEpochUse, KeyEpoch};
    let epoch = |status, key: u8| KeyEpoch {
        id: HistoryEpochId::generate(),
        owner_domain: [3; 32],
        suite: HistorySuite::PallasPoseidonV1,
        public_key: [key; 32],
        ksf: HistoryKsf::DEFAULT,
        ksf_salt: [key; 32],
        status,
        created_at: chrono::Utc::now(),
    };
    let (active, old) = (
        epoch(HistoryEpochUse::Active, 1),
        epoch(HistoryEpochUse::CompareOnly, 2),
    );
    let epochs = KeyEpochs {
        epochs: vec![old.clone(), active.clone()],
    };
    let domain = |e: &KeyEpoch| OperationDomain::of(&e.descriptor()).comparison_domain;
    let settled = uuid::Uuid::now_v7();
    let live = LiveDomains {
        revision: 7,
        domains: vec![domain(&old), domain(&active)],
        settled: vec![settled, settled],
    };
    let mapped = live_epochs(&epochs, &live).unwrap();
    let mut expected = vec![active.id, old.id];
    expected.sort_unstable();
    assert_eq!(mapped.live, expected);
    assert_eq!(mapped.settled, vec![settled]);
    assert_eq!(mapped.revision, 7);

    for unknown in [vec![[9; 32]], vec![domain(&old), domain(&old)]] {
        let refused = live_epochs(
            &epochs,
            &LiveDomains {
                domains: unknown,
                ..live.clone()
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                refused,
                PasswordOperationError::Unavailable("history lifecycle")
            ),
            "{refused:?}"
        );
    }
    for unbounded in [
        LiveDomains {
            revision: -1,
            ..live.clone()
        },
        // The live set names every retained epoch, beyond what one
        // operation selects; past what history retains it is refused.
        LiveDomains {
            domains: vec![
                domain(&old);
                sid_core::models::password_history::MAX_LIVE_HISTORY_DOMAINS + 1
            ],
            ..live.clone()
        },
    ] {
        let refused = live_set_bounds(&unbounded).unwrap_err();
        assert!(
            matches!(refused, PasswordOperationError::InvalidField { .. }),
            "{refused:?}"
        );
    }
}

/// An installation's organization and the same UUID name one history scope,
/// so existing owners' domains are unchanged whichever form the credential
/// authority passes.
#[test]
fn an_organization_and_its_uuid_are_one_history_scope() {
    let org = sid_core::models::OrgId::generate();
    let uuid = uuid::Uuid::from_bytes(*org.as_bytes());
    assert_eq!(HistoryScope::from(org), HistoryScope::from(uuid));
    assert_ne!(
        HistoryScope::from(org),
        HistoryScope::from(uuid::Uuid::now_v7())
    );
}

/// The history write cutoff is a past RFC 3339 instant: an offset names the
/// same instant, a date or a free form is refused, and so is any instant
/// after `now`, which would replace every new epoch again and again.
#[test]
fn the_history_write_cutoff_is_a_past_instant() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-10-02T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let past = parse_history_write_cutoff("2026-10-01T12:00:00Z", now).unwrap();
    assert_eq!(past.to_rfc3339(), "2026-10-01T12:00:00+00:00");
    assert_eq!(
        parse_history_write_cutoff("2026-10-01T15:00:00+03:00", now).unwrap(),
        past
    );
    assert_eq!(
        parse_history_write_cutoff("2026-10-02T00:00:00Z", now).unwrap(),
        now
    );
    for malformed in ["", "yesterday", "2026-10-01", "2026-10-01 12:00:00"] {
        assert_eq!(
            parse_history_write_cutoff(malformed, now),
            Err(HistoryCutoffError::Malformed),
            "{malformed:?}"
        );
    }
    assert_eq!(
        parse_history_write_cutoff("2026-10-02T00:00:01Z", now),
        Err(HistoryCutoffError::Future)
    );
}

/// A preparation request is decoded before the evaluator acts on it, and an
/// admission travels as it was: an owner domain or live domain that is not
/// 32 bytes, an unspecified owner kind, a missing expiry, a malformed settled
/// operation or more entries than the bounds allow is a malformed field.
#[test]
fn a_malformed_admission_is_refused_by_its_field() {
    use sid_proto::sid::v1::authn::PasswordHistoryOwnerKind;
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
    let good = PreparePasswordHistoryRequest {
        operation_id: Some(PasswordOperationId::generate().into()),
        owner_domain: vec![3; 32],
        owner_kind: PasswordHistoryOwnerKind::Existing as i32,
        expires_at: Some(timestamp(expires_at)),
        charge_key: "charge".into(),
        live_comparison_domains: vec![vec![2; 32], vec![1; 32]],
        history_revision: 4,
        settled_operations: vec![PasswordOperationId::generate().into()],
        comparison_domains: vec![vec![2; 32]],
    };
    let admission = HistoryAdmission::of_request(&good).unwrap();
    assert_eq!(admission.owner_domain, [3; 32]);
    assert_eq!(admission.kind, OwnerKind::Existing);
    assert_eq!(admission.expires_at, expires_at);
    assert_eq!(admission.live.domains, vec![[1; 32], [2; 32]], "sorted");
    assert_eq!(admission.window, vec![[2; 32]]);
    assert_eq!(admission.live.revision, 4);
    assert_eq!(admission.live.settled.len(), 1);
    assert_eq!(
        HistoryAdmission::of_request(&admission.request().unwrap()).unwrap(),
        admission
    );

    for bad in [
        PreparePasswordHistoryRequest {
            owner_domain: vec![3; 31],
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            owner_kind: PasswordHistoryOwnerKind::Unspecified as i32,
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            expires_at: None,
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            live_comparison_domains: vec![vec![1; 31]],
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            live_comparison_domains: vec![
                vec![1; 32];
                sid_core::models::password_history::MAX_LIVE_HISTORY_DOMAINS
                    + 1
            ],
            ..good.clone()
        },
        // A window domain outside the live set, one named twice, a window
        // larger than an operation holds.
        PreparePasswordHistoryRequest {
            comparison_domains: vec![vec![9; 32]],
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            comparison_domains: vec![vec![2; 32], vec![2; 32]],
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            comparison_domains: vec![vec![1; 32]; MAX_HISTORY_DOMAINS + 1],
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            settled_operations: vec![sid_ids_proto::PasswordOperationId { value: vec![1; 3] }],
            ..good.clone()
        },
        PreparePasswordHistoryRequest {
            history_revision: u64::MAX,
            ..good.clone()
        },
    ] {
        let refused = HistoryAdmission::of_request(&bad).unwrap_err();
        assert!(
            matches!(
                refused,
                PasswordOperationError::InvalidField { .. }
                    | PasswordOperationError::InvalidOperationId(_)
            ),
            "{refused:?}"
        );
    }
}

/// A remote evaluator's answer is accepted only when it describes each
/// domain it returns: as many epochs as domains, each domain the one its
/// epoch gives under the shared relation, each description well formed.
#[test]
fn a_remote_selection_must_describe_its_domains() {
    use sid_core::models::HistoryEpochUse;
    let described = sid_core::models::KeyEpoch {
        id: HistoryEpochId::generate(),
        owner_domain: [3; 32],
        suite: HistorySuite::PallasPoseidonV1,
        public_key: [5; 32],
        ksf: HistoryKsf::DEFAULT,
        ksf_salt: [6; 32],
        status: HistoryEpochUse::Active,
        created_at: chrono::Utc::now(),
    }
    .descriptor();
    let good = preparation_response(std::slice::from_ref(&described));
    assert_eq!(selection_of(&good), Some(vec![described]));
    let mut other_salt = good.clone();
    other_salt.epochs[0].ksf_salt = vec![7; 32];
    let mut malformed = good.clone();
    malformed.epochs[0].epoch_id = vec![1; 3];
    let mut unknown_suite = good.clone();
    unknown_suite.epochs[0].suite = "pallas-poseidon-v0".into();
    let mut missing = good.clone();
    missing.epochs.clear();
    for refused in [other_salt, malformed, unknown_suite, missing] {
        assert_eq!(selection_of(&refused), None);
    }
}
