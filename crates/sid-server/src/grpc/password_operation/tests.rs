// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use ff::PrimeField;
use pasta_curves::pallas;
use sid_core::models::MutationContext;
use sid_storage::sqlite::SqliteBackend;
use tonic::Code;
use tonic_types::StatusExt;

fn change() -> OperationPurpose {
    OperationPurpose::Change {
        profile_id: ProfileId::generate(),
        credential_id: CredentialId(uuid::Uuid::now_v7()),
        password: [5; 16],
    }
}

/// A key manager over its own master secret.
fn manager(master: u8) -> Arc<dyn sid_keys::KeyManager> {
    Arc::new(
        sid_keys::SoftwareKeyManager::new(
            secrecy::SecretBox::new(Box::new([master; 32])),
            vec![sid_keys::KeyVersionParams::new(1, vec![1; 32], "test")],
            Arc::new(sid_keys::RustCryptoPrimitives::new()),
        )
        .unwrap(),
    )
}

async fn sqlite() -> Arc<SqliteBackend> {
    Arc::new(SqliteBackend::new_in_memory().await.unwrap())
}

/// The two authorities over one database and cache, as a standalone
/// installation runs them: the evaluator over its own store, sealing history
/// keys and its records with `history_keys`; the credential side sealing its
/// records with `field_keys`, holding no history key.
fn split(
    storage: Arc<SqliteBackend>,
    installation: sid_core::models::OrgId,
    history_keys: Arc<dyn sid_keys::KeyManager>,
    field_keys: Arc<dyn sid_keys::KeyManager>,
) -> (PasswordOperations, Arc<HistoryEvaluation>) {
    let cache: Arc<dyn CacheBackend> = Arc::new(sid_plugin::cache::InMemoryCacheBackend::new());
    let evaluation = Arc::new(HistoryEvaluation::new(
        Arc::new(storage.history_keys()),
        cache.clone(),
        history_keys,
    ));
    let ops = PasswordOperations::new(storage, cache, field_keys, installation, evaluation.clone());
    (ops, evaluation)
}

/// A ZKPP server that verifies no proof and accepts unproven passwords.
fn zkpp_without_proofs() -> ZkppOpaqueServer {
    use sid_authn::opaque::{OpaqueRouter, PallasOpaque};
    use sid_authn::opaque_zkpp::ZkppConfig;
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
fn pending(purpose: OperationPurpose) -> PendingOperation {
    PendingOperation {
        id: PasswordOperationId::generate(),
        purpose,
        owner: ProfileId::generate(),
        kind: OwnerKind::Existing,
        owner_domain: [1; 32],
        epochs: vec![],
        history_revision: 0,
        policy_version: 3,
        credential_identifier: [7; 16],
        registration_request: None,
        current_password: CurrentPassword::Absent,
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
    }
}

fn finished(op: PendingOperation, evidence: PolicyEvidence) -> FinishedOperation {
    let command = op.finish_command(b"record");
    FinishedOperation {
        operation: op,
        password_file: vec![],
        evidence,
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
    assert_eq!(short.code(), Code::InvalidArgument);
    let beyond = decode_proof(PasswordRegistrationProof {
        zkpp_proof: vec![],
        instances: vec![vec![0xff; 32]],
        evaluation_proofs: vec![],
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
        let status = relayed_proofs(&[bad]).unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(
            status.get_details_bad_request().unwrap().field_violations[0].field,
            "proof.evaluation_proofs"
        );
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

/// Exercise the actual finish path with real proofs and sealed operations.
/// Overload must preserve the evaluated operation and accept its exact retry
/// after capacity becomes available, without installing an unverified record.
/// While saturated, a wrong proof shape, missing relayed evaluator proofs or
/// another operation's relayed proofs are refused as invalid before any
/// verification is scheduled.
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
                |_| Ok(()),
            )
            .await;
        let status = match refused {
            Err(status) => status,
            Ok(_) => panic!("an invalid submission must refuse"),
        };
        assert_eq!(status.code(), Code::InvalidArgument, "{}", status.message());
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
    let result = ops
        .finish(zkpp, &op.id, "change", b"", None, |_| Ok(()))
        .await;
    let status = match result {
        Err(status) => status,
        Ok(_) => panic!("another policy must not finish the old operation"),
    };
    assert_eq!(status.code(), Code::FailedPrecondition);
    let details = status.get_details_precondition_failure().unwrap();
    assert_eq!(details.violations[0].r#type, "PASSWORD_POLICY_VERSION");
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
    let status = restored_evaluation
        .evaluate(&id, &blinded)
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unavailable, "{}", status.message());
    assert_eq!(
        status.get_details_error_info().unwrap().reason,
        "PASSWORD_HISTORY_UNAVAILABLE"
    );
    assert!(status.get_details_retry_info().is_some());

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
    keys.create_first_epoch(&old, audit("test")).await.unwrap();
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
                depth: 2,
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
    assert!(field_keys.decrypt(&sealed).await.is_err());
    assert!(history_keys.decrypt(&sealed).await.is_ok());

    ops.store(&op).await.unwrap();
    let evaluator_view = ChallengeStore::<PendingOperation>::new(
        evaluation.cache.clone(),
        history_keys,
        "password-operation",
        OPERATION_TTL,
    );
    assert!(
        evaluator_view.take(&id.to_string()).await.is_err(),
        "the evaluator's keys open no credential record"
    );
    let credential_view = ChallengeStore::<EvaluatorOperation>::new(
        evaluation.cache.clone(),
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
    let status = prepare().await.map(|_| ()).unwrap_err();
    assert_eq!(status.code(), Code::Unavailable, "{}", status.message());
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
        let status = evaluation.prepare(&other).await.unwrap_err();
        assert_eq!(
            status.get_details_error_info().unwrap().reason,
            "OPERATION_KEY_CONFLICT",
            "{}",
            status.message()
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
        let status = evaluation.prepare(&refused).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{}", status.message());
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
    let status = evaluation.prepare(&beyond).await.unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument, "{}", status.message());
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

    let withdrawn = |status: Status| {
        let violation = &status
            .get_details_precondition_failure()
            .expect("precondition")
            .violations[0];
        assert_eq!(
            violation.r#type, "PASSWORD_HISTORY_WRITE_CUTOFF",
            "{status:?}"
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
    let complete = |kind, epochs: &[HistoryEpochDescriptor], history: &PasswordHistory| {
        selection_is_complete(kind, epochs, history)
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
}

/// An evaluator co-located with the credential service prepares in process
/// only: its network interface refuses preparation from anyone, since a
/// caller could otherwise create keys for operations it names.
#[tokio::test]
async fn an_in_process_evaluator_refuses_preparation_over_the_network() {
    let (_, evaluation) = split(
        sqlite().await,
        sid_core::models::OrgId::generate(),
        manager(3),
        manager(3),
    );
    let service = PasswordHistoryEvaluatorImpl::new(evaluation, Arc::new(InProcessOnly));
    let status = service
        .prepare_password_history(Request::new(PreparePasswordHistoryRequest {
            operation_id: Some(PasswordOperationId::generate().into()),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
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
            OperationOwner::Decoy,
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
    let status = evaluation.evaluate(&op.id, &[2; 32]).await.unwrap_err();
    assert_eq!(
        status.get_details_error_info().unwrap().reason,
        "OPERATION_EXPIRED"
    );

    let expired_id = PasswordOperationId::generate();
    evaluation
        .store(
            &expired_id,
            &EvaluatorOperation {
                owner_domain: [1; 32],
                kind: OwnerKind::Existing,
                expires_at: chrono::Utc::now() - chrono::Duration::seconds(1),
                charge_key: charge_key("profile:test"),
                epochs: vec![],
                decoy_keys: vec![],
                evaluation: None,
            },
        )
        .await
        .unwrap();
    let status = evaluation
        .evaluate(&expired_id, &[2; 32])
        .await
        .unwrap_err();
    assert_eq!(
        status.get_details_error_info().unwrap().reason,
        "OPERATION_EXPIRED"
    );
    assert_eq!(
        evaluation
            .cache
            .incr(
                &format!(
                    "password-history-evaluations:{}",
                    charge_key("profile:test")
                ),
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
        let status = live_epochs(
            &epochs,
            &LiveDomains {
                domains: unknown,
                ..live.clone()
            },
        )
        .unwrap_err();
        assert_eq!(status.code(), Code::Unavailable, "{}", status.message());
    }
    for unbounded in [
        LiveDomains {
            revision: -1,
            ..live.clone()
        },
        LiveDomains {
            domains: vec![domain(&old); MAX_HISTORY_DOMAINS + 1],
            ..live.clone()
        },
    ] {
        let status = live_set_bounds(&unbounded).unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{}", status.message());
    }
}

/// A preparation request is decoded before the evaluator acts on it: an
/// owner domain or live domain that is not 32 bytes, an unspecified owner
/// kind, a missing expiry, a malformed settled operation or more entries than
/// the bounds allow is an invalid argument.
#[test]
fn a_malformed_admission_is_an_invalid_argument() {
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
    let good = PreparePasswordHistoryRequest {
        operation_id: Some(PasswordOperationId::generate().into()),
        owner_domain: vec![3; 32],
        owner_kind: PasswordHistoryOwnerKind::Existing as i32,
        expires_at: Some(crate::grpc::convert::to_timestamp(expires_at)),
        charge_key: "charge".into(),
        live_comparison_domains: vec![vec![2; 32], vec![1; 32]],
        history_revision: 4,
        settled_operations: vec![PasswordOperationId::generate().into()],
    };
    let admission = admission_of(&good).unwrap();
    assert_eq!(admission.owner_domain, [3; 32]);
    assert_eq!(admission.kind, OwnerKind::Existing);
    assert_eq!(admission.expires_at, expires_at);
    assert_eq!(admission.live.domains, vec![[1; 32], [2; 32]], "sorted");
    assert_eq!(admission.live.revision, 4);
    assert_eq!(admission.live.settled.len(), 1);

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
            live_comparison_domains: vec![vec![1; 32]; MAX_HISTORY_DOMAINS + 1],
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
        let status = admission_of(&bad).unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{}", status.message());
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
    let good = PreparePasswordHistoryResponse {
        domains: vec![domain_message(&OperationDomain::of(&described))],
        epochs: vec![descriptor_message(&described)],
    };
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
