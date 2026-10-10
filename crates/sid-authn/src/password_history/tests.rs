use super::*;
use crate::test_support::{foreign_key_manager, key_manager};
use sid_core::models::{HistoryEntry, HistoryEpoch, HistoryEvidence};
use sid_pake_core::types::{DomainPublicInputs, HistoryTag};

/// Cheap KSF: these tests check the relation and the admission, not cost.
const KSF: HistoryKsf = HistoryKsf {
    memory_kib: 64,
    passes: 1,
    lanes: 1,
};

const INSTALLATION: [u8; 16] = [7; 16];
const OPERATION: &[u8] = b"operation-0001";

/// The client side of one operation: the proved public inputs for
/// `password` against `domains` answered by `evaluation`.
fn client_inputs(
    password: &[u8],
    owner: ProfileId,
    r: pallas::Base,
    domains: &[OperationDomain],
    evaluation: &OperationEvaluation,
) -> ZkppPublicInputs {
    let d = pallas::Base::from_repr(owner_domain(&INSTALLATION, owner)).unwrap();
    let u = relation::history_input(d, password);
    ZkppPublicInputs {
        owner_domain: d.to_repr(),
        blinded: evaluation.blinded,
        domains: domains
            .iter()
            .zip(&evaluation.evaluations)
            .map(|(domain, answer)| {
                let c = pallas::Base::from_repr(domain.comparison_domain).unwrap();
                let z = pallas::Affine::from_bytes(&answer.evaluated).unwrap();
                DomainPublicInputs {
                    comparison_domain: domain.comparison_domain,
                    evaluated: answer.evaluated,
                    tag: HistoryTag::new(relation::finalize_tag(c, u, r, z).to_repr()),
                }
            })
            .collect(),
    }
}

/// An owner with one prepared epoch: the evaluator, the owner and its
/// stored epoch with its key.
async fn owner_with_epoch() -> (HistoryEvaluator, ProfileId, NewKeyEpoch) {
    let evaluator = HistoryEvaluator::new(key_manager());
    let owner = ProfileId::generate();
    let epoch = evaluator
        .new_epoch(owner_domain(&INSTALLATION, owner), KSF)
        .await
        .unwrap();
    (evaluator, owner, epoch)
}

/// The history snapshot of `owner` with `entries` under `epoch`.
fn snapshot(owner: ProfileId, epoch: &NewKeyEpoch, entries: Vec<[u8; 32]>) -> PasswordHistory {
    let e = &epoch.epoch;
    PasswordHistory {
        revision: 2,
        epochs: vec![HistoryEpoch {
            id: e.id,
            owner,
            suite: e.suite,
            public_key: e.public_key,
            ksf: e.ksf,
            ksf_salt: e.ksf_salt,
            status: e.status,
            created_at: e.created_at,
        }],
        entries: entries
            .into_iter()
            .enumerate()
            .map(|(i, entry)| HistoryEntry {
                epoch: epoch.epoch.id,
                seq: i as i64 + 1,
                entry,
                evidence: HistoryEvidence {
                    operation: uuid::Uuid::now_v7(),
                    policy_version: 1,
                },
                created_at: chrono::Utc::now(),
            })
            .collect(),
    }
}

/// Blind, evaluate and derive the proved inputs for `password`.
async fn run_operation(
    evaluator: &HistoryEvaluator,
    owner: ProfileId,
    epoch: &NewKeyEpoch,
    password: &[u8],
) -> (Vec<OperationDomain>, OperationEvaluation, ZkppPublicInputs) {
    let domain = owner_domain(&INSTALLATION, owner);
    let d = pallas::Base::from_repr(domain).unwrap();
    let r = relation::random_blind(rand::rng());
    let b = relation::blind_request(relation::history_input(d, password), r).to_bytes();
    let domains = vec![OperationDomain::of(&epoch.epoch.descriptor())];
    let evaluation = evaluator
        .evaluate(
            &b,
            &domain,
            &[(epoch.epoch.id, epoch.key.clone())],
            OPERATION,
        )
        .await
        .unwrap();
    let public = client_inputs(password, owner, r, &domains, &evaluation);
    (domains, evaluation, public)
}

fn checker() -> HistoryChecker {
    HistoryChecker::new(KsfAdmission::new(64, Duration::from_secs(5)))
}

/// The evaluator's proofs as a client relays them.
fn relayed(evaluation: &OperationEvaluation) -> Vec<RelayedProof> {
    evaluation
        .evaluations
        .iter()
        .map(|e| RelayedProof {
            challenge: e.challenge,
            response: e.response,
        })
        .collect()
}

fn request<'a>(
    owner: ProfileId,
    domains: &'a [OperationDomain],
    epochs: &'a [HistoryEpochDescriptor],
    proofs: &'a [RelayedProof],
    history: &'a PasswordHistory,
) -> CheckRequest<'a> {
    CheckRequest {
        owner_domain: owner_domain(&INSTALLATION, owner),
        domains,
        epochs,
        proofs,
        context: OPERATION,
        history,
    }
}

/// A new password is accepted with one entry under the active epoch, and
/// that entry is the KSF of its tag: the same password, blinded afresh in a
/// later operation, is then refused as reused.
#[tokio::test]
async fn a_new_password_is_accepted_and_its_reuse_refused() {
    let (evaluator, owner, epoch) = owner_with_epoch().await;
    let epochs = [epoch.epoch.descriptor()];
    let empty = snapshot(owner, &epoch, vec![]);
    let (domains, evaluation, public) = run_operation(&evaluator, owner, &epoch, b"Pw-1").await;
    let proofs = relayed(&evaluation);
    let accepted = checker()
        .check(&public, request(owner, &domains, &epochs, &proofs, &empty))
        .await
        .unwrap();
    assert_eq!(accepted.new_entries.len(), 1);
    assert_eq!(accepted.new_entries[0].0, epoch.epoch.id);

    let retained = snapshot(owner, &epoch, vec![accepted.new_entries[0].1]);
    let (domains, evaluation, public) = run_operation(&evaluator, owner, &epoch, b"Pw-1").await;
    let proofs = relayed(&evaluation);
    assert_eq!(
        checker()
            .check(
                &public,
                request(owner, &domains, &epochs, &proofs, &retained)
            )
            .await
            .unwrap_err(),
        HistoryCheckError::Reused
    );
    let (domains, evaluation, public) = run_operation(&evaluator, owner, &epoch, b"Pw-2").await;
    let proofs = relayed(&evaluation);
    assert!(
        checker()
            .check(
                &public,
                request(owner, &domains, &epochs, &proofs, &retained)
            )
            .await
            .is_ok()
    );
}

/// The first domain is where the accepted entry goes, even when the
/// credential service has not recorded that epoch yet (a rotation prepared
/// for this operation): its descriptor comes from the operation.
#[tokio::test]
async fn the_entry_goes_under_the_operations_first_epoch() {
    let (evaluator, owner, epoch) = owner_with_epoch().await;
    let mut unrecorded = snapshot(owner, &epoch, vec![]);
    unrecorded.epochs.clear();
    let (domains, evaluation, public) = run_operation(&evaluator, owner, &epoch, b"Pw").await;
    let proofs = relayed(&evaluation);
    let accepted = checker()
        .check(
            &public,
            request(
                owner,
                &domains,
                &[epoch.epoch.descriptor()],
                &proofs,
                &unrecorded,
            ),
        )
        .await
        .unwrap();
    assert_eq!(accepted.new_entries.len(), 1);
    assert_eq!(accepted.new_entries[0].0, epoch.epoch.id);
}

/// Ten retained passwords: every one of them is refused, a new one accepted.
#[tokio::test]
async fn each_of_ten_retained_passwords_is_refused() {
    let (evaluator, owner, epoch) = owner_with_epoch().await;
    let epochs = [epoch.epoch.descriptor()];
    let mut entries = Vec::new();
    for i in 0..10u8 {
        let (domains, evaluation, public) =
            run_operation(&evaluator, owner, &epoch, &[b'p', i]).await;
        let proofs = relayed(&evaluation);
        let history = snapshot(owner, &epoch, entries.clone());
        let accepted = checker()
            .check(
                &public,
                request(owner, &domains, &epochs, &proofs, &history),
            )
            .await
            .unwrap();
        entries.push(accepted.new_entries[0].1);
    }
    let history = snapshot(owner, &epoch, entries);
    for i in 0..10u8 {
        let (domains, evaluation, public) =
            run_operation(&evaluator, owner, &epoch, &[b'p', i]).await;
        let proofs = relayed(&evaluation);
        assert_eq!(
            checker()
                .check(
                    &public,
                    request(owner, &domains, &epochs, &proofs, &history)
                )
                .await
                .unwrap_err(),
            HistoryCheckError::Reused,
            "password {i}"
        );
    }
}

/// The pre-SNARK check: the operation's own inputs with the evaluator's
/// relayed proofs verify, and each field taken from elsewhere (owner domain,
/// blinded input, a comparison domain, an evaluated element, the domain
/// count) does not.
#[tokio::test]
async fn verify_inputs_accepts_only_the_operations_own_inputs() {
    let (evaluator, owner, epoch) = owner_with_epoch().await;
    let (domains, evaluation, mut public) = run_operation(&evaluator, owner, &epoch, b"Pw").await;
    let proofs = relayed(&evaluation);
    let own = owner_domain(&INSTALLATION, owner);
    let check = |public: &ZkppPublicInputs, owner: &[u8; 32]| {
        verify_inputs(public, owner, &domains, &proofs, OPERATION)
    };
    assert_eq!(check(&public, &own), Ok(()));

    let other_owner = owner_domain(&INSTALLATION, ProfileId::generate());
    assert_eq!(
        check(&public, &other_owner),
        Err(HistoryCheckError::Mismatch)
    );

    // One field changed at a time, then restored: the inputs carry a secret
    // tag and are not cloneable. A changed B or Z is caught by the DLEQ
    // proof, which binds both.
    public.blinded[0] ^= 1;
    assert!(check(&public, &own).is_err());
    public.blinded[0] ^= 1;

    public.domains[0].comparison_domain[0] ^= 1;
    assert_eq!(check(&public, &own), Err(HistoryCheckError::Mismatch));
    public.domains[0].comparison_domain[0] ^= 1;

    public.domains[0].evaluated[0] ^= 1;
    assert!(check(&public, &own).is_err());
    public.domains[0].evaluated[0] ^= 1;

    assert_eq!(check(&public, &own), Ok(()));
    let kept = public.domains.pop().unwrap();
    assert_eq!(check(&public, &own), Err(HistoryCheckError::Mismatch));
    public.domains.push(kept);
    assert_eq!(check(&public, &own), Ok(()));
}

/// The relayed proofs come from an untrusted client: a missing or extra
/// proof, a forged one, one of another evaluation (another blinded input) or
/// one bound to another operation is refused before any KSF runs.
#[tokio::test]
async fn relayed_proofs_from_elsewhere_are_refused() {
    let (evaluator, owner, epoch) = owner_with_epoch().await;
    let epochs = [epoch.epoch.descriptor()];
    let empty = snapshot(owner, &epoch, vec![]);
    let (domains, evaluation, public) = run_operation(&evaluator, owner, &epoch, b"Pw").await;
    let proofs = relayed(&evaluation);

    assert_eq!(
        checker()
            .check(&public, request(owner, &domains, &epochs, &[], &empty))
            .await
            .unwrap_err(),
        HistoryCheckError::Mismatch,
        "a missing proof"
    );
    let doubled = [proofs[0], proofs[0]];
    assert_eq!(
        checker()
            .check(&public, request(owner, &domains, &epochs, &doubled, &empty))
            .await
            .unwrap_err(),
        HistoryCheckError::Mismatch,
        "an extra proof"
    );

    let other_owner = ProfileId::generate();
    assert_eq!(
        checker()
            .check(
                &public,
                request(other_owner, &domains, &epochs, &proofs, &empty)
            )
            .await
            .unwrap_err(),
        HistoryCheckError::Mismatch
    );

    let (_, other_evaluation, _) = run_operation(&evaluator, owner, &epoch, b"Pw").await;
    assert_eq!(
        checker()
            .check(
                &public,
                request(
                    owner,
                    &domains,
                    &epochs,
                    &relayed(&other_evaluation),
                    &empty
                )
            )
            .await
            .unwrap_err(),
        HistoryCheckError::EvaluationProof,
        "the proof of another blinded input"
    );

    let forged = [RelayedProof {
        challenge: proofs[0].challenge,
        response: proofs[0].challenge,
    }];
    assert_eq!(
        checker()
            .check(&public, request(owner, &domains, &epochs, &forged, &empty))
            .await
            .unwrap_err(),
        HistoryCheckError::EvaluationProof
    );

    let mut other_context = request(owner, &domains, &epochs, &proofs, &empty);
    other_context.context = b"operation-0002";
    assert_eq!(
        checker().check(&public, other_context).await.unwrap_err(),
        HistoryCheckError::EvaluationProof,
        "an evaluation bound to another operation"
    );
}

/// Two domains: the proofs relayed in the wrong order, or descriptors that
/// are not the operation's own, are refused.
#[tokio::test]
async fn reordered_proofs_or_foreign_descriptors_are_refused() {
    let evaluator = HistoryEvaluator::new(key_manager());
    let owner = ProfileId::generate();
    let domain = owner_domain(&INSTALLATION, owner);
    let first = evaluator.new_epoch(domain, KSF).await.unwrap();
    let second = evaluator.new_epoch(domain, KSF).await.unwrap();
    let d = pallas::Base::from_repr(domain).unwrap();
    let r = relation::random_blind(rand::rng());
    let b = relation::blind_request(relation::history_input(d, b"Pw"), r).to_bytes();
    let epochs = [first.epoch.descriptor(), second.epoch.descriptor()];
    let domains: Vec<_> = epochs.iter().map(OperationDomain::of).collect();
    let evaluation = evaluator
        .evaluate(
            &b,
            &domain,
            &[
                (first.epoch.id, first.key.clone()),
                (second.epoch.id, second.key.clone()),
            ],
            OPERATION,
        )
        .await
        .unwrap();
    let public = client_inputs(b"Pw", owner, r, &domains, &evaluation);
    let empty = snapshot(owner, &first, vec![]);
    let proofs = relayed(&evaluation);
    assert!(
        checker()
            .check(&public, request(owner, &domains, &epochs, &proofs, &empty))
            .await
            .is_ok()
    );

    let swapped = [proofs[1], proofs[0]];
    assert_eq!(
        checker()
            .check(&public, request(owner, &domains, &epochs, &swapped, &empty))
            .await
            .unwrap_err(),
        HistoryCheckError::EvaluationProof
    );

    let reversed = [epochs[1], epochs[0]];
    assert_eq!(
        checker()
            .check(
                &public,
                request(owner, &domains, &reversed, &proofs, &empty)
            )
            .await
            .unwrap_err(),
        HistoryCheckError::Mismatch
    );
}

/// A key is used only as the key it was sealed as: another owner's epoch
/// key, or a key read by another installation, is refused.
#[tokio::test]
async fn a_key_sealed_for_another_epoch_or_installation_is_refused() {
    let (evaluator, owner, epoch) = owner_with_epoch().await;
    let b = relation::blind_request(pallas::Base::from(5u64), pallas::Base::from(3u64)).to_bytes();
    let other_owner = owner_domain(&INSTALLATION, ProfileId::generate());
    let err = evaluator
        .evaluate(
            &b,
            &other_owner,
            &[(epoch.epoch.id, epoch.key.clone())],
            OPERATION,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SidError::Internal(_)), "{err:?}");

    let foreign = HistoryEvaluator::new(foreign_key_manager());
    assert!(
        foreign
            .evaluate(
                &b,
                &owner_domain(&INSTALLATION, owner),
                &[(epoch.epoch.id, epoch.key.clone())],
                OPERATION
            )
            .await
            .is_err()
    );
}

/// A check needing more KSF memory than the whole budget is refused, and
/// one that cannot get its memory within the wait gives up as busy rather
/// than queueing without bound.
#[tokio::test]
async fn ksf_admission_bounds_memory_and_wait() {
    let big = HistoryKsf {
        memory_kib: 4 * 1024,
        ..KSF
    };
    let small = KsfAdmission::new(2, Duration::from_millis(50));
    assert_eq!(
        small
            .run(vec![(Zeroizing::new([1u8; 32]), [2; 32], big)])
            .await
            .unwrap_err(),
        HistoryCheckError::Ksf
    );

    let admission = KsfAdmission::new(1, Duration::from_millis(50));
    let held = Arc::clone(&admission.permits)
        .acquire_many_owned(1)
        .await
        .unwrap();
    assert_eq!(
        admission
            .run(vec![(Zeroizing::new([1u8; 32]), [2; 32], KSF)])
            .await
            .unwrap_err(),
        HistoryCheckError::Busy
    );
    drop(held);
    assert!(
        admission
            .run(vec![(Zeroizing::new([1u8; 32]), [2; 32], KSF)])
            .await
            .is_ok()
    );
}

/// The KSF's work is bounded before it starts, like its memory: an epoch
/// asking for more passes than any accepted epoch uses is refused at once
/// instead of holding a blocking worker for as long as it asks.
#[tokio::test]
async fn ksf_admission_bounds_passes() {
    let endless = HistoryKsf {
        passes: sid_core::models::password_history::MAX_HISTORY_KSF_PASSES + 1,
        ..KSF
    };
    let admission = KsfAdmission::new(64, Duration::from_millis(50));
    let refused = tokio::time::timeout(
        Duration::from_secs(1),
        admission.run(vec![(Zeroizing::new([1u8; 32]), [2; 32], endless)]),
    )
    .await
    .expect("refused before any KSF runs");
    assert_eq!(refused.unwrap_err(), HistoryCheckError::Ksf);
}

/// The comparison domain moves with every part of the epoch manifest, so an
/// epoch's tags never compare with another's.
#[test]
fn the_comparison_domain_binds_the_whole_manifest() {
    let owner = ProfileId::generate();
    let epoch = HistoryEpochDescriptor {
        id: HistoryEpochId::generate(),
        suite: HistorySuite::PallasPoseidonV1,
        public_key: [1; 32],
        ksf: KSF,
        ksf_salt: [2; 32],
        created_at: chrono::Utc::now(),
    };
    let base = comparison_domain(&epoch);
    let mut other = epoch;
    other.ksf.passes += 1;
    assert_ne!(comparison_domain(&other), base);
    let mut other = epoch;
    other.ksf_salt[0] ^= 1;
    assert_ne!(comparison_domain(&other), base);
    let mut other = epoch;
    other.id = HistoryEpochId::generate();
    assert_ne!(comparison_domain(&other), base);
    assert_ne!(
        owner_domain(&INSTALLATION, owner),
        owner_domain(&[8; 16], owner),
        "installations"
    );
}
