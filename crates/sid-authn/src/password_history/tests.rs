use super::*;
use crate::test_support::{foreign_key_manager, key_manager};
use sid_core::models::{HistoryEntry, HistoryEvidence};
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

/// An owner with one prepared epoch: the evaluator, the stored epoch and
/// its key, and the history snapshot with `entries`.
async fn owner_with_epoch() -> (HistoryEvaluator, ProfileId, NewHistoryEpoch) {
    let evaluator = HistoryEvaluator::new(key_manager());
    let owner = ProfileId::generate();
    let epoch = evaluator.new_epoch(owner, KSF).await.unwrap();
    (evaluator, owner, epoch)
}

fn snapshot(epoch: &NewHistoryEpoch, entries: Vec<[u8; 32]>) -> PasswordHistory {
    PasswordHistory {
        revision: 2,
        epochs: vec![epoch.epoch.clone()],
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
    epoch: &NewHistoryEpoch,
    password: &[u8],
) -> (Vec<OperationDomain>, OperationEvaluation, ZkppPublicInputs) {
    let d = pallas::Base::from_repr(owner_domain(&INSTALLATION, owner)).unwrap();
    let r = relation::random_blind(rand::rng());
    let b = relation::blind_request(relation::history_input(d, password), r).to_bytes();
    let domains = vec![OperationDomain::of(&epoch.epoch)];
    let evaluation = evaluator
        .evaluate(&b, &[(epoch.epoch.id, owner, epoch.key.clone())], OPERATION)
        .await
        .unwrap();
    let public = client_inputs(password, owner, r, &domains, &evaluation);
    (domains, evaluation, public)
}

fn checker() -> HistoryChecker {
    HistoryChecker::new(KsfAdmission::new(64, Duration::from_secs(5)))
}

fn request<'a>(
    owner: ProfileId,
    domains: &'a [OperationDomain],
    evaluation: &'a OperationEvaluation,
    history: &'a PasswordHistory,
) -> CheckRequest<'a> {
    CheckRequest {
        owner_domain: owner_domain(&INSTALLATION, owner),
        domains,
        evaluation,
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
    let empty = snapshot(&epoch, vec![]);
    let (domains, evaluation, public) = run_operation(&evaluator, owner, &epoch, b"Pw-1").await;
    let accepted = checker()
        .check(&public, request(owner, &domains, &evaluation, &empty))
        .await
        .unwrap();
    assert_eq!(accepted.new_entries.len(), 1);
    assert_eq!(accepted.new_entries[0].0, epoch.epoch.id);

    let retained = snapshot(&epoch, vec![accepted.new_entries[0].1]);
    let (domains, evaluation, public) = run_operation(&evaluator, owner, &epoch, b"Pw-1").await;
    assert_eq!(
        checker()
            .check(&public, request(owner, &domains, &evaluation, &retained))
            .await
            .unwrap_err(),
        HistoryCheckError::Reused
    );
    let (domains, evaluation, public) = run_operation(&evaluator, owner, &epoch, b"Pw-2").await;
    assert!(
        checker()
            .check(&public, request(owner, &domains, &evaluation, &retained))
            .await
            .is_ok()
    );
}

/// Ten retained passwords: every one of them is refused, a new one accepted.
#[tokio::test]
async fn each_of_ten_retained_passwords_is_refused() {
    let (evaluator, owner, epoch) = owner_with_epoch().await;
    let mut entries = Vec::new();
    for i in 0..10u8 {
        let (domains, evaluation, public) =
            run_operation(&evaluator, owner, &epoch, &[b'p', i]).await;
        let history = snapshot(&epoch, entries.clone());
        let accepted = checker()
            .check(&public, request(owner, &domains, &evaluation, &history))
            .await
            .unwrap();
        entries.push(accepted.new_entries[0].1);
    }
    let history = snapshot(&epoch, entries);
    for i in 0..10u8 {
        let (domains, evaluation, public) =
            run_operation(&evaluator, owner, &epoch, &[b'p', i]).await;
        assert_eq!(
            checker()
                .check(&public, request(owner, &domains, &evaluation, &history))
                .await
                .unwrap_err(),
            HistoryCheckError::Reused,
            "password {i}"
        );
    }
}

/// The pre-SNARK comparison: the operation's own inputs match, and each
/// field taken from elsewhere (owner domain, blinded input, a comparison
/// domain, an evaluator answer, the domain count) does not.
#[tokio::test]
async fn inputs_match_only_the_operations_own_inputs() {
    let (evaluator, owner, epoch) = owner_with_epoch().await;
    let (domains, evaluation, mut public) = run_operation(&evaluator, owner, &epoch, b"Pw").await;
    let own = owner_domain(&INSTALLATION, owner);
    assert!(inputs_match(&public, &own, &domains, &evaluation));

    let other_owner = owner_domain(&INSTALLATION, ProfileId::generate());
    assert!(!inputs_match(&public, &other_owner, &domains, &evaluation));

    // One field changed at a time, then restored: the inputs carry a secret
    // tag and are not cloneable.
    public.blinded[0] ^= 1;
    assert!(!inputs_match(&public, &own, &domains, &evaluation));
    public.blinded[0] ^= 1;

    public.domains[0].comparison_domain[0] ^= 1;
    assert!(!inputs_match(&public, &own, &domains, &evaluation));
    public.domains[0].comparison_domain[0] ^= 1;

    public.domains[0].evaluated[0] ^= 1;
    assert!(!inputs_match(&public, &own, &domains, &evaluation));
    public.domains[0].evaluated[0] ^= 1;

    assert!(inputs_match(&public, &own, &domains, &evaluation));
    let kept = public.domains.pop().unwrap();
    assert!(!inputs_match(&public, &own, &domains, &evaluation));
    public.domains.push(kept);
    assert!(inputs_match(&public, &own, &domains, &evaluation));
}

/// A proof made for another owner, another request or another evaluation
/// is refused before any KSF runs.
#[tokio::test]
async fn inputs_of_another_operation_are_refused() {
    let (evaluator, owner, epoch) = owner_with_epoch().await;
    let empty = snapshot(&epoch, vec![]);
    let (domains, evaluation, public) = run_operation(&evaluator, owner, &epoch, b"Pw").await;

    let other_owner = ProfileId::generate();
    assert_eq!(
        checker()
            .check(&public, request(other_owner, &domains, &evaluation, &empty))
            .await
            .unwrap_err(),
        HistoryCheckError::Mismatch
    );

    let (_, other_evaluation, _) = run_operation(&evaluator, owner, &epoch, b"Pw").await;
    assert_eq!(
        checker()
            .check(&public, request(owner, &domains, &other_evaluation, &empty))
            .await
            .unwrap_err(),
        HistoryCheckError::Mismatch,
        "another request's blinded input"
    );

    let mut forged = evaluation.clone();
    forged.evaluations[0].response = forged.evaluations[0].challenge;
    assert_eq!(
        checker()
            .check(&public, request(owner, &domains, &forged, &empty))
            .await
            .unwrap_err(),
        HistoryCheckError::EvaluationProof
    );

    let mut other_context = request(owner, &domains, &evaluation, &empty);
    other_context.context = b"operation-0002";
    assert_eq!(
        checker().check(&public, other_context).await.unwrap_err(),
        HistoryCheckError::EvaluationProof,
        "an evaluation bound to another operation"
    );
}

/// A key is used only as the key it was sealed as: another owner's epoch
/// key, or a key read by another installation, is refused.
#[tokio::test]
async fn a_key_sealed_for_another_epoch_or_installation_is_refused() {
    let (evaluator, owner, epoch) = owner_with_epoch().await;
    let b = relation::blind_request(pallas::Base::from(5u64), pallas::Base::from(3u64)).to_bytes();
    let err = evaluator
        .evaluate(
            &b,
            &[(epoch.epoch.id, ProfileId::generate(), epoch.key.clone())],
            OPERATION,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SidError::Internal(_)), "{err:?}");

    let foreign = HistoryEvaluator::new(foreign_key_manager());
    assert!(
        foreign
            .evaluate(&b, &[(epoch.epoch.id, owner, epoch.key.clone())], OPERATION)
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

/// The comparison domain moves with every part of the epoch manifest, so an
/// epoch's tags never compare with another's.
#[test]
fn the_comparison_domain_binds_the_whole_manifest() {
    let owner = ProfileId::generate();
    let epoch = HistoryEpoch {
        id: HistoryEpochId::generate(),
        owner,
        suite: HistorySuite::PallasPoseidonV1,
        public_key: [1; 32],
        ksf: KSF,
        ksf_salt: [2; 32],
        status: HistoryEpochUse::Active,
        created_at: chrono::Utc::now(),
    };
    let base = comparison_domain(&epoch);
    let mut other = epoch.clone();
    other.ksf.passes += 1;
    assert_ne!(comparison_domain(&other), base);
    let mut other = epoch.clone();
    other.ksf_salt[0] ^= 1;
    assert_ne!(comparison_domain(&other), base);
    let mut other = epoch.clone();
    other.id = HistoryEpochId::generate();
    assert_ne!(comparison_domain(&other), base);
    assert_ne!(
        owner_domain(&INSTALLATION, owner),
        owner_domain(&[8; 16], owner),
        "installations"
    );
}
