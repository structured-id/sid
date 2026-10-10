// SPDX-License-Identifier: AGPL-3.0-only
use super::super::tests::{change, manager, split, sqlite, zkpp_without_proofs};
use super::super::*;
use super::*;
use sid_core::models::{WorkId, WorkState};
use sid_plugin::work_store::WorkStore;
use tonic::Code;

/// The claimed work of `operation`'s admission, as the runner hands it over
/// once due.
async fn claimed(
    storage: &dyn StorageBackend,
    operation: PasswordOperationId,
    owner_domain: [u8; 32],
) -> ClaimedWork {
    let record = storage
        .get_work(WorkId(operation.into_uuid()))
        .await
        .unwrap()
        .expect("the admission is owed");
    let admission = EnrollmentAdmission {
        operation: operation.into_uuid(),
        owner_domain,
        expires_at: record.not_before,
    };
    ClaimedWork {
        id: record.id,
        kind: record.kind,
        payload: admission.work().payload,
        attempt: 1,
        max_attempts: record.max_attempts,
        generation: 1,
        expires_at: None,
    }
}

/// A first enrollment prepared for a new owner: its operation and the
/// owner's history input domain.
async fn enrolled(
    ops: &PasswordOperations,
    installation: sid_core::models::OrgId,
) -> (PasswordOperationId, [u8; 32]) {
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
    (
        operation_id(prepared.context.operation_id.as_ref()).unwrap(),
        owner_domain(installation.as_bytes(), owner),
    )
}

/// A registration that never commits loses the key it was given, without
/// any further request: its admission was owed before the key was made, so
/// even a crash that lost the credential side's record of it (here: taken
/// and never stored back) leaves the cleanup due. The aborted operation is
/// evaluated no more, and a repeated cleanup is harmless.
#[tokio::test]
async fn an_abandoned_registration_loses_its_key() {
    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let (ops, evaluation) = split(storage.clone(), installation, manager(3), manager(3));
    let (id, domain) = enrolled(&ops, installation).await;
    ops.take(&id).await.unwrap();
    let owed = storage
        .get_work(WorkId(id.into_uuid()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owed.state, WorkState::Pending);
    assert!(
        owed.not_before > chrono::Utc::now(),
        "due at the registration's expiry, not before"
    );
    assert_eq!(
        storage
            .history_keys()
            .get_key_epochs(&domain)
            .await
            .unwrap()
            .epochs
            .len(),
        1
    );

    let handler = EnrollmentHandler::new(
        storage.clone(),
        EnrollmentDelivery::InProcess(evaluation.clone()),
    );
    let work = claimed(storage.as_ref(), id, domain).await;
    assert_eq!(
        handler.handle(&work).await,
        WorkOutcome::Done(Some("reclaimed".into()))
    );
    assert!(
        storage
            .history_keys()
            .get_key_epochs(&domain)
            .await
            .unwrap()
            .epochs
            .is_empty()
    );
    let refused = evaluation.evaluate(&id, &[2; 32]).await.unwrap_err();
    assert_eq!(
        refused.code(),
        Code::FailedPrecondition,
        "{}",
        refused.message()
    );
    assert_eq!(
        handler.handle(&work).await,
        WorkOutcome::Done(Some("no key created".into())),
        "a repeated cleanup"
    );
}

/// A registration that committed keeps its key, even though its owner never
/// prepares again: the commit completed the operation first, so the abort
/// is not recorded and nothing is reclaimed.
#[tokio::test]
async fn a_committed_registration_keeps_its_key() {
    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let (ops, evaluation) = split(storage.clone(), installation, manager(3), manager(3));
    let (id, domain) = enrolled(&ops, installation).await;
    let committed =
        MutationContext::from(audit("test.commit")).with_operation(OperationCompletion::new(
            RESULT_NAMESPACE,
            OperationKey::parse(&id.to_string()).unwrap(),
            "registration",
            b"record",
            b"profile".to_vec(),
        ));
    storage.record_outcome(committed).await.unwrap();

    let handler = EnrollmentHandler::new(
        storage.clone(),
        EnrollmentDelivery::InProcess(evaluation.clone()),
    );
    let work = claimed(storage.as_ref(), id, domain).await;
    assert_eq!(
        handler.handle(&work).await,
        WorkOutcome::Done(Some("committed".into()))
    );
    assert_eq!(
        storage
            .history_keys()
            .get_key_epochs(&domain)
            .await
            .unwrap()
            .epochs
            .len(),
        1,
        "the committed owner's key"
    );
    assert!(
        !storage
            .history_keys()
            .enrollment_abandoned(id.into_uuid())
            .await
            .unwrap()
    );
}

/// A cleanup that arrives before its preparation fences it: the delayed
/// preparation is refused and makes no key.
#[tokio::test]
async fn an_abort_before_its_preparation_fences_it() {
    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let (_, evaluation) = split(storage.clone(), installation, manager(3), manager(3));
    let domain = owner_domain(installation.as_bytes(), ProfileId::generate());
    let id = PasswordOperationId::generate();
    let admission = EnrollmentAdmission {
        operation: id.into_uuid(),
        owner_domain: domain,
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
    };
    storage.enqueue_work(&admission.work(), 10).await.unwrap();
    let handler = EnrollmentHandler::new(
        storage.clone(),
        EnrollmentDelivery::InProcess(evaluation.clone()),
    );
    assert_eq!(
        handler
            .handle(&claimed(storage.as_ref(), id, domain).await)
            .await,
        WorkOutcome::Done(Some("no key created".into()))
    );
    let delayed = evaluation
        .prepare(&HistoryAdmission {
            id,
            owner_domain: domain,
            kind: OwnerKind::New,
            expires_at: admission.expires_at,
            charge_key: charge_key("profile:test"),
            live: LiveDomains::default(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        delayed.code(),
        Code::FailedPrecondition,
        "{}",
        delayed.message()
    );
    assert!(
        storage
            .history_keys()
            .get_key_epochs(&domain)
            .await
            .unwrap()
            .epochs
            .is_empty()
    );
}

/// With a separate evaluator, the abort is recorded together with the event
/// that tells it; this side holds no key to touch.
#[tokio::test]
async fn a_separate_evaluator_is_told_with_the_abort() {
    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let (ops, _) = split(storage.clone(), installation, manager(3), manager(3));
    let (id, domain) = enrolled(&ops, installation).await;
    let handler = EnrollmentHandler::new(
        storage.clone(),
        EnrollmentDelivery::Relay {
            source: "https://sid.example.com".into(),
        },
    );
    let work = claimed(storage.as_ref(), id, domain).await;
    assert_eq!(
        handler.handle(&work).await,
        WorkOutcome::Done(Some("abort relayed".into()))
    );
    let event = WorkId(uuid::Uuid::new_v5(
        &ABORT_EVENT_NAMESPACE,
        id.into_uuid().as_bytes(),
    ));
    let relay = storage.get_work(event).await.unwrap().expect("relay owed");
    assert_eq!(relay.kind.as_str(), sid_core::models::EVENT_RELAY_KIND);
    assert_eq!(
        handler.handle(&work).await,
        WorkOutcome::Done(Some("abort relayed".into())),
        "a retry owes no second event"
    );
}

/// First enrollments are bounded across replicas: at capacity a new one is
/// refused before the evaluator makes its key.
#[tokio::test]
async fn first_enrollments_are_refused_at_capacity() {
    let storage = sqlite().await;
    let installation = sid_core::models::OrgId::generate();
    let (ops, _) = split(storage.clone(), installation, manager(3), manager(3));
    let ops = ops.with_enrollment_capacity(1);
    enrolled(&ops, installation).await;
    let owner = ProfileId::generate();
    let refused = ops
        .prepare(
            &zkpp_without_proofs(),
            change(),
            OperationOwner::New(owner),
            owner.to_string(),
            None,
        )
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(refused.code(), Code::Unavailable, "{}", refused.message());
    assert!(
        storage
            .history_keys()
            .get_key_epochs(&owner_domain(installation.as_bytes(), owner))
            .await
            .unwrap()
            .epochs
            .is_empty(),
        "no key past capacity"
    );
}
