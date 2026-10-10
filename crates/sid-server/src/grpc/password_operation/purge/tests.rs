// SPDX-License-Identifier: AGPL-3.0-only
use super::super::tests::{change, manager, split, sqlite, zkpp_without_proofs};
use super::super::*;
use super::*;
use sid_core::models::{Organization, Profile, WorkId, WorkState};
use sid_plugin::work_store::WorkStore;

/// The work as the runner hands it over.
async fn claimed(storage: &dyn StorageBackend, id: WorkId) -> ClaimedWork {
    let record = storage
        .get_work(id)
        .await
        .unwrap()
        .expect("the purge is owed");
    let payload = storage
        .export_work()
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.record.id == id)
        .unwrap()
        .payload;
    ClaimedWork {
        id: record.id,
        kind: record.kind,
        payload,
        attempt: 1,
        max_attempts: record.max_attempts,
        generation: 1,
        expires_at: None,
    }
}

/// An installation of its own authority with one profile whose first
/// enrollment made it a history key: the store, the authority, the profile
/// and both sides.
async fn owner_with_a_key() -> (
    Arc<sid_storage::sqlite::SqliteBackend>,
    Organization,
    ProfileId,
    PasswordOperations,
    Arc<HistoryEvaluation>,
) {
    let storage = sqlite().await;
    let org = Organization::implicit_community("sid.example.com");
    storage
        .insert_instance_organization(&org, AuditEntry::system("test", "org").into())
        .await
        .unwrap();
    let (ops, evaluation) = split(storage.clone(), org.id, manager(3), manager(3));
    let profile = Profile::new(Some("purged-owner"));
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    ops.prepare(
        &zkpp_without_proofs(),
        change(),
        OperationOwner::New(profile.id),
        profile.id.to_string(),
        None,
    )
    .await
    .unwrap();
    (storage, org, profile.id, ops, evaluation)
}

/// Deleting a profile owes its keys' purge in the deletion's transaction;
/// the purge destroys them, and a preparation of the owner still in flight
/// makes no key afterwards. A repeated purge is harmless.
#[tokio::test]
async fn a_deleted_owners_keys_are_destroyed() {
    let (storage, org, profile, ops, evaluation) = owner_with_a_key().await;
    let domain = sid_authn::password_history::owner_domain(org.id.as_bytes(), profile);
    let keys = || async {
        storage
            .history_keys()
            .get_key_epochs(&domain)
            .await
            .unwrap()
            .epochs
            .len()
    };
    assert_eq!(keys().await, 1);

    let purge = owner_purge(storage.as_ref(), profile)
        .await
        .unwrap()
        .expect("an installation with an authority owes the purge");
    storage
        .delete_profile(
            profile,
            MutationContext::from(AuditEntry::system("test", "delete")).with_work(purge.clone()),
        )
        .await
        .unwrap();
    let owed = storage.get_work(purge.id).await.unwrap().unwrap();
    assert_eq!(owed.state, WorkState::Pending);

    let handler = OwnerPurgeHandler::new(
        storage.clone(),
        EvaluatorDelivery::InProcess(evaluation.clone()),
    );
    let work = claimed(storage.as_ref(), purge.id).await;
    assert_eq!(
        handler.handle(&work).await,
        WorkOutcome::Done(Some("1 keys destroyed".into()))
    );
    assert_eq!(keys().await, 0);

    let delayed = ops
        .prepare(
            &zkpp_without_proofs(),
            change(),
            OperationOwner::New(profile),
            profile.to_string(),
            None,
        )
        .await;
    assert!(delayed.is_err(), "a key was made for a deleted owner");
    assert_eq!(keys().await, 0);
    assert_eq!(
        handler.handle(&work).await,
        WorkOutcome::Done(Some("0 keys destroyed".into())),
        "a repeated purge"
    );
}

/// With a separate evaluator, the purge owes the event that tells it, once
/// per owner however often it runs.
#[tokio::test]
async fn a_separate_evaluator_is_told_of_the_purge() {
    let (storage, org, profile, _, _) = owner_with_a_key().await;
    let purge = owner_purge(storage.as_ref(), profile)
        .await
        .unwrap()
        .unwrap();
    storage.enqueue_work(&purge, 10).await.unwrap();
    let handler = OwnerPurgeHandler::new(
        storage.clone(),
        EvaluatorDelivery::Relay {
            source: "https://sid.example.com".into(),
        },
    );
    let work = claimed(storage.as_ref(), purge.id).await;
    for _ in 0..2 {
        assert_eq!(
            handler.handle(&work).await,
            WorkOutcome::Done(Some("purge relayed".into()))
        );
    }
    let domain = sid_authn::password_history::owner_domain(org.id.as_bytes(), profile);
    let event = WorkId(uuid::Uuid::new_v5(&PURGE_EVENT_NAMESPACE, &domain));
    let relay = storage.get_work(event).await.unwrap().expect("relay owed");
    assert_eq!(relay.kind.as_str(), sid_core::models::EVENT_RELAY_KIND);
}

/// Before the installation has an authority there is no history domain, so
/// no key, and nothing is owed.
#[tokio::test]
async fn nothing_is_owed_without_an_authority() {
    let storage = sqlite().await;
    assert!(
        owner_purge(storage.as_ref(), ProfileId::generate())
            .await
            .unwrap()
            .is_none()
    );
}
