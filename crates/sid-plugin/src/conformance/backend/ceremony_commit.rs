// SPDX-License-Identifier: AGPL-3.0-only
//! A mutation that completes a ceremony consumes its state in the same
//! transaction: exactly once, only while it is live and exactly as read, and
//! never when the mutation itself does not commit. A ceremony state that owes
//! durable work commits with it, or neither is stored.

use std::time::Duration;

use sid_core::Error;
use sid_core::models::{
    CeremonyConsumption, NewWork, OperationCompletion, OperationKey, Project, WorkKind,
};
use sid_plugin::OwedWork;
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

const NAMESPACE: &str = "test-ceremony-commit";
const TTL: Duration = Duration::from_secs(300);

/// A pending ceremony with `stored` as its state, and its consumption.
async fn pending(backend: &dyn StorageBackend, stored: &[u8]) -> CeremonyConsumption {
    let key = Uuid::now_v7().to_string();
    backend
        .put_ceremony_state(NAMESPACE, &key, stored, TTL)
        .await
        .unwrap();
    CeremonyConsumption {
        namespace: NAMESPACE,
        key,
        stored: stored.to_vec(),
    }
}

fn project() -> Project {
    Project::new(format!("ceremony_{}", Uuid::now_v7().simple()), None)
}

/// The mutation commits with its ceremony consumed.
pub async fn test_a_mutation_consumes_its_ceremony(backend: &dyn StorageBackend) {
    let ceremony = pending(backend, b"state").await;
    let project = project();

    backend
        .create_project(&project, test_audit().consuming(ceremony.clone()))
        .await
        .unwrap();

    assert!(backend.get_project(project.id).await.unwrap().is_some());
    assert!(
        backend
            .read_ceremony_state(NAMESPACE, &ceremony.key)
            .await
            .unwrap()
            .is_none(),
        "the ceremony is still pending after its completion committed"
    );
}

/// A ceremony changed since it was read, or never stored, completes
/// nothing: the mutation is refused and writes nothing.
pub async fn test_a_changed_or_absent_ceremony_completes_nothing(backend: &dyn StorageBackend) {
    let mut changed = pending(backend, b"state").await;
    changed.stored = b"another state".to_vec();
    let project = project();
    let refused = backend
        .create_project(&project, test_audit().consuming(changed.clone()))
        .await
        .expect_err("a ceremony changed since it was read");
    assert!(matches!(refused, Error::Expired(_)), "{refused:?}");
    assert!(backend.get_project(project.id).await.unwrap().is_none());
    assert!(
        backend
            .read_ceremony_state(NAMESPACE, &changed.key)
            .await
            .unwrap()
            .is_some(),
        "a refused mutation consumed the ceremony"
    );

    let absent = CeremonyConsumption {
        namespace: NAMESPACE,
        key: Uuid::now_v7().to_string(),
        stored: b"state".to_vec(),
    };
    let project = self::project();
    let refused = backend
        .create_project(&project, test_audit().consuming(absent))
        .await
        .expect_err("a ceremony never stored");
    assert!(matches!(refused, Error::Expired(_)), "{refused:?}");
    assert!(backend.get_project(project.id).await.unwrap().is_none());
}

/// An expired ceremony completes nothing, though its row may remain.
pub async fn test_an_expired_ceremony_completes_nothing(backend: &dyn StorageBackend) {
    let key = Uuid::now_v7().to_string();
    backend
        .put_ceremony_state(NAMESPACE, &key, b"state", Duration::from_millis(1))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let project = project();

    let refused = backend
        .create_project(
            &project,
            test_audit().consuming(CeremonyConsumption {
                namespace: NAMESPACE,
                key,
                stored: b"state".to_vec(),
            }),
        )
        .await
        .expect_err("an expired ceremony");

    assert!(matches!(refused, Error::Expired(_)), "{refused:?}");
    assert!(backend.get_project(project.id).await.unwrap().is_none());
}

/// Of two concurrent completions of one ceremony exactly one commits.
pub async fn test_concurrent_completions_commit_once(backend: &dyn StorageBackend) {
    let ceremony = pending(backend, b"state").await;
    let (first, second) = (project(), project());

    let (a, b) = tokio::join!(
        backend.create_project(&first, test_audit().consuming(ceremony.clone())),
        backend.create_project(&second, test_audit().consuming(ceremony.clone())),
    );

    let committed = [a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count();
    assert_eq!(committed, 1, "first: {a:?}, second: {b:?}");
    let stored = [
        backend.get_project(first.id).await.unwrap().is_some(),
        backend.get_project(second.id).await.unwrap().is_some(),
    ];
    assert_eq!(stored.iter().filter(|s| **s).count(), 1);
    for refused in [a, b].into_iter().filter_map(Result::err) {
        assert!(matches!(refused, Error::Expired(_)), "{refused:?}");
    }
}

/// A work kind no other scenario owes, so its open count is this one's.
fn own_kind() -> WorkKind {
    WorkKind::new(&format!("test.ceremony_owing.{}", Uuid::now_v7().simple())).unwrap()
}

fn owed(work: &NewWork, capacity: u64) -> OwedWork<'_> {
    OwedWork { work, capacity }
}

/// A ceremony state stored with the work it owes commits both.
pub async fn test_a_ceremony_state_commits_with_its_owed_work(backend: &dyn StorageBackend) {
    let key = Uuid::now_v7().to_string();
    let work = NewWork::new(own_kind(), b"mail".to_vec());

    backend
        .put_ceremony_state_owing(NAMESPACE, &key, b"state", TTL, owed(&work, 10))
        .await
        .unwrap();

    assert_eq!(
        backend.read_ceremony_state(NAMESPACE, &key).await.unwrap(),
        Some(b"state".to_vec())
    );
    assert!(backend.get_work(work.id).await.unwrap().is_some());
}

/// A ceremony state whose owed work finds its kind full stores neither: a
/// state without the work it needs is never left behind.
pub async fn test_a_ceremony_state_refused_for_capacity_stores_neither(
    backend: &dyn StorageBackend,
) {
    let kind = own_kind();
    backend
        .enqueue_work(&NewWork::new(kind.clone(), vec![]), 1)
        .await
        .unwrap();
    let key = Uuid::now_v7().to_string();
    let work = NewWork::new(kind, b"mail".to_vec());

    let refused = backend
        .put_ceremony_state_owing(NAMESPACE, &key, b"state", TTL, owed(&work, 1))
        .await
        .expect_err("the work's kind is full");

    assert!(
        matches!(refused, Error::ResourceExhausted(_)),
        "{refused:?}"
    );
    assert!(
        backend
            .read_ceremony_state(NAMESPACE, &key)
            .await
            .unwrap()
            .is_none(),
        "the state was stored without its work"
    );
    assert!(backend.get_work(work.id).await.unwrap().is_none());
}

/// A replacement commits with its owed work; one from a state no longer
/// held stores neither.
pub async fn test_a_replacement_commits_with_its_owed_work(backend: &dyn StorageBackend) {
    let key = Uuid::now_v7().to_string();
    backend
        .put_ceremony_state(NAMESPACE, &key, b"first", TTL)
        .await
        .unwrap();
    let (kind, stale) = (own_kind(), NewWork::new(own_kind(), vec![]));
    let work = NewWork::new(kind, b"mail".to_vec());

    assert!(
        !backend
            .replace_ceremony_state_owing(
                NAMESPACE,
                &key,
                b"other",
                b"second",
                TTL,
                owed(&stale, 10)
            )
            .await
            .unwrap()
    );
    assert!(backend.get_work(stale.id).await.unwrap().is_none());
    assert!(
        backend
            .replace_ceremony_state_owing(
                NAMESPACE,
                &key,
                b"first",
                b"second",
                TTL,
                owed(&work, 10)
            )
            .await
            .unwrap()
    );
    assert_eq!(
        backend.read_ceremony_state(NAMESPACE, &key).await.unwrap(),
        Some(b"second".to_vec())
    );
    assert!(backend.get_work(work.id).await.unwrap().is_some());
}

/// A replacement whose owed work finds its kind full leaves the state as it
/// was: the current state keeps what it already owes.
pub async fn test_a_replacement_refused_for_capacity_keeps_the_state(backend: &dyn StorageBackend) {
    let kind = own_kind();
    backend
        .enqueue_work(&NewWork::new(kind.clone(), vec![]), 1)
        .await
        .unwrap();
    let key = Uuid::now_v7().to_string();
    backend
        .put_ceremony_state(NAMESPACE, &key, b"first", TTL)
        .await
        .unwrap();
    let work = NewWork::new(kind, b"mail".to_vec());

    let refused = backend
        .replace_ceremony_state_owing(NAMESPACE, &key, b"first", b"second", TTL, owed(&work, 1))
        .await
        .expect_err("the work's kind is full");

    assert!(
        matches!(refused, Error::ResourceExhausted(_)),
        "{refused:?}"
    );
    assert_eq!(
        backend.read_ceremony_state(NAMESPACE, &key).await.unwrap(),
        Some(b"first".to_vec())
    );
    assert!(backend.get_work(work.id).await.unwrap().is_none());
}

/// Of two concurrent replacements of one state exactly one commits, with
/// its own work: the other owes nothing.
pub async fn test_concurrent_replacements_owe_once(backend: &dyn StorageBackend) {
    let key = Uuid::now_v7().to_string();
    backend
        .put_ceremony_state(NAMESPACE, &key, b"first", TTL)
        .await
        .unwrap();
    let kind = own_kind();
    let (a, b) = (
        NewWork::new(kind.clone(), b"a".to_vec()),
        NewWork::new(kind, b"b".to_vec()),
    );

    let (ra, rb) = tokio::join!(
        backend.replace_ceremony_state_owing(NAMESPACE, &key, b"first", b"a", TTL, owed(&a, 10)),
        backend.replace_ceremony_state_owing(NAMESPACE, &key, b"first", b"b", TTL, owed(&b, 10)),
    );

    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert!(ra ^ rb, "first: {ra}, second: {rb}");
    let winner = if ra { &a } else { &b };
    let loser = if ra { &b } else { &a };
    assert_eq!(
        backend.read_ceremony_state(NAMESPACE, &key).await.unwrap(),
        Some(winner.payload.clone())
    );
    assert!(backend.get_work(winner.id).await.unwrap().is_some());
    assert!(backend.get_work(loser.id).await.unwrap().is_none());
}

/// A retry of a keyed command whose completion already committed is
/// answered as completed, although its ceremony is gone: a lost response is
/// resolved by the recorded outcome, never by another use of the ceremony.
pub async fn test_a_completed_command_is_answered_before_its_ceremony(
    backend: &dyn StorageBackend,
) {
    let ceremony = pending(backend, b"state").await;
    let namespace = format!("profile:{}", Uuid::now_v7().simple());
    let key = OperationKey::parse(&Uuid::new_v4().to_string()).unwrap();
    let keyed = || {
        test_audit()
            .with_operation(OperationCompletion::new(
                &namespace,
                key.clone(),
                "sid.v1.test/Complete",
                b"inputs",
                b"result".to_vec(),
            ))
            .consuming(ceremony.clone())
    };
    backend.create_project(&project(), keyed()).await.unwrap();

    let retry = backend
        .create_project(&project(), keyed())
        .await
        .expect_err("a retry of a committed command");

    assert!(matches!(retry, Error::OperationCompleted(_)), "{retry:?}");
}
