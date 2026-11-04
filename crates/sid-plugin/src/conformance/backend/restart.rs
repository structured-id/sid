// SPDX-License-Identifier: AGPL-3.0-only
//! What a store owes across a restart: a command whose reply was lost
//! resolves by its key, and work its executor left behind is taken over.

use std::future::Future;
use std::slice::from_ref;
use std::time::Duration;

use sid_core::models::{NewWork, OperationCompletion, OperationKey, Project, WorkKind, WorkState};
use sid_plugin::WorkStore;
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

const METHOD: &str = "sid.v1.ProjectService/CreateProject";
const LEASE: Duration = Duration::from_millis(300);
const PAST_LEASE: Duration = Duration::from_millis(450);
const NEXT_LEASE: Duration = Duration::from_secs(60);

/// `open` connects to the same store each time, as a restarted process does.
/// The process that committed is gone, and with it the reply and the executor.
pub async fn test_commit_survives_restart<B, O, F>(open: O)
where
    B: StorageBackend + WorkStore,
    O: Fn() -> F,
    F: Future<Output = B>,
{
    let namespace = format!("profile:{}", Uuid::now_v7());
    let key = OperationKey::parse(&Uuid::new_v4().to_string()).unwrap();
    let project = Project::new(format!("restart_{}", Uuid::now_v7().simple()), None);
    let kind = WorkKind::new(&format!("test.restart.{}", Uuid::now_v7().simple())).unwrap();
    let work = NewWork::new(kind.clone(), b"payload".to_vec());

    let before = open().await;
    let period = before
        .current_operation_period(chrono::Utc::now(), chrono::Duration::hours(1))
        .await
        .unwrap()
        .period;
    let completion = OperationCompletion::new(
        &namespace,
        key.clone(),
        METHOD,
        b"inputs",
        b"result".to_vec(),
    )
    .in_period(period);
    before
        .create_project(&project, test_audit().with_operation(completion))
        .await
        .unwrap();
    WorkStore::enqueue_work(&before, &work, 10).await.unwrap();
    let left = before
        .claim_work(from_ref(&kind), "before", 10, LEASE)
        .await
        .unwrap();
    assert_eq!(left.len(), 1);
    drop(before);

    let after = open().await;
    let record = after
        .get_operation_result(&namespace, &key)
        .await
        .unwrap()
        .expect("a lost reply resolves by its key");
    assert!(record.matches(METHOD, b"inputs", Some(period)));
    assert_eq!(record.completion.result, b"result");
    // The period the command was named with still admits after the restart.
    let next = OperationKey::parse(&Uuid::new_v4().to_string()).unwrap();
    after
        .record_outcome(
            test_audit().with_operation(
                OperationCompletion::new(&namespace, next, METHOD, b"inputs", Vec::new())
                    .in_period(period),
            ),
        )
        .await
        .unwrap();
    assert!(after.get_project(project.id).await.unwrap().is_some());

    tokio::time::sleep(PAST_LEASE).await;
    let taken = after
        .claim_work(from_ref(&kind), "after", 10, NEXT_LEASE)
        .await
        .unwrap();
    assert_eq!(taken.len(), 1, "work left behind was not taken over");
    assert!(taken[0].generation > left[0].generation);
    assert_eq!(taken[0].payload, b"payload");
    assert!(
        !after
            .complete_work(work.id, left[0].generation, Some("late"))
            .await
            .unwrap(),
        "the replaced executor published a late result"
    );
    assert!(
        after
            .complete_work(work.id, taken[0].generation, Some("done"))
            .await
            .unwrap()
    );
    let finished = after.get_work(work.id).await.unwrap().unwrap();
    assert_eq!(finished.state, WorkState::Completed);
    assert_eq!(finished.result.as_deref(), Some("done"));
}
