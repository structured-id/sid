// SPDX-License-Identifier: AGPL-3.0-only
//! Two SID instances in one host store: each keeps its records in a namespace
//! of its own, and neither reads, lists, claims or changes the other's
//! records, whether through the engine or through its own database account.

use std::slice::from_ref;
use std::time::Duration;

use sid_core::models::{NewWork, OperationCompletion, OperationKey, Profile, ProfileId, WorkKind};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::{create_test_profile, test_audit};

const METHOD: &str = "sid.v1.ProjectService/CreateProject";

/// Through the engine: `b` sees none of the profile, work and operation
/// result `a` committed, a record `b` writes under the same id and username
/// is its own, and `b` deleting it leaves `a`'s record in place.
pub async fn test_instances_are_isolated(a: &dyn StorageBackend, b: &dyn StorageBackend) {
    let profile = create_test_profile("namespace");
    a.create_profile(&profile, test_audit()).await.unwrap();
    let username = profile.username.clone().unwrap();

    // Direct paths.
    assert!(b.get_profile(profile.id).await.unwrap().is_none());
    assert!(
        b.get_profile_by_username(&username)
            .await
            .unwrap()
            .is_none()
    );
    // Query path: no page of the other instance's listing holds it.
    assert!(
        !lists(b, profile.id).await,
        "a listing reached the other instance"
    );

    // Work and results stay with the instance that owes them.
    let kind = WorkKind::new(&format!("test.namespace.{}", Uuid::now_v7().simple())).unwrap();
    let work = NewWork::new(kind.clone(), b"payload".to_vec());
    a.enqueue_work(&work, 10).await.unwrap();
    let claimed = b
        .claim_work(from_ref(&kind), "other", 10, Duration::from_secs(60))
        .await
        .unwrap();
    assert!(claimed.is_empty(), "an instance claimed the other's work");
    assert!(b.get_work(work.id).await.unwrap().is_none());

    let namespace = format!("profile:{}", profile.id);
    let key = OperationKey::parse(&Uuid::new_v4().to_string()).unwrap();
    a.record_outcome(test_audit().with_operation(OperationCompletion::new(
        &namespace,
        key.clone(),
        METHOD,
        b"inputs",
        b"result".to_vec(),
    )))
    .await
    .unwrap();
    assert!(
        b.get_operation_result(&namespace, &key)
            .await
            .unwrap()
            .is_none()
    );

    // The same identifiers in the other namespace are another record.
    let twin = Profile {
        given_name: Some("Twin".into()),
        ..profile.clone()
    };
    b.create_profile(&twin, test_audit()).await.unwrap();
    b.delete_profile(twin.id, test_audit()).await.unwrap();
    let kept = a
        .get_profile(profile.id)
        .await
        .unwrap()
        .expect("a's profile");
    assert_eq!(kept.given_name, profile.given_name);
    assert!(a.get_work(work.id).await.unwrap().is_some());
}

/// Whether any page of `backend`'s profile listing holds `id`.
async fn lists(backend: &dyn StorageBackend, id: ProfileId) -> bool {
    let mut offset = 0;
    loop {
        let page = backend.list_profiles(offset, 100).await.unwrap();
        if page.iter().any(|p| p.id == id) {
            return true;
        }
        if page.len() < 100 {
            return false;
        }
        offset += 100;
    }
}

/// A database access the store's harness makes with one instance's own
/// account, outside the engine, at the namespace of another instance.
pub enum Reach {
    /// Read one record by its id.
    Read(ProfileId),
    /// List the records of the namespace.
    Query,
    /// Change one record by its id.
    Write(ProfileId),
}

/// What the database answered such an access.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// The database refused it: the account holds no right on that namespace.
    Refused,
    /// The access ran and reached the other instance's records.
    Reached,
}

/// A store whose native access control separates the namespaces of
/// instances. The harness reaches with the account of one instance (`b`)
/// for the records of another (`a`); only the database's own enforcement
/// decides, never a name prefix the engine adds.
#[async_trait::async_trait]
pub trait NativeNamespaces: Send + Sync {
    async fn reach(&self, access: Reach) -> Answer;
}

/// Through the database itself: `b`'s account is refused every read, listing
/// and change of `a`'s records, while the engine of `a` keeps them.
pub async fn test_native_namespace_refuses_the_other_instance(
    a: &dyn StorageBackend,
    b_account: &dyn NativeNamespaces,
) {
    let profile = create_test_profile("native_namespace");
    a.create_profile(&profile, test_audit()).await.unwrap();

    assert_eq!(
        b_account.reach(Reach::Read(profile.id)).await,
        Answer::Refused
    );
    assert_eq!(b_account.reach(Reach::Query).await, Answer::Refused);
    assert_eq!(
        b_account.reach(Reach::Write(profile.id)).await,
        Answer::Refused
    );
    let kept = a
        .get_profile(profile.id)
        .await
        .unwrap()
        .expect("a's profile");
    assert_eq!(kept.given_name, profile.given_name);
}
