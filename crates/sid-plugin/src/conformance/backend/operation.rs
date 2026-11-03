// SPDX-License-Identifier: AGPL-3.0-only
//! Durable operation results: a keyed command's completion commits with its
//! effect, once per key within its namespace.

use sid_core::Error;
use sid_core::models::{MutationContext, OperationCompletion, OperationKey, Project, ProjectId};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

use super::test_audit;

const METHOD: &str = "sid.v1.ProjectService/CreateProject";

fn key() -> OperationKey {
    OperationKey::parse(&Uuid::new_v4().to_string()).unwrap()
}

fn namespace() -> String {
    format!("profile:{}", Uuid::now_v7())
}

fn completion(namespace: &str, key: &OperationKey, inputs: &[u8]) -> OperationCompletion {
    OperationCompletion::new(namespace, key.clone(), METHOD, inputs, inputs.to_vec())
}

fn keyed(namespace: &str, key: &OperationKey, inputs: &[u8]) -> MutationContext {
    test_audit().with_operation(completion(namespace, key, inputs))
}

async fn project_exists(backend: &dyn StorageBackend, project: &Project) -> bool {
    backend.get_project(project.id).await.unwrap().is_some()
}

/// The completion commits with the effect and resolves the key afterwards.
pub async fn test_operation_completion_commits_with_effect(backend: &dyn StorageBackend) {
    let (ns, key) = (namespace(), key());
    let project = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&project, keyed(&ns, &key, b"inputs"))
        .await
        .unwrap();

    let record = backend
        .get_operation_result(&ns, &key)
        .await
        .unwrap()
        .expect("recorded");
    assert!(record.matches(METHOD, b"inputs"));
    assert!(!record.matches(METHOD, b"other"));
    assert_eq!(record.completion.result, b"inputs");
    assert!(project_exists(backend, &project).await);
}

/// An update's completion records the state the update left, read inside its
/// transaction, so a retry answers with exactly what that commit made.
pub async fn test_update_records_the_state_it_left(backend: &dyn StorageBackend) {
    let (ns, key) = (namespace(), key());
    let project = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&project, test_audit())
        .await
        .unwrap();
    let change = sid_core::models::ProjectChange {
        name: Some(format!("renamed_{}", Uuid::now_v7().simple())),
        description: None,
        updated_at: chrono::Utc::now(),
    };
    let updated = backend
        .update_project(
            project.id,
            &change,
            test_audit().with_operation(OperationCompletion::new(
                &ns,
                key.clone(),
                "sid.v1.ProjectService/UpdateProject",
                b"edit",
                Vec::new(),
            )),
        )
        .await
        .unwrap()
        .expect("updated");

    let record = backend
        .get_operation_result(&ns, &key)
        .await
        .unwrap()
        .expect("recorded");
    let recorded: Project = serde_json::from_slice(&record.completion.result).unwrap();
    assert_eq!(recorded.name, updated.name);
    assert_eq!(recorded.name, change.name.unwrap());
    assert_eq!(recorded.description, project.description);
}

/// A second commit under a completed key commits nothing, whatever it
/// carries, and says so; the same key in another namespace is its own.
pub async fn test_completed_operation_commits_nothing(backend: &dyn StorageBackend) {
    let (ns, key) = (namespace(), key());
    let first = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&first, keyed(&ns, &key, b"inputs"))
        .await
        .unwrap();

    let retry = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    let err = backend
        .create_project(&retry, keyed(&ns, &key, b"inputs"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::OperationCompleted(_)), "{err:?}");
    assert!(
        !project_exists(backend, &retry).await,
        "a retry executed again"
    );

    let elsewhere = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&elsewhere, keyed(&namespace(), &key, b"inputs"))
        .await
        .unwrap();
    assert!(project_exists(backend, &elsewhere).await);
}

/// Two attempts of one command at once: one commits, the other commits
/// nothing.
pub async fn test_concurrent_duplicate_operation_commits_once(backend: &dyn StorageBackend) {
    let (ns, key) = (namespace(), key());
    let a = Project::new(format!("op_a_{}", Uuid::now_v7().simple()), None);
    let b = Project::new(format!("op_b_{}", Uuid::now_v7().simple()), None);
    let (ra, rb) = tokio::join!(
        backend.create_project(&a, keyed(&ns, &key, b"inputs")),
        backend.create_project(&b, keyed(&ns, &key, b"inputs")),
    );
    assert_eq!(
        usize::from(ra.is_ok()) + usize::from(rb.is_ok()),
        1,
        "{ra:?} {rb:?}"
    );
    let loser_err = if ra.is_ok() { rb } else { ra }.unwrap_err();
    assert!(
        matches!(loser_err, Error::OperationCompleted(_)),
        "{loser_err:?}"
    );
    assert_eq!(
        usize::from(project_exists(backend, &a).await)
            + usize::from(project_exists(backend, &b).await),
        1
    );
}

/// A completion leaves in the export and comes back through import with its
/// original time; importing it again writes nothing, and the imported key
/// refuses a second execution like any completed key.
pub async fn test_operation_results_travel_between_stores(backend: &dyn StorageBackend) {
    let (ns, key) = (namespace(), key());
    let project = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    backend
        .create_project(&project, keyed(&ns, &key, b"inputs"))
        .await
        .unwrap();
    let exported = backend.export_operation_results().await.unwrap();
    let mine = exported
        .iter()
        .find(|r| r.completion.namespace == ns && r.completion.key == key)
        .expect("exported")
        .clone();
    assert!(
        !backend.import_operation_result(&mine).await.unwrap(),
        "an existing completion is kept"
    );

    let mut moved = mine.clone();
    moved.completion.namespace = namespace();
    moved.completed_at -= chrono::Duration::days(1);
    assert!(backend.import_operation_result(&moved).await.unwrap());
    let restored = backend
        .get_operation_result(&moved.completion.namespace, &key)
        .await
        .unwrap()
        .expect("imported");
    assert_eq!(restored.completion, moved.completion);
    assert_eq!(
        restored.completed_at.timestamp_millis(),
        moved.completed_at.timestamp_millis()
    );

    let retry = Project::new(format!("op_{}", Uuid::now_v7().simple()), None);
    let err = backend
        .create_project(&retry, keyed(&moved.completion.namespace, &key, b"inputs"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::OperationCompleted(_)), "{err:?}");
}

/// A registration's commit and the terminal abort of the same operation
/// complete one key: of the two racing, exactly one is written, and the
/// account exists exactly when the commit won. An abort recorded alone
/// carries its owed work with it.
pub async fn test_terminal_abort_races_the_commit(backend: &dyn StorageBackend) {
    use sid_core::models::{
        Credential, CredentialType, NewRegistration, Profile, SignupIdentifier,
    };
    for round in 0..4 {
        let (ns, key) = (namespace(), key());
        let name = format!("enrolled{}", &Uuid::now_v7().simple().to_string()[16..]);
        let profile = Profile::new(Some(&name));
        let credential = Credential::new(profile.id, CredentialType::Opaque, vec![round], None);
        let registration = NewRegistration::new(
            profile.clone(),
            SignupIdentifier::Username(&name),
            Some(credential),
        )
        .unwrap();
        let commit = test_audit().with_operation(OperationCompletion::new(
            &ns,
            key.clone(),
            "registration",
            b"record",
            b"committed".to_vec(),
        ));
        let owed = sid_core::models::NewWork::new(
            sid_core::models::WorkKind::new("test.enrollment_abort").unwrap(),
            vec![round],
        );
        let abort = test_audit()
            .with_operation(OperationCompletion::new(
                &ns,
                key.clone(),
                "abort",
                &[],
                Vec::new(),
            ))
            .with_work(owed.clone());
        let (committed, aborted) = tokio::join!(
            backend.register_profile(&registration, commit),
            backend.record_outcome(abort),
        );
        assert_eq!(
            usize::from(committed.is_ok()) + usize::from(aborted.is_ok()),
            1,
            "{committed:?} {aborted:?}"
        );
        let loser = if committed.is_ok() {
            aborted
        } else {
            committed
        }
        .unwrap_err();
        assert!(matches!(loser, Error::OperationCompleted(_)), "{loser:?}");
        let record = backend
            .get_operation_result(&ns, &key)
            .await
            .unwrap()
            .expect("one completion");
        let account = backend.get_profile(profile.id).await.unwrap();
        let abort_work = backend.get_work(owed.id).await.unwrap();
        if record.completion.method == "registration" {
            assert!(account.is_some(), "the commit won but wrote no account");
            assert!(abort_work.is_none(), "a lost abort owed its work");
        } else {
            assert!(account.is_none(), "the abort won but an account exists");
            assert!(abort_work.is_some(), "the abort's work was not owed");
        }
    }
}

/// A keyed claim decision already in effect changes nothing and owes no
/// work, yet commits its completion: a retry after a later opposite decision
/// must find it completed rather than apply it over that decision.
pub async fn test_unchanged_mutation_records_its_completion(backend: &dyn StorageBackend) {
    use sid_core::models::Profile;
    use sid_core::models::consent::{ClaimDecision, ClaimGrantChange, ClaimType, ConsentRecord};
    let profile = Profile::new(Some(&format!(
        "unchanged{}",
        &Uuid::now_v7().simple().to_string()[16..]
    )));
    backend
        .create_profile(&profile, test_audit())
        .await
        .unwrap();
    let mut consent = ConsentRecord::new(profile.id, &format!("app_{}", Uuid::now_v7().simple()));
    consent.grant_claim("phone", ClaimType::Data);
    if let Some(requested) = consent.as_requested() {
        requested.grant();
    }
    backend
        .create_consent(&consent, test_audit())
        .await
        .unwrap();

    let (ns, key) = (namespace(), key());
    let owed = sid_core::models::NewWork::new(
        sid_core::models::WorkKind::new("test.claim_event").unwrap(),
        vec![1],
    );
    let decide = || {
        test_audit()
            .with_operation(OperationCompletion::new(
                &ns,
                key.clone(),
                "sid.v1.account.AccountService/UpdateClaimConsent",
                b"grant phone",
                Vec::new(),
            ))
            .with_work(owed.clone())
    };
    let change = backend
        .change_claim_grant(
            consent.id,
            "phone",
            ClaimDecision::Grant(ClaimType::Data),
            decide(),
        )
        .await
        .unwrap();
    assert_eq!(change, ClaimGrantChange::Unchanged);
    assert!(
        backend
            .get_operation_result(&ns, &key)
            .await
            .unwrap()
            .is_some(),
        "an unchanged keyed decision recorded no completion"
    );
    assert!(
        backend.get_work(owed.id).await.unwrap().is_none(),
        "a decision that changed nothing owed its event"
    );

    // A later opposite decision, then the retry: it commits nothing.
    backend
        .change_claim_grant(consent.id, "phone", ClaimDecision::Revoke, test_audit())
        .await
        .unwrap();
    let err = backend
        .change_claim_grant(
            consent.id,
            "phone",
            ClaimDecision::Grant(ClaimType::Data),
            decide(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::OperationCompleted(_)), "{err:?}");
    let stored = backend.get_consent(consent.id).await.unwrap().unwrap();
    assert!(
        !stored
            .grants
            .iter()
            .any(|g| g.claim_name == "phone" && g.is_active()),
        "the retry applied the decision over a later one"
    );
}

/// A mutation that fails records no completion: the key stays free.
pub async fn test_failed_mutation_records_no_completion(backend: &dyn StorageBackend) {
    backend.ensure_system_project(test_audit()).await.unwrap();
    let (ns, key) = (namespace(), key());
    let refused = backend
        .delete_project(ProjectId::system(), keyed(&ns, &key, b"inputs"))
        .await;
    assert!(refused.is_err());
    assert!(
        backend
            .get_operation_result(&ns, &key)
            .await
            .unwrap()
            .is_none()
    );
}
