// SPDX-License-Identifier: AGPL-3.0-only
//! What a store owes across its own backup and restore: the restored store
//! is the state at the backup point, all of it and nothing written later.

use std::future::Future;
use std::slice::from_ref;
use std::time::Duration;

use sid_core::models::audit::AuditEntry;
use sid_core::models::machine_user::{MachineCredentialType, MachineUserCredential};
use sid_core::models::{NewWork, OperationCompletion, OperationKey, Project, WorkKind};
use sid_plugin::storage::StorageBackend;
use sid_plugin::{AuditLog, WorkStore};
use uuid::Uuid;

use super::machine::stored_machine_user;
use super::{create_test_profile, create_test_session, test_audit, test_session_end};

const METHOD: &str = "sid.v1.ProjectService/CreateProject";

/// `backup` takes a backup of `live` by the backend's own procedure, and
/// `restore` brings one back as a store with its audit log. What `live` held
/// at the backup comes back (an identity, a machine key reference, a live
/// and an ended session, an audit record, a stored outcome, pending work);
/// what was written after it does not, and the restored audit chain
/// verifies.
pub async fn test_restore_returns_the_backed_up_state<B, L, Bk, BkF, P, Rs, RsF>(
    live: &B,
    log: &L,
    backup: Bk,
    restore: Rs,
) where
    B: StorageBackend + WorkStore,
    L: AuditLog,
    Bk: FnOnce() -> BkF,
    BkF: Future<Output = P>,
    Rs: FnOnce(P) -> RsF,
    RsF: Future<Output = (B, L)>,
{
    let tag = Uuid::now_v7().simple().to_string();
    let chain = format!("test:backup:{tag}");
    let namespace = format!("profile:{tag}");
    let key = OperationKey::parse(&Uuid::new_v4().to_string()).unwrap();
    let kind = WorkKind::new(&format!("test.backup.{tag}")).unwrap();

    // The state at the backup point.
    let profile = create_test_profile("backup");
    live.create_profile(&profile, test_audit()).await.unwrap();
    let machine = stored_machine_user(live).await;
    let credential = MachineUserCredential::new(
        machine.id,
        format!("kid-{tag}"),
        MachineCredentialType::ClientSecret,
        format!("hash-{tag}"),
    );
    live.add_machine_credential(&credential, Some(2), test_audit())
        .await
        .unwrap();
    let kept = create_test_session(profile.id);
    live.create_session(&kept, test_audit()).await.unwrap();
    let ended = create_test_session(profile.id);
    live.create_session(&ended, test_audit()).await.unwrap();
    live.delete_session(ended.id, &test_session_end(), test_audit())
        .await
        .unwrap();
    log.log(&chain, AuditEntry::system("test.backup", &chain))
        .await
        .unwrap();
    let project = Project::new(format!("backup_{tag}"), None);
    let period = live
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
    live.create_project(&project, test_audit().with_operation(completion))
        .await
        .unwrap();
    let pending = NewWork::new(kind.clone(), b"pending".to_vec());
    WorkStore::enqueue_work(live, &pending).await.unwrap();

    let point = backup().await;

    // Written after the backup point.
    live.delete_session(kept.id, &test_session_end(), test_audit())
        .await
        .unwrap();
    let later = Project::new(format!("later_{tag}"), None);
    live.create_project(&later, test_audit()).await.unwrap();
    let after = NewWork::new(kind.clone(), b"after".to_vec());
    WorkStore::enqueue_work(live, &after).await.unwrap();
    log.log(&chain, AuditEntry::system("test.after", &chain))
        .await
        .unwrap();

    let (restored, restored_log) = restore(point).await;

    assert!(restored.get_profile(profile.id).await.unwrap().is_some());
    let stored = restored
        .get_machine_credential_by_kid(&credential.kid)
        .await
        .unwrap()
        .expect("the machine key reference came back");
    assert_eq!(stored.machine_user_id, machine.id);
    assert!(
        restored.get_session(kept.id).await.unwrap().is_some(),
        "the session live at the backup came back"
    );
    assert!(
        restored.get_session(ended.id).await.unwrap().is_none(),
        "a session ended before the backup came back"
    );
    let record = restored
        .get_operation_result(&namespace, &key)
        .await
        .unwrap()
        .expect("the stored outcome came back");
    assert!(record.matches(METHOD, b"inputs", Some(period)));
    // The period it was named with came back admitted with it.
    let next = OperationKey::parse(&Uuid::new_v4().to_string()).unwrap();
    restored
        .record_outcome(
            test_audit().with_operation(
                OperationCompletion::new(&namespace, next, METHOD, b"inputs", Vec::new())
                    .in_period(period),
            ),
        )
        .await
        .unwrap();
    assert!(restored.get_project(project.id).await.unwrap().is_some());
    assert!(
        restored.get_project(later.id).await.unwrap().is_none(),
        "a write after the backup point was restored"
    );

    let claimed = restored
        .claim_work(from_ref(&kind), "restored", 10, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(
        claimed.iter().map(|w| w.id).collect::<Vec<_>>(),
        vec![pending.id],
        "the restored queue is not the queue at the backup point"
    );

    let actions: Vec<String> = restored_log
        .query(&chain, None, None)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.action)
        .collect();
    assert_eq!(actions, vec!["test.backup".to_string()]);
    let verified = restored_log.verify_chain(&chain).await.unwrap();
    assert!(
        verified.valid,
        "the restored audit chain does not verify: {verified:?}"
    );
}
