// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use sid_core::models::{AuditEntry, Principal, PrincipalType, Profile, ProfileId, WorkState};
use sid_plugin::WorkStore;
use sid_storage::sqlite::SqliteBackend;

async fn storage() -> Arc<SqliteBackend> {
    Arc::new(SqliteBackend::new_in_memory().await.unwrap())
}

/// A profile that binds `email`.
async fn holder(storage: &SqliteBackend, email: &str) -> ProfileId {
    let profile = Profile::new(Some(&format!("u{}", uuid::Uuid::now_v7().simple())));
    storage
        .create_profile(&profile, AuditEntry::system("test", "profile").into())
        .await
        .unwrap();
    let principal = Principal::new(profile.id, PrincipalType::Email, email);
    storage
        .save_principal(&principal, AuditEntry::system("test", "principal").into())
        .await
        .unwrap();
    profile.id
}

fn claimed(check: &ContestCheck) -> ClaimedWork {
    let work = check.work();
    ClaimedWork {
        id: work.id,
        kind: work.kind,
        payload: work.payload,
        attempt: 1,
        max_attempts: work.max_attempts,
        generation: 1,
        expires_at: None,
    }
}

async fn owed(storage: &SqliteBackend, check: &ContestCheck, to: ProfileId) -> Option<WorkState> {
    storage
        .get_work(check.contested_event(to).relay().id)
        .await
        .unwrap()
        .map(|w| w.state)
}

/// When a second profile binds an identifier, the earlier holder is owed
/// the contested event and the new holder is not; running the check again
/// owes nothing new.
#[tokio::test]
async fn test_second_holder_contests_the_first() {
    let storage = storage().await;
    let first = holder(&storage, "shared@sid.example.com").await;
    let second = holder(&storage, "shared@sid.example.com").await;
    let handler = PrincipalContestHandler::new(storage.clone());
    let check = ContestCheck::new(PrincipalType::Email, "shared@sid.example.com", second);

    assert_eq!(
        handler.handle(&claimed(&check)).await,
        WorkOutcome::Done(None)
    );
    assert_eq!(
        owed(&storage, &check, first).await,
        Some(WorkState::Pending)
    );
    assert_eq!(owed(&storage, &check, second).await, None);

    assert_eq!(
        handler.handle(&claimed(&check)).await,
        WorkOutcome::Done(None)
    );
    let again = storage
        .get_work(check.contested_event(first).relay().id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.attempts, 0, "the holder was told twice");
}

/// A sole holder contests nobody.
#[tokio::test]
async fn test_sole_holder_owes_nothing() {
    let storage = storage().await;
    let only = holder(&storage, "alone@sid.example.com").await;
    let handler = PrincipalContestHandler::new(storage.clone());
    let check = ContestCheck::new(PrincipalType::Email, "alone@sid.example.com", only);

    assert_eq!(
        handler.handle(&claimed(&check)).await,
        WorkOutcome::Done(None)
    );
    assert_eq!(owed(&storage, &check, only).await, None);
}

/// A check for an identifier that is gone again is done with nothing owed;
/// an unreadable check can never succeed.
#[tokio::test]
async fn test_missing_or_malformed_check() {
    let storage = storage().await;
    let handler = PrincipalContestHandler::new(storage.clone());
    let gone = ContestCheck::new(
        PrincipalType::Email,
        "gone@sid.example.com",
        ProfileId::generate(),
    );
    assert_eq!(
        handler.handle(&claimed(&gone)).await,
        WorkOutcome::Done(None)
    );

    let mut malformed = claimed(&gone);
    malformed.payload = b"not json".to_vec();
    assert!(matches!(
        handler.handle(&malformed).await,
        WorkOutcome::Permanent(_)
    ));
}
