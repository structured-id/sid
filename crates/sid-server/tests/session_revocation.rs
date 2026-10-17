// SPDX-License-Identifier: AGPL-3.0-only
//! Ending a session is one storage transition: the session, the sessions it
//! authenticated and their refresh tokens end together or not at all.

mod common;

use common::mock_storage::MockStorage;
use sid_authn::revocation_cache::RevocationCache;
use sid_authn::revocation_cascade::RevocationCascadeService;
use sid_core::models::{
    AuditEntry, ProfileId, RefreshToken, RevocationReason, RevocationTarget, Session,
};
use sid_plugin::{GrantStore, StorageBackend};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

fn profile_id() -> ProfileId {
    ProfileId::parse("0192b1e0-7c3a-7f4e-8a5d-3c2b1a0f9e8d").unwrap()
}

fn session() -> Session {
    Session::new(
        profile_id(),
        "127.0.0.1".into(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
}

fn refresh_token(session: &Session, hash: &[u8]) -> RefreshToken {
    let id = Uuid::now_v7();
    RefreshToken {
        id,
        token_hash: hash.to_vec(),
        session_id: session.id,
        profile_id: session.profile_id,
        client_id: "client".into(),
        scopes: vec!["openid".into()],
        resource: sid_core::models::ResourceId::generate(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        created_at: chrono::Utc::now(),
        revoked: false,
        replaced_by: None,
        family_id: id,
        grace_expires_at: None,
        dpop_jkt: None,
    }
}

fn cascade(storage: Arc<MockStorage>) -> RevocationCascadeService {
    RevocationCascadeService::new(
        storage,
        Arc::new(RevocationCache::new(
            Duration::from_secs(900),
            Arc::new(sid_plugin::cache::InMemoryCacheBackend::new()),
        )),
    )
}

async fn store(storage: &MockStorage, session: &Session, token: &RefreshToken) {
    let audit = || AuditEntry::system("test", "setup").into();
    storage.create_session(session, audit()).await.unwrap();
    storage.create_refresh_token(token, audit()).await.unwrap();
}

// A session end that fails commits nothing: its refresh tokens are not
// revoked ahead of a deletion that did not happen, so a retry finds the
// same state instead of a live session that can no longer refresh.
#[tokio::test]
async fn test_failed_session_end_changes_nothing() {
    let storage = Arc::new(MockStorage::new().with_failing_session_end());
    let s = session();
    let token = refresh_token(&s, b"failed-end");
    store(&storage, &s, &token).await;

    let result = cascade(storage.clone())
        .revoke_session(s.id, RevocationReason::Admin, "admin", "session.revoke")
        .await;

    assert!(result.is_err(), "the failed end is reported");
    assert!(storage.get_session(s.id).await.unwrap().is_some());
    let stored = storage
        .get_refresh_token_by_hash(b"failed-end")
        .await
        .unwrap()
        .expect("token kept");
    assert!(
        !stored.revoked,
        "nothing revoked when the end did not commit"
    );
}

// A session end takes the refresh tokens of the session and of the sessions
// it authenticated with them: none can refresh afterwards.
#[tokio::test]
async fn test_session_end_takes_refresh_tokens_with_it() {
    let storage = Arc::new(MockStorage::new());
    let parent = session();
    let mut dependent = session();
    dependent.authenticated_by = Some(parent.id);
    store(&storage, &parent, &refresh_token(&parent, b"parent")).await;
    store(
        &storage,
        &dependent,
        &refresh_token(&dependent, b"dependent"),
    )
    .await;

    cascade(storage.clone())
        .revoke_session(
            parent.id,
            RevocationReason::Admin,
            "admin",
            "session.revoke",
        )
        .await
        .unwrap();

    for hash in [b"parent".as_slice(), b"dependent"] {
        assert!(
            storage
                .get_refresh_token_by_hash(hash)
                .await
                .unwrap()
                .is_none(),
            "refresh token of an ended session is gone"
        );
    }
    assert!(storage.get_session(dependent.id).await.unwrap().is_none());
}

// The report of a session end names only what ended: a browser session that
// never held a refresh token counts as the session alone, and the sessions it
// authenticated as one entry each.
#[tokio::test]
async fn test_session_end_reports_only_what_ended() {
    let storage = Arc::new(MockStorage::new());
    let parent = session();
    let mut dependent = session();
    dependent.authenticated_by = Some(parent.id);
    let audit = || AuditEntry::system("test", "setup").into();
    storage.create_session(&parent, audit()).await.unwrap();
    storage.create_session(&dependent, audit()).await.unwrap();

    let req = cascade(storage)
        .revoke_session(
            parent.id,
            RevocationReason::Admin,
            "admin",
            "session.revoke",
        )
        .await
        .unwrap();

    assert_eq!(req.cascade_entries.len(), 1);
    assert_eq!(req.cascade_entries[0].target, RevocationTarget::Session);
    assert_eq!(req.cascade_entries[0].entity_id, dependent.id.to_string());
    assert_eq!(req.total_revoked(), 2);
}
