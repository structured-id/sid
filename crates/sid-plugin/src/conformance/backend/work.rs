// SPDX-License-Identifier: AGPL-3.0-only
//! Work the full backend's mutations owe, committed with them. The work store
//! contract itself is the work store conformance. Each scenario uses its own
//! work kind, so scenarios sharing one database never see each other's work.

use chrono::{Duration, Utc};
use sid_core::Error;
use sid_core::models::{
    Event, LOGOUT_DELIVERY_ATTEMPTS, LogoutDelivery, NewWork, RevocationReason, Session,
    SessionEnd, WorkKind, WorkState,
};
use sid_plugin::storage::StorageBackend;
use uuid::Uuid;

fn unique_kind(scenario: &str) -> WorkKind {
    WorkKind::new(&format!("test.{scenario}.{}", Uuid::now_v7().simple())).unwrap()
}

fn work(kind: &WorkKind) -> NewWork {
    NewWork::new(kind.clone(), b"payload".to_vec())
}

/// A magic link is consumed at most once: the first consumption returns it,
/// every later one (and one of an expired link) returns nothing, and of
/// concurrent consumptions exactly one wins.
pub async fn test_magic_link_consumed_once(backend: &dyn StorageBackend) {
    use sid_core::models::MagicLinkSession;

    let link = MagicLinkSession::new("once@sid.example.com", "hash-once".into());
    backend
        .create_magic_link_session(&link, super::test_audit())
        .await
        .unwrap();
    let first = backend
        .try_consume_magic_link_session(link.id, super::test_audit())
        .await
        .unwrap();
    assert_eq!(first.map(|s| s.id), Some(link.id));
    assert!(
        backend
            .try_consume_magic_link_session(link.id, super::test_audit())
            .await
            .unwrap()
            .is_none(),
        "a consumed magic link was consumed again"
    );

    let mut expired = MagicLinkSession::new("late@sid.example.com", "hash-late".into());
    expired.expires_at = Utc::now() - Duration::minutes(1);
    backend
        .create_magic_link_session(&expired, super::test_audit())
        .await
        .unwrap();
    assert!(
        backend
            .try_consume_magic_link_session(expired.id, super::test_audit())
            .await
            .unwrap()
            .is_none(),
        "an expired magic link was consumed"
    );

    let raced = MagicLinkSession::new("race@sid.example.com", "hash-race".into());
    backend
        .create_magic_link_session(&raced, super::test_audit())
        .await
        .unwrap();
    let take = || backend.try_consume_magic_link_session(raced.id, super::test_audit());
    let (a, b, c, d) = tokio::join!(take(), take(), take(), take());
    let winners = [a, b, c, d]
        .into_iter()
        .filter(|r| r.as_ref().unwrap().is_some())
        .count();
    assert_eq!(winners, 1, "concurrent consumptions of one link");
}

/// A session the limit evicts ends like any other: its client is owed a
/// logout, committed with the eviction. Which session is evicted is the grant
/// store's conformance.
pub async fn test_session_limit_evicts_oldest(backend: &dyn StorageBackend) {
    let client = super::create_test_oauth2_client(&format!("limit_{}", Uuid::now_v7().simple()));
    super::application::store_client(backend, &client, super::test_audit())
        .await
        .unwrap();
    let profile = super::create_test_profile("session_limit");
    backend
        .create_profile(&profile, super::test_audit())
        .await
        .unwrap();

    let mut oldest = super::create_test_session(profile.id);
    oldest.client_id = Some(client.client_id.clone());
    oldest.created_at = Utc::now() - Duration::minutes(2);
    backend
        .create_session_atomic(&oldest, 0, None, super::test_audit())
        .await
        .unwrap();

    let newest = super::create_test_session(profile.id);
    let evicted = backend
        .create_session_atomic(&newest, 1, None, super::test_audit())
        .await
        .unwrap();
    assert_eq!(evicted, vec![oldest.id]);
    let owed = LogoutDelivery::for_ended_session(&oldest).unwrap().work();
    assert_eq!(
        backend.get_work(owed.id).await.unwrap().map(|r| r.state),
        Some(WorkState::Pending),
        "the evicted session's client was not owed a logout"
    );
}

/// Every ended session owes what `SessionEnd` names, stored with the
/// deletion: its client's back-channel logout (a first-party session owes
/// none) and the `sid.session.revoked.v1` event with the reason and actor.
/// Ending the same session again owes nothing new; work the caller owes
/// commits with the deletion too, and deleting a missing session owes nothing.
pub async fn test_session_end_owes_client_logout(backend: &dyn StorageBackend) {
    let client = super::create_test_oauth2_client(&format!("logout_{}", Uuid::now_v7().simple()));
    super::application::store_client(backend, &client, super::test_audit())
        .await
        .unwrap();
    let profile = super::create_test_profile("logout_owed");
    backend
        .create_profile(&profile, super::test_audit())
        .await
        .unwrap();
    let end = SessionEnd::new(RevocationReason::Admin, "admin-actor");
    let logout = |s: &Session| LogoutDelivery::for_ended_session(s).map(|l| l.work().id);
    let revoked = |s: &Session| end.revoked_event(s.id, s.profile_id).relay().id;

    let mut single = super::create_test_session(profile.id);
    single.client_id = Some(client.client_id.clone());
    backend
        .create_session(&single, super::test_audit())
        .await
        .unwrap();
    let caller_owed = work(&unique_kind("session_end"));
    backend
        .delete_session(
            single.id,
            &end,
            super::test_audit().with_work(caller_owed.clone()),
        )
        .await
        .unwrap();
    for id in [logout(&single).unwrap(), revoked(&single), caller_owed.id] {
        let record = backend.get_work(id).await.unwrap();
        assert_eq!(
            record.map(|r| r.state),
            Some(WorkState::Pending),
            "work owed by the session's end was not stored with it"
        );
    }
    let owed_event = backend
        .export_work()
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.record.id == revoked(&single))
        .expect("the revoked event is exported with its payload");
    let event: Event = serde_json::from_slice(&owed_event.payload).unwrap();
    assert_eq!(event.data["reason"], "admin");
    assert_eq!(event.data["by"], "admin-actor");

    // A session that is already gone ends nothing and owes nothing.
    let missing = super::create_test_session(profile.id);
    backend
        .delete_session(missing.id, &end, super::test_audit())
        .await
        .unwrap();
    assert!(backend.get_work(revoked(&missing)).await.unwrap().is_none());

    let mut bulk = super::create_test_session(profile.id);
    bulk.client_id = Some(client.client_id.clone());
    let first_party = super::create_test_session(profile.id);
    for s in [&bulk, &first_party] {
        backend
            .create_session(s, super::test_audit())
            .await
            .unwrap();
    }
    let ended = backend
        .delete_sessions_by_profile(profile.id, &end, super::test_audit())
        .await
        .unwrap();
    assert_eq!(ended.len(), 2);
    let record = backend
        .get_work(logout(&bulk).unwrap())
        .await
        .unwrap()
        .expect("the client's logout was not stored with the deletion");
    assert_eq!(record.state, WorkState::Pending);
    assert_eq!(record.max_attempts, LOGOUT_DELIVERY_ATTEMPTS);
    assert!(logout(&first_party).is_none());
    for s in [&bulk, &first_party] {
        assert!(
            backend.get_work(revoked(s)).await.unwrap().is_some(),
            "an ended session's revoked event was not stored with the deletion"
        );
    }

    // The session is ended again (a retried revocation): nothing new is owed.
    backend
        .create_session(&bulk, super::test_audit())
        .await
        .unwrap();
    backend
        .delete_sessions_by_profile(profile.id, &end, super::test_audit())
        .await
        .unwrap();
    for id in [logout(&bulk).unwrap(), revoked(&bulk)] {
        assert_eq!(
            backend.get_work(id).await.unwrap().map(|r| r.attempts),
            Some(0)
        );
    }
}

/// Removing expired role assignments returns them and stores, with the
/// deletion, the `role_expired` event each owes; active and permanent
/// assignments stay. A second run finds them gone and owes nothing new.
/// (Other scenarios may share the database, so only this one's assignments
/// are looked at.)
pub async fn test_expired_role_assignments_owe_event(backend: &dyn StorageBackend) {
    use sid_core::models::{ProjectId, Role, RoleAssignment, RoleAssignmentPrincipal};

    let profile = super::create_test_profile("role_expiry");
    backend
        .create_profile(&profile, super::test_audit())
        .await
        .unwrap();
    let key = format!("temp_{}", Uuid::now_v7().simple());
    let role = Role::new(ProjectId::system(), &key, &key);
    backend
        .create_role(&role, super::test_audit())
        .await
        .unwrap();
    let principal = RoleAssignmentPrincipal::Profile(profile.id);
    let expired = RoleAssignment::new(principal.clone(), role.id)
        .with_expiry(Utc::now() - Duration::hours(1));
    let active = RoleAssignment::new(principal.clone(), role.id)
        .with_expiry(Utc::now() + Duration::hours(24));
    let permanent = RoleAssignment::new(principal, role.id);
    for a in [&expired, &active, &permanent] {
        backend
            .create_role_assignment(a, super::test_audit())
            .await
            .unwrap();
    }

    let removed = backend
        .cleanup_expired_role_assignments(super::test_audit())
        .await
        .unwrap();
    let mine: Vec<_> = removed
        .iter()
        .filter(|a| [expired.id, active.id, permanent.id].contains(&a.id))
        .map(|a| a.id)
        .collect();
    assert_eq!(mine, [expired.id], "only the expired assignment is removed");
    let owed = expired.expired_event().relay().id;
    assert_eq!(
        backend.get_work(owed).await.unwrap().map(|r| r.state),
        Some(WorkState::Pending),
        "the expired event was not stored with the deletion"
    );
    for kept in [&active, &permanent] {
        assert!(
            backend
                .get_work(kept.expired_event().relay().id)
                .await
                .unwrap()
                .is_none()
        );
    }
    let left: Vec<_> = backend
        .list_role_assignments_for_profile(profile.id)
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.id)
        .collect();
    assert!(left.contains(&active.id) && left.contains(&permanent.id));
    assert!(!left.contains(&expired.id));

    let again = backend
        .cleanup_expired_role_assignments(super::test_audit())
        .await
        .unwrap();
    assert!(again.iter().all(|a| a.id != expired.id));
}

/// Work a mutation owes is stored in the mutation's own transaction: it
/// exists once the mutation returns, and a mutation that is refused (here a
/// client id that already exists) leaves no work behind.
pub async fn test_mutation_commits_owed_work(backend: &dyn StorageBackend) {
    let kind = unique_kind("owed");
    let profile = super::create_test_profile("owed_work");
    let owed_by_profile = work(&kind);
    backend
        .create_profile(
            &profile,
            super::test_audit().with_work(owed_by_profile.clone()),
        )
        .await
        .unwrap();
    let session = super::create_test_session(profile.id);
    let owed_by_session = work(&kind);
    backend
        .create_session(
            &session,
            super::test_audit().with_work(owed_by_session.clone()),
        )
        .await
        .unwrap();
    for owed in [&owed_by_profile, &owed_by_session] {
        let record = backend
            .get_work(owed.id)
            .await
            .unwrap()
            .expect("owed work was not stored with its mutation");
        assert_eq!(record.state, WorkState::Pending);
    }

    let client = super::create_test_oauth2_client(&format!("owed_{}", Uuid::now_v7().simple()));
    super::application::store_client(backend, &client, super::test_audit())
        .await
        .unwrap();
    let orphan = work(&kind);
    let refused = super::application::store_client(
        backend,
        &client,
        super::test_audit().with_work(orphan.clone()),
    )
    .await;
    assert!(matches!(refused, Err(Error::Conflict(_))), "{refused:?}");
    assert!(
        backend.get_work(orphan.id).await.unwrap().is_none(),
        "a refused mutation stored the work it owed"
    );
}
